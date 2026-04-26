"""
FactoSupero
-----------
Facts sharing + attestation relay + bounty workflow companion for HermesSup.

This is intentionally a single-file Python app (per request) that provides:
- REST API for creating facts, tagging, reacting, and managing bounties
- Optional on-chain publish / attestation stamping helpers
- Local SQLite persistence for browsing and basic analytics
- An event indexer that can backfill / follow HermesSup logs (optional)

Run:
  python FactoSupero/app.py

Env:
  FACTO_HOST=127.0.0.1
  FACTO_PORT=8787
  FACTO_DB=FactoSupero.sqlite3
  FACTO_CHAIN_RPC=https://...
  FACTO_CHAIN_ID=1
  FACTO_CONTRACT=0x....
  FACTO_PRIVATE_KEY=0x....   (optional, used for on-chain tx helpers)
  FACTO_ENABLE_INDEXER=0/1
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import contextlib
import dataclasses
import datetime as dt
import hashlib
import json
import logging
import os
import secrets
import signal
import sqlite3
import string
import textwrap
import time
import typing as t
import uuid

import httpx
import orjson
from dotenv import load_dotenv
from eth_account import Account
from eth_account.messages import encode_typed_data
from fastapi import (
    Body,
    Depends,
    FastAPI,
    HTTPException,
    Request,
    Response,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, ORJSONResponse, PlainTextResponse
from pydantic import BaseModel, Field, field_validator
from rich.console import Console
from rich.logging import RichHandler
from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    create_engine,
    func,
    select,
    text as sql_text,
)
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, relationship, sessionmaker
from web3 import Web3
from web3.contract import Contract
from web3.middleware import geth_poa_middleware

# ------------------------------ logging ------------------------------

console = Console()
LOG = logging.getLogger("FactoSupero")


def _setup_logging() -> None:
    level = os.getenv("FACTO_LOG_LEVEL", "INFO").upper().strip()
    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(rich_tracebacks=True, markup=False)],
    )


# ------------------------------ helpers ------------------------------


def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def to_iso(ts: dt.datetime) -> str:
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=dt.timezone.utc)
    return ts.astimezone(dt.timezone.utc).isoformat()


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def keccak_hex(b: bytes) -> str:
    return Web3.keccak(b).hex()


def b32_hex(s: str) -> str:
    """
    Convert a string to a 32-byte hex (keccak) used as bytes32 in Solidity.
    """
    if not isinstance(s, str) or not s.strip():
        raise ValueError("Empty string")
    return Web3.keccak(text=s.strip()).hex()


def is_hex_address(addr: str) -> bool:
    with contextlib.suppress(Exception):
        return Web3.is_checksum_address(addr)
    return False


def checksum(addr: str) -> str:
    return Web3.to_checksum_address(addr)


def rand_topic_like() -> str:
    # produce a human-ish topic label; client can also use keccak to bytes32
    words = [
        "orbit",
        "ledger",
        "memo",
        "signal",
        "gloss",
        "vector",
        "proof",
        "trace",
        "delta",
        "atlas",
        "glyph",
        "axiom",
        "kernel",
        "pact",
        "wave",
        "grain",
        "chime",
        "cipher",
    ]
    return f"{secrets.choice(words)}.{secrets.choice(words)}.{secrets.randbelow(10_000)}"


def short_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


def now_s() -> int:
    return int(time.time())


def clamp(n: int, lo: int, hi: int) -> int:
    if n < lo:
        return lo
    if n > hi:
        return hi
    return n


def safe_int(x: t.Any, default: int) -> int:
    try:
        return int(x)
    except Exception:
        return default


def json_dumps(obj: t.Any) -> str:
    return orjson.dumps(obj, option=orjson.OPT_SORT_KEYS).decode("utf-8")


def json_loads(s: str) -> t.Any:
    return orjson.loads(s.encode("utf-8"))


def normalize_text(s: str) -> str:
    s = s.replace("\r\n", "\n").replace("\r", "\n")
    s = "\n".join(line.rstrip() for line in s.split("\n"))
    return s.strip()


def bytes32_from_hex(h: str) -> bytes:
    if not isinstance(h, str):
        raise ValueError("hex string expected")
    if h.startswith("0x"):
        h = h[2:]
    b = bytes.fromhex(h)
    if len(b) != 32:
        raise ValueError("expected 32 bytes")
    return b


def bytes32_hex_or_keccak(x: str) -> str:
    x = x.strip()
    if x.startswith("0x") and len(x) == 66:
        bytes32_from_hex(x)
        return x
    return Web3.keccak(text=x).hex()


def validate_bytes32_hex(h: str) -> str:
    if not isinstance(h, str) or not h.startswith("0x") or len(h) != 66:
        raise ValueError("bytes32 must be 0x + 64 hex chars")
    bytes32_from_hex(h)
    return h


def mk_client_origin_list() -> list[str]:
    env = os.getenv("FACTO_CORS_ORIGINS", "")
    if not env.strip():
        return ["*"]
    return [x.strip() for x in env.split(",") if x.strip()]


# ------------------------------ config ------------------------------


@dataclasses.dataclass(frozen=True)
class Settings:
    host: str
    port: int
    db_path: str
    enable_indexer: bool
    chain_rpc: str
    chain_id: int
    contract_address: str
    private_key: str | None
    indexer_poll_s: float
    indexer_from_block: int
    max_page_size: int
    ui_title: str
    ui_brand: str

    @staticmethod
    def load() -> "Settings":
        load_dotenv()
        host = os.getenv("FACTO_HOST", "127.0.0.1").strip()
