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
        port = safe_int(os.getenv("FACTO_PORT", "8787"), 8787)
        db_path = os.getenv("FACTO_DB", "FactoSupero.sqlite3").strip()
        enable_indexer = os.getenv("FACTO_ENABLE_INDEXER", "0").strip() in ("1", "true", "yes", "on")
        chain_rpc = os.getenv("FACTO_CHAIN_RPC", "").strip()
        chain_id = safe_int(os.getenv("FACTO_CHAIN_ID", "1"), 1)
        contract_address = os.getenv(
            "FACTO_CONTRACT",
            "0xD0aB9cE1f2A3b4C5d6E7f8091a2B3c4D5e6F7081",
        ).strip()
        private_key = os.getenv("FACTO_PRIVATE_KEY", "").strip() or None
        poll = float(os.getenv("FACTO_INDEXER_POLL_S", "6.7").strip())
        from_block = safe_int(os.getenv("FACTO_INDEXER_FROM_BLOCK", "0").strip(), 0)
        max_page_size = clamp(safe_int(os.getenv("FACTO_MAX_PAGE", "200").strip(), 200), 50, 2000)
        ui_title = os.getenv("FACTO_UI_TITLE", "FactoSupero").strip() or "FactoSupero"
        ui_brand = os.getenv("FACTO_UI_BRAND", "Facts · Attestations · Bounties").strip() or "Facts · Attestations · Bounties"
        if contract_address:
            with contextlib.suppress(Exception):
                contract_address = checksum(contract_address)
        return Settings(
            host=host,
            port=port,
            db_path=db_path,
            enable_indexer=enable_indexer,
            chain_rpc=chain_rpc,
            chain_id=chain_id,
            contract_address=contract_address,
            private_key=private_key,
            indexer_poll_s=poll,
            indexer_from_block=from_block,
            max_page_size=max_page_size,
            ui_title=ui_title,
            ui_brand=ui_brand,
        )


SETTINGS = Settings.load()


# ------------------------------ database ------------------------------


class Base(DeclarativeBase):
    pass


class FactRow(Base):
    __tablename__ = "facts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    topic_label: Mapped[str] = mapped_column(String(200), index=True)
    topic_b32: Mapped[str] = mapped_column(String(66), index=True)
    fact_b32: Mapped[str] = mapped_column(String(66), index=True)
    uri_b32: Mapped[str] = mapped_column(String(66), index=True)
    submitter: Mapped[str] = mapped_column(String(64), index=True)
    flags: Mapped[int] = mapped_column(Integer, default=0)
    note: Mapped[str] = mapped_column(Text, default="")
    source: Mapped[str] = mapped_column(String(32), default="api")  # api|chain|import
    chain_fact_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    chain_tx: Mapped[str] = mapped_column(String(90), default="", index=True)
    chain_block: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    attestation_score: Mapped[int] = mapped_column(Integer, default=0)
    reaction_sum: Mapped[int] = mapped_column(Integer, default=0)
    tag_count: Mapped[int] = mapped_column(Integer, default=0)

    tags: Mapped[list["TagRow"]] = relationship(back_populates="fact", cascade="all,delete-orphan")
    reactions: Mapped[list["ReactionRow"]] = relationship(back_populates="fact", cascade="all,delete-orphan")
    attestations: Mapped[list["AttestationRow"]] = relationship(back_populates="fact", cascade="all,delete-orphan")
    bounties: Mapped[list["BountyRow"]] = relationship(back_populates="fact", cascade="all,delete-orphan")

    __table_args__ = (
        UniqueConstraint("topic_b32", "fact_b32", "uri_b32", "submitter", name="uq_fact_core"),
        CheckConstraint("length(topic_b32)=66", name="ck_topic_len"),
        CheckConstraint("length(fact_b32)=66", name="ck_fact_len"),
        CheckConstraint("length(uri_b32)=66", name="ck_uri_len"),
    )


class TagRow(Base):
    __tablename__ = "tags"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    fact_id: Mapped[int] = mapped_column(ForeignKey("facts.id", ondelete="CASCADE"), index=True)
    tag_b32: Mapped[str] = mapped_column(String(66), index=True)
    tag_label: Mapped[str] = mapped_column(String(200), index=True)
    who: Mapped[str] = mapped_column(String(64), index=True)

    fact: Mapped[FactRow] = relationship(back_populates="tags")

    __table_args__ = (UniqueConstraint("fact_id", "tag_b32", name="uq_fact_tag"),)


class ReactionRow(Base):
    __tablename__ = "reactions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    fact_id: Mapped[int] = mapped_column(ForeignKey("facts.id", ondelete="CASCADE"), index=True)
    who: Mapped[str] = mapped_column(String(64), index=True)
    delta: Mapped[int] = mapped_column(Integer)
    lane_hint: Mapped[int] = mapped_column(Integer, default=0)

    fact: Mapped[FactRow] = relationship(back_populates="reactions")

    __table_args__ = (UniqueConstraint("fact_id", "who", name="uq_fact_reaction"), CheckConstraint("delta IN (-1,1)", name="ck_delta"))


class AttestationRow(Base):
    __tablename__ = "attestations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    fact_id: Mapped[int] = mapped_column(ForeignKey("facts.id", ondelete="CASCADE"), index=True)
    lane_id: Mapped[int] = mapped_column(Integer, index=True)
    signer: Mapped[str] = mapped_column(String(64), index=True)
    relay: Mapped[str] = mapped_column(String(64), index=True)
    packet_hash: Mapped[str] = mapped_column(String(66), index=True)
    weight: Mapped[int] = mapped_column(Integer, default=0)
    signer_nonce: Mapped[int] = mapped_column(Integer, default=0)
    chain_tx: Mapped[str] = mapped_column(String(90), default="", index=True)
    chain_block: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)

    fact: Mapped[FactRow] = relationship(back_populates="attestations")

    __table_args__ = (Index("ix_att_fact_lane", "fact_id", "lane_id"),)


class BountyRow(Base):
    __tablename__ = "bounties"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
