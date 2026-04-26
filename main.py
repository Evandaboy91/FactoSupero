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
