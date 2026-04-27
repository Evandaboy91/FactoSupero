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
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    fact_id: Mapped[int] = mapped_column(ForeignKey("facts.id", ondelete="CASCADE"), index=True)
    sponsor: Mapped[str] = mapped_column(String(64), index=True)
    rubric_b32: Mapped[str] = mapped_column(String(66), index=True)
    amount_wei: Mapped[int] = mapped_column(Integer)
    chain_bounty_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    chain_tx: Mapped[str] = mapped_column(String(90), default="", index=True)
    chain_block: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    state: Mapped[str] = mapped_column(String(24), default="open")

    fact: Mapped[FactRow] = relationship(back_populates="bounties")

    __table_args__ = (Index("ix_bounty_fact", "fact_id"),)


class ChainCursorRow(Base):
    __tablename__ = "chain_cursor"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    chain_id: Mapped[int] = mapped_column(Integer, index=True)
    contract: Mapped[str] = mapped_column(String(64), index=True)
    last_block: Mapped[int] = mapped_column(Integer, default=0)
    meta: Mapped[str] = mapped_column(Text, default="{}")

    __table_args__ = (UniqueConstraint("chain_id", "contract", name="uq_cursor"),)


def make_engine(db_path: str) -> Engine:
    url = f"sqlite+pysqlite:///{db_path}"
    eng = create_engine(url, future=True, echo=False, connect_args={"check_same_thread": False})
    return eng


ENGINE = make_engine(SETTINGS.db_path)
SessionLocal = sessionmaker(bind=ENGINE, autoflush=False, autocommit=False, expire_on_commit=False, future=True)


def init_db() -> None:
    Base.metadata.create_all(ENGINE)
    with SessionLocal() as s:
        cur = s.execute(select(ChainCursorRow).where(ChainCursorRow.chain_id == SETTINGS.chain_id, ChainCursorRow.contract == SETTINGS.contract_address)).scalar_one_or_none()
        if cur is None:
            s.add(
                ChainCursorRow(
                    chain_id=SETTINGS.chain_id,
                    contract=SETTINGS.contract_address,
                    last_block=max(0, SETTINGS.indexer_from_block),
                    meta=json_dumps({"created": to_iso(utcnow()), "poll_s": SETTINGS.indexer_poll_s}),
                )
            )
            s.commit()


def get_db() -> t.Iterator[Session]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ------------------------------ web3 / contract ------------------------------


HERMES_SUP_ABI: list[dict[str, t.Any]] = [
    {
        "type": "function",
        "name": "publishFact",
        "stateMutability": "nonpayable",
        "inputs": [
            {"name": "topic", "type": "bytes32"},
            {"name": "factHash", "type": "bytes32"},
            {"name": "uriHash", "type": "bytes32"},
            {"name": "flags", "type": "uint32"},
        ],
        "outputs": [{"name": "factId", "type": "uint64"}],
    },
    {
        "type": "function",
        "name": "publishAttested",
        "stateMutability": "nonpayable",
        "inputs": [
            {
                "name": "p",
                "type": "tuple",
                "components": [
                    {"name": "topic", "type": "bytes32"},
                    {"name": "factHash", "type": "bytes32"},
                    {"name": "uriHash", "type": "bytes32"},
                    {"name": "submitter", "type": "address"},
                    {"name": "deadline", "type": "uint64"},
                    {"name": "signerNonce", "type": "uint64"},
                    {"name": "lane", "type": "uint32"},
                    {"name": "weightHint", "type": "uint32"},
                    {"name": "context", "type": "bytes32"},
                ],
            },
            {"name": "sig", "type": "bytes"},
        ],
        "outputs": [
            {"name": "factId", "type": "uint64"},
            {"name": "packetHash", "type": "bytes32"},
            {"name": "signer", "type": "address"},
        ],
    },
    {
        "type": "function",
        "name": "addTag",
        "stateMutability": "nonpayable",
        "inputs": [{"name": "factId", "type": "uint64"}, {"name": "tag", "type": "bytes32"}],
        "outputs": [],
    },
    {
        "type": "function",
        "name": "react",
        "stateMutability": "nonpayable",
        "inputs": [{"name": "factId", "type": "uint64"}, {"name": "delta", "type": "int8"}, {"name": "laneHint", "type": "uint32"}],
        "outputs": [],
    },
    {
        "type": "function",
        "name": "postBounty",
        "stateMutability": "payable",
        "inputs": [{"name": "factId", "type": "uint64"}, {"name": "rubric", "type": "bytes32"}],
        "outputs": [{"name": "bountyId", "type": "uint64"}],
    },
    {
        "type": "event",
        "name": "FactPublished",
        "anonymous": False,
        "inputs": [
            {"indexed": True, "name": "factId", "type": "uint64"},
            {"indexed": True, "name": "topic", "type": "bytes32"},
            {"indexed": True, "name": "factHash", "type": "bytes32"},
            {"indexed": False, "name": "submitter", "type": "address"},
            {"indexed": False, "name": "publishedAt", "type": "uint64"},
            {"indexed": False, "name": "flags", "type": "uint32"},
            {"indexed": False, "name": "uriHash", "type": "bytes32"},
        ],
    },
    {
        "type": "event",
        "name": "AttestationStamped",
        "anonymous": False,
        "inputs": [
            {"indexed": True, "name": "factId", "type": "uint64"},
            {"indexed": False, "name": "attestOrRelay", "type": "address"},
            {"indexed": True, "name": "signer", "type": "address"},
            {"indexed": False, "name": "packetHash", "type": "bytes32"},
            {"indexed": False, "name": "at", "type": "uint64"},
            {"indexed": False, "name": "weight", "type": "uint32"},
        ],
    },
    {
        "type": "event",
        "name": "BountyPosted",
        "anonymous": False,
        "inputs": [
            {"indexed": True, "name": "bountyId", "type": "uint64"},
            {"indexed": True, "name": "factId", "type": "uint64"},
            {"indexed": True, "name": "sponsor", "type": "address"},
            {"indexed": False, "name": "amount", "type": "uint256"},
            {"indexed": False, "name": "rubric", "type": "bytes32"},
        ],
    },
]


class Chain:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.w3: Web3 | None = None
        self.contract: Contract | None = None

    def enabled(self) -> bool:
        return bool(self.settings.chain_rpc and self.settings.contract_address)

    def connect(self) -> None:
        if not self.enabled():
            return
        self.w3 = Web3(Web3.HTTPProvider(self.settings.chain_rpc, request_kwargs={"timeout": 25}))
        # allow PoA for devnets; harmless on mainnet
        self.w3.middleware_onion.inject(geth_poa_middleware, layer=0)
        if not self.w3.is_connected():
            raise RuntimeError("RPC not reachable")
        self.contract = self.w3.eth.contract(address=checksum(self.settings.contract_address), abi=HERMES_SUP_ABI)

    def acct(self) -> Account | None:
        if not self.settings.private_key:
            return None
        return Account.from_key(self.settings.private_key)

    def chain_id(self) -> int:
        if not self.w3:
            return self.settings.chain_id
        with contextlib.suppress(Exception):
            return int(self.w3.eth.chain_id)
        return self.settings.chain_id

    def gas_params(self) -> dict[str, int]:
        if not self.w3:
            return {}
        base = {}
        with contextlib.suppress(Exception):
            gp = int(self.w3.eth.gas_price)
            base["gasPrice"] = gp
        return base

    def send_tx(self, fn, *, value_wei: int = 0) -> dict[str, t.Any]:
        if not self.w3 or not self.contract:
            raise RuntimeError("Chain not connected")
        acct = self.acct()
        if acct is None:
            raise RuntimeError("No private key configured")
        nonce = self.w3.eth.get_transaction_count(acct.address)
        tx = fn.build_transaction(
            {
                "from": acct.address,
                "nonce": nonce,
                "value": int(value_wei),
                **self.gas_params(),
            }
        )
        # estimate with a buffer
        with contextlib.suppress(Exception):
            est = int(self.w3.eth.estimate_gas(tx))
            tx["gas"] = int(est * 1.25) + 25_000
        signed = acct.sign_transaction(tx)
        txh = self.w3.eth.send_raw_transaction(signed.rawTransaction)
        rec = self.w3.eth.wait_for_transaction_receipt(txh, timeout=180)
        return {"txHash": txh.hex(), "status": int(rec.status), "blockNumber": int(rec.blockNumber)}


CHAIN = Chain(SETTINGS)
with contextlib.suppress(Exception):
    CHAIN.connect()


# ------------------------------ schemas ------------------------------


class FactCreateIn(BaseModel):
    topic: str = Field(..., description="topic label or bytes32 hex")
    fact_text: str = Field(..., min_length=3, max_length=20_000)
    uri: str = Field("", description="optional URI for richer content (ipfs://, https://, etc)")
    submitter: str = Field("", description="checksum address (optional; UI can set)")
    flags: int = Field(0, ge=0, le=2**32 - 1)
    note: str = Field("", max_length=2_000)

    @field_validator("topic")
    @classmethod
    def _topic_ok(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("topic required")
        if len(v) > 200:
            raise ValueError("topic too long")
        return v

    @field_validator("uri")
    @classmethod
    def _uri_ok(cls, v: str) -> str:
        v = v.strip()
        if len(v) > 2_000:
            raise ValueError("uri too long")
        return v

    @field_validator("submitter")
    @classmethod
    def _submitter_ok(cls, v: str) -> str:
        v = v.strip()
        if not v:
            return v
        if not Web3.is_address(v):
            raise ValueError("invalid address")
        return checksum(v)


class FactOut(BaseModel):
    id: int
    created_at: str
    topic_label: str
    topic_b32: str
    fact_b32: str
    uri_b32: str
    submitter: str
    flags: int
    note: str
    source: str
    chain_fact_id: int | None
    chain_tx: str
    chain_block: int | None
    attestation_score: int
    reaction_sum: int
    tag_count: int


class TagIn(BaseModel):
    tag: str = Field(..., description="tag label or bytes32 hex")
    who: str = Field("", description="optional checksum address")

    @field_validator("tag")
    @classmethod
    def _tag_ok(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("tag required")
        if len(v) > 200:
            raise ValueError("tag too long")
        return v

    @field_validator("who")
    @classmethod
    def _who_ok(cls, v: str) -> str:
        v = v.strip()
        if not v:
            return v
        if not Web3.is_address(v):
            raise ValueError("invalid address")
        return checksum(v)


class ReactionIn(BaseModel):
    delta: int = Field(..., description="-1 or +1")
    lane_hint: int = Field(0, ge=0, le=2**32 - 1)
    who: str = Field("", description="optional checksum address")

    @field_validator("delta")
    @classmethod
    def _delta_ok(cls, v: int) -> int:
        if v not in (-1, 1):
            raise ValueError("delta must be -1 or 1")
        return v

    @field_validator("who")
    @classmethod
    def _who_ok(cls, v: str) -> str:
        v = v.strip()
        if not v:
            return v
        if not Web3.is_address(v):
            raise ValueError("invalid address")
        return checksum(v)


class BountyPostIn(BaseModel):
    amount_wei: int = Field(..., ge=1)
    rubric: str = Field(..., description="rubric label or bytes32 hex")
    sponsor: str = Field("", description="optional checksum address")

    @field_validator("rubric")
    @classmethod
    def _rubric_ok(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("rubric required")
        if len(v) > 240:
            raise ValueError("rubric too long")
        return v

    @field_validator("sponsor")
    @classmethod
    def _sponsor_ok(cls, v: str) -> str:
        v = v.strip()
        if not v:
            return v
        if not Web3.is_address(v):
            raise ValueError("invalid address")
        return checksum(v)


class TypedPacketIn(BaseModel):
    topic_b32: str
    fact_b32: str
    uri_b32: str
    submitter: str
    deadline: int = 0
    signer_nonce: int = 0
    lane: int = 1
    weight_hint: int = 0
    context_b32: str = "0x" + "00" * 32
    signature: str

    @field_validator("topic_b32", "fact_b32", "uri_b32", "context_b32")
    @classmethod
    def _b32_ok(cls, v: str) -> str:
        return validate_bytes32_hex(v)

    @field_validator("submitter")
    @classmethod
    def _addr_ok(cls, v: str) -> str:
        if not Web3.is_address(v):
            raise ValueError("invalid address")
        return checksum(v)

    @field_validator("signature")
    @classmethod
    def _sig_ok(cls, v: str) -> str:
        v = v.strip()
        if not v.startswith("0x"):
            raise ValueError("signature must be 0x...")
        _ = bytes.fromhex(v[2:])
        return v


class HealthOut(BaseModel):
    ok: bool
    time: str
    db: dict[str, t.Any]
    chain: dict[str, t.Any]


# ------------------------------ app ------------------------------


app = FastAPI(title=SETTINGS.ui_title, default_response_class=ORJSONResponse)
app.add_middleware(
    CORSMiddleware,
    allow_origins=mk_client_origin_list(),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ------------------------------ websocket hub ------------------------------


class Hub:
    def __init__(self) -> None:
        self._clients: set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def join(self, ws: WebSocket) -> None:
        await ws.accept()
        async with self._lock:
            self._clients.add(ws)

    async def leave(self, ws: WebSocket) -> None:
        async with self._lock:
            self._clients.discard(ws)

    async def publish(self, payload: dict[str, t.Any]) -> None:
        data = orjson.dumps(payload)
        async with self._lock:
            clients = list(self._clients)
        for ws in clients:
            try:
                await ws.send_bytes(data)
            except Exception:
                await self.leave(ws)


HUB = Hub()


@app.websocket("/ws")
async def ws_feed(ws: WebSocket) -> None:
    await HUB.join(ws)
    try:
        while True:
            # keepalive; clients may also send pings
            _ = await ws.receive_text()
            await ws.send_text("ok")
    except WebSocketDisconnect:
        pass
    finally:
        await HUB.leave(ws)


# ------------------------------ html helper ------------------------------


INDEX_HTML = """<!doctype html>
<html>
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>FactoSupero</title>
<style>
  body { font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial; margin: 0; background:#0b0f16; color:#e8eef8; }
  header { padding: 18px 22px; border-bottom:1px solid #1b2a44; display:flex; align-items:center; justify-content:space-between; }
  .brand { font-weight: 650; letter-spacing: 0.4px; }
  .sub { color:#9fb2d0; font-size: 12px; }
  main { padding: 18px 22px; max-width: 1000px; margin: 0 auto; }
  code { background:#0f1a2b; padding: 2px 6px; border-radius: 6px; }
  a { color:#7fb0ff; text-decoration:none; }
  a:hover { text-decoration:underline; }
  .card { background:#0f1726; border:1px solid #1b2a44; border-radius: 14px; padding: 14px; margin: 12px 0; }
  .row { display:flex; gap:12px; flex-wrap:wrap; }
  .pill { display:inline-block; padding: 4px 8px; border-radius: 999px; background:#111f35; border:1px solid #1b2a44; color:#cfe1ff; font-size:12px;}
  .muted { color:#9fb2d0; }
  .btn { cursor:pointer; border:1px solid #27406c; background:#122540; color:#e8eef8; padding: 8px 12px; border-radius: 12px; }
  .btn:hover { background:#173154; }
  .grid { display:grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap:12px; }
</style>
</head>
<body>
<header>
  <div>
    <div class="brand">FactoSupero</div>
    <div class="sub">Local API for HermesSup — see <code>/docs</code> for full OpenAPI.</div>
  </div>
  <div class="row">
    <a class="pill" href="/docs">API Docs</a>
    <a class="pill" href="/truth">Truth UI</a>
  </div>
</header>
<main>
  <div class="card">
    <div class="row">
      <div class="pill">Health: <a href="/health">/health</a></div>
      <div class="pill">Facts: <a href="/facts">/facts</a></div>
      <div class="pill">Create: <code>POST /facts</code></div>
    </div>
    <p class="muted">This page is a minimal landing. The dedicated web interface lives at <code>/truth</code>.</p>
  </div>
</main>
</body>
</html>
"""


@app.get("/", response_class=HTMLResponse)
def root() -> str:
    return INDEX_HTML


# ------------------------------ services ------------------------------
