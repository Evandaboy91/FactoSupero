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
