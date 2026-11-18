"""
========================================================================
  OBLIVION ORBITAL — Unified Knowledge-Graph, Code-Intelligence &
                      GOTHAM Scoped Threat-Intelligence Suite
========================================================================
  GOTHAM (new in this build) is a scoped exposure-detection module:
    - Crawls ONLY domains you add to an explicit allow-list (assets you
      own / are authorized to test) — never the open internet, never
      "find a person".
    - Detects exposed secrets/credentials/PII patterns with masking,
      confidence scores and evidence — never raw sensitive values.
    - Scores threats from evidence signals (never a verdict about a
      person's identity).
    - Detects scam / phishing messages with a small feed-forward
      neural network written from scratch with numpy (no sklearn /
      tensorflow / torch) — falls back to a keyword heuristic if numpy
      isn't installed.
    - Exports findings to CSV (Excel), JSON, and GEXF (Gephi), and can
      optionally ask a LOCAL LM Studio server to turn a case into a
      short prose summary (nothing is sent anywhere else).
    - The old in-process `exec()` code console (a real RCE risk) now
      runs in an isolated subprocess with a timeout and, on POSIX,
      CPU/memory/file-descriptor limits.
========================================================================
یک برنامه‌ی پایتونی تک‌فایلی که با اجرای همین یک فایل، هم موتور گراف دانش،
هم محیط کد‌نویسی هوشمند (بر پایه‌ی ایده‌های Python LSP) و هم یک سیستم
کنترل داده (احراز هویت + نقش کاربری + ثبت رخداد) را بالا می‌آورد.

این فایل حاصل ادغام و یکپارچه‌سازی فایل‌های زیر است:
  • model_version_1.bin  → هسته‌ی اصلی برنامه (سرور HTTP + گراف دانش + ویرایشگر)
  • __init__.py / hookspecs.py  → سیستم افزونه (Plugin Hooks) برای فرمت‌های ورودی
  • uris.py                     → توابع تبدیل مسیر فایل <-> URI
  • _utils.py                   → ابزارهای کمکی عمومی (merge_dicts و ...)
  • lsp.py / python_ls.py / workspace.py → منطق پایه‌ی Language Server که
    به یک لایه‌ی «هوش کد» (Code Intelligence) سبک برای ویرایشگر توکار
    تبدیل شده: تشخیص خطا (Diagnostics) و تکمیل خودکار (Completion).
  • __main__.py / versioneer.py / _version.py → الگوی خط‌فرمان و شماره‌گذاری
    نسخه، به شکل ساده‌شده در همین فایل بازتولید شده است.

نحوه‌ی اجرا:
    python oblivion_orbital.py
    python oblivion_orbital.py --host 0.0.0.0 --port 8080

کتابخانه‌های مورد نیاز:
    - این برنامه با کتابخانه‌ی استاندارد پایتون (stdlib) به‌تنهایی کار می‌کند.
    - برای فعال‌سازی قابلیت‌های پیشرفته‌ی «هوش کد» (لینت دقیق‌تر و تکمیل
      هوشمند)، نصب اختیاری زیر توصیه می‌شود:

        pip install pyflakes jedi pluggy

      اگر این پکیج‌ها نصب نباشند، برنامه به‌صورت خودکار روی حالت‌های
      جایگزینِ مبتنی بر stdlib (ast / compile) سوییچ می‌کند و باز هم کامل
      اجرا می‌شود.
========================================================================
"""
from __future__ import annotations


import argparse
try:
    import cgi
except ImportError:  # Python 3.13+
    cgi = None
import csv
import hashlib
import hmac
import http.server
import io
import math
import json
import os
import random
import re
import secrets
import shutil
import socketserver
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
import urllib.robotparser
import uuid
import zipfile
import xml.etree.ElementTree as ET
from collections import defaultdict, deque, Counter
from datetime import datetime, timedelta
from http import cookies
from pathlib import Path

# ------------------------------------------------------------------ #
#  Optional third-party enhancers (graceful degradation if missing)  #
# ------------------------------------------------------------------ #
try:
    import pyflakes.api as _pyflakes_api          # noqa: F401
    import pyflakes.reporter as _pyflakes_reporter  # noqa: F401
    HAVE_PYFLAKES = True
except Exception:
    HAVE_PYFLAKES = False

try:
    import jedi as _jedi                          # noqa: F401
    HAVE_JEDI = True
except Exception:
    HAVE_JEDI = False

try:
    import pluggy
    HAVE_PLUGGY = True
except Exception:
    HAVE_PLUGGY = False

try:
    import numpy as np                             # noqa: F401
    HAVE_NUMPY = True
except Exception:
    HAVE_NUMPY = False

try:
    import resource as _resource                   # POSIX only
    HAVE_RESOURCE = True
except Exception:
    HAVE_RESOURCE = False

# ======================================================================
#  APP IDENTITY  (rebrand: "Oblivion XQDatabase" -> "Oblivion Orbital")
# ======================================================================
APP_NAME = "Oblivion Orbital"
APP_VERSION = "5.3"
APP_TAGLINE = "Unified Knowledge-Graph & Code-Intelligence Platform"

# ======================================================================
#  CONFIG
# ======================================================================
HOST, PORT = "127.0.0.1", 8080
DATA_DIR = Path("data")
UPLOAD_DIR = DATA_DIR / "files"
DB_PATH = DATA_DIR / "knowledge.db"
GOTHAM_EXPORT_DIR = DATA_DIR / "gotham_exports"
GOTHAM_MODEL_PATH = DATA_DIR / "gotham_scam_model.json"
GOTHAM_IOC_FEED_PATH = DATA_DIR / "gotham_ioc_feed.json"
for d in [DATA_DIR, UPLOAD_DIR, GOTHAM_EXPORT_DIR]:
    d.mkdir(parents=True, exist_ok=True)

IS_WIN = os.name == "nt"

# ------------------------------------------------------------------ #
#  GOTHAM  — scoped OSINT / exposure-detection / threat-intel module #
#  Optional local integrations (all best-effort, never required):    #
#    - LM Studio  : local OpenAI-compatible endpoint for report text #
#    - Gephi      : GEXF graph export                                #
#    - Excel      : CSV export (opens natively in Excel)             #
# ------------------------------------------------------------------ #
LMSTUDIO_URL = os.environ.get("LMSTUDIO_URL", "http://localhost:1234/v1/chat/completions")
LMSTUDIO_MODEL = os.environ.get("LMSTUDIO_MODEL", "local-model")

# ------------------------------------------------------------------ #
#  ACCESS CODES  (two-tier login, Apollo-style platform gate)        #
#  - FULL_ACCESS_*  : unrestricted, no expiry                        #
#  - TRIAL_ACCESS_* : opens a rolling window of TRIAL_DAYS days,      #
#                      starting the first time it is ever used        #
#                                                                      #
#  The actual codes are never stored as plaintext in this file —     #
#  only their salted PBKDF2 hashes are. A login attempt is checked   #
#  by hashing the submitted value with the stored salt and comparing #
#  the result; the real codes cannot be recovered by reading the     #
#  source. To change a code, generate a new salt/hash pair with:     #
#      python3 -c "from oblivion_orbital import _hash_password as h; print(h('new-code'))" #
# ------------------------------------------------------------------ #
FULL_ACCESS_SALT = "83ffa733ba6ab2ae91706c666ebfa975"
FULL_ACCESS_HASH = "4b117f03251241bbd2006cd18017d1862b60067aee20be2a536d1336f222b097"
TRIAL_ACCESS_SALT = "b3d6a72cf0fb3fc620438894c587c246"
TRIAL_ACCESS_HASH = "7adc5e7f12354dfed0b6bfaf6827b065e74631321d85051f70fe2501a9f1e86b"
TRIAL_DAYS = 10

STOPWORDS = frozenset({
    "a", "an", "the", "and", "or", "but", "if", "because", "as", "what", "which",
    "this", "that", "these", "those", "then", "just", "so", "than", "such", "both",
    "through", "about", "for", "is", "of", "while", "during", "to", "from", "in",
    "on", "at", "by", "with", "without", "up", "down", "out", "off", "over", "under",
    "again", "further", "once", "here", "there", "when", "where", "why", "how",
    "all", "each", "every", "few", "more", "most", "other", "some", "no", "nor",
    "not", "only", "own", "same", "too", "very", "can", "will", "should", "now",
    "also", "after", "before", "between", "above", "below", "i", "me", "my", "we",
    "our", "you", "he", "she", "it", "they", "am", "is", "are", "was", "were", "be",
    "been", "being", "have", "has", "had", "doing", "do", "does", "did", "would",
    "could", "should", "may", "might", "must", "shall", "can", "need", "dare", "used",
    "و", "در", "به", "از", "که", "با", "برای", "تا", "را", "این", "آن", "است", "هست",
    "بود", "شد", "شده", "می", "ها", "های", "هر", "هم", "نیز", "اما", "یا", "اگر",
    "چون", "چه", "چرا", "کجا", "کی", "کدام", "همه", "یک", "دو", "سه", "نه", "بله",
    "خیر", "بعد", "قبل", "بالا", "پایین", "بیش", "کم", "بزرگ", "کوچک", "خوب",
    "بد", "نو", "کهنه", "اول", "آخر", "تنها", "چنین", "چنان", "همان", "همین",
    "آنجا", "اینجا", "من", "تو", "او", "ما", "شما", "آنها", "ایشان", "خود", "خویش",
    "همدیگر", "یکدیگر", "هستند", "باشند", "بودند", "شوند", "گردند", "کرد", "کرده",
    "کن", "کنید", "گفت", "گفته", "گوی", "گو", "ز", "بر", "اند", "ای", "ام", "ات",
    "اش", "مان", "تان", "شان"
})

# ======================================================================
#  SMALL UTILITIES  (derived from _utils.py)
# ======================================================================
def merge_dicts(dict_a, dict_b):
    """Merge dict_b into dict_a (shallow, dict_b wins on conflicts)."""
    merged = dict(dict_a)
    merged.update(dict_b)
    return merged


def list_to_string(lst, sep=", "):
    return sep.join(str(x) for x in lst)


def clip_columns(text, limit=4000):
    """Guard against pasting enormous blobs into a single API response field."""
    if text is None:
        return text
    return text if len(text) <= limit else text[:limit] + "\n... [truncated]"


# ======================================================================
#  URI HELPERS  (derived from uris.py — used by the file/import endpoints
#  to give every uploaded/edited file a stable, LSP-style URI identity)
# ======================================================================
RE_DRIVE_LETTER_PATH = re.compile(r'^/[a-zA-Z]:')


def _normalize_win_path(path):
    netloc = ''
    if IS_WIN:
        path = path.replace('\\', '/')
    if path[:2] == '//':
        idx = path.find('/', 2)
        netloc = path[2:] if idx == -1 else path[2:idx]
        if idx != -1:
            path = path[idx:]
    if not path.startswith('/'):
        path = '/' + path
    if RE_DRIVE_LETTER_PATH.match(path):
        path = path[0] + path[1].lower() + path[2:]
    return path, netloc


def from_fs_path(path):
    """Filesystem path -> a stable 'file://' URI, used as a document id."""
    path, netloc = _normalize_win_path(str(path))
    return urllib.parse.urlunparse(('file', netloc, urllib.parse.quote(path), '', '', ''))


def to_fs_path(uri):
    """'file://' URI -> filesystem path."""
    scheme, netloc, path, _p, _q, _f = urllib.parse.urlparse(uri)
    path = urllib.parse.unquote(path)
    if netloc and path and scheme == 'file':
        value = "//{}{}".format(netloc, path)
    elif RE_DRIVE_LETTER_PATH.match(path):
        value = path[1].lower() + path[2:]
    else:
        value = path
    return value.replace('/', '\\') if IS_WIN else value


# ======================================================================
#  PLUGIN / HOOK SYSTEM  (derived from hookspecs.py + __init__.py)
#  Lets new importer formats be registered without touching core code.
# ======================================================================
PLUGIN_NAMESPACE = "oblivion_orbital"

if HAVE_PLUGGY:
    hookspec = pluggy.HookspecMarker(PLUGIN_NAMESPACE)
    hookimpl = pluggy.HookimplMarker(PLUGIN_NAMESPACE)

    class ImporterHookSpecs:
        @hookspec
        def oo_extract_text(self, path, ext):
            """Return extracted plain text for a given uploaded file, or None
            if this plugin does not handle the extension."""

    _plugin_manager = pluggy.PluginManager(PLUGIN_NAMESPACE)
    _plugin_manager.add_hookspecs(ImporterHookSpecs)
else:
    _plugin_manager = None

    def hookimpl(func=None, **kw):  # no-op decorator fallback
        if func is not None:
            return func
        return lambda f: f


# ======================================================================
#  DATA-CONTROL SYSTEM: users, sessions, roles, audit log
# ======================================================================
SESSION_COOKIE = "oo_session"
SESSIONS = {}          # token -> {"user": username, "role": role, "ts": time}
SESSIONS_LOCK = threading.Lock()
SESSION_TTL = 60 * 60 * 8  # 8h


def _hash_password(password, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 200_000)
    return salt, digest.hex()


def _verify_password(password, salt, expected_hex):
    _, computed = _hash_password(password, salt)
    return hmac.compare_digest(computed, expected_hex)


class DataControl:
    """Authentication, roles and a tamper-evident audit trail."""

    def __init__(self, path):
        self.path = path
        self._init()

    def _init(self):
        with sqlite3.connect(self.path) as conn:
            conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                salt TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'viewer',
                created_at TEXT DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS audit_log (
                id TEXT PRIMARY KEY,
                ts TEXT DEFAULT (datetime('now')),
                username TEXT,
                action TEXT,
                detail TEXT,
                ip TEXT
            );
            CREATE TABLE IF NOT EXISTS app_config (
                key TEXT PRIMARY KEY,
                value TEXT
            );
            """)
            conn.commit()
        # bootstrap a default admin on first run
        with sqlite3.connect(self.path) as conn:
            row = conn.execute("SELECT COUNT(*) FROM users").fetchone()
            if row[0] == 0:
                salt, ph = _hash_password(secrets.token_urlsafe(18))
                conn.execute(
                    "INSERT INTO users (username, salt, password_hash, role) VALUES (?,?,?,?)",
                    ("admin", salt, ph, "admin")
                )
                conn.commit()
                print("[Oblivion Orbital] Created default 'admin' account with a random "
                      "password. Use one of the master access codes to sign in, then set "
                      "a real password for this account via /api/users/create or your own "
                      "admin tooling.")

    def create_user(self, username, password, role="viewer"):
        salt, ph = _hash_password(password)
        with sqlite3.connect(self.path) as conn:
            conn.execute(
                "INSERT INTO users (username, salt, password_hash, role) VALUES (?,?,?,?)",
                (username, salt, ph, role)
            )
            conn.commit()

    def authenticate(self, username, password):
        with sqlite3.connect(self.path) as conn:
            row = conn.execute(
                "SELECT salt, password_hash, role FROM users WHERE username=?", (username,)
            ).fetchone()
        if not row:
            return None
        salt, ph, role = row
        if _verify_password(password, salt, ph):
            return {"user": username, "role": role}
        return None

    # --- key/value config (used for the trial-password activation window) ---
    def get_config(self, key, default=None):
        with sqlite3.connect(self.path) as conn:
            row = conn.execute("SELECT value FROM app_config WHERE key=?", (key,)).fetchone()
        return row[0] if row else default

    def set_config(self, key, value):
        with sqlite3.connect(self.path) as conn:
            conn.execute(
                "INSERT INTO app_config (key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, value)
            )
            conn.commit()

    def trial_status(self):
        """Return the trial window's current state without consuming/starting it."""
        start_raw = self.get_config("trial_start")
        if not start_raw:
            return {"started": False, "active": None, "expires_at": None, "days_left": TRIAL_DAYS}
        start = datetime.fromisoformat(start_raw)
        expires = start + timedelta(days=TRIAL_DAYS)
        now = datetime.utcnow()
        days_left = max(0, (expires - now).days + (1 if (expires - now).seconds > 0 else 0))
        return {
            "started": True,
            "active": now <= expires,
            "expires_at": expires.isoformat(),
            "days_left": days_left,
        }

    def trial_login_attempt(self):
        """Start the trial window on first use, then validate against it.
        Returns a session identity dict if the trial code is still valid,
        or None if the 10-day window has already elapsed."""
        start_raw = self.get_config("trial_start")
        now = datetime.utcnow()
        if not start_raw:
            self.set_config("trial_start", now.isoformat())
            start = now
        else:
            start = datetime.fromisoformat(start_raw)
        expires = start + timedelta(days=TRIAL_DAYS)
        if now > expires:
            return None
        return {"user": "trial", "role": "trial", "expires_at": expires.isoformat()}

    def log(self, username, action, detail="", ip=""):
        with sqlite3.connect(self.path) as conn:
            conn.execute(
                "INSERT INTO audit_log (id, username, action, detail, ip) VALUES (?,?,?,?,?)",
                (str(uuid.uuid4()), username, action, clip_columns(detail, 500), ip)
            )
            conn.commit()

    def recent_log(self, limit=200):
        with sqlite3.connect(self.path) as conn:
            rows = conn.execute(
                "SELECT ts, username, action, detail, ip FROM audit_log "
                "ORDER BY ts DESC LIMIT ?", (limit,)
            ).fetchall()
        return [{"ts": r[0], "user": r[1], "action": r[2], "detail": r[3], "ip": r[4]} for r in rows]

    # --- sessions ---
    def new_session(self, user, role):
        token = secrets.token_urlsafe(32)
        with SESSIONS_LOCK:
            SESSIONS[token] = {"user": user, "role": role, "ts": time.time()}
        return token

    def session_for(self, token):
        with SESSIONS_LOCK:
            s = SESSIONS.get(token)
            if not s:
                return None
            if time.time() - s["ts"] > SESSION_TTL:
                SESSIONS.pop(token, None)
                return None
            return s

    def drop_session(self, token):
        with SESSIONS_LOCK:
            SESSIONS.pop(token, None)


# ======================================================================
#  SQLite knowledge-graph store  (core engine, unchanged in behaviour)
# ======================================================================
class GraphDB:
    def __init__(self, path):
        self.path = path
        self._init()

    def _init(self):
        with sqlite3.connect(self.path) as conn:
            conn.execute("PRAGMA foreign_keys = ON")
            conn.executescript("""
            CREATE TABLE IF NOT EXISTS graphs (
                id TEXT PRIMARY KEY,
                name TEXT UNIQUE,
                created REAL DEFAULT (julianday('now'))
            );
            CREATE TABLE IF NOT EXISTS nodes (
                id TEXT PRIMARY KEY,
                graph_id TEXT,
                label TEXT,
                x REAL,
                y REAL,
                size REAL DEFAULT 10,
                shape TEXT DEFAULT 'circle',
                color TEXT,
                community INT DEFAULT -1,
                betweenness REAL DEFAULT 0,
                source_file TEXT DEFAULT '',
                created_at TEXT DEFAULT (datetime('now')),
                FOREIGN KEY(graph_id) REFERENCES graphs(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS edges (
                id TEXT PRIMARY KEY,
                graph_id TEXT,
                source TEXT,
                target TEXT,
                weight REAL DEFAULT 1,
                source_file TEXT DEFAULT '',
                created_at TEXT DEFAULT (datetime('now')),
                FOREIGN KEY(graph_id) REFERENCES graphs(id) ON DELETE CASCADE,
                FOREIGN KEY(source) REFERENCES nodes(id) ON DELETE CASCADE,
                FOREIGN KEY(target) REFERENCES nodes(id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_nodes_graph ON nodes(graph_id);
            CREATE INDEX IF NOT EXISTS idx_edges_graph ON edges(graph_id);
            CREATE VIRTUAL TABLE IF NOT EXISTS nodes_fts USING fts5(
                label, content='nodes', content_rowid='rowid'
            );
            CREATE TABLE IF NOT EXISTS sentences (
                id TEXT PRIMARY KEY,
                graph_id TEXT,
                filename TEXT,
                text TEXT,
                created_at TEXT DEFAULT (datetime('now')),
                FOREIGN KEY(graph_id) REFERENCES graphs(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS sentence_nodes (
                sentence_id TEXT,
                node_id TEXT,
                PRIMARY KEY (sentence_id, node_id),
                FOREIGN KEY(sentence_id) REFERENCES sentences(id) ON DELETE CASCADE,
                FOREIGN KEY(node_id) REFERENCES nodes(id) ON DELETE CASCADE
            );
            """)
            self._migrate(conn)
            conn.commit()

    def _migrate(self, conn):
        for stmt in (
            "ALTER TABLE nodes ADD COLUMN source_file TEXT DEFAULT ''",
            "ALTER TABLE nodes ADD COLUMN created_at TEXT DEFAULT (datetime('now'))",
            "ALTER TABLE edges ADD COLUMN source_file TEXT DEFAULT ''",
            "ALTER TABLE edges ADD COLUMN created_at TEXT DEFAULT (datetime('now'))",
        ):
            try:
                conn.execute(stmt)
            except sqlite3.OperationalError:
                pass

    def create_graph(self, name):
        gid = str(uuid.uuid4())
        with sqlite3.connect(self.path) as conn:
            conn.execute("INSERT INTO graphs (id, name) VALUES(?,?)", (gid, name))
        return gid

    def get_or_create_master(self):
        with sqlite3.connect(self.path) as conn:
            row = conn.execute("SELECT id FROM graphs WHERE name='Master Graph'").fetchone()
            if row:
                return row[0]
        return self.create_graph("Master Graph")

    def add_node(self, gid, label, **kw):
        nid = str(uuid.uuid4())
        with sqlite3.connect(self.path) as conn:
            conn.execute(
                """INSERT INTO nodes
                   (id, graph_id, label, x, y, size, shape, color,
                    community, betweenness, source_file)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                (nid, gid, label,
                 kw.get('x', random.uniform(100, 700)),
                 kw.get('y', random.uniform(100, 500)),
                 kw.get('size', 10),
                 kw.get('shape', 'circle'),
                 kw.get('color', '#%06x' % random.randint(0, 0xFFFFFF)),
                 kw.get('community', -1),
                 kw.get('betweenness', 0.0),
                 kw.get('source_file', ''))
            )
        return nid

    def add_edge(self, gid, src, dst, weight=1, source_file=''):
        eid = str(uuid.uuid4())
        with sqlite3.connect(self.path) as conn:
            conn.execute(
                "INSERT INTO edges (id,graph_id,source,target,weight,source_file) VALUES(?,?,?,?,?,?)",
                (eid, gid, src, dst, weight, source_file)
            )
        return eid

    def get_graph(self, gid):
        with sqlite3.connect(self.path) as conn:
            g = conn.execute("SELECT id, name FROM graphs WHERE id=?", (gid,)).fetchone()
            if not g:
                return None
            nodes = []
            for r in conn.execute(
                "SELECT id, label, x, y, size, shape, color, community, betweenness, source_file "
                "FROM nodes WHERE graph_id=?", (gid,)
            ):
                nodes.append({
                    "id": r[0], "label": r[1], "x": r[2], "y": r[3],
                    "size": r[4], "shape": r[5], "color": r[6],
                    "community": r[7], "betweenness": r[8], "source_file": r[9]
                })
            edges = []
            for r in conn.execute(
                "SELECT id, source, target, weight, source_file FROM edges WHERE graph_id=?", (gid,)
            ):
                edges.append({"id": r[0], "source": r[1], "target": r[2],
                               "weight": r[3], "source_file": r[4]})
            return {"graph": {"id": g[0], "name": g[1]}, "nodes": nodes, "edges": edges}

    def get_node_details(self, node_id):
        with sqlite3.connect(self.path) as conn:
            node = conn.execute(
                "SELECT id, label, x, y, size, shape, color, community, betweenness, source_file "
                "FROM nodes WHERE id=?", (node_id,)
            ).fetchone()
            if not node:
                return None
            node_data = {
                "id": node[0], "label": node[1], "x": node[2], "y": node[3],
                "size": node[4], "shape": node[5], "color": node[6],
                "community": node[7], "betweenness": node[8], "source_file": node[9]
            }
            edges = []
            for r in conn.execute(
                "SELECT id, source, target, weight, source_file "
                "FROM edges WHERE source=? OR target=?", (node_id, node_id)
            ):
                edges.append({"id": r[0], "source": r[1], "target": r[2],
                               "weight": r[3], "source_file": r[4]})
            sentences = []
            for r in conn.execute("""
                SELECT s.text, s.filename
                FROM sentences s
                JOIN sentence_nodes sn ON s.id = sn.sentence_id
                WHERE sn.node_id = ?
                ORDER BY s.filename, s.created_at
            """, (node_id,)):
                sentences.append({"text": r[0], "filename": r[1]})
            article = "\n\n".join(f"[{s['filename']}] {s['text']}" for s in sentences[:15])
            if not article:
                article = "No source sentences found for this term."
            return {"node": node_data, "edges": edges, "article": article}

    def search_nodes(self, gid, query):
        with sqlite3.connect(self.path) as conn:
            safe = query.strip()
            if not any(c in safe for c in '*"^'):
                safe = safe + '*'
            rows = conn.execute(
                """SELECT n.id, n.label, n.x, n.y, n.size, n.shape,
                          n.color, n.community, n.betweenness, n.source_file
                   FROM nodes n
                   JOIN nodes_fts f ON n.rowid = f.rowid
                   WHERE n.graph_id = ? AND f.label MATCH ?""",
                (gid, safe)
            ).fetchall()
            return [{
                "id": r[0], "label": r[1], "x": r[2], "y": r[3],
                "size": r[4], "shape": r[5], "color": r[6],
                "community": r[7], "betweenness": r[8], "source_file": r[9]
            } for r in rows]

    def update_node(self, nid, **kw):
        sets = ', '.join(f"{k}=?" for k in kw)
        with sqlite3.connect(self.path) as conn:
            conn.execute(f"UPDATE nodes SET {sets} WHERE id=?", (*kw.values(), nid))

    def get_node_id(self, label, gid):
        with sqlite3.connect(self.path) as conn:
            r = conn.execute(
                "SELECT id FROM nodes WHERE graph_id=? AND label=?", (gid, label)
            ).fetchone()
            return r[0] if r else None

    def store_sentence(self, gid, filename, text, node_ids):
        sid = str(uuid.uuid4())
        with sqlite3.connect(self.path) as conn:
            conn.execute(
                "INSERT INTO sentences (id, graph_id, filename, text) VALUES(?,?,?,?)",
                (sid, gid, filename, text)
            )
            for nid in node_ids:
                conn.execute(
                    "INSERT OR IGNORE INTO sentence_nodes (sentence_id, node_id) VALUES(?,?)",
                    (sid, nid)
                )
        return sid

    def stats(self, gid):
        with sqlite3.connect(self.path) as conn:
            n = conn.execute("SELECT COUNT(*) FROM nodes WHERE graph_id=?", (gid,)).fetchone()[0]
            e = conn.execute("SELECT COUNT(*) FROM edges WHERE graph_id=?", (gid,)).fetchone()[0]
            s = conn.execute("SELECT COUNT(*) FROM sentences WHERE graph_id=?", (gid,)).fetchone()[0]
        return {"nodes": n, "edges": e, "sentences": s}

    # ---- data-lifecycle: remove a previously imported source ----------
    def delete_source_file(self, gid, filename):
        """Cascade-remove everything a single imported file contributed:
        its sentences, any edges tagged with it, and — where a node's
        source list becomes empty as a result — the node itself."""
        with sqlite3.connect(self.path) as conn:
            conn.execute("PRAGMA foreign_keys = ON")
            conn.execute(
                "DELETE FROM sentences WHERE graph_id=? AND filename=?", (gid, filename)
            )
            conn.execute(
                "DELETE FROM edges WHERE graph_id=? AND source_file=?", (gid, filename)
            )
            rows = conn.execute(
                "SELECT id, source_file FROM nodes WHERE graph_id=?", (gid,)
            ).fetchall()
            for nid, src in rows:
                parts = [p for p in (src or "").split(",") if p and p != filename]
                new_src = ",".join(parts)
                if new_src != (src or ""):
                    if new_src:
                        conn.execute("UPDATE nodes SET source_file=? WHERE id=?", (new_src, nid))
                    else:
                        conn.execute("DELETE FROM nodes WHERE id=?", (nid,))
            conn.commit()

    def reset_graph(self, gid):
        """Full wipe of a graph's content (nodes/edges/sentences), keeping
        the graph record itself so the console has somewhere to render to."""
        with sqlite3.connect(self.path) as conn:
            conn.execute("PRAGMA foreign_keys = ON")
            conn.execute("DELETE FROM sentences WHERE graph_id=?", (gid,))
            conn.execute("DELETE FROM edges WHERE graph_id=?", (gid,))
            conn.execute("DELETE FROM nodes WHERE graph_id=?", (gid,))
            conn.commit()


db = GraphDB(DB_PATH)
dc = DataControl(DB_PATH)
master_gid = db.get_or_create_master()


# ======================================================================
#  PLATFORM STORE  (Apollo Control Panel-style operational entities)
#  A single generic table backs Environments / Products & Releases /
#  Release Channels / Teams & Permissions / Change Management /
#  Plans & Constraints, mirroring the "Reference" section of Apollo's
#  navigation sidebar. A lightweight Notifications feed is fed
#  automatically whenever something in these sections changes.
# ======================================================================
PLATFORM_CATEGORIES = {
    "environment": "Environments",
    "product": "Products & Releases",
    "channel": "Release Channels",
    "team": "Teams & Permissions",
    "change": "Change Management",
    "plan": "Upgrades & Plans",
}


class PlatformStore:
    def __init__(self, path):
        self.path = path
        self._init()

    def _init(self):
        with sqlite3.connect(self.path) as conn:
            conn.executescript("""
            CREATE TABLE IF NOT EXISTS platform_items (
                id TEXT PRIMARY KEY,
                category TEXT NOT NULL,
                title TEXT NOT NULL,
                fields TEXT DEFAULT '{}',
                status TEXT DEFAULT 'active',
                created_at TEXT DEFAULT (datetime('now'))
            );
            CREATE INDEX IF NOT EXISTS idx_platform_category ON platform_items(category);
            CREATE TABLE IF NOT EXISTS notifications (
                id TEXT PRIMARY KEY,
                message TEXT,
                level TEXT DEFAULT 'info',
                created_at TEXT DEFAULT (datetime('now'))
            );
            """)
            conn.commit()

    def list_items(self, category):
        with sqlite3.connect(self.path) as conn:
            rows = conn.execute(
                "SELECT id, category, title, fields, status, created_at "
                "FROM platform_items WHERE category=? ORDER BY created_at DESC",
                (category,)
            ).fetchall()
        out = []
        for r in rows:
            try:
                fields = json.loads(r[3]) if r[3] else {}
            except Exception:
                fields = {}
            out.append({
                "id": r[0], "category": r[1], "title": r[2],
                "fields": fields, "status": r[4], "created_at": r[5]
            })
        return out

    def create_item(self, category, title, fields=None, status="active"):
        if category not in PLATFORM_CATEGORIES:
            raise ValueError("unknown category")
        iid = str(uuid.uuid4())
        with sqlite3.connect(self.path) as conn:
            conn.execute(
                "INSERT INTO platform_items (id, category, title, fields, status) "
                "VALUES (?,?,?,?,?)",
                (iid, category, title, json.dumps(fields or {}, ensure_ascii=False), status)
            )
            conn.commit()
        self.notify(f"{PLATFORM_CATEGORIES[category]}: \u201c{title}\u201d created.")
        return iid

    def delete_item(self, item_id):
        with sqlite3.connect(self.path) as conn:
            row = conn.execute(
                "SELECT category, title FROM platform_items WHERE id=?", (item_id,)
            ).fetchone()
            conn.execute("DELETE FROM platform_items WHERE id=?", (item_id,))
            conn.commit()
        if row:
            cat, title = row
            self.notify(f"{PLATFORM_CATEGORIES.get(cat, cat)}: \u201c{title}\u201d removed.")

    def notify(self, message, level="info"):
        with sqlite3.connect(self.path) as conn:
            conn.execute(
                "INSERT INTO notifications (id, message, level) VALUES (?,?,?)",
                (str(uuid.uuid4()), message, level)
            )
            conn.commit()

    def recent_notifications(self, limit=100):
        with sqlite3.connect(self.path) as conn:
            rows = conn.execute(
                "SELECT id, message, level, created_at FROM notifications "
                "ORDER BY created_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [{"id": r[0], "message": r[1], "level": r[2], "created_at": r[3]} for r in rows]


platform_store = PlatformStore(DB_PATH)


# ======================================================================
#  Text processing / graph construction
# ======================================================================
def tokenize(text):
    return [w.lower() for w in re.findall(r'\b\w+\b', text) if w.isalpha() and len(w) > 1]


def lemma(w):
    for sf in ['ترین', 'تر', 'ها', 'ان', 'ات', 'ی', 'ای', 'ing', 'ed', 'ly',
               'ment', 'ness', 'tion', 's', 'es', 'er', 'est']:
        if w.endswith(sf) and len(w) > len(sf) + 2:
            w = w[:-len(sf)]
            break
    return w


def extract_sentences(text):
    return re.split(r'(?<=[.!?])\s+', text)


def build_graph_from_text(text, gid, source_file=''):
    tokens = tokenize(text)
    lemmas = [lemma(t) for t in tokens if t not in STOPWORDS]
    if not lemmas:
        return 0
    freq = Counter(lemmas)
    maxf = max(freq.values()) if freq else 1

    adj = defaultdict(lambda: defaultdict(float))
    win = 4
    for i, w in enumerate(lemmas):
        for j in range(max(0, i - win), min(len(lemmas), i + win + 1)):
            if i != j:
                adj[w][lemmas[j]] += 1

    node_ids = {}
    for w, f in freq.items():
        nid = db.get_node_id(w, gid)
        if nid:
            with sqlite3.connect(DB_PATH) as conn:
                row = conn.execute(
                    "SELECT source_file, size FROM nodes WHERE id=?", (nid,)
                ).fetchone()
            old_sources = row[0] if row else ''
            if source_file and source_file not in old_sources:
                new_sources = (old_sources + ',' + source_file).strip(',')
            else:
                new_sources = old_sources
            old_size = row[1] if row else 10
            new_size = old_size + (5 + (f / maxf) * 10)
            db.update_node(nid, source_file=new_sources, size=new_size)
            node_ids[w] = nid
        else:
            size = 5 + (f / maxf) * 25
            nid = db.add_node(gid, w, size=size, source_file=source_file)
            node_ids[w] = nid

    for src, neigh in adj.items():
        if src not in node_ids or node_ids[src] is None:
            continue
        for dst, wgt in neigh.items():
            if src < dst and dst in node_ids and node_ids[dst] is not None:
                db.add_edge(gid, node_ids[src], node_ids[dst], wgt, source_file=source_file)

    comms = louvain(adj)
    for w, c in comms.items():
        if w in node_ids and node_ids[w]:
            db.update_node(node_ids[w], community=c)

    bcs = betweenness(adj)
    for w, bc in bcs.items():
        if w in node_ids and node_ids[w]:
            db.update_node(node_ids[w], betweenness=bc)

    sentences = extract_sentences(text)
    for sent in sentences:
        sent = sent.strip()
        if len(sent) < 10:
            continue
        sent_tokens = tokenize(sent)
        sent_lemmas = {lemma(t) for t in sent_tokens if t not in STOPWORDS}
        linked_node_ids = [node_ids[lem] for lem in sent_lemmas
                            if lem in node_ids and node_ids[lem] is not None]
        if linked_node_ids:
            db.store_sentence(gid, source_file, sent, linked_node_ids)

    return len(node_ids)


def louvain(adj, max_iter=50):
    nodes = list(adj.keys())
    if not nodes:
        return {}
    comm = {n: i for i, n in enumerate(nodes)}
    m = sum(sum(nb.values()) for nb in adj.values()) / 2
    if m == 0:
        return comm
    for _ in range(max_iter):
        changed = False
        random.shuffle(nodes)
        for n in nodes:
            cur = comm[n]
            nb_comms = {comm[nb] for nb in adj[n] if nb in comm}
            comm_w = defaultdict(float)
            for nn, cc in comm.items():
                for nb, w in adj[nn].items():
                    if comm.get(nb) == cc:
                        comm_w[cc] += w
            best_gain, best = 0, cur
            for c in nb_comms:
                k_i = sum(adj[n].values())
                k_i_in = sum(w for nb, w in adj[n].items() if comm.get(nb) == c)
                sum_tot = comm_w.get(c, 0)
                gain = (k_i_in / (2 * m)) - (sum_tot * k_i / (2 * m) ** 2)
                if gain > best_gain:
                    best_gain, best = gain, c
            if best != cur:
                comm[n] = best
                changed = True
        if not changed:
            break
    mapping = {o: i for i, o in enumerate(sorted(set(comm.values())))}
    return {n: mapping[c] for n, c in comm.items()}


def betweenness(adj):
    nodes = list(adj.keys())
    C = {n: 0.0 for n in nodes}
    for s in nodes:
        S, P = [], {n: [] for n in nodes}
        sigma = {n: 0 for n in nodes}
        sigma[s] = 1
        d = {n: -1 for n in nodes}
        d[s] = 0
        Q = deque([s])
        while Q:
            v = Q.popleft()
            S.append(v)
            for w in adj[v]:
                if d[w] < 0:
                    Q.append(w)
                    d[w] = d[v] + 1
                if d[w] == d[v] + 1:
                    sigma[w] += sigma[v]
                    P[w].append(v)
        delta = {n: 0.0 for n in nodes}
        while S:
            w = S.pop()
            for v in P[w]:
                delta[v] += (sigma[v] / sigma[w]) * (1 + delta[w])
            if w != s:
                C[w] += delta[w]
    n = len(nodes)
    if n > 2:
        for nn in C:
            C[nn] /= ((n - 1) * (n - 2))
    return C


def extract_docx(path):
    try:
        with zipfile.ZipFile(path) as z:
            xml = z.read('word/document.xml')
            root = ET.fromstring(xml)
            ns = 'http://schemas.openxmlformats.org/wordprocessingml/2006/main'
            paragraphs = []
            for p in root.iter(f'{{{ns}}}p'):
                texts = [t.text or '' for t in p.iter(f'{{{ns}}}t')]
                paragraphs.append(''.join(texts))
            return '\n'.join(paragraphs)
    except Exception:
        return ""


def extract_ipynb_text(path):
    try:
        with open(path, 'r', encoding='utf-8') as f:
            nb = json.load(f)
        texts = []
        for cell in nb.get('cells', []):
            if cell.get('cell_type') in ('code', 'markdown'):
                texts.append(''.join(cell.get('source', [])))
        return '\n'.join(texts)
    except Exception:
        return ""


def read_text_file(path):
    try:
        return Path(path).read_text(encoding='utf-8')
    except Exception:
        return ""


@hookimpl
def _builtin_extract_text(path, ext):
    """Default importer plugin: txt/py/md/csv/rst/tex/log, docx, ipynb, else best-effort text."""
    if ext in ('txt', 'py', 'md', 'csv', 'rst', 'tex', 'log'):
        return read_text_file(path)
    if ext == 'docx':
        return extract_docx(path)
    if ext == 'ipynb':
        return extract_ipynb_text(path)
    return read_text_file(path)


if HAVE_PLUGGY:
    class _BuiltinImporterPlugin:
        oo_extract_text = staticmethod(_builtin_extract_text)
    _plugin_manager.register(_BuiltinImporterPlugin())


def extract_text_for_file(path, ext):
    """Run through registered import plugins (pluggy) first, then the builtin fallback."""
    if HAVE_PLUGGY:
        for result in _plugin_manager.hook.oo_extract_text(path=str(path), ext=ext):
            if result:
                return result
    return _builtin_extract_text(path, ext)


# ======================================================================
#  CODE INTELLIGENCE  (derived from lsp.py / python_ls.py / workspace.py)
#  A light in-process substitute for the stdio Language Server protocol,
#  exposed over plain HTTP so the built-in web editor gets diagnostics
#  and completions without needing an external editor client.
# ======================================================================
class DiagnosticSeverity:
    ERROR = 1
    WARNING = 2
    INFORMATION = 3
    HINT = 4


class CodeDocument:
    """Mirrors workspace.py's Document: tracks a source buffer + version."""

    def __init__(self, uri, source=""):
        self.uri = uri
        self.source = source
        self.version = 0

    def apply_change(self, new_source):
        self.source = new_source
        self.version += 1


class CodeIntelligence:
    """In-process code intelligence engine (diagnostics + completions)."""

    def __init__(self):
        self._docs = {}
        self._lock = threading.Lock()

    def open(self, uri, source):
        with self._lock:
            doc = self._docs.get(uri)
            if doc is None:
                doc = CodeDocument(uri, source)
                self._docs[uri] = doc
            else:
                doc.apply_change(source)
            return doc

    # ---- diagnostics -------------------------------------------------
    def diagnostics(self, uri, source):
        self.open(uri, source)
        if HAVE_PYFLAKES:
            return self._diagnostics_pyflakes(source)
        return self._diagnostics_stdlib(source)

    def _diagnostics_pyflakes(self, source):
        import ast as _ast

        class _Collector(_pyflakes_reporter.Reporter):
            def __init__(self):
                self.messages = []

            def unexpectedError(self, filename, msg):
                self.messages.append((1, str(msg)))

            def syntaxError(self, filename, msg, lineno, offset, text):
                self.messages.append((lineno or 1, str(msg)))

            def flake(self, message):
                self.messages.append((message.lineno, str(message)))

        collector = _Collector()
        try:
            _pyflakes_api.check(source, "editor_buffer", reporter=collector)
        except Exception as e:  # pyflakes internal error -> fall back
            return self._diagnostics_stdlib(source) or [{
                "line": 1, "severity": DiagnosticSeverity.WARNING, "message": str(e)
            }]
        return [{"line": ln, "severity": DiagnosticSeverity.WARNING, "message": msg}
                for ln, msg in collector.messages]

    def _diagnostics_stdlib(self, source):
        """No pyflakes available: fall back to a plain compile() syntax check."""
        try:
            compile(source, "editor_buffer", "exec")
            return []
        except SyntaxError as e:
            return [{
                "line": e.lineno or 1,
                "severity": DiagnosticSeverity.ERROR,
                "message": f"SyntaxError: {e.msg}"
            }]
        except Exception as e:
            return [{"line": 1, "severity": DiagnosticSeverity.ERROR, "message": str(e)}]

    # ---- completions ---------------------------------------------------
    def complete(self, uri, source, line, column):
        self.open(uri, source)
        if HAVE_JEDI:
            try:
                script = _jedi.Script(code=source, path=uri)
                completions = script.complete(line=line, column=column)
                return [{"label": c.name, "detail": c.type} for c in completions[:30]]
            except Exception:
                pass
        return self._complete_keywords(source, line, column)

    _PY_KEYWORDS = sorted([
        "def", "class", "return", "import", "from", "if", "elif", "else",
        "for", "while", "try", "except", "finally", "with", "as", "lambda",
        "yield", "global", "nonlocal", "pass", "break", "continue", "print",
        "len", "range", "self", "None", "True", "False", "and", "or", "not",
        "in", "is", "raise", "assert", "async", "await"
    ])

    def _complete_keywords(self, source, line, column):
        lines = source.splitlines() or [""]
        idx = max(0, min(line, len(lines) - 1))
        text_before = lines[idx][:column] if idx < len(lines) else ""
        m = re.search(r'([A-Za-z_][A-Za-z0-9_]*)$', text_before)
        prefix = m.group(1) if m else ""
        matches = [kw for kw in self._PY_KEYWORDS if kw.startswith(prefix)] if prefix else self._PY_KEYWORDS[:15]
        return [{"label": kw, "detail": "keyword"} for kw in matches]


code_intel = CodeIntelligence()


# ======================================================================
#  HTTP REQUEST HANDLER
# ======================================================================
PUBLIC_PATHS = {"/login", "/api/login"}


# ======================================================================
#  GOTHAM — Threat Intelligence / OSINT / Exposure-Detection module
# ======================================================================
#
#  Design principle (intentional and non-negotiable):
#  Gotham is a SCOPED exposure-detection tool for assets you own or are
#  explicitly authorized to test — it is NOT a general "find a person"
#  tool. The crawler refuses to touch any domain that has not been added
#  to gotham_scope by an admin. It never attempts to identify, profile,
#  or dossier a private individual; it flags TYPES of exposed data
#  (secrets, credentials, PII patterns) on in-scope assets, with
#  evidence, confidence and a recommended action — never a verdict
#  about a person's identity.
# ======================================================================

GOTHAM_SIGNAL_WEIGHTS = {
    "exposed_credential": 35,
    "exposed_secret": 30,
    "malicious_ioc_match": 25,
    "malware_infra_pattern": 15,
    "suspicious_repository": 7,
    "pii_bulk_exposure": 12,
    "self_signed_or_expired_cert": 6,
    "open_directory_listing": 8,
    "repeated_pattern": 5,
}

GOTHAM_SEVERITY_BANDS = [
    (85, "CRITICAL"),
    (60, "HIGH"),
    (35, "MEDIUM"),
    (0, "LOW"),
]


def gotham_severity_for(score):
    for threshold, label in GOTHAM_SEVERITY_BANDS:
        if score >= threshold:
            return label
    return "LOW"


def _mask_value(value, keep=2):
    """Mask a sensitive string, keeping only a few edge characters."""
    if not value:
        return value
    if "@" in value:
        local, _, domain = value.partition("@")
        if len(local) <= keep:
            masked_local = local[0] + "*" * max(1, len(local) - 1)
        else:
            masked_local = local[:keep] + "*" * max(1, len(local) - keep)
        return f"{masked_local}@{domain}"
    if len(value) <= keep * 2:
        return value[0] + "*" * max(1, len(value) - 1)
    return value[:keep] + "*" * (len(value) - keep * 2) + value[-keep:]


def _luhn_ok(digits):
    total = 0
    parity = len(digits) % 2
    for i, d in enumerate(int(c) for c in digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


# ---- Detector patterns (regex-based, stdlib `re` only) ----------------
_RE_EMAIL = re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b')
_RE_PHONE = re.compile(r'(?:\+?\d{1,3}[\s\-]?)?(?:\(?0?9\d{2}\)?[\s\-]?\d{3}[\s\-]?\d{4}|\d{3}[\s\-]?\d{3}[\s\-]?\d{4})')
_RE_CC = re.compile(r'\b(?:\d[ \-]?){13,19}\b')
_RE_JWT = re.compile(r'\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b')
_RE_AWS_KEY = re.compile(r'\bAKIA[0-9A-Z]{16}\b')
_RE_GENERIC_SECRET = re.compile(
    r'(?i)\b(api[_\-]?key|secret[_\-]?key|access[_\-]?token|password|passwd|pwd|token)\b\s*[:=]\s*["\']?([A-Za-z0-9/_\-\.]{8,64})["\']?'
)
_RE_PRIVATE_KEY = re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----')
_RE_INTERNAL_IP = re.compile(
    r'\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3})\b'
)
_RE_PUBLIC_IP = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b')
_RE_URL = re.compile(r'https?://[^\s"\'<>]+', re.I)
_RE_SHORTENER = re.compile(r'(?i)\b(bit\.ly|tinyurl\.com|t\.co|goo\.gl|is\.gd|rebrand\.ly|cutt\.ly)\b')
_RE_CRYPTO_WALLET = re.compile(r'\b0x[a-fA-F0-9]{40}\b')
_RE_NATIONAL_ID_IR = re.compile(r'\b\d{10}\b')


def detect_pii_and_secrets(text, source_url=""):
    """Scan a blob of text and return a list of finding dicts.
    Never returns raw sensitive values — only masked previews."""
    findings = []
    seen = set()

    def add(ftype, raw_value, confidence, extra=""):
        key = (ftype, raw_value)
        if key in seen:
            return
        seen.add(key)
        findings.append({
            "type": ftype,
            "masked_value": _mask_value(raw_value),
            "confidence": round(confidence, 2),
            "evidence": extra or f"pattern match in content from {source_url or 'submitted text'}",
        })

    for m in _RE_PRIVATE_KEY.finditer(text):
        add("private_key", m.group(0), 0.99, "PEM private key header found")
    for m in _RE_AWS_KEY.finditer(text):
        add("aws_access_key", m.group(0), 0.95)
    for m in _RE_JWT.finditer(text):
        add("jwt_token", m.group(0), 0.75)
    for m in _RE_GENERIC_SECRET.finditer(text):
        add("credential_assignment", m.group(2), 0.6, f"assignment to '{m.group(1)}' key")
    for m in _RE_EMAIL.finditer(text):
        add("email", m.group(0), 0.9)
    for m in _RE_PHONE.finditer(text):
        digits = re.sub(r'\D', '', m.group(0))
        if 9 <= len(digits) <= 13:
            add("phone", m.group(0), 0.55)
    for m in _RE_CC.finditer(text):
        digits = re.sub(r'[ \-]', '', m.group(0))
        if 13 <= len(digits) <= 19 and _luhn_ok(digits):
            add("credit_card_like", digits, 0.85)
    for m in _RE_INTERNAL_IP.finditer(text):
        add("internal_ip", m.group(0), 0.7)
    for m in _RE_CRYPTO_WALLET.finditer(text):
        add("crypto_wallet", m.group(0), 0.4)
    return findings


def load_ioc_feed():
    """Local IOC allow-list/blocklist the user maintains themselves
    (no outbound network dependency). Seeded empty; add entries via
    the Gotham UI or by editing the JSON file directly."""
    if GOTHAM_IOC_FEED_PATH.exists():
        try:
            return json.loads(GOTHAM_IOC_FEED_PATH.read_text(encoding="utf-8"))
        except Exception:
            pass
    seed = {"domains": [], "ips": [], "hashes": [], "note":
            "Add known-bad indicators here (your own feeds/exports). "
            "Gotham correlates scan findings against this local list."}
    GOTHAM_IOC_FEED_PATH.write_text(json.dumps(seed, indent=2, ensure_ascii=False), encoding="utf-8")
    return seed


# ---- Scoped, rate-limited, allowlist-only web collector ----------------
class ScopedCollector:
    """Crawls ONLY domains present in gotham_scope. Respects robots.txt,
    a max page cap, a per-request size cap, a redirect cap, and a
    requests-per-second throttle. This is a passive OSINT collector —
    it fetches public pages, it does not attempt exploitation of any kind."""

    USER_AGENT = "GothamScopedCollector/1.0 (+authorized-scan)"
    MAX_PAGES = 40
    MAX_BYTES_PER_PAGE = 2_000_000
    REQUEST_TIMEOUT = 8

    def __init__(self, allowed_domains, max_depth=2, requests_per_second=1, respect_robots=True):
        self.allowed_domains = {d.lower().strip() for d in allowed_domains if d.strip()}
        self.max_depth = max(0, min(int(max_depth), 4))
        self.delay = 1.0 / max(0.1, float(requests_per_second))
        self.respect_robots = respect_robots
        self._robots_cache = {}

    def _in_scope(self, url):
        try:
            host = urllib.parse.urlparse(url).hostname or ""
        except Exception:
            return False
        host = host.lower()
        return any(host == d or host.endswith("." + d) for d in self.allowed_domains)

    def _robots_allows(self, url):
        if not self.respect_robots:
            return True
        parsed = urllib.parse.urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        rp = self._robots_cache.get(base)
        if rp is None:
            rp = urllib.robotparser.RobotFileParser()
            try:
                rp.set_url(base + "/robots.txt")
                rp.read()
            except Exception:
                rp = None
            self._robots_cache[base] = rp
        if rp is None:
            return True
        try:
            return rp.can_fetch(self.USER_AGENT, url)
        except Exception:
            return True

    def _fetch(self, url):
        req = urllib.request.Request(url, headers={"User-Agent": self.USER_AGENT})
        with urllib.request.urlopen(req, timeout=self.REQUEST_TIMEOUT) as resp:
            status = resp.status
            ctype = resp.headers.get("Content-Type", "")
            body = resp.read(self.MAX_BYTES_PER_PAGE)
            charset = "utf-8"
            if "charset=" in ctype:
                charset = ctype.split("charset=")[-1].strip()
            try:
                text = body.decode(charset, errors="replace")
            except Exception:
                text = body.decode("utf-8", errors="replace")
            return status, ctype, text

    @staticmethod
    def _extract_links(html, base_url):
        links = set()
        for m in re.finditer(r'href=["\']([^"\'#]+)', html, re.I):
            href = m.group(1)
            joined = urllib.parse.urljoin(base_url, href)
            if joined.startswith("http"):
                links.add(joined.split("#")[0])
        return links

    @staticmethod
    def _strip_tags(html):
        html = re.sub(r'(?is)<(script|style).*?>.*?</\1>', ' ', html)
        return re.sub(r'(?s)<[^>]+>', ' ', html)

    @staticmethod
    def _title(html):
        m = re.search(r'(?is)<title[^>]*>(.*?)</title>', html)
        return re.sub(r'\s+', ' ', m.group(1)).strip() if m else ""

    def crawl(self, seed_url, on_page=None):
        """BFS crawl within scope; on_page(url, status, title, text) is
        called for every fetched page. Returns list of visited URLs."""
        if not self._in_scope(seed_url):
            raise ValueError(f"'{seed_url}' is outside the authorized scope")
        visited = []
        queue = deque([(seed_url, 0)])
        seen_urls = {seed_url}
        while queue and len(visited) < self.MAX_PAGES:
            url, depth = queue.popleft()
            if not self._in_scope(url) or not self._robots_allows(url):
                continue
            try:
                status, ctype, text = self._fetch(url)
            except Exception as e:
                if on_page:
                    on_page(url, 0, "", f"[fetch error: {e}]")
                continue
            title = self._title(text) if "html" in ctype else ""
            plain = self._strip_tags(text) if "html" in ctype else text
            if on_page:
                on_page(url, status, title, plain)
            visited.append(url)
            time.sleep(self.delay)
            if depth < self.max_depth and "html" in ctype:
                for link in self._extract_links(text, url):
                    if link not in seen_urls and self._in_scope(link):
                        seen_urls.add(link)
                        queue.append((link, depth + 1))
        return visited


# ---- NumPy hand-rolled neural network for scam/phishing text scoring ---
GOTHAM_SCAM_KEYWORDS_HIGH = [
    "برنده شدید", "جایزه", "کد تخفیف ویژه", "تایید حساب", "مسدود شدن حساب",
    "همین الان کلیک کنید", "کلیک کنید", "واریز فوری", "سود تضمینی", "دو برابر کردن پول",
    "رمز عبور خود را وارد کنید", "کد otp", "کد پیامکی", "حساب شما مسدود",
    "به کسی نگویید", "این پیام محرمانه است", "بازداشت", "اقدام قانونی",
    "urgent action required", "verify your account", "account suspended",
    "click here now", "you have won", "claim your prize", "guaranteed profit",
    "double your money", "wire transfer immediately", "confirm your password",
    "one time password", "do not tell anyone", "act now", "limited time offer",
    "gift card", "irs", "tax refund", "lottery winner",
]
GOTHAM_SCAM_KEYWORDS_MED = [
    "تخفیف", "پیشنهاد ویژه", "فرصت محدود", "برنده", "هدیه رایگان",
    "discount", "free gift", "offer expires", "congratulations", "تبریک",
]


def _text_to_features(text):
    """Hand-crafted 24-dim feature vector — no external NLP library."""
    t = text or ""
    tl = t.lower()
    n = max(1, len(t))
    urls = _RE_URL.findall(t)
    shortener = 1.0 if _RE_SHORTENER.search(t) else 0.0
    emails = _RE_EMAIL.findall(t)
    phones = _RE_PHONE.findall(t)
    digits = sum(c.isdigit() for c in t)
    upper = sum(c.isupper() for c in t if c.isalpha())
    alpha = sum(c.isalpha() for c in t) or 1
    exclaim = t.count("!")
    high_hits = sum(1 for k in GOTHAM_SCAM_KEYWORDS_HIGH if k in tl)
    med_hits = sum(1 for k in GOTHAM_SCAM_KEYWORDS_MED if k in tl)
    emoji_hits = sum(t.count(e) for e in ["🎉", "💰", "🔥", "🏆", "🎁", "✅"])
    money_syms = sum(t.count(s) for s in ["$", "€", "تومان", "ریال", "دلار", "دلار آمریکا"])
    secret_ask = 1.0 if re.search(r'(?i)(رمز|cvv|otp|password|کارت بانکی|verify your account|ssn|کد ملی)', t) else 0.0
    brand_link_combo = 1.0 if (urls and re.search(r'(?i)(paypal|amazon|بانک|bank|apple id)', t)) else 0.0
    threat_words = 1.0 if re.search(r'(?i)(حساب شما مسدود|account suspended|legal action|بازداشت|پلیس|police)', t) else 0.0
    secrecy_ask = 1.0 if re.search(r'(?i)(به کسی نگو|confidential|don.?t tell anyone|keep this secret)', t) else 0.0
    wallet = 1.0 if _RE_CRYPTO_WALLET.search(t) else 0.0
    exe_mention = 1.0 if re.search(r'(?i)\.(exe|apk|scr|bat)\b', t) else 0.0
    guaranteed_profit = 1.0 if re.search(r'(?i)(سود تضمینی|guaranteed (profit|return)|double your money)', t) else 0.0
    click_phrase = 1.0 if re.search(r'(?i)(کلیک کنید|click here|tap here)', t) else 0.0
    reply_urgency = 1.0 if re.search(r'(?i)(فورا پاسخ|reply immediately|respond now|همین الان پاسخ)', t) else 0.0

    feats = [
        min(1.0, n / 300.0),
        min(1.0, exclaim / 5.0),
        min(1.0, high_hits / 3.0),
        min(1.0, med_hits / 3.0),
        min(1.0, secret_ask),
        min(1.0, len(urls) / 2.0),
        shortener,
        min(1.0, len(phones) / 2.0),
        min(1.0, len(emails) / 2.0),
        upper / alpha,
        min(1.0, money_syms / 3.0),
        click_phrase,
        threat_words,
        brand_link_combo,
        1.0 if re.search(r'(?i)(congratulations|تبریک)', t) else 0.0,
        min(1.0, emoji_hits / 3.0),
        reply_urgency,
        secrecy_ask,
        digits / n,
        wallet,
        guaranteed_profit,
        exe_mention,
        1.0,  # bias-ish feature
        min(1.0, (high_hits * 2 + med_hits) / 6.0),
    ]
    return feats


def _build_scam_training_set():
    scam_examples = [
        "تبریک! شما برنده یک میلیون تومان جایزه شده‌اید، همین الان کلیک کنید و کد تخفیف ویژه را دریافت کنید",
        "حساب بانکی شما مسدود شده است، برای تایید حساب رمز عبور و کد پیامکی خود را همین الان ارسال کنید",
        "URGENT: Your account has been suspended, click here now to verify your account and password",
        "You have won a lottery prize of $50,000, wire transfer a small fee to claim your gift card now",
        "سرمایه گذاری کنید و سود تضمینی روزانه دریافت کنید، پول خود را دو برابر کنید، به کسی نگویید",
        "This is confidential, do not tell anyone, send your OTP code to confirm your identity immediately",
        "Congratulations! You've been selected for a free gift, act now, limited time offer expires today",
        "کد otp خود را برای دریافت جایزه وارد کنید وگرنه حساب شما بازداشت می‌شود توسط پلیس",
        "Your PayPal account will be suspended, verify your account at bit.ly/verify-now immediately",
        "برنده شدید! برای دریافت جایزه کارت بانکی و رمز عبور خود را در این لینک وارد کنید http://claim-prize.tk",
        "IRS tax refund pending, click here to claim your refund before it expires, act now",
        "دوست عزیز فرصت محدود است، با واریز فوری وجه سود تضمینی دریافت کنید، این پیام محرمانه است",
        "Reply immediately with your bank details or your account will be closed within 24 hours",
        "🎉🎉 You are our lucky winner today! Claim your $1000 gift card now, click here 🎁",
        "بانک ملی: به دلیل فعالیت مشکوک حساب شما مسدود شد، برای رفع مسدودی این لینک را باز کنید",
        "Double your money in 48 hours guaranteed, send bitcoin to this wallet 0x1234567890abcdef1234567890abcdef12345678",
        "Apple ID: your account was locked, verify your password now at appleid-verify-secure.tk",
        "این یک فرصت استثنایی است، همین الان پاسخ دهید و کد ملی و رمز کارت بانکی را ارسال کنید",
        "Your package could not be delivered, pay a small customs fee here to release it: bit.ly/pkg123",
        "افتخار میکنیم اعلام کنیم شما برنده قرعه کشی شدید، جایزه نقدی منتظر شماست، کلیک کنید",
    ]
    ham_examples = [
        "سلام، جلسه فردا ساعت ده صبح در اتاق کنفرانس برگزار می‌شود، لطفا گزارش را آماده کنید",
        "Hi team, the sprint review is scheduled for Thursday at 3pm, please share your updates beforehand",
        "متشکرم بابت فایل، فردا بررسی می‌کنم و بازخورد می‌دهم",
        "Can you send me the invoice for last month's consulting work when you get a chance?",
        "یادت نره کتاب رو برگردونی کتابخونه، تا آخر هفته مهلت داره",
        "The quarterly report shows a 5% increase in revenue compared to last quarter",
        "سلام مامان، امروز دیر میام خونه، یه جلسه کاری طول کشید",
        "Attached is the updated project timeline, let me know if the deadlines work for your team",
        "بچه‌ها امشب فوتبال میبینیم خونه من، ساعت نه شروع میشه",
        "Please review the attached contract draft and share any comments by Friday",
        "دیروز رفتم دکتر، گفت باید یه هفته استراحت کنم",
        "Reminder: the office will be closed on Monday for the public holiday",
        "کد رو پوش کردم روی گیت‌هاب، می‌تونی ریویو کنی؟",
        "Happy birthday! Hope you have a wonderful day with family and friends",
        "لطفا فاکتور خرید ماه گذشته رو برام ایمیل کن",
        "The weather forecast says it will rain tomorrow afternoon, bring an umbrella",
        "جلسه هفتگی تیم به ساعت دو بعدازظهر منتقل شد",
        "I finished the analysis, the results are in the shared drive folder",
        "سلام استاد، تکلیف هفته آینده رو کی باید تحویل بدیم؟",
        "Our flight got delayed by two hours, we'll arrive around 9pm instead",
    ]
    X = [_text_to_features(t) for t in scam_examples + ham_examples]
    y = [1.0] * len(scam_examples) + [0.0] * len(ham_examples)
    return X, y


class ScamNeuralNet:
    """A tiny feed-forward network (24 -> 12 -> 1) implemented from
    scratch with numpy: manual forward pass, manual backprop, manual
    gradient descent. No scikit-learn / no tensorflow / no torch."""

    def __init__(self, n_in=24, n_hidden=12, seed=7):
        if not HAVE_NUMPY:
            self.ready = False
            return
        self.ready = True
        rng = np.random.default_rng(seed)
        self.W1 = rng.normal(0, 0.5, size=(n_in, n_hidden))
        self.b1 = np.zeros(n_hidden)
        self.W2 = rng.normal(0, 0.5, size=(n_hidden, 1))
        self.b2 = np.zeros(1)

    @staticmethod
    def _sigmoid(z):
        return 1.0 / (1.0 + np.exp(-np.clip(z, -30, 30)))

    def forward(self, X):
        z1 = X @ self.W1 + self.b1
        a1 = np.tanh(z1)
        z2 = a1 @ self.W2 + self.b2
        a2 = self._sigmoid(z2)
        return a1, a2

    def train(self, X, y, epochs=3000, lr=0.15):
        if not self.ready:
            return
        X = np.array(X, dtype=float)
        y = np.array(y, dtype=float).reshape(-1, 1)
        m = X.shape[0]
        for _ in range(epochs):
            a1, a2 = self.forward(X)
            dz2 = (a2 - y) / m
            dW2 = a1.T @ dz2
            db2 = dz2.sum(axis=0)
            da1 = dz2 @ self.W2.T
            dz1 = da1 * (1 - a1 ** 2)
            dW1 = X.T @ dz1
            db1 = dz1.sum(axis=0)
            self.W1 -= lr * dW1
            self.b1 -= lr * db1
            self.W2 -= lr * dW2
            self.b2 -= lr * db2

    def predict_one(self, text):
        if not self.ready:
            # Deterministic keyword fallback if numpy is unavailable.
            feats = _text_to_features(text)
            score = min(1.0, (feats[2] * 0.5 + feats[3] * 0.2 + feats[4] * 0.15 + feats[13] * 0.15))
            return float(score)
        x = np.array([_text_to_features(text)], dtype=float)
        _, a2 = self.forward(x)
        return float(a2[0, 0])

    def save(self, path):
        if not self.ready:
            return
        payload = {
            "W1": self.W1.tolist(), "b1": self.b1.tolist(),
            "W2": self.W2.tolist(), "b2": self.b2.tolist(),
        }
        Path(path).write_text(json.dumps(payload), encoding="utf-8")

    def load(self, path):
        if not self.ready or not Path(path).exists():
            return False
        try:
            payload = json.loads(Path(path).read_text(encoding="utf-8"))
            self.W1 = np.array(payload["W1"])
            self.b1 = np.array(payload["b1"])
            self.W2 = np.array(payload["W2"])
            self.b2 = np.array(payload["b2"])
            return True
        except Exception:
            return False


def get_scam_model():
    """Lazy singleton: load cached weights, or train once and cache."""
    global _GOTHAM_SCAM_MODEL
    try:
        return _GOTHAM_SCAM_MODEL
    except NameError:
        pass
    net = ScamNeuralNet()
    if not net.load(GOTHAM_MODEL_PATH):
        X, y = _build_scam_training_set()
        net.train(X, y)
        net.save(GOTHAM_MODEL_PATH)
    _GOTHAM_SCAM_MODEL = net
    return net


# ---- Gotham persistence layer (SQLite, same DB file as the graph) -----
class GothamDB:
    def __init__(self, path):
        self.path = path
        with sqlite3.connect(self.path) as conn:
            conn.executescript("""
            CREATE TABLE IF NOT EXISTS gotham_scope (
                domain TEXT PRIMARY KEY,
                added_by TEXT,
                added_at TEXT DEFAULT (datetime('now')),
                notes TEXT
            );
            CREATE TABLE IF NOT EXISTS gotham_scans (
                id TEXT PRIMARY KEY,
                target TEXT,
                scan_type TEXT,
                started_at TEXT DEFAULT (datetime('now')),
                finished_at TEXT,
                status TEXT DEFAULT 'running',
                pages_visited INTEGER DEFAULT 0,
                findings_count INTEGER DEFAULT 0,
                started_by TEXT
            );
            CREATE TABLE IF NOT EXISTS gotham_findings (
                id TEXT PRIMARY KEY,
                scan_id TEXT,
                source_url TEXT,
                domain TEXT,
                finding_type TEXT,
                severity TEXT,
                confidence REAL,
                masked_value TEXT,
                evidence TEXT,
                first_seen TEXT DEFAULT (datetime('now')),
                last_seen TEXT DEFAULT (datetime('now')),
                status TEXT DEFAULT 'open'
            );
            CREATE TABLE IF NOT EXISTS gotham_cases (
                id TEXT PRIMARY KEY,
                title TEXT,
                asset TEXT,
                severity TEXT,
                threat_score REAL,
                status TEXT DEFAULT 'open',
                signals TEXT,
                created_at TEXT DEFAULT (datetime('now')),
                updated_at TEXT DEFAULT (datetime('now')),
                created_by TEXT
            );
            CREATE TABLE IF NOT EXISTS gotham_scam_checks (
                id TEXT PRIMARY KEY,
                ts TEXT DEFAULT (datetime('now')),
                excerpt TEXT,
                score REAL,
                verdict TEXT,
                checked_by TEXT
            );
            """)
            conn.commit()

    # ---- scope -----------------------------------------------------
    def add_scope(self, domain, added_by, notes=""):
        domain = domain.lower().strip().lstrip("http://").lstrip("https://").split("/")[0]
        with sqlite3.connect(self.path) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO gotham_scope (domain, added_by, notes) VALUES (?,?,?)",
                (domain, added_by, notes)
            )
        return domain

    def remove_scope(self, domain):
        with sqlite3.connect(self.path) as conn:
            conn.execute("DELETE FROM gotham_scope WHERE domain=?", (domain,))

    def list_scope(self):
        with sqlite3.connect(self.path) as conn:
            rows = conn.execute("SELECT domain, added_by, added_at, notes FROM gotham_scope ORDER BY added_at DESC").fetchall()
        return [{"domain": r[0], "added_by": r[1], "added_at": r[2], "notes": r[3]} for r in rows]

    def is_in_scope(self, domain):
        domain = domain.lower().strip()
        with sqlite3.connect(self.path) as conn:
            rows = [r[0] for r in conn.execute("SELECT domain FROM gotham_scope").fetchall()]
        return any(domain == d or domain.endswith("." + d) for d in rows)

    # ---- scans -------------------------------------------------------
    def create_scan(self, target, scan_type, started_by):
        sid = "GTH-" + uuid.uuid4().hex[:8].upper()
        with sqlite3.connect(self.path) as conn:
            conn.execute(
                "INSERT INTO gotham_scans (id, target, scan_type, started_by) VALUES (?,?,?,?)",
                (sid, target, scan_type, started_by)
            )
        return sid

    def finish_scan(self, sid, pages_visited, findings_count, status="completed"):
        with sqlite3.connect(self.path) as conn:
            conn.execute(
                "UPDATE gotham_scans SET finished_at=datetime('now'), status=?, "
                "pages_visited=?, findings_count=? WHERE id=?",
                (status, pages_visited, findings_count, sid)
            )

    def list_scans(self, limit=100):
        with sqlite3.connect(self.path) as conn:
            rows = conn.execute(
                "SELECT id, target, scan_type, started_at, finished_at, status, "
                "pages_visited, findings_count, started_by FROM gotham_scans "
                "ORDER BY started_at DESC LIMIT ?", (limit,)
            ).fetchall()
        cols = ["id", "target", "scan_type", "started_at", "finished_at", "status",
                "pages_visited", "findings_count", "started_by"]
        return [dict(zip(cols, r)) for r in rows]

    # ---- findings ------------------------------------------------------
    def add_finding(self, scan_id, source_url, domain, finding_type, severity, confidence, masked_value, evidence):
        fid = str(uuid.uuid4())
        with sqlite3.connect(self.path) as conn:
            conn.execute(
                "INSERT INTO gotham_findings (id, scan_id, source_url, domain, finding_type, "
                "severity, confidence, masked_value, evidence) VALUES (?,?,?,?,?,?,?,?,?)",
                (fid, scan_id, source_url, domain, finding_type, severity, confidence, masked_value, evidence)
            )
        return fid

    def list_findings(self, scan_id=None, limit=500):
        with sqlite3.connect(self.path) as conn:
            if scan_id:
                rows = conn.execute(
                    "SELECT id, scan_id, source_url, domain, finding_type, severity, confidence, "
                    "masked_value, evidence, first_seen, last_seen, status FROM gotham_findings "
                    "WHERE scan_id=? ORDER BY first_seen DESC LIMIT ?", (scan_id, limit)
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT id, scan_id, source_url, domain, finding_type, severity, confidence, "
                    "masked_value, evidence, first_seen, last_seen, status FROM gotham_findings "
                    "ORDER BY first_seen DESC LIMIT ?", (limit,)
                ).fetchall()
        cols = ["id", "scan_id", "source_url", "domain", "finding_type", "severity", "confidence",
                "masked_value", "evidence", "first_seen", "last_seen", "status"]
        return [dict(zip(cols, r)) for r in rows]

    def get_finding(self, fid):
        with sqlite3.connect(self.path) as conn:
            r = conn.execute(
                "SELECT id, scan_id, source_url, domain, finding_type, severity, confidence, "
                "masked_value, evidence, first_seen, last_seen, status FROM gotham_findings WHERE id=?",
                (fid,)
            ).fetchone()
        if not r:
            return None
        cols = ["id", "scan_id", "source_url", "domain", "finding_type", "severity", "confidence",
                "masked_value", "evidence", "first_seen", "last_seen", "status"]
        return dict(zip(cols, r))

    # ---- cases -----------------------------------------------------
    def create_case(self, title, asset, severity, threat_score, signals, created_by):
        cid = "CASE-" + uuid.uuid4().hex[:6].upper()
        with sqlite3.connect(self.path) as conn:
            conn.execute(
                "INSERT INTO gotham_cases (id, title, asset, severity, threat_score, signals, created_by) "
                "VALUES (?,?,?,?,?,?,?)",
                (cid, title, asset, severity, threat_score, json.dumps(signals, ensure_ascii=False), created_by)
            )
        return cid

    def update_case(self, cid, status):
        with sqlite3.connect(self.path) as conn:
            conn.execute(
                "UPDATE gotham_cases SET status=?, updated_at=datetime('now') WHERE id=?",
                (status, cid)
            )

    def list_cases(self):
        with sqlite3.connect(self.path) as conn:
            rows = conn.execute(
                "SELECT id, title, asset, severity, threat_score, status, signals, created_at, updated_at, created_by "
                "FROM gotham_cases ORDER BY created_at DESC"
            ).fetchall()
        cols = ["id", "title", "asset", "severity", "threat_score", "status", "signals",
                "created_at", "updated_at", "created_by"]
        out = []
        for r in rows:
            d = dict(zip(cols, r))
            try:
                d["signals"] = json.loads(d["signals"] or "[]")
            except Exception:
                d["signals"] = []
            out.append(d)
        return out

    def get_case(self, cid):
        cases = [c for c in self.list_cases() if c["id"] == cid]
        return cases[0] if cases else None

    def log_scam_check(self, excerpt, score, verdict, checked_by):
        with sqlite3.connect(self.path) as conn:
            conn.execute(
                "INSERT INTO gotham_scam_checks (id, excerpt, score, verdict, checked_by) VALUES (?,?,?,?,?)",
                (str(uuid.uuid4()), clip_columns(excerpt, 300), score, verdict, checked_by)
            )


gotham_db = GothamDB(DB_PATH)


def gotham_run_scan(target, scan_type, depth, rps, respect_robots, started_by):
    """Executed on a worker thread. Refuses out-of-scope targets."""
    domain = urllib.parse.urlparse(target).hostname or target.split("/")[0]
    domain = domain.lower()
    if not gotham_db.is_in_scope(domain):
        raise ValueError(f"'{domain}' is not in the authorized Gotham scope. Add it first.")
    scan_id = gotham_db.create_scan(target, scan_type, started_by)
    seed_url = target if target.startswith("http") else f"https://{target}"
    collector = ScopedCollector([domain], max_depth=depth, requests_per_second=rps, respect_robots=respect_robots)
    findings_count = 0
    ioc = load_ioc_feed()
    bad_domains = set(d.lower() for d in ioc.get("domains", []))
    bad_ips = set(ioc.get("ips", []))

    def on_page(url, status, title, text):
        nonlocal findings_count
        pii = detect_pii_and_secrets(text, source_url=url)
        for f in pii:
            sev = "HIGH" if f["type"] in ("private_key", "aws_access_key", "credential_assignment") else "MEDIUM"
            gotham_db.add_finding(scan_id, url, domain, f["type"], sev, f["confidence"], f["masked_value"], f["evidence"])
            findings_count += 1
        for m in _RE_PUBLIC_IP.finditer(text):
            if m.group(0) in bad_ips:
                gotham_db.add_finding(scan_id, url, domain, "malicious_ioc_match", "CRITICAL", 0.9,
                                       _mask_value(m.group(0)), "IP matches local IOC feed")
                findings_count += 1
        for bd in bad_domains:
            if bd in text.lower():
                gotham_db.add_finding(scan_id, url, domain, "malicious_ioc_match", "HIGH", 0.7,
                                       _mask_value(bd), "Referenced domain matches local IOC feed")
                findings_count += 1

    try:
        visited = collector.crawl(seed_url, on_page=on_page)
        gotham_db.finish_scan(scan_id, len(visited), findings_count, "completed")
    except Exception as e:
        gotham_db.finish_scan(scan_id, 0, findings_count, f"failed: {e}")
        raise
    return scan_id


def gotham_threat_score(findings):
    """Evidence-based aggregate score, never a verdict on a person."""
    type_to_signal = {
        "private_key": "exposed_secret", "aws_access_key": "exposed_secret",
        "credential_assignment": "exposed_credential", "jwt_token": "exposed_secret",
        "malicious_ioc_match": "malicious_ioc_match",
        "email": "pii_bulk_exposure", "phone": "pii_bulk_exposure",
        "credit_card_like": "pii_bulk_exposure", "internal_ip": "suspicious_repository",
    }
    counts = Counter()
    for f in findings:
        sig = type_to_signal.get(f["finding_type"])
        if sig:
            counts[sig] += 1
    score = 0
    signals = []
    for sig, cnt in counts.items():
        weight = GOTHAM_SIGNAL_WEIGHTS.get(sig, 5)
        contrib = min(weight, weight * (1 if cnt == 1 else min(1.5, 1 + 0.1 * (cnt - 1))))
        score += contrib
        signals.append({"signal": sig, "count": cnt, "points": round(contrib, 1)})
    score = min(100, round(score, 1))
    return score, signals


GOTHAM_REPORT_TEMPLATE = """CASE {case_id}
{sep}
Severity        {severity}
Threat Score    {threat_score}/100
Status          {status}
Asset           {asset}
Created         {created_at}

Signals (evidence-based, not an identity claim)
{sep}
{signals_block}

Findings summary
{sep}
{findings_block}

Recommended action
{sep}
{recommendation}

Note: Gotham reports describe exposure patterns found on in-scope,
authorized assets. They are not identity determinations about any
individual, and every line here can be traced back to its source
finding via the finding ID.
"""


def gotham_recommendation_for(severity):
    return {
        "CRITICAL": "Rotate all exposed credentials immediately, take the affected endpoint offline "
                    "if possible, and open an incident response ticket.",
        "HIGH": "Rotate the exposed credential/secret, restrict public access to the asset, and "
                "review recent access logs for misuse.",
        "MEDIUM": "Reduce the amount of personal/contact data published on the asset and re-scan "
                  "after remediation.",
        "LOW": "Monitor; no immediate action required beyond routine hygiene.",
    }.get(severity, "Review the finding manually.")


def gotham_build_report(case):
    findings = [f for f in gotham_db.list_findings() if f["domain"] == case["asset"]]
    sig_lines = "\n".join(f"  + {s['signal']:<28} count={s['count']:<3} +{s['points']}" for s in case["signals"]) or "  (none)"
    find_lines = "\n".join(
        f"  [{f['severity']:<8}] {f['finding_type']:<22} {f['masked_value']:<30} conf={f['confidence']} src={f['source_url']}"
        for f in findings[:25]
    ) or "  (no findings recorded for this asset)"
    return GOTHAM_REPORT_TEMPLATE.format(
        case_id=case["id"], sep="-" * 60, severity=case["severity"],
        threat_score=case["threat_score"], status=case["status"], asset=case["asset"],
        created_at=case["created_at"], signals_block=sig_lines, findings_block=find_lines,
        recommendation=gotham_recommendation_for(case["severity"]),
    )


def gotham_lmstudio_narrative(case, timeout=6):
    """Best-effort call to a LOCAL LM Studio server to turn the report
    into prose. Purely optional — silently skipped if LM Studio isn't
    running. Never sends data anywhere but the user-configured local URL."""
    try:
        prompt = (
            "Write a concise, professional 3-sentence executive summary of this "
            "security case for a SOC report. Do not invent facts beyond what is given.\n\n"
            + gotham_build_report(case)
        )
        payload = json.dumps({
            "model": LMSTUDIO_MODEL,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.2,
            "max_tokens": 200,
        }).encode("utf-8")
        req = urllib.request.Request(
            LMSTUDIO_URL, data=payload,
            headers={"Content-Type": "application/json"}, method="POST"
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        return data["choices"][0]["message"]["content"].strip()
    except Exception as e:
        return f"[LM Studio unavailable or not running locally: {e}]"


# ---- Exports: Excel(CSV) / JSON / Gephi(GEXF) ---------------------------
def gotham_export_csv(rows, filename):
    path = GOTHAM_EXPORT_DIR / filename
    if not rows:
        path.write_text("", encoding="utf-8")
        return path
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    return path


def gotham_export_json(obj, filename):
    path = GOTHAM_EXPORT_DIR / filename
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def gotham_export_gexf(filename="gotham_graph.gexf"):
    """Builds a Gephi-compatible GEXF graph: domains -> findings -> IOC types."""
    gexf = ET.Element("gexf", {"xmlns": "http://www.gexf.net/1.2draft", "version": "1.2"})
    graph = ET.SubElement(gexf, "graph", {"mode": "static", "defaultedgetype": "directed"})
    nodes_el = ET.SubElement(graph, "nodes")
    edges_el = ET.SubElement(graph, "edges")

    node_ids = {}

    def get_node(label, kind):
        key = f"{kind}:{label}"
        if key not in node_ids:
            nid = str(len(node_ids) + 1)
            node_ids[key] = nid
            ET.SubElement(nodes_el, "node", {"id": nid, "label": f"[{kind}] {label}"})
        return node_ids[key]

    eid = 0
    for f in gotham_db.list_findings(limit=2000):
        dom_id = get_node(f["domain"] or "unknown", "domain")
        type_id = get_node(f["finding_type"], "finding_type")
        eid += 1
        ET.SubElement(edges_el, "edge", {
            "id": str(eid), "source": dom_id, "target": type_id,
            "weight": str(f["confidence"] or 1.0),
        })
    path = GOTHAM_EXPORT_DIR / filename
    ET.ElementTree(gexf).write(path, encoding="utf-8", xml_declaration=True)
    return path


# ======================================================================
#  CODE-CONSOLE HARDENING
#  The original in-process `exec(code, {'__builtins__': __builtins__})`
#  gave the browser-side code editor full remote-code-execution rights
#  inside the server's own process. That is unacceptable next to a
#  security module like Gotham. This runs user code in a *separate*
#  subprocess with a wall-clock timeout and, on POSIX, CPU/memory/file
#  limits. It is a mitigation, not a full sandbox — real isolation
#  needs OS-level containment (see the worker-queue note in the
#  original design doc) — but it removes in-process RCE and bounds
#  runaway resource usage.
# ======================================================================
def _posix_limits():
    if not HAVE_RESOURCE:
        return
    try:
        _resource.setrlimit(_resource.RLIMIT_CPU, (5, 5))
        _resource.setrlimit(_resource.RLIMIT_AS, (256 * 1024 * 1024, 256 * 1024 * 1024))
        _resource.setrlimit(_resource.RLIMIT_NOFILE, (64, 64))
    except Exception:
        pass


def sandboxed_exec(code, timeout=8):
    """Run `code` in a fresh Python subprocess. Returns (output, error)."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False, encoding="utf-8") as tf:
        tf.write(code)
        script_path = tf.name
    try:
        kwargs = {}
        if not IS_WIN and HAVE_RESOURCE:
            kwargs["preexec_fn"] = _posix_limits
        proc = subprocess.run(
            [sys.executable, "-I", script_path],
            capture_output=True, text=True, timeout=timeout, **kwargs
        )
        if proc.returncode != 0:
            return proc.stdout, proc.stderr or f"exited with code {proc.returncode}"
        return proc.stdout, None
    except subprocess.TimeoutExpired:
        return "", f"execution timed out after {timeout}s"
    except Exception as e:
        return "", str(e)
    finally:
        try:
            os.unlink(script_path)
        except Exception:
            pass



# ======================================================================
# GOTHAM RASHT ATLAS — local geospatial dataset (OpenStreetMap + imagery)
# ======================================================================
RASHT_ATLAS_DIR = DATA_DIR / "gotham_rasht"
RASHT_ATLAS_DIR.mkdir(parents=True, exist_ok=True)
RASHT_ATLAS_GEOJSON = RASHT_ATLAS_DIR / "rasht_features.geojson"
RASHT_ATLAS_META = RASHT_ATLAS_DIR / "metadata.json"
RASHT_ATLAS_BBOX = {"south": 37.20, "west": 49.48, "north": 37.36, "east": 49.75}
RASHT_ATLAS_MAX_BYTES = 32 * 1024 * 1024


def _rasht_atlas_meta():
    try:
        if RASHT_ATLAS_META.exists():
            obj = json.loads(RASHT_ATLAS_META.read_text(encoding="utf-8"))
            if isinstance(obj, dict):
                return obj
    except Exception:
        pass
    return {
        "available": RASHT_ATLAS_GEOJSON.exists(),
        "source": "OpenStreetMap contributors",
        "bbox": RASHT_ATLAS_BBOX,
        "feature_count": 0, "roads": 0, "named_roads": 0,
        "places": 0, "waterways": 0, "buildings": 0, "landuse": 0,
        "downloaded_at": None,
        "coverage_note": "No local Rasht vector extract has been downloaded yet."
    }


def _rasht_geojson_from_overpass(payload):
    features = []
    counts = Counter()
    for el in payload.get("elements", []):
        tags = el.get("tags") or {}
        etype = el.get("type")
        geom = None
        category = None
        if etype == "node":
            if not tags.get("place") and not tags.get("amenity") and not tags.get("shop"):
                continue
            if "lat" not in el or "lon" not in el:
                continue
            geom = {"type": "Point", "coordinates": [el["lon"], el["lat"]]}
            category = "place" if tags.get("place") else "poi"
        elif etype == "way":
            points = [[pt.get("lon"), pt.get("lat")] for pt in el.get("geometry", [])
                      if pt.get("lon") is not None and pt.get("lat") is not None]
            if len(points) < 2:
                continue
            closed = len(points) >= 4 and points[0] == points[-1]
            if tags.get("highway"):
                geom = {"type": "LineString", "coordinates": points}
                category = "road"
            elif tags.get("waterway"):
                geom = {"type": "LineString", "coordinates": points}
                category = "waterway"
            elif tags.get("building"):
                if closed:
                    geom = {"type": "Polygon", "coordinates": [points]}
                    category = "building"
                else:
                    continue
            elif tags.get("boundary") == "administrative" and closed:
                geom = {"type": "Polygon", "coordinates": [points]}
                category = "boundary"
            elif tags.get("landuse") or tags.get("natural") in ("wood", "water", "wetland") or tags.get("leisure") == "park":
                if closed:
                    geom = {"type": "Polygon", "coordinates": [points]}
                    category = "landuse"
                else:
                    continue
            elif tags.get("place") and closed:
                geom = {"type": "Polygon", "coordinates": [points]}
                category = "place_area"
            else:
                continue
        else:
            continue
        if not geom:
            continue
        keep = ("name", "name:fa", "name:en", "ref", "highway", "waterway", "place",
                "building", "landuse", "natural", "leisure", "amenity", "shop",
                "surface", "lanes", "oneway", "access", "admin_level", "boundary")
        props = {k: tags[k] for k in keep if k in tags}
        props["atlas_category"] = category
        props["osm_type"] = etype
        props["osm_id"] = el.get("id")
        features.append({"type": "Feature", "id": f"{etype}/{el.get('id')}",
                         "geometry": geom, "properties": props})
        counts[category] += 1
    return {"type": "FeatureCollection", "name": "Rasht and surroundings — OpenStreetMap extract",
            "features": features}, counts


def _rasht_save_geojson(geojson, metadata):
    if not isinstance(geojson, dict) or geojson.get("type") != "FeatureCollection":
        raise ValueError("GeoJSON must be a FeatureCollection")
    feats = geojson.get("features")
    if not isinstance(feats, list) or len(feats) > 250000:
        raise ValueError("Invalid or oversized feature collection")
    payload = json.dumps(geojson, ensure_ascii=False, separators=(",", ":"))
    if len(payload.encode("utf-8")) > RASHT_ATLAS_MAX_BYTES:
        raise ValueError("GeoJSON exceeds the 32 MB local import limit")
    tmp = RASHT_ATLAS_GEOJSON.with_suffix(".geojson.tmp")
    tmp.write_text(payload, encoding="utf-8")
    tmp.replace(RASHT_ATLAS_GEOJSON)
    meta = dict(metadata or {})
    meta.update({"available": True, "feature_count": len(feats), "stored_at": datetime.utcnow().isoformat(timespec="seconds") + "Z"})
    RASHT_ATLAS_META.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
    return meta


def _rasht_download_osm(include_buildings=False):
    """Fetch a fixed, bounded Rasht study-area extract from Overpass; no arbitrary URL proxy."""
    b = RASHT_ATLAS_BBOX
    box = f'{b["south"]},{b["west"]},{b["north"]},{b["east"]}'
    selectors = [
        f'way["highway"]({box});',
        f'way["waterway"]({box});',
        f'node["place"~"city|town|village|hamlet|suburb|neighbourhood"]({box});',
        f'way["place"~"city|town|village|hamlet|suburb|neighbourhood"]({box});',
        f'way["landuse"~"farmland|forest|residential|commercial|industrial|grass"]({box});',
        f'way["natural"~"wood|water|wetland"]({box});',
        f'way["leisure"="park"]({box});',
        f'way["boundary"="administrative"]["admin_level"~"6|7|8|9|10"]({box});',
    ]
    if include_buildings:
        selectors.append(f'way["building"]({box});')
    query = "[out:json][timeout:150];(\n" + "\n".join(selectors) + "\n);out body geom;"
    body = urllib.parse.urlencode({"data": query}).encode("utf-8")
    endpoints = ("https://overpass-api.de/api/interpreter", "https://overpass.kumi.systems/api/interpreter")
    last_error = None
    raw = None
    for endpoint in endpoints:
        try:
            req = urllib.request.Request(endpoint, data=body, headers={
                "User-Agent": "OblivionOrbital-RashtAtlas/5.4 (local GIS data import)",
                "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                "Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=180) as response:
                raw = response.read(RASHT_ATLAS_MAX_BYTES + 1)
            if len(raw) > RASHT_ATLAS_MAX_BYTES:
                raise ValueError("Overpass response exceeds the 32 MB safety limit; retry without building footprints")
            break
        except Exception as exc:
            last_error = exc
    if raw is None:
        raise RuntimeError("Could not reach the OpenStreetMap Overpass service: " + str(last_error))
    payload = json.loads(raw.decode("utf-8"))
    fc, counts = _rasht_geojson_from_overpass(payload)
    meta = {
        "source": "OpenStreetMap contributors via Overpass API",
        "source_url": "https://www.openstreetmap.org/copyright",
        "overpass_endpoint": endpoint,
        "bbox": RASHT_ATLAS_BBOX,
        "downloaded_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "osm_timestamp": payload.get("osm3s", {}).get("timestamp_osm_base"),
        "roads": counts.get("road", 0), "named_roads": sum(1 for f in fc["features"] if f["properties"].get("atlas_category") == "road" and (f["properties"].get("name") or f["properties"].get("name:fa"))),
        "places": counts.get("place", 0) + counts.get("place_area", 0),
        "waterways": counts.get("waterway", 0), "buildings": counts.get("building", 0),
        "landuse": counts.get("landuse", 0), "poi": counts.get("poi", 0),
        "include_buildings": bool(include_buildings),
        "coverage_note": "OSM community mapping within the stated rectangular study-area bbox; not a certified municipal inventory. Unmapped streets or missing names may exist."
    }
    return _rasht_save_geojson(fc, meta)



class Handler(http.server.BaseHTTPRequestHandler):
    server_version = f"{APP_NAME.replace(' ', '')}/{APP_VERSION}"

    # ---- auth helpers --------------------------------------------------
    def _get_cookie(self, name):
        raw = self.headers.get("Cookie")
        if not raw:
            return None
        jar = cookies.SimpleCookie()
        jar.load(raw)
        morsel = jar.get(name)
        return morsel.value if morsel else None

    def _current_session(self):
        token = self._get_cookie(SESSION_COOKIE)
        if not token:
            return None
        return dc.session_for(token)

    def _require_auth(self):
        session = self._current_session()
        if not session:
            self._json({"error": "authentication required"}, 401)
            return None
        return session

    def _require_admin(self):
        session = self._require_auth()
        if session and session["role"] != "admin":
            self._json({"error": "admin role required"}, 403)
            return None
        return session

    def _client_ip(self):
        return self.client_address[0] if self.client_address else ""

    # ---- routing ---------------------------------------------------
    def do_GET(self):
        p = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(p.query)

        if p.path not in PUBLIC_PATHS and p.path not in ("/login.html",):
            if p.path in ("/", "/dashboard") and not self._current_session():
                self._redirect("/login")
                return

        if p.path == '/' or p.path == '/dashboard':
            self._dash()
        elif p.path == '/login':
            self._login_page()
        elif p.path == '/api/whoami':
            self._json(self._current_session() or {})
        elif p.path == '/api/master':
            if not self._require_auth():
                return
            self._json(db.get_graph(master_gid))
        elif p.path == '/api/stats':
            if not self._require_auth():
                return
            self._json(db.stats(master_gid))
        elif p.path == '/api/search':
            if not self._require_auth():
                return
            self._search(q)
        elif p.path == '/api/node':
            if not self._require_auth():
                return
            self._node_detail(q)
        elif p.path == '/api/files':
            if not self._require_auth():
                return
            self._json([f.name for f in UPLOAD_DIR.iterdir() if f.is_file()])
        elif p.path == '/api/file':
            if not self._require_auth():
                return
            self._file(q)
        elif p.path == '/api/audit':
            if not self._require_admin():
                return
            self._json(dc.recent_log())
        elif p.path == '/api/trial/status':
            if not self._require_auth():
                return
            self._json(dc.trial_status())
        elif p.path == '/api/platform':
            if not self._require_auth():
                return
            category = q.get('category', [''])[0]
            if category not in PLATFORM_CATEGORIES:
                self._json({'error': 'unknown category'}, 400)
                return
            self._json(platform_store.list_items(category))
        elif p.path == '/api/notifications':
            if not self._require_auth():
                return
            self._json(platform_store.recent_notifications())
        elif p.path == '/api/gotham/rasht/status':
            if not self._require_auth():
                return
            self._json(_rasht_atlas_meta())
        elif p.path == '/api/gotham/rasht/data':
            if not self._require_auth():
                return
            meta = _rasht_atlas_meta()
            if not RASHT_ATLAS_GEOJSON.exists():
                self._json({"metadata": meta, "geojson": {"type": "FeatureCollection", "features": []}})
                return
            try:
                geo = json.loads(RASHT_ATLAS_GEOJSON.read_text(encoding="utf-8"))
                self._json({"metadata": meta, "geojson": geo})
            except Exception as exc:
                self._json({"error": "stored Rasht dataset is unreadable", "detail": str(exc)}, 500)
        elif p.path == '/api/gotham/rasht/export':
            if not self._require_auth():
                return
            if not RASHT_ATLAS_GEOJSON.exists():
                self._json({"error": "No local Rasht dataset yet. Download or import GeoJSON first."}, 404)
                return
            raw = RASHT_ATLAS_GEOJSON.read_bytes()
            self.send_response(200)
            self.send_header('Content-Type', 'application/geo+json; charset=utf-8')
            self.send_header('Content-Disposition', 'attachment; filename="rasht_atlas.geojson"')
            self.send_header('Content-Length', str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
        elif p.path == '/api/gotham/scope':
            if not self._require_auth():
                return
            self._json(gotham_db.list_scope())
        elif p.path == '/api/gotham/scans':
            if not self._require_auth():
                return
            self._json(gotham_db.list_scans())
        elif p.path == '/api/gotham/findings':
            if not self._require_auth():
                return
            self._json(gotham_db.list_findings(scan_id=q.get('scan_id', [None])[0]))
        elif p.path == '/api/gotham/finding':
            if not self._require_auth():
                return
            fid = q.get('id', [''])[0]
            found = gotham_db.get_finding(fid)
            self._json(found or {"error": "not found"}, 200 if found else 404)
        elif p.path == '/api/gotham/cases':
            if not self._require_auth():
                return
            self._json(gotham_db.list_cases())
        elif p.path == '/api/gotham/report':
            if not self._require_auth():
                return
            self._gotham_report(q)
        elif p.path == '/api/gotham/graph':
            if not self._require_auth():
                return
            self._gotham_graph()
        elif p.path == '/api/gotham/export':
            if not self._require_auth():
                return
            self._gotham_export(q)
        elif p.path == '/orbital-app':
            if not self._require_auth():
                return
            self._send_html(_apply_shared_theme(DASHBOARD, "orbital"))
        elif p.path in ('/umbra', '/umbra/'):
            if not self._require_auth():
                return
            if not UMBRA_AVAILABLE:
                self._send_html(_module_unavailable_html("Umbra", UMBRA_IMPORT_ERROR))
                return
            self._send_html(_umbra_frontend_html())
        elif p.path.startswith('/umbra/api/'):
            if not self._require_auth():
                return
            if not UMBRA_AVAILABLE:
                self._json({"error": "Umbra dependency unavailable", "detail": UMBRA_IMPORT_ERROR}, 503)
                return
            self._dispatch_umbra("GET")
        elif p.path in ('/web', '/web/'):
            if not self._require_auth():
                return
            self._send_html(_apply_shared_theme(WEB_HTML, "web"))
        elif p.path == '/health':
            if not self._require_auth():
                return
            self._bridge_health()
        elif p.path == '/proxy':
            if not self._require_auth():
                return
            self._bridge_proxy()
        elif p.path.startswith('/lm/'):
            if not self._require_auth():
                return
            self._bridge_lm_proxy()
        else:
            self.send_error(404)

    def do_POST(self):
        p = urllib.parse.urlparse(self.path)
        if p.path == '/api/login':
            self._do_login()
            return
        if p.path == '/api/logout':
            self._do_logout()
            return

        if p.path == '/api/import':
            if not self._require_auth():
                return
            self._import()
        elif p.path == '/api/run':
            if not self._require_auth():
                return
            self._run()
        elif p.path == '/api/notebook':
            if not self._require_auth():
                return
            self._notebook()
        elif p.path == '/api/lsp/diagnostics':
            if not self._require_auth():
                return
            self._lsp_diagnostics()
        elif p.path == '/api/lsp/complete':
            if not self._require_auth():
                return
            self._lsp_complete()
        elif p.path == '/api/users/create':
            if not self._require_admin():
                return
            self._create_user()
        elif p.path == '/api/platform/create':
            if not self._require_auth():
                return
            self._platform_create()
        elif p.path == '/api/platform/delete':
            if not self._require_admin():
                return
            self._platform_delete()
        elif p.path == '/api/file/delete':
            if not self._require_admin():
                return
            self._file_delete()
        elif p.path == '/api/graph/reset':
            if not self._require_admin():
                return
            self._graph_reset()
        elif p.path == '/api/gotham/rasht/download':
            if not self._require_auth():
                return
            self._gotham_rasht_download()
        elif p.path == '/api/gotham/rasht/import':
            if not self._require_auth():
                return
            self._gotham_rasht_import()
        elif p.path == '/api/gotham/scope/add':
            if not self._require_admin():
                return
            self._gotham_scope_add()
        elif p.path == '/api/gotham/scope/remove':
            if not self._require_admin():
                return
            self._gotham_scope_remove()
        elif p.path == '/api/gotham/scan':
            if not self._require_auth():
                return
            self._gotham_scan()
        elif p.path == '/api/gotham/case':
            if not self._require_auth():
                return
            self._gotham_case_create()
        elif p.path == '/api/gotham/case/update':
            if not self._require_auth():
                return
            self._gotham_case_update()
        elif p.path == '/api/gotham/scam/check':
            if not self._require_auth():
                return
            self._gotham_scam_check()
        elif p.path.startswith('/umbra/api/'):
            if not self._require_auth():
                return
            if not UMBRA_AVAILABLE:
                self._json({"error": "Umbra dependency unavailable", "detail": UMBRA_IMPORT_ERROR}, 503)
                return
            self._dispatch_umbra("POST")
        elif p.path.startswith('/lm/'):
            if not self._require_auth():
                return
            self._bridge_lm_proxy()
        else:
            self.send_error(404)

    # ---- responses ---------------------------------------------------
    def _redirect(self, location):
        self.send_response(302)
        self.send_header('Location', location)
        self.end_headers()

    def _dash(self):
        self._send_html(UI_SHELL_HTML)

    def _login_page(self):
        self._send_html(_apply_shared_theme(LOGIN_PAGE, "login"))

    def _json(self, data, code=200):
        body = json.dumps(data, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header('Content-type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json_body(self):
        length = int(self.headers.get('Content-Length', 0))
        raw = self.rfile.read(length) if length else b"{}"
        return json.loads(raw or b"{}")

    # ---- auth endpoints ---------------------------------------------
    def _issue_session(self, username, role, extra=None):
        token = dc.new_session(username, role)
        self.send_response(200)
        cookie = cookies.SimpleCookie()
        cookie[SESSION_COOKIE] = token
        cookie[SESSION_COOKIE]["path"] = "/"
        cookie[SESSION_COOKIE]["httponly"] = True
        self.send_header('Set-Cookie', cookie[SESSION_COOKIE].OutputString())
        payload = {"ok": True, "user": username, "role": role}
        if extra:
            payload.update(extra)
        body = json.dumps(payload, ensure_ascii=False).encode()
        self.send_header('Content-type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _do_login(self):
        data = self._read_json_body()
        username = (data.get("username") or "").strip()
        password = data.get("password") or ""

        # --- Access code 1: unrestricted, no expiry ---
        if password and _verify_password(password, FULL_ACCESS_SALT, FULL_ACCESS_HASH):
            user = username or "admin"
            dc.log(user, "login_success_full", ip=self._client_ip())
            self._issue_session(user, "admin")
            return

        # --- Access code 2: rolling 10-day trial window ---
        if password and _verify_password(password, TRIAL_ACCESS_SALT, TRIAL_ACCESS_HASH):
            trial = dc.trial_login_attempt()
            if not trial:
                dc.log(username or "trial", "login_failed_trial_expired", ip=self._client_ip())
                self._json({"error": "دوره ۱۰ روزه‌ی این رمز عبور به پایان رسیده است."}, 403)
                return
            user = username or "trial"
            dc.log(user, "login_success_trial", detail=f"expires {trial['expires_at']}",
                   ip=self._client_ip())
            self._issue_session(user, "trial", {"trial_expires": trial["expires_at"]})
            return

        # --- fallback: any additional accounts created via /api/users/create ---
        result = dc.authenticate(username, password)
        if not result:
            dc.log(username or "?", "login_failed", ip=self._client_ip())
            self._json({"error": "invalid credentials"}, 401)
            return
        dc.log(result["user"], "login_success", ip=self._client_ip())
        self._issue_session(result["user"], result["role"])

    def _do_logout(self):
        token = self._get_cookie(SESSION_COOKIE)
        session = dc.session_for(token) if token else None
        if token:
            dc.drop_session(token)
        if session:
            dc.log(session["user"], "logout", ip=self._client_ip())
        self._json({"ok": True})

    def _create_user(self):
        data = self._read_json_body()
        username = (data.get("username") or "").strip()
        password = data.get("password") or ""
        role = data.get("role") or "viewer"
        if not username or not password:
            self._json({"error": "username and password required"}, 400)
            return
        try:
            dc.create_user(username, password, role)
        except sqlite3.IntegrityError:
            self._json({"error": "user already exists"}, 409)
            return
        session = self._current_session()
        dc.log(session["user"], "user_created", detail=f"{username} ({role})", ip=self._client_ip())
        self._json({"ok": True})

    # ---- Apollo-style platform panels (Environments, Products, ------
    #      Release Channels, Teams, Change Mgmt, Plans) ----------------
    def _platform_create(self):
        session = self._current_session()
        data = self._read_json_body()
        category = data.get("category", "")
        title = (data.get("title") or "").strip()
        fields = data.get("fields") or {}
        status = data.get("status") or "active"
        if category not in PLATFORM_CATEGORIES or not title:
            self._json({"error": "category and title are required"}, 400)
            return
        iid = platform_store.create_item(category, title, fields, status)
        dc.log(session["user"], "platform_item_created",
               detail=f"{category}: {title}", ip=self._client_ip())
        self._json({"ok": True, "id": iid})

    def _platform_delete(self):
        session = self._current_session()
        data = self._read_json_body()
        item_id = data.get("id")
        if not item_id:
            self._json({"error": "id required"}, 400)
            return
        platform_store.delete_item(item_id)
        dc.log(session["user"], "platform_item_deleted", detail=item_id, ip=self._client_ip())
        self._json({"ok": True})

    # ---- data lifecycle: delete previously imported data --------------
    def _file_delete(self):
        session = self._current_session()
        data = self._read_json_body()
        name = (data.get("name") or "").strip()
        if not name or "/" in name or "\\" in name or name in (".", ".."):
            self._json({"error": "invalid filename"}, 400)
            return
        path = UPLOAD_DIR / name
        if not path.exists():
            self._json({"error": "not found"}, 404)
            return
        db.delete_source_file(master_gid, name)
        path.unlink()
        dc.log(session["user"], "file_deleted", detail=name, ip=self._client_ip())
        platform_store.notify(f"Imported data \u201c{name}\u201d was deleted from the knowledge graph.")
        self._json({"ok": True})

    def _graph_reset(self):
        session = self._current_session()
        db.reset_graph(master_gid)
        for f in UPLOAD_DIR.iterdir():
            if f.is_file():
                f.unlink()
        dc.log(session["user"], "graph_reset", ip=self._client_ip())
        platform_store.notify("The master knowledge graph and all imported files were reset.", "warn")
        self._json({"ok": True})

    # ---- graph endpoints ---------------------------------------------
    def _search(self, q):
        term = q.get('q', [''])[0]
        gid = q.get('gid', [master_gid])[0]
        self._json(db.search_nodes(gid, term) if term else [])

    def _node_detail(self, q):
        nid = q.get('id', [None])[0]
        if not nid:
            self._json({'error': 'missing id'}, 400)
            return
        details = db.get_node_details(nid)
        if not details:
            self._json({'error': 'node not found'}, 404)
            return
        self._json(details)

    def _file(self, q):
        name = q.get('name', [None])[0]
        if not name:
            self._json({'error': 'no name'}, 400)
            return
        path = UPLOAD_DIR / name
        if not path.exists():
            self._json({'error': 'not found'}, 404)
            return
        try:
            self._json({'content': path.read_text(encoding='utf-8'), 'uri': from_fs_path(path)})
        except Exception:
            self._json({'error': 'binary'}, 400)

    def _import(self):
        session = self._current_session()
        ct = self.headers.get('Content-Type', '')
        if 'multipart/form-data' not in ct:
            self._json({'error': 'multipart required'}, 400)
            return
        if cgi is not None:
            form = cgi.FieldStorage(
                fp=self.rfile, headers=self.headers,
                environ={'REQUEST_METHOD': 'POST', 'CONTENT_TYPE': ct}
            )
            item = form['file']
            if not item.file:
                self._json({'error': 'no file'}, 400)
                return
            fname = Path(item.filename or 'upload.bin').name
            dest = UPLOAD_DIR / fname
            with open(dest, 'wb') as f:
                shutil.copyfileobj(item.file, f)
        else:
            raw = self.rfile.read(int(self.headers.get('Content-Length', '0') or 0))
            fields = _umbra_parse_multipart(raw, ct)
            item = fields.get('file')
            if not item:
                self._json({'error': 'no file'}, 400)
                return
            fname = Path(item.get('filename') or 'upload.bin').name
            dest = UPLOAD_DIR / fname
            dest.write_bytes(item['data'])

        ext = fname.lower().rsplit('.', 1)[-1] if '.' in fname else ''
        text = extract_text_for_file(dest, ext)

        added = build_graph_from_text(text, master_gid, source_file=fname) if text.strip() else 0
        dc.log(session["user"], "import_file", detail=f"{fname} (+{added} nodes)", ip=self._client_ip())
        self._json({'status': 'ok', 'filename': fname, 'new_nodes': added, 'uri': from_fs_path(dest)})

    def _run(self):
        session = self._current_session()
        data = self._read_json_body()
        code = data.get('code', '')
        out, err = sandboxed_exec(code)
        dc.log(session["user"], "run_code", detail=code[:200], ip=self._client_ip())
        self._json({'output': out, 'error': err})

    def _notebook(self):
        session = self._current_session()
        nb = self._read_json_body()
        code = '\n'.join(
            ''.join(c.get('source', []))
            for c in nb.get('cells', [])
            if c.get('cell_type') == 'code'
        )
        out, err = sandboxed_exec(code)
        dc.log(session["user"], "run_notebook", ip=self._client_ip())
        self._json({'output': out, 'error': err})

    # ---- GOTHAM endpoints ---------------------------------------------
    def _gotham_scope_add(self):
        session = self._current_session()
        data = self._read_json_body()
        domain = (data.get("domain") or "").strip()
        notes = data.get("notes", "")
        if not domain:
            self._json({"error": "domain is required"}, 400)
            return
        added = gotham_db.add_scope(domain, session["user"], notes)
        dc.log(session["user"], "gotham_scope_add", detail=added, ip=self._client_ip())
        self._json({"ok": True, "domain": added})

    def _gotham_scope_remove(self):
        session = self._current_session()
        data = self._read_json_body()
        domain = (data.get("domain") or "").strip()
        gotham_db.remove_scope(domain)
        dc.log(session["user"], "gotham_scope_remove", detail=domain, ip=self._client_ip())
        self._json({"ok": True})

    def _gotham_scan(self):
        session = self._current_session()
        data = self._read_json_body()
        target = (data.get("target") or "").strip()
        scan_type = data.get("mode", "passive")
        depth = int(data.get("depth", 2))
        rps = float(data.get("requests_per_second", 1))
        respect_robots = bool(data.get("respect_robots", True))
        if not target:
            self._json({"error": "target is required"}, 400)
            return

        def worker():
            try:
                gotham_run_scan(target, scan_type, depth, rps, respect_robots, session["user"])
            except Exception as e:
                dc.log(session["user"], "gotham_scan_failed", detail=str(e), ip=self._client_ip())

        threading.Thread(target=worker, daemon=True).start()
        dc.log(session["user"], "gotham_scan_started", detail=target, ip=self._client_ip())
        self._json({"ok": True, "status": "started", "target": target})

    def _gotham_case_create(self):
        session = self._current_session()
        data = self._read_json_body()
        asset = (data.get("asset") or "").strip()
        if not asset:
            self._json({"error": "asset is required"}, 400)
            return
        findings = gotham_db.list_findings()
        findings = [f for f in findings if f["domain"] == asset]
        score, signals = gotham_threat_score(findings)
        severity = gotham_severity_for(score)
        title = data.get("title") or f"Exposure review — {asset}"
        cid = gotham_db.create_case(title, asset, severity, score, signals, session["user"])
        dc.log(session["user"], "gotham_case_created", detail=f"{cid} ({asset})", ip=self._client_ip())
        self._json({"ok": True, "case_id": cid, "severity": severity, "threat_score": score})

    def _gotham_case_update(self):
        session = self._current_session()
        data = self._read_json_body()
        cid = data.get("id")
        status = data.get("status", "open")
        if not cid:
            self._json({"error": "id is required"}, 400)
            return
        gotham_db.update_case(cid, status)
        dc.log(session["user"], "gotham_case_updated", detail=f"{cid} -> {status}", ip=self._client_ip())
        self._json({"ok": True})

    def _gotham_scam_check(self):
        session = self._current_session()
        data = self._read_json_body()
        text = data.get("text", "")
        if not text.strip():
            self._json({"error": "text is required"}, 400)
            return
        model = get_scam_model()
        score = model.predict_one(text)
        verdict = "LIKELY SCAM" if score >= 0.7 else ("SUSPICIOUS" if score >= 0.4 else "LIKELY SAFE")
        gotham_db.log_scam_check(text, score, verdict, session["user"])
        dc.log(session["user"], "gotham_scam_check", detail=verdict, ip=self._client_ip())
        self._json({"ok": True, "score": round(score, 3), "verdict": verdict})

    def _gotham_report(self, q):
        case_id = q.get("case_id", [""])[0]
        case = gotham_db.get_case(case_id)
        if not case:
            self._json({"error": "case not found"}, 404)
            return
        use_lm = q.get("narrative", ["0"])[0] == "1"
        report = gotham_build_report(case)
        if use_lm:
            report += "\n\nAI-assisted executive summary (local LM Studio):\n" + gotham_lmstudio_narrative(case)
        body = report.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _gotham_graph(self):
        nodes, edges, seen = [], [], set()

        def node(label, kind):
            key = f"{kind}:{label}"
            if key not in seen:
                seen.add(key)
                nodes.append({"id": key, "label": label, "kind": kind})
            return key

        for f in gotham_db.list_findings(limit=1000):
            d = node(f["domain"] or "unknown", "domain")
            t = node(f["finding_type"], "finding_type")
            edges.append({"source": d, "target": t, "weight": f["confidence"] or 1.0})
        self._json({"nodes": nodes, "edges": edges})

    def _gotham_export(self, q):
        kind = q.get("type", ["csv"])[0]
        session = self._current_session()
        if kind == "csv":
            path = gotham_export_csv(gotham_db.list_findings(limit=5000), "gotham_findings.csv")
            ctype = "text/csv"
        elif kind == "json":
            path = gotham_export_json({
                "scans": gotham_db.list_scans(),
                "findings": gotham_db.list_findings(limit=5000),
                "cases": gotham_db.list_cases(),
            }, "gotham_export.json")
            ctype = "application/json"
        elif kind == "gexf":
            path = gotham_export_gexf()
            ctype = "application/xml"
        else:
            self._json({"error": "unknown export type"}, 400)
            return
        dc.log(session["user"], "gotham_export", detail=kind, ip=self._client_ip())
        data = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-type", ctype)
        self.send_header("Content-Disposition", f'attachment; filename="{path.name}"')
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    # ---- GOTHAM Rasht Atlas endpoints ---------------------------------
    def _gotham_rasht_download(self):
        try:
            data = self._read_json_body()
            include_buildings = bool(data.get("include_buildings", False))
            meta = _rasht_download_osm(include_buildings=include_buildings)
            dc.log(self._current_session()["user"], "gotham_rasht_osm_download",
                   detail=f'{meta.get("feature_count", 0)} features', ip=self._client_ip())
            self._json({"ok": True, "metadata": meta})
        except Exception as exc:
            self._json({"error": str(exc), "hint": "Check internet access and retry. Existing local data is preserved."}, 502)

    def _gotham_rasht_import(self):
        try:
            length = int(self.headers.get("Content-Length", "0") or 0)
            if length <= 0 or length > RASHT_ATLAS_MAX_BYTES:
                self._json({"error": "Upload must be between 1 byte and 32 MB"}, 413)
                return
            data = self._read_json_body()
            geo = data.get("geojson")
            if not isinstance(geo, dict) or geo.get("type") != "FeatureCollection":
                self._json({"error": "Expected a GeoJSON FeatureCollection"}, 400)
                return
            meta = _rasht_save_geojson(geo, {
                "source": "User-imported GeoJSON",
                "downloaded_at": None,
                "coverage_note": "Imported by the user. Confirm its source, date, coverage and licence before relying on it."
            })
            dc.log(self._current_session()["user"], "gotham_rasht_geojson_import",
                   detail=f'{meta.get("feature_count", 0)} features', ip=self._client_ip())
            self._json({"ok": True, "metadata": meta})
        except Exception as exc:
            self._json({"error": str(exc)}, 400)

    # ---- code intelligence endpoints ---------------------------------
    def _lsp_diagnostics(self):
        data = self._read_json_body()
        source = data.get('source', '')
        uri = data.get('uri', 'inmemory://editor_buffer')
        self._json({'diagnostics': code_intel.diagnostics(uri, source),
                     'engine': 'pyflakes' if HAVE_PYFLAKES else 'stdlib-compile'})

    def _lsp_complete(self):
        data = self._read_json_body()
        source = data.get('source', '')
        uri = data.get('uri', 'inmemory://editor_buffer')
        line = int(data.get('line', 0))
        column = int(data.get('column', 0))
        self._json({'completions': code_intel.complete(uri, source, line, column),
                     'engine': 'jedi' if HAVE_JEDI else 'keyword-fallback'})

    # quieter logging
    def log_message(self, fmt, *args):
        sys.stderr.write(f"[{APP_NAME}] {self.address_string()} - {fmt % args}\n")


# ======================================================================
#  FRONTEND — Login page
# ======================================================================
LOGIN_PAGE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>OBLIVION ORBITAL — Secure Access</title>
<link rel="icon" href="data:image/jpeg;base64,/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAQDAwMDAgQDAwMEBAQFBgoGBgUFBgwICQcKDgwPDg4MDQ0PERYTDxAVEQ0NExoTFRcYGRkZDxIbHRsYHRYYGRj/2wBDAQQEBAYFBgsGBgsYEA0QGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBj/wAARCABHAFADASIAAhEBAxEB/8QAGwABAAIDAQEAAAAAAAAAAAAAAAcIAQMGCQL/xAArEAABBAEDAwMDBQEAAAAAAAABAAIDBAUGBxEIEiETMWEiQVEJFBVCcZL/xAAUAQEAAAAAAAAAAAAAAAAAAAAA/8QAFBEBAAAAAAAAAAAAAAAAAAAAAP/aAAwDAQACEQMRAD8A8/0REBERAREQEREBERAREQFtrVbN25HUpwS2J5XBkcUTS973H2AA8k/4tSnDpo3wymy+t8lJh9D1dV38zAynSrFobPHZ7+IzG8Mc/g9zmljeO7lvnwEHU7XdDu8mvmw5DUFOLRWHeA42Mw0/uHN/Law+r/ssHysbo9D28egWzZDT9OLWuHYC4WMO0/uGt/Lqx+r/AILx8qzmq9tN0twdHNzfUzv1R26wtz20zhpIqleMHz2SzSPAlf5HLT6gH5TSu2m6W3uj3Zrpm36obi4Wn76ZzMkVuvJx57Ipo3kRPPHho9MH8oPNCzVs0rclS5BLBPE4skilaWPY4e4IPkH/AFalN/UtvhlN6NcY2XL6Hq6Uv4au+ndrBodPJZ7+JDI8sa/gdrWhjue3h3nyVCCAiIgIiICt7+nzo7E5jfLO6zy0LJhprF+tWDhz6c0ri31B8iNsoHy7n7KoSsx0RbrYjbfqFfi9R2oquG1LV/jZLEzu2OGbvDoXPJ9mk9zCT4HqAngAoIl3h3V1HvDurktX5+5NIyWVzaNRziY6dfn6ImN9gAOOSPc8k+SvnaDdTUmz+6mN1fp65LG2KVrbtRriI7lfn64pG+xBHPHPseCPIUndQPSluDthuFkbOntNZLN6QsTuloXsfA6wYI3HkRTNYCWObz29xHDgAQfJAz0+9KW4O524eOtai03kcJpCtO2W/eyEDq5nY08mKFrwC9zuO3uA7Wgkk+ACHZfqDaOxOH3zwWssTC2Ealxfr2Q0cepNE4M9Q/JY6IH5bz91UJWW63N18TuV1DNx2nLMVrDabq/xkViEh0c03eXTOYR7tB7WAjwfT5HghVpQEREBERAREQWB216zN79tMHBg6uZp57F12hkFXOwmwYWD+rZGubIGgcAAuIH2AWNy+sre/czBWMHczVPBYuw0snq4OE1zMw/1dI5zpC0jwQHAH7gqv6ICIiAiIgIiICIiAiIgIiICIiD/2Q==">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500&family=Inter:wght@400;500&display=swap" rel="stylesheet">
<style>
  :root{
    --black:#050607; --panel:#0c0f11; --panel-2:#111518;
    --line:#232a2e; --line-soft:#1a2023;
    --ink:#eceeee; --ink-dim:#8a969b;
    --steel:#5c8fb5; --steel-2:#3f6a8a; --steel-glow:rgba(92,143,181,0.16);
    --err:#c1655d;
  }
  *{margin:0;padding:0;box-sizing:border-box;}
  body{
    height:100vh;background:var(--black);color:var(--ink);
    font-family:'Inter',sans-serif;display:flex;flex-direction:column;
    align-items:center;justify-content:center;position:relative;overflow:hidden;
  }
  h1,h2,h3{font-family:'Space Grotesk',sans-serif;font-weight:600;letter-spacing:-0.01em;}
  .mono{font-family:'IBM Plex Mono',monospace;}
  .bg-grid{
    position:absolute;inset:0;
    background-image:linear-gradient(var(--line-soft) 1px, transparent 1px),linear-gradient(90deg, var(--line-soft) 1px, transparent 1px);
    background-size:56px 56px;opacity:0.4;
    mask-image:radial-gradient(ellipse 65% 55% at 50% 45%, black 20%, transparent 75%);
  }
  .brandmark{position:relative;z-index:2;display:flex;align-items:center;gap:12px;margin-bottom:26px;}
  .brandmark img{width:34px;height:auto;filter:drop-shadow(0 0 30px var(--steel-glow));}
  .brandmark span{font-size:14px;font-weight:700;letter-spacing:0.14em;}
  .eyebrow{
    position:relative;z-index:2;font-size:12px;color:var(--steel);letter-spacing:0.14em;
    display:flex;align-items:center;gap:10px;margin-bottom:16px;
  }
  .eyebrow::before,.eyebrow::after{content:'';width:20px;height:1px;background:var(--steel);}
  h1.title{position:relative;z-index:2;font-size:clamp(36px,6vw,54px);letter-spacing:0.02em;text-align:center;}
  .sub{position:relative;z-index:2;margin-top:12px;color:var(--ink-dim);font-size:14.5px;text-align:center;max-width:380px;line-height:1.6;}

  .panel{
    position:relative;z-index:2;margin-top:38px;width:360px;max-width:90vw;
    background:var(--panel);border:1px solid var(--line);padding:34px 32px;
  }
  .field-label{font-size:11px;color:var(--ink-dim);letter-spacing:0.08em;margin-bottom:6px;display:block;}
  input{
    width:100%;padding:11px 12px;margin-bottom:18px;
    background:var(--panel-2);border:1px solid var(--line);color:var(--ink);
    font-size:14px;font-family:'Inter',sans-serif;transition:border-color .2s;
  }
  input:focus{outline:none;border-color:var(--steel);}
  button.btn-primary{
    width:100%;background:var(--ink);color:var(--black);border:none;
    padding:13px;font-size:14px;font-weight:500;cursor:pointer;transition:background .2s;
    font-family:'Inter',sans-serif;
  }
  button.btn-primary:hover{background:var(--steel);}
  #msg{color:var(--err);font-size:12.5px;margin-top:14px;min-height:14px;text-align:center;}
  :focus-visible{outline:2px solid var(--steel);outline-offset:2px;}
</style>
</head>
<body>
  <div class="bg-grid"></div>
  <div class="brandmark">
    <img src="data:image/jpeg;base64,/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAQDAwMDAgQDAwMEBAQFBgoGBgUFBgwICQcKDgwPDg4MDQ0PERYTDxAVEQ0NExoTFRcYGRkZDxIbHRsYHRYYGRj/2wBDAQQEBAYFBgsGBgsYEA0QGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBj/wAARCABHAFADASIAAhEBAxEB/8QAGwABAAIDAQEAAAAAAAAAAAAAAAcIAQMGCQL/xAArEAABBAEDAwMDBQEAAAAAAAABAAIDBAUGBxEIEiETMWEiQVEJFBVCcZL/xAAUAQEAAAAAAAAAAAAAAAAAAAAA/8QAFBEBAAAAAAAAAAAAAAAAAAAAAP/aAAwDAQACEQMRAD8A8/0REBERAREQEREBERAREQFtrVbN25HUpwS2J5XBkcUTS973H2AA8k/4tSnDpo3wymy+t8lJh9D1dV38zAynSrFobPHZ7+IzG8Mc/g9zmljeO7lvnwEHU7XdDu8mvmw5DUFOLRWHeA42Mw0/uHN/Law+r/ssHysbo9D28egWzZDT9OLWuHYC4WMO0/uGt/Lqx+r/AILx8qzmq9tN0twdHNzfUzv1R26wtz20zhpIqleMHz2SzSPAlf5HLT6gH5TSu2m6W3uj3Zrpm36obi4Wn76ZzMkVuvJx57Ipo3kRPPHho9MH8oPNCzVs0rclS5BLBPE4skilaWPY4e4IPkH/AFalN/UtvhlN6NcY2XL6Hq6Uv4au+ndrBodPJZ7+JDI8sa/gdrWhjue3h3nyVCCAiIgIiICt7+nzo7E5jfLO6zy0LJhprF+tWDhz6c0ri31B8iNsoHy7n7KoSsx0RbrYjbfqFfi9R2oquG1LV/jZLEzu2OGbvDoXPJ9mk9zCT4HqAngAoIl3h3V1HvDurktX5+5NIyWVzaNRziY6dfn6ImN9gAOOSPc8k+SvnaDdTUmz+6mN1fp65LG2KVrbtRriI7lfn64pG+xBHPHPseCPIUndQPSluDthuFkbOntNZLN6QsTuloXsfA6wYI3HkRTNYCWObz29xHDgAQfJAz0+9KW4O524eOtai03kcJpCtO2W/eyEDq5nY08mKFrwC9zuO3uA7Wgkk+ACHZfqDaOxOH3zwWssTC2Ealxfr2Q0cepNE4M9Q/JY6IH5bz91UJWW63N18TuV1DNx2nLMVrDabq/xkViEh0c03eXTOYR7tB7WAjwfT5HghVpQEREBERAREQWB216zN79tMHBg6uZp57F12hkFXOwmwYWD+rZGubIGgcAAuIH2AWNy+sre/czBWMHczVPBYuw0snq4OE1zMw/1dI5zpC0jwQHAH7gqv6ICIiAiIgIiICIiAiIgIiICIiD/2Q==" alt="OBLIVION mark">
    <span>OBLIVION</span>
  </div>
  <div class="eyebrow mono">[ AUTHENTICATION REQUIRED ]</div>
  <h1 class="title">ORBITAL</h1>
  <div class="sub">Unified knowledge-graph &amp; code-intelligence console. Sign in to continue.</div>

  <form class="panel" id="f">
    <label class="field-label mono">USERNAME (optional)</label>
    <input id="u" autocomplete="username" placeholder="admin">
    <label class="field-label mono">ACCESS CODE</label>
    <input id="p" type="password" autocomplete="current-password" required>
    <button class="btn-primary" type="submit">Sign in</button>
    <div id="msg"></div>
  </form>

<script>
document.getElementById('f').onsubmit = async (e) => {
  e.preventDefault();
  const username = document.getElementById('u').value;
  const password = document.getElementById('p').value;
  const r = await fetch('/api/login', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({username, password})
  });
  if (r.ok) { window.location.href = '/dashboard'; }
  else {
    const d = await r.json();
    document.getElementById('msg').textContent = d.error || 'Login failed';
  }
};
</script>
</body>
</html>"""


# ======================================================================
#  FRONTEND — Main dashboard
# ======================================================================
DASHBOARD = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>OBLIVION ORBITAL — Console</title>
<link rel="icon" href="data:image/jpeg;base64,/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAQDAwMDAgQDAwMEBAQFBgoGBgUFBgwICQcKDgwPDg4MDQ0PERYTDxAVEQ0NExoTFRcYGRkZDxIbHRsYHRYYGRj/2wBDAQQEBAYFBgsGBgsYEA0QGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBj/wAARCABHAFADASIAAhEBAxEB/8QAGwABAAIDAQEAAAAAAAAAAAAAAAcIAQMGCQL/xAArEAABBAEDAwMDBQEAAAAAAAABAAIDBAUGBxEIEiETMWEiQVEJFBVCcZL/xAAUAQEAAAAAAAAAAAAAAAAAAAAA/8QAFBEBAAAAAAAAAAAAAAAAAAAAAP/aAAwDAQACEQMRAD8A8/0REBERAREQEREBERAREQFtrVbN25HUpwS2J5XBkcUTS973H2AA8k/4tSnDpo3wymy+t8lJh9D1dV38zAynSrFobPHZ7+IzG8Mc/g9zmljeO7lvnwEHU7XdDu8mvmw5DUFOLRWHeA42Mw0/uHN/Law+r/ssHysbo9D28egWzZDT9OLWuHYC4WMO0/uGt/Lqx+r/AILx8qzmq9tN0twdHNzfUzv1R26wtz20zhpIqleMHz2SzSPAlf5HLT6gH5TSu2m6W3uj3Zrpm36obi4Wn76ZzMkVuvJx57Ipo3kRPPHho9MH8oPNCzVs0rclS5BLBPE4skilaWPY4e4IPkH/AFalN/UtvhlN6NcY2XL6Hq6Uv4au+ndrBodPJZ7+JDI8sa/gdrWhjue3h3nyVCCAiIgIiICt7+nzo7E5jfLO6zy0LJhprF+tWDhz6c0ri31B8iNsoHy7n7KoSsx0RbrYjbfqFfi9R2oquG1LV/jZLEzu2OGbvDoXPJ9mk9zCT4HqAngAoIl3h3V1HvDurktX5+5NIyWVzaNRziY6dfn6ImN9gAOOSPc8k+SvnaDdTUmz+6mN1fp65LG2KVrbtRriI7lfn64pG+xBHPHPseCPIUndQPSluDthuFkbOntNZLN6QsTuloXsfA6wYI3HkRTNYCWObz29xHDgAQfJAz0+9KW4O524eOtai03kcJpCtO2W/eyEDq5nY08mKFrwC9zuO3uA7Wgkk+ACHZfqDaOxOH3zwWssTC2Ealxfr2Q0cepNE4M9Q/JY6IH5bz91UJWW63N18TuV1DNx2nLMVrDabq/xkViEh0c03eXTOYR7tB7WAjwfT5HghVpQEREBERAREQWB216zN79tMHBg6uZp57F12hkFXOwmwYWD+rZGubIGgcAAuIH2AWNy+sre/czBWMHczVPBYuw0snq4OE1zMw/1dI5zpC0jwQHAH7gqv6ICIiAiIgIiICIiAiIgIiICIiD/2Q==">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500&family=Inter:wght@400;500&display=swap" rel="stylesheet">
<style>
:root{
  --black:#050607; --panel:#0c0f11; --panel-2:#111518;
  --line:#232a2e; --line-soft:#1a2023;
  --ink:#eceeee; --ink-dim:#8a969b;
  --steel:#5c8fb5; --steel-2:#3f6a8a; --steel-glow:rgba(92,143,181,0.16);
  --warn:#c9a35f; --err:#c1655d; --ok:#5fae8d;
}
*{box-sizing:border-box;margin:0;padding:0;}
html,body{height:100%;}
body{
  display:flex;flex-direction:column;background:var(--black);color:var(--ink);
  font-family:'Inter',sans-serif;overflow:hidden;
}
h1,h2,h3{font-family:'Space Grotesk',sans-serif;font-weight:600;letter-spacing:-0.01em;}
.mono{font-family:'IBM Plex Mono',monospace;}
::selection{background:var(--steel);color:#000;}

/* ---- TOP NAV ---- */
#topnav{
  height:56px;flex:0 0 56px;display:flex;align-items:center;justify-content:space-between;
  padding:0 22px;border-bottom:1px solid var(--line);background:var(--panel);z-index:50;
}
#topnav .brand{display:flex;align-items:center;gap:10px;font-size:13.5px;font-weight:700;letter-spacing:0.1em;}
#topnav .brand img{width:22px;height:auto;}
#topnav .status{margin-left:18px;font-size:11px;color:var(--steel);letter-spacing:0.1em;display:flex;align-items:center;gap:8px;}
.dot{width:6px;height:6px;border-radius:50%;background:var(--ok);box-shadow:0 0 8px var(--ok);}
#topnav-right{display:flex;align-items:center;gap:14px;}
#whoami{font-size:12px;color:var(--ink-dim);}
.navbtn{
  font-size:12px;border:1px solid var(--line);padding:7px 14px;color:var(--ink);
  background:transparent;cursor:pointer;font-family:'Inter',sans-serif;transition:border-color .2s,color .2s;
}
.navbtn:hover{border-color:var(--steel);color:var(--steel);}

/* ---- APP BODY ---- */
#appbody{flex:1;display:flex;min-height:0;}

/* ---- SIDEBAR ---- */
#sidebar{width:250px;flex:0 0 250px;background:var(--panel);border-right:1px solid var(--line);display:flex;flex-direction:column;min-height:0;}
.side-tag{padding:14px 16px 8px;font-size:11px;color:var(--steel);letter-spacing:0.12em;}
#files{flex:1;overflow-y:auto;padding:0 8px;}
.file{padding:8px 10px;cursor:pointer;font-size:13px;color:var(--ink-dim);border-left:2px solid transparent;transition:.15s;}
.file:hover{background:var(--panel-2);color:var(--ink);border-left-color:var(--steel);}
#import-btn{
  margin:14px;padding:11px;background:var(--ink);color:var(--black);border:none;
  font-weight:500;cursor:pointer;font-size:13px;transition:background .2s;
}
#import-btn:hover{background:var(--steel);}
#userbar{display:none;} /* legacy anchor kept for JS ids; visuals moved to topnav */

/* ---- MAIN ---- */
#main{flex:1;display:flex;flex-direction:column;min-width:0;}
#toolbar{
  background:var(--panel);padding:10px 18px;display:flex;gap:10px;align-items:center;
  border-bottom:1px solid var(--line);
}
.btn-outline{
  font-size:12.5px;border:1px solid var(--line);padding:8px 16px;color:var(--ink);
  background:transparent;cursor:pointer;font-family:'Inter',sans-serif;transition:border-color .2s,color .2s;
}
.btn-outline:hover{border-color:var(--steel);color:var(--steel);}
#stats{margin-left:auto;font-size:12px;color:var(--ink-dim);}
#stats.mono{letter-spacing:0.04em;}

#panels{flex:1;display:flex;min-height:0;}
#editor-panel{width:46%;display:flex;flex-direction:column;border-right:1px solid var(--line);position:relative;min-height:0;}
.panel-label{
  padding:9px 16px;font-size:11px;color:var(--steel);letter-spacing:0.12em;
  border-bottom:1px solid var(--line-soft);background:var(--panel);
}
#editor{
  flex:1;background:var(--black);color:#c9d6db;border:none;padding:14px 16px;
  font-family:'IBM Plex Mono',monospace;resize:none;font-size:13px;line-height:1.6;
}
#editor:focus{outline:none;}
#completions{
  position:absolute;background:var(--panel);border:1px solid var(--line);
  max-height:170px;overflow-y:auto;display:none;z-index:20;font-size:12.5px;
}
.comp-item{padding:6px 12px;cursor:pointer;font-family:'IBM Plex Mono',monospace;}
.comp-item:hover{background:var(--panel-2);color:var(--steel);}
#diag-bar{max-height:76px;overflow-y:auto;background:var(--panel-2);border-top:1px solid var(--line);font-size:11.5px;font-family:'IBM Plex Mono',monospace;}
.diag-item{padding:4px 14px;border-bottom:1px solid var(--line-soft);color:var(--warn);}
.diag-item.err{color:var(--err);}
#output{
  height:150px;flex:0 0 150px;background:var(--black);color:var(--ok);border-top:1px solid var(--line);
  padding:10px 16px;overflow:auto;font-size:11.5px;white-space:pre-wrap;font-family:'IBM Plex Mono',monospace;
}

#graph-panel{flex:1;position:relative;background:var(--panel-2);}
#graph-panel::before{
  content:'';position:absolute;inset:0;pointer-events:none;
  background-image:linear-gradient(var(--line-soft) 1px, transparent 1px),linear-gradient(90deg, var(--line-soft) 1px, transparent 1px);
  background-size:44px 44px;opacity:0.5;
}
#search-wrap{position:absolute;top:14px;left:14px;z-index:5;width:220px;}
#search{
  width:100%;padding:9px 12px;background:var(--panel);border:1px solid var(--line);
  color:var(--ink);font-size:12.5px;font-family:'Inter',sans-serif;
}
#search:focus{outline:none;border-color:var(--steel);}
#search-results{
  position:absolute;top:100%;left:0;width:100%;background:var(--panel);
  border:1px solid var(--line);border-top:none;max-height:160px;overflow-y:auto;display:none;z-index:10;
}
.search-item{padding:8px 12px;cursor:pointer;font-size:12.5px;color:var(--ink-dim);border-bottom:1px solid var(--line-soft);}
.search-item:hover{background:var(--panel-2);color:var(--ink);}
canvas{display:block;position:relative;z-index:1;}

/* ---- MODALS ---- */
.modal{display:none;position:fixed;z-index:100;left:0;top:0;width:100%;height:100%;background:rgba(5,6,7,0.82);}
.modal-content{
  background:var(--panel);margin:5% auto;padding:28px 30px;border:1px solid var(--line);
  width:620px;max-width:90vw;max-height:80vh;overflow-y:auto;color:var(--ink);
}
.modal-content h3{font-size:19px;margin-bottom:4px;}
.close{color:var(--ink-dim);float:right;font-size:22px;font-weight:400;cursor:pointer;line-height:1;}
.close:hover{color:var(--ink);}
.modal-table{width:100%;border-collapse:collapse;font-size:13px;margin-top:14px;}
.modal-table td,.modal-table th{padding:7px 6px;border-bottom:1px solid var(--line-soft);text-align:left;}
.modal-table th{color:var(--ink-dim);width:140px;font-weight:500;font-size:12px;}
.article-box{
  background:var(--panel-2);border:1px solid var(--line);padding:14px;margin-top:10px;
  max-height:280px;overflow-y:auto;white-space:pre-wrap;font-size:13px;line-height:1.6;color:var(--ink-dim);
}
h4.modal-h{margin-top:20px;font-size:12px;color:var(--steel);letter-spacing:0.1em;font-family:'IBM Plex Mono',monospace;font-weight:500;}
#audit-modal .modal-content{width:760px;}
#audit-table{width:100%;font-size:11.5px;border-collapse:collapse;font-family:'IBM Plex Mono',monospace;}
#audit-table th{text-align:left;padding:6px;color:var(--steel);border-bottom:1px solid var(--line);font-weight:500;}
#audit-table td{padding:6px;border-bottom:1px solid var(--line-soft);color:var(--ink-dim);}

::-webkit-scrollbar{width:9px;height:9px;}
::-webkit-scrollbar-track{background:var(--black);}
::-webkit-scrollbar-thumb{background:var(--line);}
::-webkit-scrollbar-thumb:hover{background:var(--steel-2);}
:focus-visible{outline:2px solid var(--steel);outline-offset:2px;}

/* ---- APOLLO-STYLE PLATFORM NAVIGATION ---- */
#nav-platform{padding:0 8px 14px;overflow-y:auto;}
.nav-item{
  padding:9px 10px;cursor:pointer;font-size:12.5px;color:var(--ink-dim);
  border-left:2px solid transparent;transition:.15s;display:flex;flex-direction:column;gap:1px;
}
.nav-item .nav-sub{font-size:10.5px;color:#5c6a70;}
.nav-item:hover{background:var(--panel-2);color:var(--ink);}
.nav-item.active{background:var(--panel-2);color:var(--ink);border-left-color:var(--steel);}
.nav-item.active .nav-sub{color:var(--steel);}

.trial-badge{
  font-size:10.5px;color:var(--warn);border:1px solid var(--warn);padding:3px 8px;
  letter-spacing:0.06em;margin-left:10px;
}

/* ---- SECTION PANELS (Environments / Products / Teams / etc.) ---- */
.section-panel{flex:1;display:flex;flex-direction:column;min-height:0;overflow:hidden;}
.section-panel.hidden{display:none;}
.section-head{
  padding:14px 22px;border-bottom:1px solid var(--line);background:var(--panel);
  display:flex;align-items:baseline;justify-content:space-between;
}
.section-head h2{font-size:16px;}
.section-head .section-desc{font-size:12px;color:var(--ink-dim);margin-top:3px;}
.section-body{flex:1;overflow-y:auto;padding:20px 22px;}

.platform-form{
  display:flex;flex-wrap:wrap;gap:10px;align-items:flex-end;background:var(--panel);
  border:1px solid var(--line);padding:16px;margin-bottom:18px;
}
.platform-form .f-group{display:flex;flex-direction:column;gap:5px;}
.platform-form label{font-size:10.5px;color:var(--ink-dim);letter-spacing:0.06em;}
.platform-form input,.platform-form select{
  background:var(--panel-2);border:1px solid var(--line);color:var(--ink);
  padding:8px 10px;font-size:12.5px;font-family:'Inter',sans-serif;min-width:160px;
}
.platform-form input:focus,.platform-form select:focus{outline:none;border-color:var(--steel);}
.btn-add{
  background:var(--ink);color:var(--black);border:none;padding:9px 18px;
  font-size:12.5px;font-weight:500;cursor:pointer;transition:background .2s;
}
.btn-add:hover{background:var(--steel);}
.btn-danger{
  background:transparent;color:var(--err);border:1px solid var(--err);padding:5px 12px;
  font-size:11.5px;cursor:pointer;transition:.2s;
}
.btn-danger:hover{background:var(--err);color:#fff;}

.data-table{width:100%;border-collapse:collapse;font-size:12.5px;}
.data-table th{text-align:left;padding:9px 10px;color:var(--steel);border-bottom:1px solid var(--line);font-weight:500;font-size:11.5px;letter-spacing:0.04em;}
.data-table td{padding:9px 10px;border-bottom:1px solid var(--line-soft);color:var(--ink);}
.data-table tr:hover td{background:var(--panel-2);}
.gth-h{margin:22px 0 10px;font-size:13px;letter-spacing:0.03em;color:var(--ink);text-transform:uppercase;}
.toolbar-row{display:flex;gap:10px;flex-wrap:wrap;}
.sev-CRITICAL{color:#ff5f5f;font-weight:600;}
.sev-HIGH{color:#ff9f4d;font-weight:600;}
.sev-MEDIUM{color:#ffd35f;}
.sev-LOW{color:#7fd88f;}
.badge{font-size:10.5px;padding:3px 9px;border:1px solid var(--line);letter-spacing:0.04em;display:inline-block;}
.badge-ok{color:var(--ok);border-color:var(--ok);}
.badge-warn{color:var(--warn);border-color:var(--warn);}
.badge-err{color:var(--err);border-color:var(--err);}
.empty-row{color:var(--ink-dim);font-style:italic;padding:14px 0;}
.notif-item{padding:10px 0;border-bottom:1px solid var(--line-soft);font-size:12.5px;}
.notif-item .notif-ts{font-size:10.5px;color:var(--ink-dim);margin-right:8px;font-family:'IBM Plex Mono',monospace;}
</style>
</head>
<body>

<div id="topnav">
  <div style="display:flex;align-items:center;">
    <div class="brand"><img src="data:image/jpeg;base64,/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAQDAwMDAgQDAwMEBAQFBgoGBgUFBgwICQcKDgwPDg4MDQ0PERYTDxAVEQ0NExoTFRcYGRkZDxIbHRsYHRYYGRj/2wBDAQQEBAYFBgsGBgsYEA0QGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBj/wAARCABHAFADASIAAhEBAxEB/8QAGwABAAIDAQEAAAAAAAAAAAAAAAcIAQMGCQL/xAArEAABBAEDAwMDBQEAAAAAAAABAAIDBAUGBxEIEiETMWEiQVEJFBVCcZL/xAAUAQEAAAAAAAAAAAAAAAAAAAAA/8QAFBEBAAAAAAAAAAAAAAAAAAAAAP/aAAwDAQACEQMRAD8A8/0REBERAREQEREBERAREQFtrVbN25HUpwS2J5XBkcUTS973H2AA8k/4tSnDpo3wymy+t8lJh9D1dV38zAynSrFobPHZ7+IzG8Mc/g9zmljeO7lvnwEHU7XdDu8mvmw5DUFOLRWHeA42Mw0/uHN/Law+r/ssHysbo9D28egWzZDT9OLWuHYC4WMO0/uGt/Lqx+r/AILx8qzmq9tN0twdHNzfUzv1R26wtz20zhpIqleMHz2SzSPAlf5HLT6gH5TSu2m6W3uj3Zrpm36obi4Wn76ZzMkVuvJx57Ipo3kRPPHho9MH8oPNCzVs0rclS5BLBPE4skilaWPY4e4IPkH/AFalN/UtvhlN6NcY2XL6Hq6Uv4au+ndrBodPJZ7+JDI8sa/gdrWhjue3h3nyVCCAiIgIiICt7+nzo7E5jfLO6zy0LJhprF+tWDhz6c0ri31B8iNsoHy7n7KoSsx0RbrYjbfqFfi9R2oquG1LV/jZLEzu2OGbvDoXPJ9mk9zCT4HqAngAoIl3h3V1HvDurktX5+5NIyWVzaNRziY6dfn6ImN9gAOOSPc8k+SvnaDdTUmz+6mN1fp65LG2KVrbtRriI7lfn64pG+xBHPHPseCPIUndQPSluDthuFkbOntNZLN6QsTuloXsfA6wYI3HkRTNYCWObz29xHDgAQfJAz0+9KW4O524eOtai03kcJpCtO2W/eyEDq5nY08mKFrwC9zuO3uA7Wgkk+ACHZfqDaOxOH3zwWssTC2Ealxfr2Q0cepNE4M9Q/JY6IH5bz91UJWW63N18TuV1DNx2nLMVrDabq/xkViEh0c03eXTOYR7tB7WAjwfT5HghVpQEREBERAREQWB216zN79tMHBg6uZp57F12hkFXOwmwYWD+rZGubIGgcAAuIH2AWNy+sre/czBWMHczVPBYuw0snq4OE1zMw/1dI5zpC0jwQHAH7gqv6ICIiAiIgIiICIiAiIgIiICIiD/2Q==" alt="OBLIVION mark">OBLIVION ORBITAL</div>
    <div class="status mono"><span class="dot"></span>[ SYSTEM ONLINE ]</div>
  </div>
  <div id="topnav-right">
    <span id="trial-badge" class="trial-badge mono" style="display:none"></span>
    <span id="whoami" class="mono">...</span>
    <button id="audit-btn" class="navbtn" style="display:none">Audit Log</button>
    <button id="logout-btn" class="navbtn">Logout</button>
  </div>
</div>

<div id="appbody">
  <div id="sidebar">
    <div class="side-tag mono">FILES</div>
    <div id="files"></div>
    <button id="import-btn">Import File</button>
    <input type="file" id="file-input" hidden multiple>
    <div id="userbar"></div>
    <div class="side-tag mono">REFERENCE</div>
    <div id="nav-platform">
      <div class="nav-item active" data-section="console" onclick="switchSection('console')">
        <span>Console</span><span class="nav-sub">Code &amp; knowledge graph</span>
      </div>
      <div class="nav-item" data-section="data" onclick="switchSection('data')">
        <span>Data</span><span class="nav-sub">Imported sources &amp; reset</span>
      </div>
      <div class="nav-item" data-section="environment" onclick="switchSection('environment')">
        <span>Environments</span><span class="nav-sub">Where things run</span>
      </div>
      <div class="nav-item" data-section="product" onclick="switchSection('product')">
        <span>Products &amp; Releases</span><span class="nav-sub">Versions in flight</span>
      </div>
      <div class="nav-item" data-section="channel" onclick="switchSection('channel')">
        <span>Release Channels</span><span class="nav-sub">Promotion sequence</span>
      </div>
      <div class="nav-item" data-section="team" onclick="switchSection('team')">
        <span>Teams &amp; Permissions</span><span class="nav-sub">RBAC roster</span>
      </div>
      <div class="nav-item" data-section="change" onclick="switchSection('change')">
        <span>Change Management</span><span class="nav-sub">Approvals &amp; compliance</span>
      </div>
      <div class="nav-item" data-section="plan" onclick="switchSection('plan')">
        <span>Upgrades &amp; Plans</span><span class="nav-sub">Plans &amp; constraints</span>
      </div>
      <div class="nav-item" data-section="notifications" onclick="switchSection('notifications')">
        <span>Notifications</span><span class="nav-sub">Platform activity feed</span>
      </div>
      <div class="nav-item" data-section="gotham" onclick="switchSection('gotham')">
        <span>🦇 GOTHAM</span><span class="nav-sub">Scoped threat intel / OSINT</span>
      </div>
    </div>
  </div>
  <div id="main">

    <div id="section-console" class="section-panel">
      <div id="toolbar">
        <button id="run-btn" class="btn-outline">Run Python</button>
        <button id="nb-btn" class="btn-outline">Run Notebook</button>
        <button id="graph-refresh" class="btn-outline">Refresh Graph</button>
        <span id="stats" class="mono"></span>
      </div>
      <div id="panels">
        <div id="editor-panel">
          <div class="panel-label mono">[ CODE INTELLIGENCE ]</div>
          <textarea id="editor" spellcheck="false" placeholder="Write or load Python code..."></textarea>
          <div id="completions"></div>
          <div id="diag-bar"></div>
          <div id="output">[Output]</div>
        </div>
        <div id="graph-panel">
          <div id="search-wrap">
            <input id="search" placeholder="Search nodes...">
            <div id="search-results"></div>
          </div>
          <canvas id="c"></canvas>
        </div>
      </div>
    </div>

    <div id="section-data" class="section-panel hidden">
      <div class="section-head">
        <div><h2>Data</h2><div class="section-desc">Every file imported into the master knowledge graph. Deleting a file removes its sentences, its edges, and any node left with no remaining source.</div></div>
        <button id="reset-graph-btn" class="btn-danger" style="display:none">Reset entire graph</button>
      </div>
      <div class="section-body">
        <table class="data-table">
          <thead><tr><th>File</th><th></th></tr></thead>
          <tbody id="data-table-body"></tbody>
        </table>
      </div>
    </div>

    <div id="section-environment" class="section-panel hidden"></div>
    <div id="section-product" class="section-panel hidden"></div>
    <div id="section-channel" class="section-panel hidden"></div>
    <div id="section-team" class="section-panel hidden"></div>
    <div id="section-change" class="section-panel hidden"></div>
    <div id="section-plan" class="section-panel hidden"></div>

    <div id="section-notifications" class="section-panel hidden">
      <div class="section-head">
        <div><h2>Notifications</h2><div class="section-desc">Automatic feed of platform activity — created/removed environments, products, channels, teams, change requests and plans.</div></div>
      </div>
      <div class="section-body" id="notif-list"></div>
    </div>

    <div id="section-gotham" class="section-panel hidden">
      <div class="section-head">
        <div>
          <h2>🦇 GOTHAM — Scoped Threat Intelligence</h2>
          <div class="section-desc">
            Gotham only ever touches domains you explicitly add to the scope below — assets you
            own or are authorized to test. It never crawls the open internet or profiles people;
            it flags exposed secrets/PII patterns and known-bad indicators on in-scope assets,
            with evidence and a confidence score.
          </div>
        </div>
      </div>
      <div class="section-body">

        <h4 class="gth-h">1 · Authorized Scope</h4>
        <div class="platform-form">
          <div class="f-group"><label>Domain you own / are authorized to test</label>
            <input id="gth-scope-domain" placeholder="example.org"></div>
          <div class="f-group"><label>Notes</label><input id="gth-scope-notes" placeholder="optional"></div>
          <button class="btn-add" onclick="gthAddScope()">Add to scope</button>
        </div>
        <table class="data-table"><thead><tr><th>Domain</th><th>Added by</th><th>Notes</th><th></th></tr></thead>
          <tbody id="gth-scope-body"></tbody></table>

        <h4 class="gth-h">2 · New Scan</h4>
        <div class="platform-form">
          <div class="f-group"><label>Target (must be in scope)</label><input id="gth-scan-target" placeholder="example.org"></div>
          <div class="f-group"><label>Max depth</label><input id="gth-scan-depth" value="2" style="width:60px"></div>
          <div class="f-group"><label>Requests/sec</label><input id="gth-scan-rps" value="1" style="width:60px"></div>
          <button class="btn-add" onclick="gthStartScan()">Start passive scan</button>
        </div>
        <table class="data-table"><thead><tr><th>Scan ID</th><th>Target</th><th>Status</th><th>Pages</th><th>Findings</th><th>Started</th></tr></thead>
          <tbody id="gth-scans-body"></tbody></table>

        <h4 class="gth-h">3 · Findings</h4>
        <table class="data-table"><thead><tr><th>Severity</th><th>Type</th><th>Value</th><th>Confidence</th><th>Domain</th><th>Source</th></tr></thead>
          <tbody id="gth-findings-body"></tbody></table>
        <div class="platform-form">
          <div class="f-group"><label>Open a case for asset</label><input id="gth-case-asset" placeholder="example.org"></div>
          <button class="btn-add" onclick="gthCreateCase()">Create case (auto threat-score)</button>
        </div>

        <h4 class="gth-h">4 · Cases &amp; Reports</h4>
        <table class="data-table"><thead><tr><th>Case</th><th>Asset</th><th>Severity</th><th>Score</th><th>Status</th><th></th></tr></thead>
          <tbody id="gth-cases-body"></tbody></table>

        <h4 class="gth-h">5 · Scam / Phishing Message Check <span class="mono" style="color:var(--steel);font-weight:400;">(numpy neural net, on-device)</span></h4>
        <div class="platform-form" style="align-items:flex-start">
          <textarea id="gth-scam-text" rows="4" style="flex:1;min-width:280px;background:var(--panel-2);color:var(--ink);border:1px solid var(--line);border-radius:6px;padding:8px;font-family:inherit" placeholder="Paste a suspicious message here..."></textarea>
          <button class="btn-add" onclick="gthCheckScam()">Analyze</button>
        </div>
        <div id="gth-scam-result" class="mono" style="margin-top:8px"></div>

        <h4 class="gth-h">6 · Export &amp; Integrations</h4>
        <div class="toolbar-row">
          <button class="btn-outline" onclick="window.open('/api/gotham/export?type=csv')">Export CSV (Excel)</button>
          <button class="btn-outline" onclick="window.open('/api/gotham/export?type=json')">Export JSON</button>
          <button class="btn-outline" onclick="window.open('/api/gotham/export?type=gexf')">Export GEXF (Gephi)</button>
        </div>
        <div class="section-desc" style="margin-top:8px">
          LM Studio: report narratives can optionally be generated by a locally running LM Studio
          server (OpenAI-compatible endpoint, default <span class="mono">http://localhost:1234</span>) —
          nothing is sent anywhere else. Toggle it with the checkbox next to a report link.
        </div>
      </div>
    </div>

  </div>
</div>

<div id="node-modal" class="modal">
  <div class="modal-content">
    <span class="close" onclick="closeModal()">&times;</span>
    <h3 id="modal-title">Node Details</h3>
    <table class="modal-table" id="modal-info"></table>
    <h4 class="modal-h">CONNECTED EDGES</h4>
    <table class="modal-table" id="modal-edges"></table>
    <h4 class="modal-h">SOURCE ARTICLE</h4>
    <div class="article-box" id="modal-article"></div>
  </div>
</div>

<div id="audit-modal" class="modal">
  <div class="modal-content">
    <span class="close" onclick="document.getElementById('audit-modal').style.display='none'">&times;</span>
    <h3>Audit Log</h3>
    <table id="audit-table"><thead><tr><th>Time</th><th>User</th><th>Action</th><th>Detail</th><th>IP</th></tr></thead>
    <tbody id="audit-body"></tbody></table>
  </div>
</div>

<script>
let graphData = null, currentFile = null, currentUri = 'inmemory://editor_buffer.py';
const canvas = document.getElementById('c'), ctx = canvas.getContext('2d');
let panX = 0, panY = 0, zoom = 1;
let dragNode = null, isPan = false, lastMouse = {};
let clickCandidate = null;
const CLICK_THRESH = 3;

function resize(){
  canvas.width = canvas.parentElement.clientWidth;
  canvas.height = canvas.parentElement.clientHeight;
  draw();
}
window.onresize = resize; resize();

let currentRole = null;
fetch('/api/whoami').then(r=>r.json()).then(me=>{
  if(!me.user){ window.location.href = '/login'; return; }
  currentRole = me.role;
  document.getElementById('whoami').textContent = me.user + ' (' + me.role + ')';
  if(me.role === 'admin'){
    document.getElementById('audit-btn').style.display = 'inline-block';
    document.getElementById('reset-graph-btn').style.display = 'inline-block';
  }
  if(me.role === 'trial'){
    fetch('/api/trial/status').then(r=>r.json()).then(t=>{
      const badge = document.getElementById('trial-badge');
      if(t.active === false){
        badge.textContent = 'TRIAL EXPIRED';
      } else {
        badge.textContent = 'TRIAL — ' + t.days_left + ' day(s) left';
      }
      badge.style.display = 'inline-block';
    });
  }
});

document.getElementById('reset-graph-btn').onclick = () => {
  if(!confirm('This permanently deletes every imported file and the entire knowledge graph. Continue?')) return;
  fetch('/api/graph/reset', {method:'POST'}).then(r=>r.json()).then(()=>{
    loadDataTable(); loadFiles(); loadMaster();
  });
};

/* ---- Section navigation (Apollo-style Reference sidebar) ---- */
const PLATFORM_SECTIONS = {
  environment: {
    label: 'Environments',
    desc: 'Where this software is deployed — mirrors Apollo\u2019s Namespaces &amp; Environments panel.',
    fields: [
      {key:'default_channel', label:'Default Channel', placeholder:'stable'},
      {key:'status', label:'Health', placeholder:'healthy'}
    ]
  },
  product: {
    label: 'Products & Releases',
    desc: 'Registered products and the version currently released to each.',
    fields: [
      {key:'version', label:'Version', placeholder:'1.4.2'},
      {key:'channel', label:'Channel', placeholder:'stable'}
    ]
  },
  channel: {
    label: 'Release Channels',
    desc: 'The promotion sequence a release travels through (e.g. develop \u2192 staging \u2192 stable).',
    fields: [
      {key:'order', label:'Order', placeholder:'1'}
    ]
  },
  team: {
    label: 'Teams & Permissions',
    desc: 'Role-based access control — Administrator manages settings, Viewer is read-only.',
    fields: [
      {key:'role', label:'Role', placeholder:'Administrator / Viewer'}
    ]
  },
  change: {
    label: 'Change Management',
    desc: 'Tracked change requests awaiting or holding approval.',
    fields: [
      {key:'requester', label:'Requester', placeholder:'name'},
      {key:'approver', label:'Approver', placeholder:'name'},
      {key:'status', label:'Status', placeholder:'pending / approved / rejected'}
    ]
  },
  plan: {
    label: 'Upgrades & Plans',
    desc: 'Upgrade plans and the constraints that must hold while they run.',
    fields: [
      {key:'constraint', label:'Constraint', placeholder:'e.g. max 1 environment at a time'},
      {key:'status', label:'Status', placeholder:'scheduled / running / complete'}
    ]
  }
};

function switchSection(name){
  document.querySelectorAll('.nav-item').forEach(el=>{
    el.classList.toggle('active', el.dataset.section === name);
  });
  document.querySelectorAll('.section-panel').forEach(el=>{
    el.classList.toggle('hidden', el.id !== 'section-' + name);
  });
  if(name === 'data') loadDataTable();
  else if(name === 'notifications') loadNotifications();
  else if(name === 'gotham') loadGotham();
  else if(PLATFORM_SECTIONS[name]) loadPlatformSection(name);
}

/* ---- GOTHAM ---- */
function loadGotham(){
  gthLoadScope(); gthLoadScans(); gthLoadFindings(); gthLoadCases();
}

function gthLoadScope(){
  fetch('/api/gotham/scope').then(r=>r.json()).then(rows=>{
    const body = document.getElementById('gth-scope-body');
    const isAdmin = currentRole === 'admin';
    body.innerHTML = rows.length ? rows.map(r=>{
      const del = isAdmin ? `<button class="btn-danger" onclick="gthRemoveScope('${r.domain}')">Remove</button>` : '';
      return `<tr><td>${r.domain}</td><td>${r.added_by||''}</td><td>${r.notes||''}</td><td>${del}</td></tr>`;
    }).join('') : '<tr><td colspan="4" class="empty-row">No domains in scope yet. Add one you own or are authorized to test.</td></tr>';
  });
}
function gthAddScope(){
  const domain = document.getElementById('gth-scope-domain').value.trim();
  const notes = document.getElementById('gth-scope-notes').value.trim();
  if(!domain){ alert('Enter a domain'); return; }
  fetch('/api/gotham/scope/add', {method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({domain, notes})}).then(r=>r.json()).then(d=>{
      if(d.error){ alert(d.error); return; }
      document.getElementById('gth-scope-domain').value='';
      document.getElementById('gth-scope-notes').value='';
      gthLoadScope();
    });
}
function gthRemoveScope(domain){
  if(!confirm(`Remove ${domain} from scope?`)) return;
  fetch('/api/gotham/scope/remove', {method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({domain})}).then(()=>gthLoadScope());
}

function gthLoadScans(){
  fetch('/api/gotham/scans').then(r=>r.json()).then(rows=>{
    const body = document.getElementById('gth-scans-body');
    body.innerHTML = rows.length ? rows.map(s=>
      `<tr><td class="mono">${s.id}</td><td>${s.target}</td><td>${s.status}</td><td>${s.pages_visited}</td><td>${s.findings_count}</td><td class="mono">${s.started_at}</td></tr>`
    ).join('') : '<tr><td colspan="6" class="empty-row">No scans yet.</td></tr>';
  });
}
function gthStartScan(){
  const target = document.getElementById('gth-scan-target').value.trim();
  const depth = document.getElementById('gth-scan-depth').value.trim() || '2';
  const rps = document.getElementById('gth-scan-rps').value.trim() || '1';
  if(!target){ alert('Enter a target — it must already be in scope'); return; }
  fetch('/api/gotham/scan', {method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({target, depth: parseInt(depth), requests_per_second: parseFloat(rps), mode:'passive'})})
    .then(r=>r.json()).then(d=>{
      if(d.error){ alert(d.error); return; }
      setTimeout(()=>{ gthLoadScans(); gthLoadFindings(); }, 1500);
      const poll = setInterval(()=>{ gthLoadScans(); gthLoadFindings(); }, 4000);
      setTimeout(()=>clearInterval(poll), 40000);
    });
}

function gthLoadFindings(){
  fetch('/api/gotham/findings').then(r=>r.json()).then(rows=>{
    const body = document.getElementById('gth-findings-body');
    body.innerHTML = rows.length ? rows.map(f=>
      `<tr><td class="sev-${f.severity}">${f.severity}</td><td>${f.finding_type}</td><td class="mono">${f.masked_value||''}</td><td>${f.confidence}</td><td>${f.domain}</td><td style="max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${f.source_url||''}</td></tr>`
    ).join('') : '<tr><td colspan="6" class="empty-row">No findings yet — run a scan.</td></tr>';
  });
}

function gthCreateCase(){
  const asset = document.getElementById('gth-case-asset').value.trim();
  if(!asset){ alert('Enter an asset/domain'); return; }
  fetch('/api/gotham/case', {method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({asset})}).then(r=>r.json()).then(d=>{
      if(d.error){ alert(d.error); return; }
      gthLoadCases();
    });
}
function gthLoadCases(){
  fetch('/api/gotham/cases').then(r=>r.json()).then(rows=>{
    const body = document.getElementById('gth-cases-body');
    body.innerHTML = rows.length ? rows.map(c=>
      `<tr><td class="mono">${c.id}</td><td>${c.asset}</td><td class="sev-${c.severity}">${c.severity}</td><td>${c.threat_score}</td><td>${c.status}</td>
       <td><button class="btn-outline" onclick="window.open('/api/gotham/report?case_id=${c.id}')">Report</button>
       <button class="btn-outline" onclick="window.open('/api/gotham/report?case_id=${c.id}&narrative=1')">+LM Studio</button></td></tr>`
    ).join('') : '<tr><td colspan="6" class="empty-row">No cases yet.</td></tr>';
  });
}

function gthCheckScam(){
  const text = document.getElementById('gth-scam-text').value;
  if(!text.trim()){ alert('Paste a message first'); return; }
  fetch('/api/gotham/scam/check', {method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({text})}).then(r=>r.json()).then(d=>{
      if(d.error){ alert(d.error); return; }
      const cls = d.verdict === 'LIKELY SCAM' ? 'sev-CRITICAL' : (d.verdict === 'SUSPICIOUS' ? 'sev-MEDIUM' : 'sev-LOW');
      document.getElementById('gth-scam-result').innerHTML =
        `Verdict: <span class="${cls}">${d.verdict}</span> — score ${d.score}`;
    });
}

function renderPlatformSection(name){
  const cfg = PLATFORM_SECTIONS[name];
  const extraInputs = cfg.fields.map(f =>
    `<div class="f-group"><label>${f.label}</label><input id="pf-${name}-${f.key}" placeholder="${f.placeholder||''}"></div>`
  ).join('');
  const extraCols = cfg.fields.map(f => `<th>${f.label}</th>`).join('');
  const isAdmin = currentRole === 'admin';
  return `
    <div class="section-head"><div><h2>${cfg.label}</h2><div class="section-desc">${cfg.desc}</div></div></div>
    <div class="section-body">
      <div class="platform-form">
        <div class="f-group"><label>Name</label><input id="pf-${name}-title" placeholder="Name"></div>
        ${extraInputs}
        <button class="btn-add" onclick="createPlatformItem('${name}')">Add</button>
      </div>
      <table class="data-table">
        <thead><tr><th>Name</th>${extraCols}<th>Created</th><th></th></tr></thead>
        <tbody id="platform-table-${name}"></tbody>
      </table>
    </div>`;
}

function loadPlatformSection(name){
  const container = document.getElementById('section-' + name);
  if(!container.dataset.built){
    container.innerHTML = renderPlatformSection(name);
    container.dataset.built = '1';
  }
  fetch('/api/platform?category=' + name).then(r=>r.json()).then(items=>{
    const cfg = PLATFORM_SECTIONS[name];
    const body = document.getElementById('platform-table-' + name);
    const isAdmin = currentRole === 'admin';
    if(!items.length){
      body.innerHTML = `<tr><td colspan="${cfg.fields.length+3}" class="empty-row">No entries yet.</td></tr>`;
      return;
    }
    body.innerHTML = items.map(it => {
      const cols = cfg.fields.map(f => `<td>${(it.fields && it.fields[f.key]) || ''}</td>`).join('');
      const delBtn = isAdmin ? `<button class="btn-danger" onclick="deletePlatformItem('${name}','${it.id}')">Delete</button>` : '';
      return `<tr><td>${it.title}</td>${cols}<td class="mono">${it.created_at||''}</td><td>${delBtn}</td></tr>`;
    }).join('');
  });
}

function createPlatformItem(name){
  const cfg = PLATFORM_SECTIONS[name];
  const title = document.getElementById(`pf-${name}-title`).value.trim();
  if(!title){ alert('Name is required'); return; }
  const fields = {};
  cfg.fields.forEach(f => {
    fields[f.key] = document.getElementById(`pf-${name}-${f.key}`).value.trim();
  });
  fetch('/api/platform/create', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({category:name, title, fields})
  }).then(r=>r.json()).then(d=>{
    if(d.error){ alert(d.error); return; }
    document.getElementById(`pf-${name}-title`).value = '';
    cfg.fields.forEach(f => { document.getElementById(`pf-${name}-${f.key}`).value = ''; });
    loadPlatformSection(name);
  });
}

function deletePlatformItem(name, id){
  if(!confirm('Delete this entry?')) return;
  fetch('/api/platform/delete', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({id})
  }).then(r=>r.json()).then(()=> loadPlatformSection(name));
}

function loadDataTable(){
  fetch('/api/files').then(r=>r.json()).then(fs=>{
    const isAdmin = currentRole === 'admin';
    const body = document.getElementById('data-table-body');
    if(!fs.length){
      body.innerHTML = '<tr><td colspan="2" class="empty-row">No files imported yet.</td></tr>';
      return;
    }
    body.innerHTML = fs.map(f => {
      const delBtn = isAdmin ? `<button class="btn-danger" onclick="deleteDataFile('${f}')">Delete</button>` : '';
      return `<tr><td>${f}</td><td>${delBtn}</td></tr>`;
    }).join('');
  });
}

function deleteDataFile(name){
  if(!confirm(`Delete "${name}" and everything it contributed to the graph?`)) return;
  fetch('/api/file/delete', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({name})
  }).then(r=>r.json()).then(d=>{
    if(d.error){ alert(d.error); return; }
    loadDataTable(); loadFiles(); loadMaster();
  });
}

function loadNotifications(){
  fetch('/api/notifications').then(r=>r.json()).then(rows=>{
    const list = document.getElementById('notif-list');
    if(!rows.length){
      list.innerHTML = '<div class="empty-row">No activity yet.</div>';
      return;
    }
    list.innerHTML = rows.map(n =>
      `<div class="notif-item"><span class="notif-ts mono">${n.created_at}</span>${n.message}</div>`
    ).join('');
  });
}

document.getElementById('logout-btn').onclick = () => {
  fetch('/api/logout', {method:'POST'}).then(()=> window.location.href = '/login');
};

document.getElementById('audit-btn').onclick = () => {
  fetch('/api/audit').then(r=>r.json()).then(rows=>{
    document.getElementById('audit-body').innerHTML = rows.map(r=>
      `<tr><td>${r.ts}</td><td>${r.user||''}</td><td>${r.action||''}</td><td>${(r.detail||'').slice(0,80)}</td><td>${r.ip||''}</td></tr>`
    ).join('');
    document.getElementById('audit-modal').style.display = 'block';
  });
};

function loadFiles(){
  fetch('/api/files').then(r=>r.json()).then(fs=>{
    document.getElementById('files').innerHTML = fs.map(f=>
      `<div class="file" onclick="loadFile('${f}')">${f}</div>`
    ).join('');
  });
}
loadFiles();

function loadFile(name){
  fetch('/api/file?name='+encodeURIComponent(name)).then(r=>r.json()).then(d=>{
    if(d.error) alert(d.error);
    else{
      document.getElementById('editor').value = d.content;
      currentFile = name;
      currentUri = d.uri || currentUri;
      runDiagnostics();
    }
  });
}

document.getElementById('import-btn').onclick = ()=> document.getElementById('file-input').click();
document.getElementById('file-input').onchange = function(){
  for(let f of this.files){
    let fd = new FormData(); fd.append('file', f);
    fetch('/api/import', {method:'POST', body:fd})
      .then(r=>r.json()).then(d=>{ loadFiles(); loadMaster(); });
  }
};

function loadMaster(){
  fetch('/api/master').then(r=>r.json()).then(d=>{
    graphData = d;
    draw();
    document.getElementById('stats').textContent =
      `Nodes: ${d.nodes.length}  Edges: ${d.edges.length}`;
  });
}
loadMaster();
document.getElementById('graph-refresh').onclick = loadMaster;

const communityColors = [
  '#ff6b6b','#4ecdc4','#ffe66d','#a06cd5','#6abf69','#ff8c42','#45b7d1','#f9ca24',
  '#e056a0','#7f8c8d','#2ecc71','#9b59b6','#f39c12','#1abc9c','#e74c3c','#3498db',
  '#c0392b','#16a085','#d35400','#8e44ad'
];

function draw(){
  ctx.clearRect(0,0,canvas.width,canvas.height);
  if(!graphData) return;
  ctx.save();
  ctx.translate(panX, panY);
  ctx.scale(zoom, zoom);

  (graphData.edges||[]).forEach(e=>{
    let src = graphData.nodes.find(n=>n.id===e.source);
    let tgt = graphData.nodes.find(n=>n.id===e.target);
    if(!src||!tgt) return;
    ctx.beginPath();
    ctx.moveTo(src.x, src.y);
    ctx.lineTo(tgt.x, tgt.y);
    ctx.strokeStyle = 'rgba(255,255,255,0.2)';
    ctx.lineWidth = Math.min(e.weight*0.8, 3);
    ctx.stroke();
  });

  const searchTerm = document.getElementById('search').value.trim().toLowerCase();
  (graphData.nodes||[]).forEach(n=>{
    ctx.beginPath();
    let s = n.size||10, x = n.x||100, y = n.y||100;
    if(n.shape==='square'){
      ctx.rect(x-s/2, y-s/2, s, s);
    } else if(n.shape==='triangle'){
      ctx.moveTo(x, y-s/2);
      ctx.lineTo(x+s/2, y+s/2);
      ctx.lineTo(x-s/2, y+s/2);
      ctx.closePath();
    } else {
      ctx.arc(x, y, s/2, 0, Math.PI*2);
    }
    let color = n.color;
    if(n.community>=0){
      color = communityColors[n.community % communityColors.length];
    }
    ctx.fillStyle = color;
    ctx.fill();
    if(searchTerm && n.label.toLowerCase().includes(searchTerm)){
      ctx.strokeStyle = '#fff';
      ctx.lineWidth = 3;
      ctx.stroke();
    }
    ctx.fillStyle = '#fff';
    ctx.font = `${Math.max(8, s/2.5)}px sans-serif`;
    ctx.textAlign = 'center';
    ctx.fillText(n.label, x, y - s/2 - 4);
  });

  ctx.restore();
}

canvas.onmousedown = e => {
  if(!graphData) return;
  const rect = canvas.getBoundingClientRect();
  const mx = (e.clientX - rect.left - panX) / zoom;
  const my = (e.clientY - rect.top - panY) / zoom;
  const node = graphData.nodes.find(n=>{
    const dx = n.x - mx, dy = n.y - my;
    return Math.sqrt(dx*dx+dy*dy) < (n.size||10);
  });
  if(node){
    clickCandidate = { node, startX: e.clientX, startY: e.clientY };
    dragNode = null;
    isPan = false;
  } else {
    isPan = true;
    lastMouse = { x: e.clientX, y: e.clientY };
  }
};

canvas.onmousemove = e => {
  if(dragNode){
    const rect = canvas.getBoundingClientRect();
    dragNode.x = (e.clientX - rect.left - panX) / zoom;
    dragNode.y = (e.clientY - rect.top - panY) / zoom;
    draw();
  } else if(isPan){
    panX += e.clientX - lastMouse.x;
    panY += e.clientY - lastMouse.y;
    lastMouse = { x: e.clientX, y: e.clientY };
    draw();
  } else if(clickCandidate){
    const dx = e.clientX - clickCandidate.startX;
    const dy = e.clientY - clickCandidate.startY;
    if(Math.sqrt(dx*dx+dy*dy) > CLICK_THRESH){
      dragNode = clickCandidate.node;
      clickCandidate = null;
    }
  }
};

canvas.onmouseup = e => {
  if(clickCandidate){
    openNodeDetail(clickCandidate.node);
    clickCandidate = null;
  }
  dragNode = null;
  isPan = false;
};

canvas.onwheel = e => {
  e.preventDefault();
  zoom *= e.deltaY < 0 ? 1.1 : 0.9;
  draw();
};

const searchInput = document.getElementById('search');
const searchResults = document.getElementById('search-results');
let searchTimeout;

searchInput.addEventListener('input', () => {
  draw();
  clearTimeout(searchTimeout);
  searchTimeout = setTimeout(doSearch, 200);
});

function doSearch(){
  const term = searchInput.value.trim();
  if(!term || !graphData){
    searchResults.style.display = 'none';
    return;
  }
  fetch('/api/search?q='+encodeURIComponent(term))
    .then(r=>r.json())
    .then(nodes=>{
      if(!nodes.length){
        searchResults.style.display = 'none';
        return;
      }
      searchResults.innerHTML = nodes.map(n=>
        `<div class="search-item" data-id="${n.id}">${n.label} (comm:${n.community})</div>`
      ).join('');
      searchResults.style.display = 'block';
      document.querySelectorAll('.search-item').forEach(el=>{
        el.onclick = ()=>{
          const nid = el.dataset.id;
          const node = graphData.nodes.find(n=>n.id===nid);
          if(node) openNodeDetail(node);
          searchResults.style.display = 'none';
        };
      });
    });
}

document.addEventListener('click', e => {
  if(!e.target.closest('#search-wrap')){
    searchResults.style.display = 'none';
  }
});

function openNodeDetail(node){
  document.getElementById('modal-title').textContent = 'Node: ' + node.label;
  const infoTable = document.getElementById('modal-info');
  const edgesTable = document.getElementById('modal-edges');
  const articleDiv = document.getElementById('modal-article');
  infoTable.innerHTML = `
    <tr><th>Label</th><td>${node.label}</td></tr>
    <tr><th>Community</th><td>${node.community>=0?node.community:'N/A'}</td></tr>
    <tr><th>Betweenness</th><td>${node.betweenness.toFixed(4)}</td></tr>
    <tr><th>Size</th><td>${node.size.toFixed(1)}</td></tr>
    <tr><th>Source File</th><td>${node.source_file||'N/A'}</td></tr>
  `;
  fetch('/api/node?id=' + encodeURIComponent(node.id))
    .then(r=>r.json())
    .then(detail=>{
      const connected = detail.edges || [];
      edgesTable.innerHTML = connected.length ?
        connected.map(e=>{
          const otherId = e.source===node.id ? e.target : e.source;
          const otherNode = graphData.nodes.find(n=>n.id===otherId);
          const otherLabel = otherNode ? otherNode.label : otherId;
          return `<tr><td>${otherLabel}</td><td>weight: ${e.weight.toFixed(1)}</td><td>${e.source_file||''}</td></tr>`;
        }).join('') :
        '<tr><td colspan="3">No edges</td></tr>';
      articleDiv.textContent = detail.article || 'No article information.';
    })
    .catch(()=>{
      edgesTable.innerHTML = '<tr><td colspan="3">Error loading edges.</td></tr>';
      articleDiv.textContent = 'Error loading article.';
    });
  document.getElementById('node-modal').style.display = 'block';
}

function closeModal(){
  document.getElementById('node-modal').style.display = 'none';
}
window.onclick = function(event){
  if(event.target === document.getElementById('node-modal')) closeModal();
  if(event.target === document.getElementById('audit-modal')) document.getElementById('audit-modal').style.display='none';
};

document.getElementById('run-btn').onclick = ()=>{
  fetch('/api/run',{
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify({code: document.getElementById('editor').value})
  })
  .then(r=>r.json())
  .then(d=> document.getElementById('output').textContent = d.output || d.error);
};

document.getElementById('nb-btn').onclick = ()=>{
  let nb;
  try{ nb = JSON.parse(document.getElementById('editor').value); }
  catch(e){ alert('Invalid JSON notebook'); return; }
  fetch('/api/notebook',{
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify(nb)
  })
  .then(r=>r.json())
  .then(d=> document.getElementById('output').textContent = d.output || d.error);
};

/* ---- Code Intelligence: diagnostics + completions ---- */
const editor = document.getElementById('editor');
const diagBar = document.getElementById('diag-bar');
const compBox = document.getElementById('completions');
let diagTimeout, compTimeout;

function cursorLineCol(){
  const pos = editor.selectionStart;
  const before = editor.value.slice(0, pos);
  const lines = before.split('\n');
  return { line: lines.length - 1, column: lines[lines.length-1].length };
}

function runDiagnostics(){
  fetch('/api/lsp/diagnostics', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({source: editor.value, uri: currentUri})
  }).then(r=>r.json()).then(d=>{
    const diags = d.diagnostics || [];
    diagBar.innerHTML = diags.length ?
      diags.map(x=>`<div class="diag-item ${x.severity===1?'err':''}">Line ${x.line}: ${x.message}</div>`).join('') :
      `<div class="diag-item" style="color:#4ec9b0">No issues found (${d.engine})</div>`;
  }).catch(()=>{});
}

editor.addEventListener('input', ()=>{
  clearTimeout(diagTimeout);
  diagTimeout = setTimeout(runDiagnostics, 500);
  clearTimeout(compTimeout);
  compTimeout = setTimeout(requestCompletions, 300);
});

function requestCompletions(){
  const {line, column} = cursorLineCol();
  fetch('/api/lsp/complete', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({source: editor.value, uri: currentUri, line, column})
  }).then(r=>r.json()).then(d=>{
    const items = d.completions || [];
    if(!items.length){ compBox.style.display='none'; return; }
    compBox.innerHTML = items.map(c=>`<div class="comp-item">${c.label} <span style="color:#888">${c.detail||''}</span></div>`).join('');
    compBox.style.display = 'block';
    const rect = editor.getBoundingClientRect();
    compBox.style.left = (rect.left + 20) + 'px';
    compBox.style.top = (rect.top + 40) + 'px';
    compBox.style.width = '260px';
    document.querySelectorAll('.comp-item').forEach((el, i)=>{
      el.onclick = ()=>{
        insertCompletion(items[i].label);
        compBox.style.display = 'none';
      };
    });
  }).catch(()=>{ compBox.style.display='none'; });
}

function insertCompletion(word){
  const pos = editor.selectionStart;
  const before = editor.value.slice(0, pos);
  const after = editor.value.slice(pos);
  const m = before.match(/([A-Za-z_][A-Za-z0-9_]*)$/);
  const start = m ? pos - m[1].length : pos;
  editor.value = editor.value.slice(0, start) + word + after;
  editor.selectionStart = editor.selectionEnd = start + word.length;
  editor.focus();
}

document.addEventListener('click', e=>{
  if(!e.target.closest('#completions') && e.target !== editor) compBox.style.display = 'none';
});

runDiagnostics();
</script>
</body>
</html>"""


# ======================================================================
#  CLI ENTRYPOINT  (pattern derived from __main__.py)
# ======================================================================
def add_arguments(parser):
    parser.description = f"{APP_NAME} — {APP_TAGLINE}"
    parser.add_argument("--host", default=HOST, help="Bind address (default: %(default)s)")
    parser.add_argument("--port", type=int, default=PORT, help="Bind port (default: %(default)s)")
    parser.add_argument("-v", "--verbose", action="count", default=0,
                         help="Increase log verbosity")


def print_banner(host, port):
    engines = []
    engines.append("pyflakes" if HAVE_PYFLAKES else "stdlib-compile")
    engines.append("jedi" if HAVE_JEDI else "keyword-fallback")
    engines.append("pluggy hooks" if HAVE_PLUGGY else "no plugin manager")
    print("=" * 72)
    print(f"  {APP_NAME} v{APP_VERSION} — {APP_TAGLINE}")
    print("=" * 72)
    print(f"  URL:              http://{host}:{port}")
    print(f"  Diagnostics via:  {engines[0]}")
    print(f"  Completions via:  {engines[1]}")
    print(f"  Plugin system:    {engines[2]}")
    print(f"  Data store:       {DB_PATH.resolve()}")
    print("-" * 72)
    print("  Umbra dependency:   pip install numpy")
    print("  Optional enhancers: pip install pyflakes jedi pluggy")
    print("=" * 72)




# ===== NAMESPACED UMBRA MODULE =====
"""
================================================================================
 UMBRA  —  Local-First Operational Intelligence & Knowledge Graph Platform
 Built by: OBLIVION
--------------------------------------------------------------------------------
 Single-file, dependency-minimal (stdlib + numpy only) implementation of:

    DATA -> INGEST -> PROFILE -> ONTOLOGY -> ENTITIES -> GRAPH -> SEARCH
         -> ANALYTICS -> AI AGENT (LM Studio) -> EVIDENCE -> UI

 Design principles enforced throughout this file:
   1. The database (SQLite) is the single source of truth. The graph, search
      index and UI are all *derived views* over it and can be rebuilt.
   2. The LLM (via LM Studio) never touches storage directly. It can only
      call registered, typed, read-mostly Tools. Every tool call and every
      claim the agent makes is logged and traceable back to a source record
      (provenance / evidence chain).
   3. No fake UI. Every button in the HTML frontend calls a real HTTP API
      endpoint implemented below, which calls a real engine, which touches
      real, persisted data.
   4. Runs fully offline. LM Studio is optional — if it's not running, every
      other subsystem (ingestion, ontology, graph, search, analytics) still
      works.
   5. Can run in LOCAL mode (bind 127.0.0.1, single user) or SERVER mode
      (bind 0.0.0.0, still single-process but reachable on a LAN).

 Usage:
   python umbra.py serve --mode local --port 8877
   python umbra.py serve --mode server --host 0.0.0.0 --port 8877
   python umbra.py ingest path/to/file.csv
   python umbra.py health
   python umbra.py lmstudio-test

 Requires: Python 3.10+, numpy (only used for graph/vector math).
================================================================================
"""
import os as _umbra_os
import re as _umbra_re
import io as _umbra_io
import csv as _umbra_csv
import sys as _umbra_sys
import json as _umbra_json
import time as _umbra_time
import uuid as _umbra_uuid
import math as _umbra_math
import sqlite3 as _umbra_sqlite3
import logging as _umbra_logging
import argparse as _umbra_argparse
import mimetypes as _umbra_mimetypes
import threading as _umbra_threading
import traceback as _umbra_traceback
import urllib.request
import urllib.error
from dataclasses import dataclass as _umbra_dataclass, field as _umbra_field, asdict as _umbra_asdict
from datetime import datetime as _umbra_datetime, timezone as _umbra_timezone
from http.server import BaseHTTPRequestHandler as _umbra_BaseHTTPRequestHandler, ThreadingHTTPServer as _umbra_ThreadingHTTPServer
from typing import Any as _umbra_Any, Optional as _umbra_Optional
from urllib.parse import urlparse as _umbra_urlparse, parse_qs as _umbra_parse_qs
try:
    import numpy as _umbra_np
    _umbra_UMBRA_NUMPY_AVAILABLE = True
except ImportError:
    _umbra_np = None
    _umbra_UMBRA_NUMPY_AVAILABLE = False
_umbra_APP_NAME = 'UMBRA'
_umbra_APP_COMPANY = 'OBLIVION'
_umbra_APP_VERSION = '5.3'

def _umbra__default_home() -> str:
    home = _umbra_os.environ.get('UMBRA_HOME')
    if home:
        return home
    return _umbra_os.path.join(_umbra_os.path.expanduser('~'), '.umbra')

@_umbra_dataclass
class _umbra_LMStudioConfig:
    host: str = 'localhost'
    port: int = 1234
    base_path: str = '/v1'
    model: _umbra_Optional[str] = None
    embedding_model: _umbra_Optional[str] = None
    api_key: _umbra_Optional[str] = None
    temperature: float = 0.2
    max_tokens: int = 1024
    timeout_seconds: float = 60.0
    streaming: bool = False

    @property
    def base_url(self) -> str:
        return f'http://{self.host}:{self.port}{self.base_path}'

@_umbra_dataclass
class _umbra_ServerConfig:
    mode: str = 'local'
    host: str = '127.0.0.1'
    port: int = 8877

@_umbra_dataclass
class _umbra_AppConfig:
    home_dir: str = _umbra_field(default_factory=_umbra__default_home)
    server: _umbra_ServerConfig = _umbra_field(default_factory=_umbra_ServerConfig)
    lm_studio: _umbra_LMStudioConfig = _umbra_field(default_factory=_umbra_LMStudioConfig)
    max_upload_bytes: int = 200 * 1024 * 1024
    max_preview_rows: int = 200

    @property
    def db_path(self) -> str:
        return _umbra_os.path.join(self.home_dir, 'umbra.db')

    @property
    def storage_dir(self) -> str:
        return _umbra_os.path.join(self.home_dir, 'objects')

    @property
    def config_path(self) -> str:
        return _umbra_os.path.join(self.home_dir, 'config.json')

    @property
    def log_path(self) -> str:
        return _umbra_os.path.join(self.home_dir, 'umbra.log')

    def ensure_dirs(self) -> None:
        _umbra_os.makedirs(self.home_dir, exist_ok=True)
        _umbra_os.makedirs(self.storage_dir, exist_ok=True)

    def save(self) -> None:
        self.ensure_dirs()
        data = {'server': _umbra_asdict(self.server), 'lm_studio': _umbra_asdict(self.lm_studio), 'max_upload_bytes': self.max_upload_bytes, 'max_preview_rows': self.max_preview_rows}
        with open(self.config_path, 'w', encoding='utf-8') as f:
            _umbra_json.dump(data, f, ensure_ascii=False, indent=2)

    @classmethod
    def load(cls) -> 'AppConfig':
        cfg = cls()
        if _umbra_os.path.exists(cfg.config_path):
            try:
                with open(cfg.config_path, 'r', encoding='utf-8') as f:
                    data = _umbra_json.load(f)
                cfg.server = _umbra_ServerConfig(**data.get('server', {}))
                cfg.lm_studio = _umbra_LMStudioConfig(**data.get('lm_studio', {}))
                cfg.max_upload_bytes = data.get('max_upload_bytes', cfg.max_upload_bytes)
                cfg.max_preview_rows = data.get('max_preview_rows', cfg.max_preview_rows)
            except Exception:
                pass
        return cfg

def _umbra_now_iso() -> str:
    return _umbra_datetime.now(_umbra_timezone.utc).isoformat()

def _umbra_new_id(prefix: str='') -> str:
    raw = _umbra_uuid.uuid4().hex[:16]
    return f'{prefix}{raw}' if prefix else raw

def _umbra_setup_logging(cfg: AppConfig) -> _umbra_logging.Logger:
    cfg.ensure_dirs()
    logger = _umbra_logging.getLogger('umbra')
    logger.setLevel(_umbra_logging.INFO)
    logger.handlers.clear()
    fmt = _umbra_logging.Formatter('%(asctime)s | %(levelname)-7s | %(name)s | %(message)s')
    fh = _umbra_logging.FileHandler(cfg.log_path, encoding='utf-8')
    fh.setFormatter(fmt)
    sh = _umbra_logging.StreamHandler(_umbra_sys.stdout)
    sh.setFormatter(fmt)
    logger.addHandler(fh)
    logger.addHandler(sh)
    return logger
_umbra_SCHEMA_SQL = "\nCREATE TABLE IF NOT EXISTS datasets (\n    dataset_id      TEXT PRIMARY KEY,\n    source_name     TEXT NOT NULL,\n    source_type     TEXT NOT NULL,\n    ingested_at     TEXT NOT NULL,\n    row_count       INTEGER DEFAULT 0,\n    column_count    INTEGER DEFAULT 0,\n    schema_json     TEXT,\n    profile_json    TEXT,\n    status          TEXT DEFAULT 'ready',\n    error           TEXT\n);\n\nCREATE TABLE IF NOT EXISTS records (\n    record_id       TEXT PRIMARY KEY,\n    dataset_id      TEXT NOT NULL,\n    row_index       INTEGER NOT NULL,\n    data_json       TEXT NOT NULL,\n    FOREIGN KEY(dataset_id) REFERENCES datasets(dataset_id)\n);\nCREATE INDEX IF NOT EXISTS idx_records_dataset ON records(dataset_id);\n\nCREATE TABLE IF NOT EXISTS object_types (\n    name            TEXT PRIMARY KEY,\n    properties_json TEXT NOT NULL,\n    description     TEXT,\n    created_at      TEXT NOT NULL,\n    ai_suggested    INTEGER DEFAULT 0\n);\n\nCREATE TABLE IF NOT EXISTS link_types (\n    name            TEXT PRIMARY KEY,\n    source_type     TEXT NOT NULL,\n    target_type     TEXT NOT NULL,\n    description     TEXT,\n    created_at      TEXT NOT NULL,\n    ai_suggested    INTEGER DEFAULT 0\n);\n\nCREATE TABLE IF NOT EXISTS objects (\n    object_id       TEXT PRIMARY KEY,\n    object_type     TEXT NOT NULL,\n    properties_json TEXT NOT NULL,\n    confidence      REAL DEFAULT 1.0,\n    created_at      TEXT NOT NULL,\n    updated_at      TEXT NOT NULL,\n    source_dataset  TEXT,\n    source_record   TEXT\n);\nCREATE INDEX IF NOT EXISTS idx_objects_type ON objects(object_type);\n\nCREATE TABLE IF NOT EXISTS links (\n    link_id         TEXT PRIMARY KEY,\n    link_type       TEXT NOT NULL,\n    source_object   TEXT NOT NULL,\n    target_object   TEXT NOT NULL,\n    properties_json TEXT,\n    confidence      REAL DEFAULT 1.0,\n    created_at      TEXT NOT NULL,\n    source_dataset  TEXT,\n    source_record   TEXT\n);\nCREATE INDEX IF NOT EXISTS idx_links_source ON links(source_object);\nCREATE INDEX IF NOT EXISTS idx_links_target ON links(target_object);\nCREATE INDEX IF NOT EXISTS idx_links_type ON links(link_type);\n\nCREATE TABLE IF NOT EXISTS evidence (\n    evidence_id     TEXT PRIMARY KEY,\n    subject_kind    TEXT NOT NULL,   -- 'object' | 'link' | 'claim'\n    subject_id      TEXT NOT NULL,\n    dataset_id      TEXT,\n    record_id       TEXT,\n    field           TEXT,\n    note            TEXT,\n    created_at      TEXT NOT NULL\n);\nCREATE INDEX IF NOT EXISTS idx_evidence_subject ON evidence(subject_kind, subject_id);\n\nCREATE TABLE IF NOT EXISTS cases (\n    case_id         TEXT PRIMARY KEY,\n    title           TEXT NOT NULL,\n    description     TEXT,\n    created_at      TEXT NOT NULL,\n    updated_at      TEXT NOT NULL,\n    payload_json    TEXT NOT NULL\n);\n\nCREATE TABLE IF NOT EXISTS audit_log (\n    log_id          TEXT PRIMARY KEY,\n    ts              TEXT NOT NULL,\n    operation       TEXT NOT NULL,\n    detail_json     TEXT,\n    status          TEXT NOT NULL,\n    duration_ms     REAL\n);\n\nCREATE TABLE IF NOT EXISTS ai_conversations (\n    conversation_id TEXT PRIMARY KEY,\n    created_at      TEXT NOT NULL,\n    title           TEXT\n);\n\nCREATE TABLE IF NOT EXISTS ai_messages (\n    message_id      TEXT PRIMARY KEY,\n    conversation_id TEXT NOT NULL,\n    role            TEXT NOT NULL,\n    content         TEXT NOT NULL,\n    tool_calls_json TEXT,\n    created_at      TEXT NOT NULL,\n    FOREIGN KEY(conversation_id) REFERENCES ai_conversations(conversation_id)\n);\nCREATE INDEX IF NOT EXISTS idx_ai_messages_conv ON ai_messages(conversation_id);\n"

class _umbra_Storage:
    """Thin, thread-safe access layer around a single SQLite file.

    All higher-level engines (ontology, graph, search, analytics, evidence)
    read and write exclusively through this class — nothing else in the
    application is allowed to open the database file directly. This keeps
    the storage backend swappable (e.g. to Postgres later) without touching
    business logic.
    """

    def __init__(self, cfg: AppConfig):
        self.cfg = cfg
        cfg.ensure_dirs()
        self._lock = _umbra_threading.RLock()
        self._conn = _umbra_sqlite3.connect(cfg.db_path, check_same_thread=False)
        self._conn.row_factory = _umbra_sqlite3.Row
        self._conn.execute('PRAGMA journal_mode=WAL;')
        self._conn.execute('PRAGMA foreign_keys=ON;')
        with self._lock:
            self._conn.executescript(_umbra_SCHEMA_SQL)
            self._conn.commit()

    def execute(self, sql: str, params: tuple=()) -> _umbra_sqlite3.Cursor:
        with self._lock:
            cur = self._conn.execute(sql, params)
            self._conn.commit()
            return cur

    def query(self, sql: str, params: tuple=()) -> list[_umbra_sqlite3.Row]:
        with self._lock:
            cur = self._conn.execute(sql, params)
            return cur.fetchall()

    def query_one(self, sql: str, params: tuple=()) -> _umbra_Optional[_umbra_sqlite3.Row]:
        rows = self.query(sql, params)
        return rows[0] if rows else None

    def raw_connection(self) -> _umbra_sqlite3.Connection:
        return self._conn

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def audit(self, operation: str, detail: dict, status: str='ok', duration_ms: float=0.0) -> None:
        self.execute('INSERT INTO audit_log (log_id, ts, operation, detail_json, status, duration_ms) VALUES (?,?,?,?,?,?)', (_umbra_new_id('log_'), _umbra_now_iso(), operation, _umbra_json.dumps(detail, ensure_ascii=False), status, duration_ms))

class _umbra_IngestionError(Exception):
    pass

def _umbra__sniff_dialect(sample: str) -> _umbra_csv.Dialect:
    try:
        return _umbra_csv.Sniffer().sniff(sample, delimiters=',;\t|')
    except Exception:
        return _umbra_csv.excel

def _umbra__read_csv(path: str) -> list[dict[str, _umbra_Any]]:
    with open(path, 'r', encoding='utf-8-sig', errors='replace', newline='') as f:
        sample = f.read(4096)
        f.seek(0)
        dialect = _umbra__sniff_dialect(sample)
        reader = _umbra_csv.DictReader(f, dialect=dialect)
        rows = []
        for row in reader:
            rows.append({(k or '').strip(): v for k, v in row.items()})
        return rows

def _umbra__read_json(path: str) -> list[dict[str, _umbra_Any]]:
    with open(path, 'r', encoding='utf-8', errors='replace') as f:
        data = _umbra_json.load(f)
    if isinstance(data, list):
        return [d if isinstance(d, dict) else {'value': d} for d in data]
    if isinstance(data, dict):
        for key in ('records', 'data', 'rows', 'items'):
            if key in data and isinstance(data[key], list):
                return [d if isinstance(d, dict) else {'value': d} for d in data[key]]
        return [data]
    raise _umbra_IngestionError('Unsupported JSON top-level structure')

def _umbra__read_jsonl(path: str) -> list[dict[str, _umbra_Any]]:
    rows = []
    with open(path, 'r', encoding='utf-8', errors='replace') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            obj = _umbra_json.loads(line)
            rows.append(obj if isinstance(obj, dict) else {'value': obj})
    return rows
_umbra_READERS = {'.csv': _umbra__read_csv, '.tsv': _umbra__read_csv, '.json': _umbra__read_json, '.jsonl': _umbra__read_jsonl, '.ndjson': _umbra__read_jsonl}

class _umbra_IngestionEngine:
    """Turns a raw file into a persisted Dataset + Records, fully audited."""

    def __init__(self, storage: Storage, logger: logging.Logger):
        self.storage = storage
        self.logger = logger

    def ingest_file(self, path: str, source_name: Optional[str]=None) -> dict:
        t0 = _umbra_time.time()
        ext = _umbra_os.path.splitext(path)[1].lower()
        reader = _umbra_READERS.get(ext)
        if reader is None:
            raise _umbra_IngestionError(f'Unsupported file extension: {ext}')
        dataset_id = _umbra_new_id('ds_')
        source_name = source_name or _umbra_os.path.basename(path)
        try:
            rows = reader(path)
        except Exception as e:
            self.storage.execute('INSERT INTO datasets (dataset_id, source_name, source_type, ingested_at, row_count, column_count, schema_json, profile_json, status, error) VALUES (?,?,?,?,?,?,?,?,?,?)', (dataset_id, source_name, ext.lstrip('.'), _umbra_now_iso(), 0, 0, '{}', '{}', 'error', str(e)))
            self.storage.audit('ingest_file', {'path': path}, status='error')
            raise _umbra_IngestionError(str(e)) from e
        columns = self._collect_columns(rows)
        schema = {c: self._infer_column_type(rows, c) for c in columns}
        self.storage.execute('INSERT INTO datasets (dataset_id, source_name, source_type, ingested_at, row_count, column_count, schema_json, profile_json, status, error) VALUES (?,?,?,?,?,?,?,?,?,?)', (dataset_id, source_name, ext.lstrip('.'), _umbra_now_iso(), len(rows), len(columns), _umbra_json.dumps(schema, ensure_ascii=False), '{}', 'ready', None))
        for idx, row in enumerate(rows):
            self.storage.execute('INSERT INTO records (record_id, dataset_id, row_index, data_json) VALUES (?,?,?,?)', (_umbra_new_id('rec_'), dataset_id, idx, _umbra_json.dumps(row, ensure_ascii=False, default=str)))
        profile = _umbra_DataProfiler(self.storage).profile_dataset(dataset_id)
        self.storage.execute('UPDATE datasets SET profile_json=? WHERE dataset_id=?', (_umbra_json.dumps(profile, ensure_ascii=False), dataset_id))
        duration = (_umbra_time.time() - t0) * 1000
        self.storage.audit('ingest_file', {'path': path, 'dataset_id': dataset_id, 'rows': len(rows)}, duration_ms=duration)
        self.logger.info(f'Ingested {source_name} -> {dataset_id} ({len(rows)} rows)')
        return {'dataset_id': dataset_id, 'source_name': source_name, 'row_count': len(rows), 'column_count': len(columns), 'schema': schema, 'profile': profile}

    @staticmethod
    def _collect_columns(rows: list[dict]) -> list[str]:
        cols: list[str] = []
        seen = set()
        for row in rows[:2000]:
            for k in row.keys():
                if k not in seen:
                    seen.add(k)
                    cols.append(k)
        return cols

    @staticmethod
    def _infer_column_type(rows: list[dict], col: str) -> str:
        sample = [r.get(col) for r in rows[:500] if r.get(col) not in (None, '')]
        if not sample:
            return 'string'
        if all((_umbra__looks_int(v) for v in sample)):
            return 'integer'
        if all((_umbra__looks_float(v) for v in sample)):
            return 'float'
        if all((_umbra__looks_bool(v) for v in sample)):
            return 'boolean'
        if all((_umbra__looks_date(v) for v in sample)):
            return 'datetime'
        return 'string'

def _umbra__looks_int(v: Any) -> bool:
    try:
        int(str(v).strip())
        return True
    except Exception:
        return False

def _umbra__looks_float(v: Any) -> bool:
    try:
        float(str(v).strip())
        return True
    except Exception:
        return False

def _umbra__looks_bool(v: Any) -> bool:
    return str(v).strip().lower() in {'true', 'false', 'yes', 'no', '0', '1'}
_umbra__DATE_RE = _umbra_re.compile('^\\d{4}-\\d{2}-\\d{2}([ T]\\d{2}:\\d{2}(:\\d{2})?)?Z?$')

def _umbra__looks_date(v: Any) -> bool:
    return bool(_umbra__DATE_RE.match(str(v).strip()))
_umbra__SEMANTIC_PATTERNS: dict[str, _umbra_re.Pattern] = {'email': _umbra_re.compile('^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$'), 'url': _umbra_re.compile('^https?://', _umbra_re.I), 'phone': _umbra_re.compile('^\\+?[\\d\\-\\s\\(\\)]{7,}$'), 'latitude': _umbra_re.compile('^-?\\d{1,2}\\.\\d+$'), 'longitude': _umbra_re.compile('^-?\\d{1,3}\\.\\d+$'), 'uuid': _umbra_re.compile('^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', _umbra_re.I)}
_umbra__NAME_HINTS = {'email': ['email', 'mail'], 'phone': ['phone', 'tel', 'mobile'], 'person_name': ['name', 'full_name', 'customer', 'person'], 'company_name': ['company', 'organization', 'employer', 'carrier', 'vendor'], 'address': ['address', 'street'], 'latitude': ['lat', 'latitude'], 'longitude': ['lon', 'lng', 'longitude'], 'timestamp': ['date', 'time', 'created', 'updated', 'at'], 'identifier': ['id', '_id', 'code', 'number', 'registration', 'tail']}

class _umbra_DataProfiler:
    """Computes statistics + semantic-type hints for every column of a dataset.

    Every semantic guess is returned with a confidence score and the reasoning
    behind it — the system never silently trusts a guess; callers (ontology
    engine, UI) decide whether to accept it.
    """

    def __init__(self, storage: Storage):
        self.storage = storage

    def profile_dataset(self, dataset_id: str) -> dict:
        ds = self.storage.query_one('SELECT * FROM datasets WHERE dataset_id=?', (dataset_id,))
        if not ds:
            raise ValueError('dataset not found')
        schema = _umbra_json.loads(ds['schema_json'] or '{}')
        rows = self.storage.query('SELECT data_json FROM records WHERE dataset_id=? LIMIT 5000', (dataset_id,))
        parsed = [_umbra_json.loads(r['data_json']) for r in rows]
        total = len(parsed)
        columns_profile = {}
        for col, dtype in schema.items():
            values = [p.get(col) for p in parsed]
            non_null = [v for v in values if v not in (None, '')]
            null_ratio = 1 - len(non_null) / total if total else 0.0
            distinct = set((str(v) for v in non_null))
            unique_ratio = len(distinct) / len(non_null) if non_null else 0.0
            semantic = self._guess_semantic(col, non_null)
            stat: dict[str, _umbra_Any] = {'dtype': dtype, 'null_ratio': round(null_ratio, 4), 'unique_ratio': round(unique_ratio, 4), 'distinct_count': len(distinct), 'semantic': semantic}
            if dtype in ('integer', 'float') and non_null:
                nums = _umbra_np.array([float(v) for v in non_null if _umbra__looks_float(v)], dtype=float)
                if nums.size:
                    stat.update({'min': float(_umbra_np.min(nums)), 'max': float(_umbra_np.max(nums)), 'mean': float(_umbra_np.mean(nums)), 'std': float(_umbra_np.std(nums))})
            columns_profile[col] = stat
        return {'dataset_id': dataset_id, 'row_count': total, 'columns': columns_profile, 'profiled_at': _umbra_now_iso()}

    @staticmethod
    def _guess_semantic(col: str, values: list[Any]) -> dict:
        col_lower = col.lower()
        best_name, best_conf, reason = (None, 0.0, '')
        for sem, hints in _umbra__NAME_HINTS.items():
            if any((h in col_lower for h in hints)):
                if 0.55 > best_conf:
                    best_name, best_conf, reason = (sem, 0.55, f"column name matches hint '{col_lower}'")
        sample = values[:100]
        for sem, pattern in _umbra__SEMANTIC_PATTERNS.items():
            if sample and all((pattern.match(str(v).strip()) for v in sample)):
                conf = 0.9
                if conf > best_conf:
                    best_name, best_conf = (sem, conf)
                    reason = f'{len(sample)}/{len(sample)} sampled values match pattern'
        if best_name is None:
            return {'guess': None, 'confidence': 0.0, 'reason': 'no pattern or name hint matched'}
        return {'guess': best_name, 'confidence': best_conf, 'reason': reason, 'source_column': col}

class _umbra_OntologyError(Exception):
    pass

class _umbra_OntologyEngine:
    """Owns the semantic model: which Object types exist, what properties they
    have, and which Link types may connect them. Objects/Links created by the
    entity-resolution step are validated against this model before being
    persisted.
    """

    def __init__(self, storage: Storage, logger: logging.Logger):
        self.storage = storage
        self.logger = logger

    def create_object_type(self, name: str, properties: dict[str, str], description: str='', ai_suggested: bool=False) -> dict:
        name = name.strip()
        if not name:
            raise _umbra_OntologyError('object type name required')
        existing = self.storage.query_one('SELECT name FROM object_types WHERE name=?', (name,))
        if existing:
            raise _umbra_OntologyError(f"object type '{name}' already exists")
        self.storage.execute('INSERT INTO object_types (name, properties_json, description, created_at, ai_suggested) VALUES (?,?,?,?,?)', (name, _umbra_json.dumps(properties, ensure_ascii=False), description, _umbra_now_iso(), int(ai_suggested)))
        self.storage.audit('create_object_type', {'name': name, 'properties': properties})
        return self.get_object_type(name)

    def get_object_type(self, name: str) -> _umbra_Optional[dict]:
        row = self.storage.query_one('SELECT * FROM object_types WHERE name=?', (name,))
        if not row:
            return None
        return {'name': row['name'], 'properties': _umbra_json.loads(row['properties_json']), 'description': row['description'], 'created_at': row['created_at'], 'ai_suggested': bool(row['ai_suggested'])}

    def list_object_types(self) -> list[dict]:
        rows = self.storage.query('SELECT * FROM object_types ORDER BY name')
        return [{'name': r['name'], 'properties': _umbra_json.loads(r['properties_json']), 'description': r['description'], 'ai_suggested': bool(r['ai_suggested'])} for r in rows]

    def create_link_type(self, name: str, source_type: str, target_type: str, description: str='', ai_suggested: bool=False) -> dict:
        if not self.get_object_type(source_type):
            raise _umbra_OntologyError(f"unknown source object type '{source_type}'")
        if not self.get_object_type(target_type):
            raise _umbra_OntologyError(f"unknown target object type '{target_type}'")
        existing = self.storage.query_one('SELECT name FROM link_types WHERE name=?', (name,))
        if existing:
            raise _umbra_OntologyError(f"link type '{name}' already exists")
        self.storage.execute('INSERT INTO link_types (name, source_type, target_type, description, created_at, ai_suggested) VALUES (?,?,?,?,?,?)', (name, source_type, target_type, description, _umbra_now_iso(), int(ai_suggested)))
        self.storage.audit('create_link_type', {'name': name, 'source': source_type, 'target': target_type})
        return self.get_link_type(name)

    def get_link_type(self, name: str) -> _umbra_Optional[dict]:
        row = self.storage.query_one('SELECT * FROM link_types WHERE name=?', (name,))
        if not row:
            return None
        return {'name': row['name'], 'source_type': row['source_type'], 'target_type': row['target_type'], 'description': row['description'], 'ai_suggested': bool(row['ai_suggested'])}

    def list_link_types(self) -> list[dict]:
        rows = self.storage.query('SELECT * FROM link_types ORDER BY name')
        return [{'name': r['name'], 'source_type': r['source_type'], 'target_type': r['target_type'], 'ai_suggested': bool(r['ai_suggested'])} for r in rows]

    def validate(self) -> list[dict]:
        """Returns a list of structural problems: dangling link types, etc."""
        problems = []
        obj_names = {o['name'] for o in self.list_object_types()}
        for lt in self.list_link_types():
            if lt['source_type'] not in obj_names:
                problems.append({'type': 'dangling_link_source', 'link_type': lt['name'], 'missing': lt['source_type']})
            if lt['target_type'] not in obj_names:
                problems.append({'type': 'dangling_link_target', 'link_type': lt['name'], 'missing': lt['target_type']})
        return problems

    def suggest_ontology_from_dataset(self, dataset_id: str) -> dict:
        """Purely local, deterministic heuristic pass over a dataset's profile
        to propose an ObjectType + candidate LinkTypes. This never mutates the
        ontology — it returns a proposal with confidence + reasoning that the
        caller (UI or agent) must explicitly approve via create_object_type /
        create_link_type.
        """
        ds = self.storage.query_one('SELECT * FROM datasets WHERE dataset_id=?', (dataset_id,))
        if not ds:
            raise _umbra_OntologyError('dataset not found')
        profile = _umbra_json.loads(ds['profile_json'] or '{}')
        columns = profile.get('columns', {})
        suggested_name = self._guess_object_type_name(ds['source_name'])
        properties = {}
        candidate_links = []
        for col, stat in columns.items():
            dtype = stat.get('dtype', 'string')
            properties[col] = dtype
            sem = stat.get('semantic', {})
            if sem.get('guess') == 'identifier' and stat.get('unique_ratio', 0) > 0.9:
                candidate_links.append({'hint': f"column '{col}' looks like a foreign key (high uniqueness, identifier-like name)", 'column': col, 'confidence': sem.get('confidence', 0.5)})
        proposal = {'dataset_id': dataset_id, 'proposed_object_type': suggested_name, 'properties': properties, 'confidence': 0.6, 'reasoning': f"Derived from column schema of dataset '{ds['source_name']}'. {len(properties)} properties detected.", 'candidate_relationships': candidate_links}
        return proposal

    @staticmethod
    def _guess_object_type_name(source_name: str) -> str:
        base = _umbra_os.path.splitext(source_name)[0]
        base = _umbra_re.sub('[_\\-]+', ' ', base).strip()
        words = [w for w in base.split() if w.lower() not in {'data', 'export', 'final'}]
        if not words:
            return 'Record'
        singular = words[-1]
        if singular.lower().endswith('ies'):
            singular = singular[:-3] + 'y'
        elif singular.lower().endswith('s') and (not singular.lower().endswith('ss')):
            singular = singular[:-1]
        return singular.capitalize()

class _umbra_EntityEngine:
    """Materializes rows of a dataset into Ontology Objects. Every created
    Object carries a source_dataset/source_record pointer, and a matching row
    is written into the `evidence` table — this is what lets the Evidence
    Engine later answer "why does the system believe this?".
    """

    def __init__(self, storage: Storage, ontology: 'OntologyEngine', logger: logging.Logger):
        self.storage = storage
        self.ontology = ontology
        self.logger = logger

    def materialize_dataset(self, dataset_id: str, object_type: str, id_column: Optional[str]=None) -> dict:
        ot = self.ontology.get_object_type(object_type)
        if not ot:
            raise _umbra_OntologyError(f"unknown object type '{object_type}'")
        rows = self.storage.query('SELECT record_id, data_json FROM records WHERE dataset_id=?', (dataset_id,))
        created = 0
        for row in rows:
            data = _umbra_json.loads(row['data_json'])
            object_id = _umbra_new_id(f'{object_type.lower()}_')
            if id_column and data.get(id_column):
                object_id = f'{object_type.lower()}_{_umbra__slug(str(data.get(id_column)))}'
            existing = self.storage.query_one('SELECT object_id FROM objects WHERE object_id=?', (object_id,))
            if existing:
                continue
            self.storage.execute('INSERT INTO objects (object_id, object_type, properties_json, confidence, created_at, updated_at, source_dataset, source_record) VALUES (?,?,?,?,?,?,?,?)', (object_id, object_type, _umbra_json.dumps(data, ensure_ascii=False, default=str), 1.0, _umbra_now_iso(), _umbra_now_iso(), dataset_id, row['record_id']))
            self.storage.execute('INSERT INTO evidence (evidence_id, subject_kind, subject_id, dataset_id, record_id, field, note, created_at) VALUES (?,?,?,?,?,?,?,?)', (_umbra_new_id('ev_'), 'object', object_id, dataset_id, row['record_id'], None, 'materialized directly from source record', _umbra_now_iso()))
            created += 1
        self.storage.audit('materialize_dataset', {'dataset_id': dataset_id, 'object_type': object_type, 'created': created})
        return {'object_type': object_type, 'created': created, 'skipped': len(rows) - created}

    def create_link(self, link_type: str, source_object: str, target_object: str, properties: Optional[dict]=None, confidence: float=1.0, dataset_id: Optional[str]=None, record_id: Optional[str]=None, note: str='') -> dict:
        lt = self.ontology.get_link_type(link_type)
        if not lt:
            raise _umbra_OntologyError(f"unknown link type '{link_type}'")
        so = self.storage.query_one('SELECT object_type FROM objects WHERE object_id=?', (source_object,))
        to = self.storage.query_one('SELECT object_type FROM objects WHERE object_id=?', (target_object,))
        if not so or not to:
            raise _umbra_OntologyError('source or target object does not exist')
        if so['object_type'] != lt['source_type'] or to['object_type'] != lt['target_type']:
            raise _umbra_OntologyError(f"type mismatch: link '{link_type}' expects {lt['source_type']}->{lt['target_type']}, got {so['object_type']}->{to['object_type']}")
        link_id = _umbra_new_id('lnk_')
        self.storage.execute('INSERT INTO links (link_id, link_type, source_object, target_object, properties_json, confidence, created_at, source_dataset, source_record) VALUES (?,?,?,?,?,?,?,?,?)', (link_id, link_type, source_object, target_object, _umbra_json.dumps(properties or {}, ensure_ascii=False), confidence, _umbra_now_iso(), dataset_id, record_id))
        self.storage.execute('INSERT INTO evidence (evidence_id, subject_kind, subject_id, dataset_id, record_id, field, note, created_at) VALUES (?,?,?,?,?,?,?,?)', (_umbra_new_id('ev_'), 'link', link_id, dataset_id, record_id, None, note or 'link created', _umbra_now_iso()))
        return {'link_id': link_id, 'link_type': link_type, 'source': source_object, 'target': target_object}

def _umbra__slug(text: str) -> str:
    text = _umbra_re.sub('\\s+', '-', text.strip().lower())
    text = _umbra_re.sub('[^a-z0-9\\-]', '', text)
    return text[:64] or _umbra_new_id()

class _umbra_GraphEngine:
    """Builds an in-memory graph view from the `objects`/`links` tables on
    demand (the tables remain the source of truth). Supports neighborhood
    queries, shortest/N-hop paths, degree & eigenvector centrality, and
    connected components. Every edge returned carries its link_id so callers
    can pull evidence for it.
    """

    def __init__(self, storage: Storage):
        self.storage = storage

    def _load(self, object_types: Optional[list[str]]=None, link_types: Optional[list[str]]=None) -> tuple[dict, dict]:
        obj_sql = 'SELECT object_id, object_type FROM objects'
        params: tuple = ()
        if object_types:
            placeholders = ','.join('?' * len(object_types))
            obj_sql += f' WHERE object_type IN ({placeholders})'
            params = tuple(object_types)
        nodes = {r['object_id']: r['object_type'] for r in self.storage.query(obj_sql, params)}
        link_sql = 'SELECT link_id, link_type, source_object, target_object, confidence FROM links'
        lparams: tuple = ()
        if link_types:
            placeholders = ','.join('?' * len(link_types))
            link_sql += f' WHERE link_type IN ({placeholders})'
            lparams = tuple(link_types)
        adjacency: dict[str, list[dict]] = {n: [] for n in nodes}
        for r in self.storage.query(link_sql, lparams):
            if r['source_object'] not in nodes or r['target_object'] not in nodes:
                continue
            edge = {'link_id': r['link_id'], 'link_type': r['link_type'], 'target': r['target_object'], 'confidence': r['confidence']}
            adjacency.setdefault(r['source_object'], []).append(edge)
            back = {'link_id': r['link_id'], 'link_type': r['link_type'], 'target': r['source_object'], 'confidence': r['confidence']}
            adjacency.setdefault(r['target_object'], []).append(back)
        return (nodes, adjacency)

    def neighbors(self, object_id: str, hops: int=1, link_types: Optional[list[str]]=None) -> dict:
        nodes, adjacency = self._load(link_types=link_types)
        if object_id not in nodes:
            return {'nodes': [], 'edges': [], 'error': 'object not found'}
        visited = {object_id}
        frontier = {object_id}
        edges_out = []
        for _ in range(max(1, hops)):
            next_frontier = set()
            for node in frontier:
                for edge in adjacency.get(node, []):
                    edges_out.append({**edge, 'source': node})
                    if edge['target'] not in visited:
                        visited.add(edge['target'])
                        next_frontier.add(edge['target'])
            frontier = next_frontier
            if not frontier:
                break
        result_nodes = [{'object_id': n, 'object_type': nodes[n]} for n in visited]
        return {'nodes': result_nodes, 'edges': edges_out}

    def shortest_path(self, source: str, target: str, max_hops: int=6) -> dict:
        nodes, adjacency = self._load()
        if source not in nodes or target not in nodes:
            return {'found': False, 'error': 'source or target not found'}
        if source == target:
            return {'found': True, 'path': [source], 'edges': []}
        from collections import deque
        parent: dict[str, tuple[str, dict]] = {}
        visited = {source}
        queue = deque([source])
        depth = {source: 0}
        while queue:
            node = queue.popleft()
            if depth[node] >= max_hops:
                continue
            for edge in adjacency.get(node, []):
                nxt = edge['target']
                if nxt in visited:
                    continue
                visited.add(nxt)
                parent[nxt] = (node, edge)
                depth[nxt] = depth[node] + 1
                if nxt == target:
                    path = [target]
                    edges = []
                    cur = target
                    while cur != source:
                        p, e = parent[cur]
                        path.append(p)
                        edges.append(e)
                        cur = p
                    path.reverse()
                    edges.reverse()
                    return {'found': True, 'path': path, 'edges': edges, 'hops': len(edges)}
                queue.append(nxt)
        return {'found': False, 'error': f'no path within {max_hops} hops'}

    def connected_components(self) -> list[list[str]]:
        nodes, adjacency = self._load()
        seen: set[str] = set()
        components = []
        for n in nodes:
            if n in seen:
                continue
            stack = [n]
            comp = []
            seen.add(n)
            while stack:
                cur = stack.pop()
                comp.append(cur)
                for e in adjacency.get(cur, []):
                    if e['target'] not in seen:
                        seen.add(e['target'])
                        stack.append(e['target'])
            components.append(comp)
        return components

    def centrality(self, object_types: Optional[list[str]]=None) -> dict:
        """Degree centrality (exact) + eigenvector centrality approximated via
        numpy power iteration on the adjacency matrix."""
        nodes, adjacency = self._load(object_types=object_types)
        ids = list(nodes.keys())
        n = len(ids)
        if n == 0:
            return {}
        index = {oid: i for i, oid in enumerate(ids)}
        A = _umbra_np.zeros((n, n), dtype=float)
        degree = {oid: 0 for oid in ids}
        for oid in ids:
            for e in adjacency.get(oid, []):
                if e['target'] in index:
                    A[index[oid], index[e['target']]] = 1.0
                    degree[oid] += 1
        vec = _umbra_np.ones(n, dtype=float)
        for _ in range(100):
            new_vec = A.T @ vec
            norm = _umbra_np.linalg.norm(new_vec)
            if norm == 0:
                break
            new_vec = new_vec / norm
            if _umbra_np.allclose(new_vec, vec, atol=1e-08):
                vec = new_vec
                break
            vec = new_vec
        eigenvector = {oid: float(vec[index[oid]]) for oid in ids}
        max_deg = max(degree.values()) if degree else 1
        return {oid: {'degree': degree[oid], 'degree_normalized': degree[oid] / max_deg if max_deg else 0.0, 'eigenvector': eigenvector[oid], 'object_type': nodes[oid]} for oid in ids}
_umbra__TOKEN_RE = _umbra_re.compile('[a-zA-Z0-9\\u0600-\\u06FF]+')

def _umbra__tokenize(text: str) -> list[str]:
    return [t.lower() for t in _umbra__TOKEN_RE.findall(text or '')]

class _umbra_SearchEngine:
    """Builds an in-memory TF-IDF index over Object properties on demand.
    Rebuilding is cheap enough (thousands of objects) to do per-query for a
    local-first tool; for larger corpora this class is the seam where a
    persistent inverted index would be swapped in without touching callers.
    """

    def __init__(self, storage: Storage):
        self.storage = storage

    def _corpus(self, object_types: Optional[list[str]]=None) -> list[dict]:
        sql = 'SELECT object_id, object_type, properties_json FROM objects'
        params: tuple = ()
        if object_types:
            placeholders = ','.join('?' * len(object_types))
            sql += f' WHERE object_type IN ({placeholders})'
            params = tuple(object_types)
        docs = []
        for r in self.storage.query(sql, params):
            props = _umbra_json.loads(r['properties_json'])
            text = ' '.join((str(v) for v in props.values() if v is not None))
            docs.append({'object_id': r['object_id'], 'object_type': r['object_type'], 'properties': props, 'text': text})
        return docs

    def search(self, query: str, object_types: Optional[list[str]]=None, top_k: int=20) -> list[dict]:
        docs = self._corpus(object_types)
        if not docs:
            return []
        query_tokens = _umbra__tokenize(query)
        if not query_tokens:
            return []
        tokenized_docs = [_umbra__tokenize(d['text']) for d in docs]
        vocab: dict[str, int] = {}
        for tokens in tokenized_docs + [query_tokens]:
            for t in tokens:
                if t not in vocab:
                    vocab[t] = len(vocab)
        n_docs = len(docs)
        n_terms = len(vocab)
        tf = _umbra_np.zeros((n_docs, n_terms), dtype=float)
        for i, tokens in enumerate(tokenized_docs):
            for t in tokens:
                tf[i, vocab[t]] += 1.0
            if tokens:
                tf[i] /= len(tokens)
        df = _umbra_np.count_nonzero(tf > 0, axis=0)
        idf = _umbra_np.log((1 + n_docs) / (1 + df)) + 1.0
        tfidf = tf * idf
        q_vec = _umbra_np.zeros(n_terms, dtype=float)
        for t in query_tokens:
            q_vec[vocab[t]] += 1.0
        if query_tokens:
            q_vec /= len(query_tokens)
        q_vec *= idf
        doc_norms = _umbra_np.linalg.norm(tfidf, axis=1)
        q_norm = _umbra_np.linalg.norm(q_vec)
        scores = _umbra_np.zeros(n_docs, dtype=float)
        if q_norm > 0:
            denom = doc_norms * q_norm
            with _umbra_np.errstate(divide='ignore', invalid='ignore'):
                scores = _umbra_np.where(denom > 0, tfidf @ q_vec / denom, 0.0)
        ranked = sorted(zip(scores.tolist(), docs), key=lambda x: x[0], reverse=True)
        results = []
        for score, doc in ranked[:top_k]:
            if score <= 0:
                continue
            results.append({'object_id': doc['object_id'], 'object_type': doc['object_type'], 'properties': doc['properties'], 'score': round(float(score), 4)})
        return results

class _umbra_AnalyticsError(Exception):
    pass
_umbra__FORBIDDEN_SQL = _umbra_re.compile('\\b(DROP|DELETE|TRUNCATE|ALTER|UPDATE|INSERT|ATTACH|PRAGMA|VACUUM|REPLACE)\\b', _umbra_re.I)

class _umbra_AnalyticsEngine:
    """Executes user/agent-supplied SQL against a read-only view of the
    database. Only SELECT statements are allowed; any destructive keyword is
    rejected before the query ever reaches SQLite, and the connection itself
    is opened in `mode=ro` so a bypass at the regex layer still can't mutate
    data.
    """

    def __init__(self, cfg: AppConfig):
        self.cfg = cfg

    def run_sql(self, sql: str, limit: int=500) -> dict:
        sql_stripped = sql.strip().rstrip(';')
        if not sql_stripped.lower().startswith('select'):
            raise _umbra_AnalyticsError('only SELECT statements are permitted')
        if _umbra__FORBIDDEN_SQL.search(sql_stripped):
            raise _umbra_AnalyticsError('statement contains a forbidden keyword')
        if ';' in sql_stripped:
            raise _umbra_AnalyticsError('multiple statements are not permitted')
        uri = f'file:{self.cfg.db_path}?mode=ro'
        conn = _umbra_sqlite3.connect(uri, uri=True)
        conn.row_factory = _umbra_sqlite3.Row
        try:
            cur = conn.execute(f'{sql_stripped} LIMIT {int(limit)}')
            cols = [d[0] for d in cur.description] if cur.description else []
            rows = [dict(r) for r in cur.fetchall()]
            return {'columns': cols, 'rows': rows, 'row_count': len(rows)}
        except _umbra_sqlite3.Error as e:
            raise _umbra_AnalyticsError(str(e)) from e
        finally:
            conn.close()

    def aggregate_property(self, object_type: str, property_name: str, op: str='count') -> dict:
        op = op.lower()
        if op not in {'count', 'sum', 'avg', 'min', 'max'}:
            raise _umbra_AnalyticsError(f"unsupported aggregation '{op}'")
        conn = _umbra_sqlite3.connect(f'file:{self.cfg.db_path}?mode=ro', uri=True)
        conn.row_factory = _umbra_sqlite3.Row
        try:
            rows = conn.execute('SELECT properties_json FROM objects WHERE object_type=?', (object_type,)).fetchall()
        finally:
            conn.close()
        values = []
        for r in rows:
            props = _umbra_json.loads(r['properties_json'])
            v = props.get(property_name)
            if v is None:
                continue
            if op != 'count':
                try:
                    v = float(v)
                except (TypeError, ValueError):
                    continue
            values.append(v)
        if op == 'count':
            return {'op': op, 'value': len(values)}
        if not values:
            return {'op': op, 'value': None}
        arr = _umbra_np.array(values, dtype=float)
        result = {'sum': float(_umbra_np.sum(arr)), 'avg': float(_umbra_np.mean(arr)), 'min': float(_umbra_np.min(arr)), 'max': float(_umbra_np.max(arr))}[op]
        return {'op': op, 'value': result, 'n': len(values)}

class _umbra_EvidenceEngine:

    def __init__(self, storage: Storage):
        self.storage = storage

    def for_object(self, object_id: str) -> dict:
        obj = self.storage.query_one('SELECT * FROM objects WHERE object_id=?', (object_id,))
        if not obj:
            return {'error': 'object not found'}
        ev_rows = self.storage.query("SELECT * FROM evidence WHERE subject_kind='object' AND subject_id=?", (object_id,))
        evidence = []
        for e in ev_rows:
            item = {'evidence_id': e['evidence_id'], 'note': e['note'], 'dataset_id': e['dataset_id'], 'record_id': e['record_id']}
            if e['record_id']:
                rec = self.storage.query_one('SELECT data_json FROM records WHERE record_id=?', (e['record_id'],))
                if rec:
                    item['source_record'] = _umbra_json.loads(rec['data_json'])
            if e['dataset_id']:
                ds = self.storage.query_one('SELECT source_name FROM datasets WHERE dataset_id=?', (e['dataset_id'],))
                if ds:
                    item['source_dataset_name'] = ds['source_name']
            evidence.append(item)
        return {'object_id': object_id, 'object_type': obj['object_type'], 'properties': _umbra_json.loads(obj['properties_json']), 'confidence': obj['confidence'], 'created_at': obj['created_at'], 'evidence': evidence}

    def for_link(self, link_id: str) -> dict:
        link = self.storage.query_one('SELECT * FROM links WHERE link_id=?', (link_id,))
        if not link:
            return {'error': 'link not found'}
        ev_rows = self.storage.query("SELECT * FROM evidence WHERE subject_kind='link' AND subject_id=?", (link_id,))
        evidence = [{'evidence_id': e['evidence_id'], 'note': e['note'], 'dataset_id': e['dataset_id'], 'record_id': e['record_id']} for e in ev_rows]
        return {'link_id': link_id, 'link_type': link['link_type'], 'source_object': link['source_object'], 'target_object': link['target_object'], 'confidence': link['confidence'], 'created_at': link['created_at'], 'evidence': evidence}

    def path_evidence(self, path_edges: list[dict]) -> list[dict]:
        return [self.for_link(e['link_id']) for e in path_edges if e.get('link_id')]

class _umbra_LLMProviderError(Exception):
    pass

class _umbra_LLMProvider:
    """Abstract interface. Only the AI infrastructure layer is allowed to know
    about a concrete backend's wire format — the rest of the app talks to
    this interface only, so LM Studio could be swapped for another
    OpenAI-compatible local server without touching the agent/tool code.
    """

    def health(self) -> dict:
        raise NotImplementedError

    def list_models(self) -> list[str]:
        raise NotImplementedError

    def chat(self, messages: list[dict], tools: Optional[list[dict]]=None, temperature: Optional[float]=None, max_tokens: Optional[int]=None) -> dict:
        raise NotImplementedError

    def embed(self, texts: list[str]) -> list[list[float]]:
        raise NotImplementedError

class _umbra_LMStudioProvider(_umbra_LLMProvider):
    """Real client for a local LM Studio server's OpenAI-compatible API.
    Nothing here is mocked: `chat()` performs an actual HTTP POST to
    `{base_url}/chat/completions` and returns LM Studio's real response
    (including any tool_calls the loaded model emits, if it supports native
    function calling). If LM Studio is not reachable, callers get a clear
    LLMProviderError instead of a silent fake answer.
    """

    def __init__(self, cfg: LMStudioConfig):
        self.cfg = cfg

    def _request(self, path: str, payload: Optional[dict]=None, method: str='GET') -> dict:
        url = f'{self.cfg.base_url}{path}'
        data = _umbra_json.dumps(payload).encode('utf-8') if payload is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header('Content-Type', 'application/json')
        if self.cfg.api_key:
            req.add_header('Authorization', f'Bearer {self.cfg.api_key}')
        try:
            with urllib.request.urlopen(req, timeout=self.cfg.timeout_seconds) as resp:
                body = resp.read().decode('utf-8')
                return _umbra_json.loads(body) if body else {}
        except urllib.error.HTTPError as e:
            detail = e.read().decode('utf-8', errors='replace')
            raise _umbra_LLMProviderError(f'LM Studio HTTP {e.code}: {detail}') from e
        except urllib.error.URLError as e:
            raise _umbra_LLMProviderError(f'LM Studio unavailable at {self.cfg.base_url} ({e.reason})') from e
        except TimeoutError as e:
            raise _umbra_LLMProviderError('LM Studio request timed out') from e

    def health(self) -> dict:
        try:
            data = self._request('/models')
            models = [m.get('id') for m in data.get('data', [])]
            return {'connected': True, 'models': models, 'base_url': self.cfg.base_url}
        except _umbra_LLMProviderError as e:
            return {'connected': False, 'error': str(e), 'base_url': self.cfg.base_url}

    def list_models(self) -> list[str]:
        data = self._request('/models')
        return [m.get('id') for m in data.get('data', [])]

    def chat(self, messages: list[dict], tools: Optional[list[dict]]=None, temperature: Optional[float]=None, max_tokens: Optional[int]=None) -> dict:
        model = self.cfg.model
        if not model:
            models = self.list_models()
            if not models:
                raise _umbra_LLMProviderError('no model loaded in LM Studio and none configured')
            model = models[0]
        payload: dict[str, _umbra_Any] = {'model': model, 'messages': messages, 'temperature': temperature if temperature is not None else self.cfg.temperature, 'max_tokens': max_tokens if max_tokens is not None else self.cfg.max_tokens, 'stream': False}
        if tools:
            payload['tools'] = tools
            payload['tool_choice'] = 'auto'
        data = self._request('/chat/completions', payload, method='POST')
        choices = data.get('choices', [])
        if not choices:
            raise _umbra_LLMProviderError(f'LM Studio returned no choices: {data}')
        message = choices[0].get('message', {})
        return {'content': message.get('content', '') or '', 'tool_calls': message.get('tool_calls') or [], 'raw': data}

    def embed(self, texts: list[str]) -> list[list[float]]:
        model = self.cfg.embedding_model or self.cfg.model
        if not model:
            raise _umbra_LLMProviderError('no embedding model configured')
        data = self._request('/embeddings', {'model': model, 'input': texts}, method='POST')
        return [item.get('embedding', []) for item in data.get('data', [])]

class _umbra_Tool:

    def __init__(self, name: str, description: str, parameters: dict, handler, read_only: bool=True):
        self.name = name
        self.description = description
        self.parameters = parameters
        self.handler = handler
        self.read_only = read_only

    def to_openai_schema(self) -> dict:
        return {'type': 'function', 'function': {'name': self.name, 'description': self.description, 'parameters': self.parameters}}

class _umbra_ToolRegistry:

    def __init__(self):
        self._tools: dict[str, _umbra_Tool] = {}

    def register(self, tool: Tool) -> None:
        self._tools[tool.name] = tool

    def get(self, name: str) -> _umbra_Optional[_umbra_Tool]:
        return self._tools.get(name)

    def all(self) -> list[_umbra_Tool]:
        return list(self._tools.values())

    def schemas(self) -> list[dict]:
        return [t.to_openai_schema() for t in self._tools.values()]

def _umbra_build_tool_registry(storage: Storage, graph: GraphEngine, search: SearchEngine, analytics: AnalyticsEngine, evidence: EvidenceEngine) -> _umbra_ToolRegistry:
    reg = _umbra_ToolRegistry()

    def search_objects(query: str, object_types: Optional[list[str]]=None, top_k: int=10):
        return {'results': search.search(query, object_types, top_k)}
    reg.register(_umbra_Tool('search_objects', 'Full-text (TF-IDF) search over stored Objects by property values.', {'type': 'object', 'properties': {'query': {'type': 'string'}, 'object_types': {'type': 'array', 'items': {'type': 'string'}}, 'top_k': {'type': 'integer', 'default': 10}}, 'required': ['query']}, search_objects))

    def get_object(object_id: str):
        return evidence.for_object(object_id)
    reg.register(_umbra_Tool('get_object', 'Fetch a single Object by id, including its evidence chain.', {'type': 'object', 'properties': {'object_id': {'type': 'string'}}, 'required': ['object_id']}, get_object))

    def get_evidence(kind: str, subject_id: str):
        return evidence.for_object(subject_id) if kind == 'object' else evidence.for_link(subject_id)
    reg.register(_umbra_Tool('get_evidence', "Return the provenance/evidence chain for an object or a link ('why does the system believe this?').", {'type': 'object', 'properties': {'kind': {'type': 'string', 'enum': ['object', 'link']}, 'subject_id': {'type': 'string'}}, 'required': ['kind', 'subject_id']}, get_evidence))

    def traverse_graph(object_id: str, hops: int=1, link_types: Optional[list[str]]=None):
        return graph.neighbors(object_id, hops, link_types)
    reg.register(_umbra_Tool('traverse_graph', 'Get the N-hop neighborhood (nodes+edges) around an Object.', {'type': 'object', 'properties': {'object_id': {'type': 'string'}, 'hops': {'type': 'integer', 'default': 1}, 'link_types': {'type': 'array', 'items': {'type': 'string'}}}, 'required': ['object_id']}, traverse_graph))

    def find_paths(source_object: str, target_object: str, max_hops: int=6):
        result = graph.shortest_path(source_object, target_object, max_hops)
        if result.get('found'):
            result['edge_evidence'] = evidence.path_evidence(result['edges'])
        return result
    reg.register(_umbra_Tool('find_paths', 'Find the shortest path between two Objects in the graph, with evidence for every edge on the path.', {'type': 'object', 'properties': {'source_object': {'type': 'string'}, 'target_object': {'type': 'string'}, 'max_hops': {'type': 'integer', 'default': 6}}, 'required': ['source_object', 'target_object']}, find_paths))

    def get_neighbors_centrality(object_types: Optional[list[str]]=None):
        return {'centrality': graph.centrality(object_types)}
    reg.register(_umbra_Tool('get_centrality', 'Compute degree + eigenvector centrality over the graph (optionally filtered by object type) to find the most connected/important objects.', {'type': 'object', 'properties': {'object_types': {'type': 'array', 'items': {'type': 'string'}}}}, get_neighbors_centrality))

    def query_sql(sql: str, limit: int=200):
        return analytics.run_sql(sql, limit)
    reg.register(_umbra_Tool('query_sql', 'Run a read-only SELECT query against the local database (tables: datasets, records, objects, links, object_types, link_types, evidence). DROP/DELETE/UPDATE/INSERT/ALTER are rejected.', {'type': 'object', 'properties': {'sql': {'type': 'string'}, 'limit': {'type': 'integer', 'default': 200}}, 'required': ['sql']}, query_sql, read_only=True))

    def get_schema():
        obj_types = storage.query('SELECT name, properties_json FROM object_types')
        link_types = storage.query('SELECT name, source_type, target_type FROM link_types')
        return {'object_types': [{'name': r['name'], 'properties': _umbra_json.loads(r['properties_json'])} for r in obj_types], 'link_types': [dict(r) for r in link_types]}
    reg.register(_umbra_Tool('get_schema', 'Return the current ontology: all Object types (with properties) and Link types.', {'type': 'object', 'properties': {}}, get_schema))

    def inspect_dataset(dataset_id: str):
        ds = storage.query_one('SELECT * FROM datasets WHERE dataset_id=?', (dataset_id,))
        if not ds:
            return {'error': 'dataset not found'}
        return {'dataset_id': ds['dataset_id'], 'source_name': ds['source_name'], 'row_count': ds['row_count'], 'schema': _umbra_json.loads(ds['schema_json'] or '{}'), 'profile': _umbra_json.loads(ds['profile_json'] or '{}')}
    reg.register(_umbra_Tool('inspect_dataset', 'Get schema + statistical profile for a previously ingested dataset.', {'type': 'object', 'properties': {'dataset_id': {'type': 'string'}}, 'required': ['dataset_id']}, inspect_dataset))

    def get_statistics(object_type: str, property_name: str, op: str='count'):
        return analytics.aggregate_property(object_type, property_name, op)
    reg.register(_umbra_Tool('get_statistics', 'Aggregate a numeric/any property across all Objects of a given type (op: count|sum|avg|min|max).', {'type': 'object', 'properties': {'object_type': {'type': 'string'}, 'property_name': {'type': 'string'}, 'op': {'type': 'string', 'enum': ['count', 'sum', 'avg', 'min', 'max']}}, 'required': ['object_type', 'property_name']}, get_statistics))
    return reg
_umbra__TOOL_CALL_FALLBACK_RE = _umbra_re.compile('```(?:json)?\\s*(\\{.*?\\"tool\\"\\s*:.*?\\})\\s*```', _umbra_re.S)

@_umbra_dataclass
class _umbra_AgentStep:
    kind: str
    detail: dict

class _umbra_Agent:
    """Evidence-aware ReAct-style agent. On every turn it either:
      - asks LM Studio for the next step, letting the model emit native
        OpenAI-style tool_calls (works for tool-calling-capable local models), or
      - falls back to parsing a fenced ```json {"tool": "...", "arguments": {}}```
        block for models that don't support native function calling.

    Every tool call, its arguments, its raw result and duration are recorded
    so the UI can show "Searching objects... / Analyzing graph..." without
    ever exposing hidden model reasoning. The final answer must be grounded
    in tool results — the system prompt explicitly forbids presenting an
    unverified claim as fact.
    """
    SYSTEM_PROMPT = 'You are UMBRA, an evidence-driven data analyst built by OBLIVION. You investigate a local knowledge graph using ONLY the tools provided — you never invent object ids, relationships, or numbers. For every factual claim in your final answer, make sure it is backed by a tool result you actually received. If you are not sure, say so explicitly and suggest what data would resolve the uncertainty. When you are ready to answer, respond with plain text and no further tool calls. If the runtime you are using does not support native function calling, emit a single fenced JSON block of the exact form ```json\\n{"tool": "<name>", "arguments": {...}}\\n``` and nothing else, one tool call at a time.'

    def __init__(self, provider: LLMProvider, registry: ToolRegistry, storage: Storage, logger: logging.Logger, max_steps: int=6):
        self.provider = provider
        self.registry = registry
        self.storage = storage
        self.logger = logger
        self.max_steps = max_steps

    def run(self, user_query: str, conversation_id: Optional[str]=None) -> dict:
        conversation_id = conversation_id or _umbra_new_id('conv_')
        self._ensure_conversation(conversation_id)
        self._save_message(conversation_id, 'user', user_query)
        messages = [{'role': 'system', 'content': self.SYSTEM_PROMPT}, {'role': 'user', 'content': user_query}]
        steps: list[dict] = []
        tool_schemas = self.registry.schemas()
        for step_index in range(self.max_steps):
            t0 = _umbra_time.time()
            try:
                response = self.provider.chat(messages, tools=tool_schemas)
            except _umbra_LLMProviderError as e:
                return {'conversation_id': conversation_id, 'answer': None, 'error': str(e), 'steps': steps}
            duration = (_umbra_time.time() - t0) * 1000
            tool_calls = response.get('tool_calls') or []
            content = response.get('content') or ''
            if not tool_calls:
                fallback = self._parse_fallback_tool_call(content)
                if fallback:
                    tool_calls = [fallback]
                    content = ''
            if not tool_calls:
                self._save_message(conversation_id, 'assistant', content)
                steps.append({'kind': 'final', 'content': content, 'duration_ms': duration})
                return {'conversation_id': conversation_id, 'answer': content, 'steps': steps}
            messages.append({'role': 'assistant', 'content': content or None, 'tool_calls': tool_calls})
            for call in tool_calls:
                name, args, call_id = self._extract_call(call)
                steps.append({'kind': 'tool_call', 'tool': name, 'arguments': args, 'label': self._friendly_label(name)})
                tool = self.registry.get(name)
                if tool is None:
                    result = {'error': f"unknown tool '{name}'"}
                else:
                    t1 = _umbra_time.time()
                    try:
                        result = tool.handler(**args)
                    except Exception as e:
                        result = {'error': str(e)}
                    tool_ms = (_umbra_time.time() - t1) * 1000
                    self.storage.audit('agent_tool_call', {'tool': name, 'arguments': args}, status='ok' if 'error' not in result else 'error', duration_ms=tool_ms)
                steps.append({'kind': 'tool_result', 'tool': name, 'result': result})
                messages.append({'role': 'tool', 'tool_call_id': call_id or _umbra_new_id('call_'), 'name': name, 'content': _umbra_json.dumps(result, ensure_ascii=False, default=str)[:8000]})
        final = 'Reached the maximum reasoning steps without a final answer. Try narrowing the question.'
        self._save_message(conversation_id, 'assistant', final)
        return {'conversation_id': conversation_id, 'answer': final, 'steps': steps}

    @staticmethod
    def _extract_call(call: dict) -> tuple[str, dict, _umbra_Optional[str]]:
        fn = call.get('function', call)
        name = fn.get('name', '')
        raw_args = fn.get('arguments', '{}')
        try:
            args = _umbra_json.loads(raw_args) if isinstance(raw_args, str) else raw_args or {}
        except _umbra_json.JSONDecodeError:
            args = {}
        return (name, args, call.get('id'))

    @staticmethod
    def _parse_fallback_tool_call(content: str) -> _umbra_Optional[dict]:
        match = _umbra__TOOL_CALL_FALLBACK_RE.search(content)
        if not match:
            return None
        try:
            obj = _umbra_json.loads(match.group(1))
        except _umbra_json.JSONDecodeError:
            return None
        if 'tool' not in obj:
            return None
        return {'id': _umbra_new_id('call_'), 'function': {'name': obj['tool'], 'arguments': _umbra_json.dumps(obj.get('arguments', {}))}}

    @staticmethod
    def _friendly_label(tool_name: str) -> str:
        labels = {'search_objects': 'Searching objects…', 'get_object': 'Fetching object…', 'get_evidence': 'Collecting evidence…', 'traverse_graph': 'Analyzing graph…', 'find_paths': 'Finding relationship paths…', 'get_centrality': 'Ranking importance…', 'query_sql': 'Querying data…', 'get_schema': 'Reading ontology…', 'inspect_dataset': 'Inspecting dataset…', 'get_statistics': 'Computing statistics…'}
        return labels.get(tool_name, f'Running {tool_name}…')

    def _ensure_conversation(self, conversation_id: str) -> None:
        existing = self.storage.query_one('SELECT conversation_id FROM ai_conversations WHERE conversation_id=?', (conversation_id,))
        if not existing:
            self.storage.execute('INSERT INTO ai_conversations (conversation_id, created_at, title) VALUES (?,?,?)', (conversation_id, _umbra_now_iso(), None))

    def _save_message(self, conversation_id: str, role: str, content: str) -> None:
        self.storage.execute('INSERT INTO ai_messages (message_id, conversation_id, role, content, tool_calls_json, created_at) VALUES (?,?,?,?,?,?)', (_umbra_new_id('msg_'), conversation_id, role, content, None, _umbra_now_iso()))

def _umbra_parse_multipart(body: bytes, content_type: str) -> dict[str, dict]:
    """Minimal multipart/form-data parser (avoids the deprecated cgi module).
    Returns {field_name: {"filename": str|None, "data": bytes}}.
    """
    m = _umbra_re.search('boundary="?([^";]+)"?', content_type)
    if not m:
        raise ValueError('no multipart boundary found')
    boundary = ('--' + m.group(1)).encode('utf-8')
    parts = body.split(boundary)
    fields: dict[str, dict] = {}
    for part in parts:
        part = part.strip(b'\r\n')
        if not part or part == b'--':
            continue
        if b'\r\n\r\n' not in part:
            continue
        header_blob, data = part.split(b'\r\n\r\n', 1)
        data = data.rstrip(b'\r\n')
        headers = header_blob.decode('utf-8', errors='replace')
        name_match = _umbra_re.search('name="([^"]+)"', headers)
        filename_match = _umbra_re.search('filename="([^"]*)"', headers)
        if not name_match:
            continue
        fields[name_match.group(1)] = {'filename': filename_match.group(1) if filename_match else None, 'data': data}
    return fields

class _umbra_UmbraApp:

    def __init__(self, cfg: AppConfig):
        self.cfg = cfg
        self.logger = _umbra_setup_logging(cfg)
        self.storage = _umbra_Storage(cfg)
        self.ingestion = _umbra_IngestionEngine(self.storage, self.logger)
        self.profiler = _umbra_DataProfiler(self.storage)
        self.ontology = _umbra_OntologyEngine(self.storage, self.logger)
        self.entities = _umbra_EntityEngine(self.storage, self.ontology, self.logger)
        self.graph = _umbra_GraphEngine(self.storage)
        self.search = _umbra_SearchEngine(self.storage)
        self.analytics = _umbra_AnalyticsEngine(cfg)
        self.evidence = _umbra_EvidenceEngine(self.storage)
        self.llm = _umbra_LMStudioProvider(cfg.lm_studio)
        self.tools = _umbra_build_tool_registry(self.storage, self.graph, self.search, self.analytics, self.evidence)
        self.agent = _umbra_Agent(self.llm, self.tools, self.storage, self.logger)
        self.logger.info(f'{_umbra_APP_NAME} core initialized. home={cfg.home_dir}')

    def reload_llm(self) -> None:
        self.llm = _umbra_LMStudioProvider(self.cfg.lm_studio)
        self.agent = _umbra_Agent(self.llm, self.tools, self.storage, self.logger)

    def health(self) -> dict:
        obj_count = self.storage.query_one('SELECT COUNT(*) c FROM objects')['c']
        link_count = self.storage.query_one('SELECT COUNT(*) c FROM links')['c']
        ds_count = self.storage.query_one('SELECT COUNT(*) c FROM datasets')['c']
        lm_health = self.llm.health()
        return {'app': _umbra_APP_NAME, 'version': _umbra_APP_VERSION, 'company': _umbra_APP_COMPANY, 'mode': self.cfg.server.mode, 'database': {'path': self.cfg.db_path, 'ok': True}, 'counts': {'datasets': ds_count, 'objects': obj_count, 'links': link_count}, 'lm_studio': lm_health, 'time': _umbra_now_iso()}

    def create_case(self, title: str, description: str, payload: dict) -> dict:
        case_id = _umbra_new_id('case_')
        self.storage.execute('INSERT INTO cases (case_id, title, description, created_at, updated_at, payload_json) VALUES (?,?,?,?,?,?)', (case_id, title, description, _umbra_now_iso(), _umbra_now_iso(), _umbra_json.dumps(payload, ensure_ascii=False)))
        return {'case_id': case_id}

    def list_cases(self) -> list[dict]:
        rows = self.storage.query('SELECT case_id, title, description, created_at, updated_at FROM cases ORDER BY updated_at DESC')
        return [dict(r) for r in rows]

    def get_case(self, case_id: str) -> _umbra_Optional[dict]:
        row = self.storage.query_one('SELECT * FROM cases WHERE case_id=?', (case_id,))
        if not row:
            return None
        d = dict(row)
        d['payload'] = _umbra_json.loads(d.pop('payload_json'))
        return d
_umbra_FRONTEND_HTML = '<!DOCTYPE html>\n<html lang="en" dir="ltr" data-theme="light">\n<head>\n<meta charset="UTF-8">\n<meta name="viewport" content="width=device-width, initial-scale=1.0">\n<title>UMBRA — OBLIVION</title>\n<style>\n/* ============================================================================\n   UMBRA design system — re-based on Palantir\'s Blueprint design language.\n   Palette, elevation, radii and component conventions follow the public\n   @blueprintjs/core Sass API (Blue3 #2D72D2 primary intent, the Gray/Dark-Gray\n   scale, 3px corner radius, and the standard elevation shadow stack). Layout\n   density (dense tables, master-detail ontology view, small icon toolbars on\n   every card) mirrors Foundry/AIP-style operational workspaces. Fully\n   original CSS — no external fonts/CDNs, app must keep working offline.\n============================================================================ */\n:root{\n  --font-sans:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Vazirmatn",Helvetica,Arial,sans-serif;\n  --font-mono:ui-monospace,"SFMono-Regular",Consolas,"Liberation Mono",Menlo,monospace;\n  /* Blueprint\'s pt-border-radius is 3px across the board; larger panels get 4-6px. */\n  --radius-sm:3px; --radius:3px; --radius-lg:4px; --radius-xl:6px;\n  --dur:100ms; --ease:cubic-bezier(.4,1,.75,.9);\n  --sp-1:4px; --sp-2:8px; --sp-3:12px; --sp-4:16px; --sp-5:20px; --sp-6:24px;\n\n  /* Monochrome black/white chrome — primary accent is ink, not blue.\n     Semantic "detail" colors (status, classification, chart, type) stay\n     saturated per Blueprint\'s intent palette; only the interactive/\n     structural accent is neutral. --accent/--accent-strong/--accent-bg/\n     --accent-border/--accent-contrast are set per theme below. */\n  --success:#238551; --success-bg:rgba(35,133,81,.15);\n  --warning:#C87619; --warning-bg:rgba(200,118,25,.15);\n  --danger:#CD4246;  --danger-bg:rgba(205,66,70,.15);\n  --purple:#7961DB;  --teal:#00A396; --orange:#C87619; --pink:#DB2C6F;\n}\nhtml[data-theme="dark"]{\n  /* Blueprint dark scale: dark-gray1/2/3/4 */\n  --bg-canvas:#111418; --bg-surface:#181D22; --bg-surface-2:#252A31; --bg-surface-3:#383E47;\n  --border:#30363F; --border-strong:#494F58;\n  --text-strong:#F6F7F9; --text:#ABB3BF; --text-muted:#8F99A8; --text-faint:#5F6B7C;\n  --shadow-1:0 0 0 1px rgba(0,0,0,.4), 0 1px 1px rgba(0,0,0,.3), 0 2px 6px rgba(0,0,0,.3);\n  --shadow-2:inset 0 0 0 1px rgba(255,255,255,.08), 0 2px 4px rgba(0,0,0,.4), 0 8px 24px rgba(0,0,0,.45);\n  --scrollbar:#383E47;\n  /* black/white theme, inverted for dark mode: near-white ink on dark chrome */\n  --accent:#EDEFF2; --accent-strong:#FFFFFF; --accent-bg:rgba(255,255,255,.12);\n  --accent-border:rgba(255,255,255,.35); --accent-contrast:#111418;\n}\nhtml[data-theme="light"]{\n  /* Blueprint light scale: light-gray5/4/3, gray1/3 text */\n  --bg-canvas:#F6F7F9; --bg-surface:#FFFFFF; --bg-surface-2:#F6F7F9; --bg-surface-3:#EBEEF1;\n  --border:#DCE0E5; --border-strong:#C5CBD3;\n  --text-strong:#111418; --text:#404854; --text-muted:#5F6B7C; --text-faint:#8F99A8;\n  --shadow-1:0 0 0 1px rgba(17,20,24,.08), 0 1px 1px rgba(17,20,24,.1), 0 1px 4px rgba(17,20,24,.08);\n  --shadow-2:0 0 0 1px rgba(17,20,24,.1), 0 2px 4px rgba(17,20,24,.15), 0 8px 24px rgba(17,20,24,.15);\n  --scrollbar:#C5CBD3;\n  /* black/white theme: near-black ink on light chrome */\n  --accent:#14181C; --accent-strong:#14181C; --accent-bg:rgba(20,24,28,.07);\n  --accent-border:rgba(20,24,28,.3); --accent-contrast:#FFFFFF;\n}\n*{box-sizing:border-box; margin:0; padding:0;}\nhtml,body{height:100%;}\nbody{\n  background:var(--bg-canvas); color:var(--text); font-family:var(--font-sans);\n  font-size:13px; overflow:hidden; direction:rtl; -webkit-font-smoothing:antialiased;\n  line-height:1.4;\n}\n::-webkit-scrollbar{width:10px; height:10px;}\n::-webkit-scrollbar-thumb{background:var(--scrollbar); border-radius:8px; border:2px solid transparent; background-clip:content-box;}\n::-webkit-scrollbar-track{background:transparent;}\n::selection{background:var(--accent-bg); color:var(--text-strong);}\n\n#app{display:flex; height:100vh; width:100vw;}\n\n/* ---------------------------- sidebar --------------------------------- */\n#sidebar{\n  width:224px; min-width:224px; background:var(--bg-surface); border-right:1px solid var(--border);\n  display:flex; flex-direction:column; padding:14px 10px; gap:2px;\n}\n#brand{display:flex; align-items:center; gap:10px; padding:4px 6px 14px 6px; margin-bottom:8px; border-bottom:1px solid var(--border);}\n#brand .logo{width:26px; height:26px; flex-shrink:0; color:var(--accent); border-radius:var(--radius-sm); background:var(--accent-bg); display:flex; align-items:center; justify-content:center;}\n#brand .logo svg{width:66%; height:66%; display:block;}\n#brand .txt b{font-size:14px; font-weight:700; letter-spacing:.2px; color:var(--text-strong); display:block;}\n#brand .txt span{font-size:9px; color:var(--text-faint); letter-spacing:2px; font-weight:600; text-transform:uppercase;}\n\n.nav-group{margin-bottom:2px;}\n.nav-title{font-size:9px; color:var(--text-faint); text-transform:uppercase; letter-spacing:1.2px; padding:12px 10px 5px 10px; font-weight:700;}\n.nav-item{\n  display:flex; align-items:center; gap:10px; padding:6px 10px; border-radius:var(--radius); cursor:pointer;\n  color:var(--text-muted); font-size:12.5px; font-weight:500; transition:background var(--dur) var(--ease), color var(--dur) var(--ease);\n  position:relative;\n}\n.nav-item:hover{background:var(--bg-surface-2); color:var(--text-strong);}\n.nav-item.active{background:var(--accent-bg); color:var(--accent-strong); font-weight:600;}\n.nav-item.active::before{\n  content:""; position:absolute; inset-inline-end:-10px; top:5px; bottom:5px; width:2px;\n  background:var(--accent); border-radius:0;\n}\n.nav-item svg{width:15px; height:15px; flex-shrink:0; opacity:.85;}\n\n#sidebar-footer{margin-top:auto; padding-top:10px; border-top:1px solid var(--border); display:flex; flex-direction:column; gap:7px;}\n.status-row{display:flex; align-items:center; gap:7px; padding:4px 6px; font-size:11px; color:var(--text-muted);}\n.status-dot{width:7px; height:7px; border-radius:50%; flex-shrink:0; transition:background var(--dur);}\n.status-dot.on{background:var(--success); box-shadow:0 0 0 3px var(--success-bg);}\n.status-dot.off{background:var(--danger); box-shadow:0 0 0 3px var(--danger-bg);}\n.status-dot.pulse{animation:pulse-dot 1.4s ease-in-out infinite;}\n@keyframes pulse-dot{0%,100%{opacity:1;} 50%{opacity:.35;}}\n\n#themeToggle{\n  display:flex; align-items:center; justify-content:space-between; padding:6px 8px; border-radius:var(--radius);\n  background:var(--bg-surface-2); border:1px solid var(--border); cursor:pointer; font-size:11px; color:var(--text-muted);\n  transition:border-color var(--dur) var(--ease), background var(--dur) var(--ease);\n}\n#themeToggle:hover{border-color:var(--border-strong); background:var(--bg-surface-3);}\n#themeToggle svg{width:14px; height:14px;}\n.version-tag{font-size:9px; color:var(--text-faint); padding:0 6px; font-family:var(--font-mono);}\n\n/* ---------------------------- main / topbar ---------------------------- */\n#main{flex:1; display:flex; flex-direction:column; min-width:0;}\n#topbar{\n  height:46px; min-height:46px; background:var(--bg-surface); border-bottom:1px solid var(--border);\n  display:flex; align-items:center; padding:0 18px; gap:8px;\n}\n.crumb{font-size:12px; color:var(--text-faint); display:flex; align-items:center; gap:8px;}\n.crumb b{color:var(--text-strong); font-size:13px; font-weight:600;}\n.crumb .sep{color:var(--text-faint); opacity:.6;}\n.crumb .sub-crumb{color:var(--text-muted); font-family:var(--font-mono); font-size:11px;\n  background:var(--bg-surface-2); padding:2px 7px; border-radius:var(--radius-sm); border:1px solid var(--border);}\n#topbar .spacer{flex:1;}\n.pill{font-size:10px; font-weight:700; padding:2px 8px; border-radius:var(--radius-sm); background:var(--bg-surface-2);\n  color:var(--text-muted); border:1px solid var(--border-strong); letter-spacing:.4px; text-transform:uppercase;}\n.pill.mode-server{color:var(--warning); border-color:rgba(200,118,25,.4); background:var(--warning-bg);}\n.pill.mode-local{color:var(--success); border-color:rgba(35,133,81,.4); background:var(--success-bg);}\n\n#content{flex:1; overflow:auto; padding:18px 20px 60px 20px; position:relative;}\n.view{display:none; animation:fade-in .15s var(--ease);}\n.view.active{display:block;}\n@keyframes fade-in{from{opacity:0; transform:translateY(3px);} to{opacity:1; transform:translateY(0);}}\n\n/* ---------------------------- cards ---------------------------- */\n.card{\n  background:var(--bg-surface); border:1px solid var(--border); border-radius:var(--radius-xl);\n  margin-bottom:14px; overflow:hidden; box-shadow:var(--shadow-1);\n}\n.card-hd{\n  display:flex; align-items:center; gap:9px; padding:9px 14px; border-bottom:1px solid var(--border);\n  background:var(--bg-surface);\n}\n.card-hd .ic-badge{\n  width:20px; height:20px; border-radius:var(--radius-sm); display:flex; align-items:center; justify-content:center;\n  background:var(--accent-bg); color:var(--accent); flex-shrink:0;\n}\n.card-hd .ic-badge svg{width:12px; height:12px;}\n.card-hd h2{font-size:12px; font-weight:600; color:var(--text-strong); flex:1; display:flex; align-items:center; gap:8px;}\n.card-hd h2 .sub{font-size:10.5px; color:var(--text-faint); font-weight:400; font-family:var(--font-mono);}\n.card-bd{padding:14px;}\n.card-toolbar{display:flex; gap:1px; align-items:center;}\n.icon-btn{\n  width:22px; height:22px; border-radius:var(--radius-sm); display:flex; align-items:center; justify-content:center;\n  background:transparent; border:none; color:var(--text-faint); cursor:pointer; transition:background var(--dur), color var(--dur);\n}\n.icon-btn:hover{background:var(--bg-surface-3); color:var(--text-strong);}\n.icon-btn svg{width:13px; height:13px;}\n.card.collapsed .card-bd{display:none;}\n.card.fullscreen{position:fixed; inset:14px; z-index:500; margin:0; box-shadow:var(--shadow-2);}\n.card.fullscreen .card-bd{max-height:calc(100vh - 90px); overflow:auto;}\n\n.grid{display:grid; gap:14px;}\n.grid.cols-2{grid-template-columns:1fr 1fr;}\n.grid.cols-3{grid-template-columns:1fr 1fr 1fr;}\n.grid.cols-4{grid-template-columns:repeat(4,1fr);}\n@media(max-width:1000px){.grid.cols-2,.grid.cols-3,.grid.cols-4{grid-template-columns:1fr;}}\n\n/* ---------------------------- metrics ---------------------------- */\n.metric{\n  background:var(--bg-surface); border:1px solid var(--border); border-inline-start:3px solid var(--accent);\n  border-radius:var(--radius-lg); padding:12px 14px; box-shadow:var(--shadow-1); transition:border-color var(--dur) var(--ease), box-shadow var(--dur) var(--ease);\n}\n.metric:hover{box-shadow:var(--shadow-2);}\n.metric.c-green{border-inline-start-color:var(--success);}\n.metric.c-orange{border-inline-start-color:var(--orange);}\n.metric.c-purple{border-inline-start-color:var(--purple);}\n.metric .n{font-size:24px; font-weight:700; color:var(--text-strong); font-family:var(--font-sans); line-height:1.15; letter-spacing:-.3px;}\n.metric .l{font-size:10.5px; color:var(--text-muted); margin-top:5px; display:flex; align-items:center; gap:6px; text-transform:uppercase; letter-spacing:.4px; font-weight:600;}\n\n/* ---------------------------- forms ---------------------------- */\nlabel{display:block; font-size:11px; color:var(--text-muted); margin-bottom:5px; margin-top:10px; font-weight:600; text-transform:uppercase; letter-spacing:.3px;}\ninput[type=text], input[type=number], textarea, select{\n  width:100%; background:var(--bg-surface); border:1px solid var(--border-strong); color:var(--text-strong);\n  padding:7px 10px; border-radius:var(--radius); font-size:12.5px; font-family:var(--font-sans);\n  box-shadow:inset 0 1px 1px rgba(17,20,24,.07);\n  transition:border-color var(--dur) var(--ease), box-shadow var(--dur) var(--ease);\n}\ninput:focus, textarea:focus, select:focus{outline:none; border-color:var(--accent); box-shadow:0 0 0 1px var(--accent), inset 0 1px 1px rgba(17,20,24,.07);}\ntextarea{font-family:var(--font-mono); min-height:80px; resize:vertical;}\nbutton{\n  background:var(--accent); color:var(--accent-contrast); border:1px solid transparent; border-radius:var(--radius);\n  padding:7px 14px; font-size:12px; font-weight:600; cursor:pointer; font-family:var(--font-sans);\n  box-shadow:inset 0 0 0 1px rgba(17,20,24,.16), inset 0 -1px 0 rgba(17,20,24,.1);\n  transition:filter var(--dur) var(--ease), box-shadow var(--dur) var(--ease);\n}\nbutton:hover{filter:brightness(.93);}\nbutton:active{filter:brightness(.85); box-shadow:inset 0 1px 2px rgba(17,20,24,.3);}\nbutton.ghost{background:var(--bg-surface-2); color:var(--text-strong); border-color:var(--border-strong); box-shadow:none;}\nbutton.ghost:hover{background:var(--bg-surface-3); border-color:var(--border-strong); filter:none;}\nbutton.sm{padding:4px 9px; font-size:11px;}\nbutton:disabled{opacity:.5; cursor:not-allowed; filter:none; box-shadow:none;}\n.collapsible-toggle{display:flex; align-items:center; gap:6px; cursor:pointer; color:var(--accent-strong); font-size:12px; font-weight:600; user-select:none;}\n.collapsible-toggle svg{width:12px; height:12px; transition:transform var(--dur) var(--ease);}\n.collapsible-toggle.open svg{transform:rotate(90deg);}\n.collapsible-body{display:none; margin-top:12px; padding-top:12px; border-top:1px dashed var(--border);}\n.collapsible-body.open{display:block; animation:fade-in .15s var(--ease);}\n\n/* ---------------------------- tables ---------------------------- */\ntable{width:100%; border-collapse:collapse; font-size:12px;}\ntable th{text-align:left; color:var(--text-faint); font-weight:700; padding:7px 10px; border-bottom:1px solid var(--border-strong);\n  font-size:10px; text-transform:uppercase; letter-spacing:.5px; position:sticky; top:0; background:var(--bg-surface); z-index:1;}\ntable td{padding:7px 10px; border-bottom:1px solid var(--border); color:var(--text); font-family:var(--font-mono); font-size:11.5px; vertical-align:middle;}\ntable tr{transition:background var(--dur);}\ntable tr:hover td{background:var(--accent-bg); color:var(--text-strong);}\n.table-scroll{max-height:420px; overflow:auto; border-radius:var(--radius-sm); border:1px solid var(--border);}\n\n.type-chip{display:inline-flex; align-items:center; gap:5px; padding:2px 8px; border-radius:var(--radius-sm); font-size:10.5px;\n  font-weight:600; font-family:var(--font-sans); border:1px solid transparent;}\n.type-chip .dot{width:6px; height:6px; border-radius:50%; flex-shrink:0;}\n.badge{display:inline-block; padding:2px 7px; border-radius:var(--radius-sm); font-size:10.5px; background:var(--bg-surface-2);\n  border:1px solid var(--border); color:var(--text-muted); font-weight:600;}\n.muted{color:var(--text-faint); font-size:11.5px;}\n.hr{height:1px; background:var(--border); margin:14px 0;}\n.flex{display:flex; gap:10px; align-items:center;}\n.flex.wrap{flex-wrap:wrap;}\n.right{margin-inline-start:auto;}\na.link{color:var(--accent-strong); cursor:pointer; text-decoration:underline; text-decoration-color:var(--border-strong); text-underline-offset:2px; font-weight:600;}\na.link:hover{text-decoration-color:currentColor;}\n.icon-inline{width:13px; height:13px; vertical-align:-2px; opacity:.85;}\n\n.checkbox{width:14px; height:14px; accent-color:var(--accent); cursor:pointer;}\n\n.toast{\n  position:fixed; bottom:20px; left:20px; background:var(--bg-surface); border:1px solid var(--border-strong);\n  padding:9px 14px; border-radius:var(--radius-lg); font-size:12px; z-index:999; box-shadow:var(--shadow-2); color:var(--text-strong);\n  animation:toast-in .15s var(--ease);\n}\n@keyframes toast-in{from{opacity:0; transform:translateY(6px);} to{opacity:1; transform:translateY(0);}}\n.toast.error{border-color:var(--danger); border-inline-start:3px solid var(--danger); color:var(--danger);}\n.toast.ok{border-color:var(--success); border-inline-start:3px solid var(--success); color:var(--success);}\n\n#dropzone{border:1px dashed var(--border-strong); border-radius:var(--radius-lg); padding:30px; text-align:center;\n  color:var(--text-faint); cursor:pointer; transition:border-color var(--dur), color var(--dur), background var(--dur);\n  display:flex; flex-direction:column; align-items:center; gap:8px;}\n#dropzone svg{width:24px; height:24px; opacity:.55;}\n#dropzone.drag{border-color:var(--accent); border-style:solid; color:var(--accent-strong); background:var(--accent-bg);}\npre.jsonview{background:var(--bg-canvas); border:1px solid var(--border); border-radius:var(--radius); padding:12px;\n  font-family:var(--font-mono); font-size:11px; color:var(--text); max-height:340px; overflow:auto; white-space:pre-wrap;}\n\n.skeleton{background:linear-gradient(90deg, var(--bg-surface-2) 25%, var(--bg-surface-3) 37%, var(--bg-surface-2) 63%);\n  background-size:400% 100%; animation:shimmer 1.3s ease infinite; border-radius:var(--radius-sm); height:12px;}\n@keyframes shimmer{0%{background-position:100% 50%;} 100%{background-position:0 50%;}}\n\n/* ---------------------------- master-detail (ontology) ---------------------------- */\n.master-detail{display:grid; grid-template-columns:250px 1fr; gap:12px; align-items:start;}\n.type-list-item{\n  display:flex; align-items:center; gap:9px; padding:7px 9px; border-radius:var(--radius); cursor:pointer;\n  border:1px solid transparent; margin-bottom:2px; transition:background var(--dur), border-color var(--dur);\n}\n.type-list-item:hover{background:var(--bg-surface-2);}\n.type-list-item.active{background:var(--accent-bg); border-color:var(--accent-border);}\n.type-list-item .sq{width:24px; height:24px; border-radius:var(--radius-sm); display:flex; align-items:center; justify-content:center; font-size:10.5px; font-weight:700; color:#fff; flex-shrink:0;}\n.type-list-item .meta b{display:block; font-size:12px; color:var(--text-strong);}\n.type-list-item .meta span{font-size:10px; color:var(--text-faint);}\n\n.detail-tabs{display:flex; gap:2px; border-bottom:1px solid var(--border); margin-bottom:14px;}\n.detail-tab{padding:8px 12px; font-size:11.5px; font-weight:600; color:var(--text-faint); cursor:pointer; border-bottom:2px solid transparent; transition:color var(--dur), border-color var(--dur);}\n.detail-tab:hover{color:var(--text-strong);}\n.detail-tab.active{color:var(--accent); border-bottom-color:var(--accent);}\n\n.prop-row{display:flex; align-items:center; gap:10px; padding:7px 0; border-bottom:1px solid var(--border);}\n.prop-row:last-child{border-bottom:none;}\n.prop-ic{width:19px; height:19px; border-radius:var(--radius-sm); display:flex; align-items:center; justify-content:center; flex-shrink:0;}\n.prop-ic svg{width:11px; height:11px;}\n.prop-name{font-size:12px; color:var(--text-strong); font-weight:500;}\n.prop-type{font-size:10.5px; color:var(--text-faint); font-family:var(--font-mono); margin-inline-start:auto;}\n\n.rel-row{display:flex; align-items:center; gap:8px; padding:8px 11px; background:var(--bg-surface-2); border:1px solid var(--border); border-radius:var(--radius); margin-bottom:5px; font-size:11.5px;}\n.rel-row svg{width:13px; height:13px; color:var(--text-faint); flex-shrink:0;}\n.rel-arrow{color:var(--accent); font-family:var(--font-mono); font-weight:700;}\n\n/* ---------------------------- graph ---------------------------- */\n#graphCanvasWrap{background:var(--bg-canvas); border:1px solid var(--border); border-radius:var(--radius-lg); height:500px; position:relative; overflow:hidden; cursor:grab;}\n#graphCanvasWrap.dragging{cursor:grabbing;}\n#graphSvg{width:100%; height:100%; display:block;}\n.gnode circle{stroke:var(--bg-canvas); stroke-width:2px; cursor:pointer; transition:r var(--dur);}\n.gnode:hover circle{filter:brightness(1.2);}\n.gnode text{fill:var(--text-strong); font-size:10px; font-family:var(--font-sans); pointer-events:none;}\n.gedge{stroke:var(--border-strong); stroke-width:1.2px;}\n.gedge-label{fill:var(--text-faint); font-size:8.5px; font-family:var(--font-mono);}\n.graph-toolbar{position:absolute; top:10px; left:10px; display:flex; flex-direction:column; gap:3px; z-index:5;}\n.graph-toolbar .icon-btn{background:var(--bg-surface); border:1px solid var(--border); box-shadow:var(--shadow-1);}\n.graph-legend{position:absolute; bottom:10px; right:10px; background:var(--bg-surface); border:1px solid var(--border);\n  border-radius:var(--radius); padding:8px 10px; display:flex; flex-direction:column; gap:5px; font-size:10.5px; box-shadow:var(--shadow-1);}\n.graph-legend .item{display:flex; align-items:center; gap:6px;}\n.graph-legend .sw{width:9px; height:9px; border-radius:2px;}\n\n/* ---------------------------- charts ---------------------------- */\n.chart-svg{width:100%; height:auto; display:block;}\n.bar-track rect.bg{fill:var(--bg-surface-2);}\n.bar-track rect.fg{transition:width .4s var(--ease);}\n.bar-label{font-size:11px; fill:var(--text); font-family:var(--font-sans);}\n.bar-value{font-size:10.5px; fill:var(--text-strong); font-family:var(--font-mono); font-weight:600;}\n.pie-slice{transition:opacity var(--dur); cursor:pointer;}\n.pie-slice:hover{opacity:.8;}\n.pie-legend-item{display:flex; align-items:center; gap:7px; font-size:11px; color:var(--text); padding:3px 0;}\n.pie-legend-item .sw{width:9px; height:9px; border-radius:2px; flex-shrink:0;}\n\n/* ---------------------------- compare panel ---------------------------- */\n#compareBar{\n  position:fixed; bottom:0; inset-inline:224px 0; background:var(--bg-surface); border-top:1px solid var(--border-strong);\n  padding:10px 20px; display:none; align-items:center; gap:12px; z-index:80; box-shadow:0 -4px 12px rgba(17,20,24,.12);\n  animation:slide-up .15s var(--ease);\n}\n#compareBar.show{display:flex;}\n@keyframes slide-up{from{transform:translateY(100%);} to{transform:translateY(0);}}\n.compare-grid{display:grid; gap:14px; grid-template-columns:repeat(auto-fit, minmax(240px,1fr));}\n.compare-card{background:var(--bg-surface-2); border:1px solid var(--border); border-radius:var(--radius-lg); padding:12px;}\n.compare-card h4{font-size:11.5px; color:var(--text-strong); margin-bottom:8px; font-family:var(--font-mono);}\n\n/* ---------------------------- ai chat ---------------------------- */\n#chatTopbar{display:flex; align-items:center; gap:10px; padding:9px 14px; border-bottom:1px solid var(--border); background:var(--bg-surface);}\n#chatTopbar .title{font-size:12px; font-weight:600; color:var(--text-strong);}\n#chatLog{display:flex; flex-direction:column; gap:11px; padding:16px; max-height:56vh; overflow:auto;}\n.msg{max-width:78%; padding:9px 12px; border-radius:var(--radius-lg); font-size:12.5px; line-height:1.6; animation:msg-in .15s var(--ease);}\n@keyframes msg-in{from{opacity:0; transform:translateY(5px);} to{opacity:1; transform:translateY(0);}}\n.msg.user{align-self:flex-end; background:var(--accent); color:var(--accent-contrast); border-bottom-right-radius:2px;}\n.msg.assistant{align-self:flex-start; background:var(--bg-surface-2); border:1px solid var(--border); color:var(--text-strong); border-bottom-left-radius:2px;}\n.msg.step{align-self:flex-start; background:transparent; border:1px dashed var(--border-strong); color:var(--text-muted);\n  font-family:var(--font-mono); font-size:10.5px; padding:6px 11px; display:flex; align-items:center; gap:7px; border-radius:var(--radius);}\n.msg.step .step-dot{width:6px; height:6px; border-radius:50%; background:var(--accent); flex-shrink:0;}\n.msg.step.busy .step-dot{animation:pulse-dot 1s ease-in-out infinite;}\n#chatInputRow{display:flex; gap:8px; padding:12px 14px; border-top:1px solid var(--border);}\n#chatInputRow input{flex:1; border-radius:var(--radius); padding:8px 14px;}\n#chatInputRow button{border-radius:var(--radius); width:36px; height:36px; padding:0; display:flex; align-items:center; justify-content:center;}\n#chatInputRow button svg{width:15px; height:15px;}\n\n/* ---------------------------- misc ---------------------------- */\n.empty-state{display:flex; flex-direction:column; align-items:center; justify-content:center; padding:40px 20px; color:var(--text-faint); text-align:center; gap:8px;}\n.empty-state svg{width:32px; height:32px; opacity:.4;}\n.kbd{font-family:var(--font-mono); background:var(--bg-surface-2); border:1px solid var(--border-strong); border-radius:var(--radius-sm); padding:1px 5px; font-size:10px; box-shadow:0 1px 0 var(--border-strong);}\n</style>\n</head>\n<body>\n<div id="app">\n  <div id="sidebar">\n    <div id="brand">\n      <div class="logo">\n        <svg viewBox="0 0 720 640" xmlns="http://www.w3.org/2000/svg" fill="none" stroke="currentColor">\n          <path d="M120 220 L360 60 L600 220" stroke-width="55"/>\n          <circle cx="360" cy="380" r="120" stroke-width="42"/>\n        </svg>\n      </div>\n      <div class="txt"><b>UMBRA</b><span>OBLIVION</span></div>\n    </div>\n\n    <div class="nav-group">\n      <div class="nav-title">Overview</div>\n      <div class="nav-item" data-view="home">\n        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M4 11L12 4l8 7"/><path d="M6 10v9h12v-9"/><path d="M10 19v-5h4v5"/></svg>\n        Home\n      </div>\n    </div>\n    <div class="nav-group">\n      <div class="nav-title">Data</div>\n      <div class="nav-item" data-view="data">\n        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><ellipse cx="12" cy="6" rx="7" ry="3"/><path d="M5 6v6c0 1.7 3.1 3 7 3s7-1.3 7-3V6"/><path d="M5 12v6c0 1.7 3.1 3 7 3s7-1.3 7-3v-6"/></svg>\n        Data\n      </div>\n      <div class="nav-item" data-view="ontology">\n        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="5" r="2.3"/><circle cx="5" cy="18" r="2.3"/><circle cx="19" cy="18" r="2.3"/><path d="M12 7.3V13M12 13L6.6 16.3M12 13l5.4 3.3"/></svg>\n        Ontology\n      </div>\n      <div class="nav-item" data-view="objects">\n        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l8 4.5v9L12 21l-8-4.5v-9L12 3z"/><path d="M4 7.5L12 12l8-4.5M12 12v9"/></svg>\n        Objects\n      </div>\n    </div>\n    <div class="nav-group">\n      <div class="nav-title">Analyze</div>\n      <div class="nav-item" data-view="graph">\n        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="5" cy="6" r="2.2"/><circle cx="19" cy="6" r="2.2"/><circle cx="12" cy="18" r="2.2"/><path d="M7 7l3.5 9M17 7l-3.5 9M7.2 6h9.6"/></svg>\n        Graph\n      </div>\n      <div class="nav-item" data-view="search">\n        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="10.5" cy="10.5" r="6.5"/><path d="M20 20l-4.8-4.8"/></svg>\n        Search\n      </div>\n      <div class="nav-item" data-view="analytics">\n        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M5 19V9M12 19V5M19 19v-7"/><path d="M3 19h18"/></svg>\n        Analytics\n      </div>\n    </div>\n    <div class="nav-group">\n      <div class="nav-title">Intelligence</div>\n      <div class="nav-item" data-view="ai">\n        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l1.8 4.6L18 9.5l-4.2 1.9L12 16l-1.8-4.6L6 9.5l4.2-1.9L12 3z"/><path d="M19 15l.8 2 2 .8-2 .8-.8 2-.8-2-2-.8 2-.8.8-2z"/></svg>\n        AI Analyst\n      </div>\n      <div class="nav-item" data-view="cases">\n        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M3 8a2 2 0 012-2h4l2 2h8a2 2 0 012 2v7a2 2 0 01-2 2H5a2 2 0 01-2-2V8z"/></svg>\n        Cases\n      </div>\n    </div>\n    <div class="nav-group">\n      <div class="nav-title">System</div>\n      <div class="nav-item" data-view="settings">\n        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 00.3 1.9l.1.1a2 2 0 11-2.9 2.9l-.1-.1a1.7 1.7 0 00-1.9-.3 1.7 1.7 0 00-1 1.6V21a2 2 0 11-4 0v-.1a1.7 1.7 0 00-1-1.6 1.7 1.7 0 00-1.9.3l-.1.1a2 2 0 11-2.9-2.9l.1-.1a1.7 1.7 0 00.3-1.9 1.7 1.7 0 00-1.6-1H3a2 2 0 110-4h.1a1.7 1.7 0 001.6-1 1.7 1.7 0 00-.3-1.9l-.1-.1a2 2 0 112.9-2.9l.1.1a1.7 1.7 0 001.9.3H9a1.7 1.7 0 001-1.6V3a2 2 0 114 0v.1a1.7 1.7 0 001 1.6 1.7 1.7 0 001.9-.3l.1-.1a2 2 0 112.9 2.9l-.1.1a1.7 1.7 0 00-.3 1.9V9a1.7 1.7 0 001.6 1H21a2 2 0 110 4h-.1a1.7 1.7 0 00-1.6 1z"/></svg>\n        Settings\n      </div>\n    </div>\n\n    <div id="sidebar-footer">\n      <div class="status-row"><span class="status-dot off pulse" id="lmDot"></span><span id="lmText">LM Studio: checking…</span></div>\n      <div id="themeToggle" onclick="toggleTheme()">\n        <span id="themeLabel">Dark mode</span>\n        <svg id="themeIcon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><path d="M21 12.8A9 9 0 1111.2 3a7 7 0 009.8 9.8z"/></svg>\n      </div>\n      <div class="version-tag">UMBRA v__VERSION__ · OBLIVION</div>\n    </div>\n  </div>\n\n  <div id="main">\n    <div id="topbar">\n      <div class="crumb"><b id="viewTitle">Home</b><span class="sep" id="crumbSepA" style="display:none">/</span><span class="sub-crumb" id="viewSub" style="display:none"></span></div>\n      <div class="spacer"></div>\n      <span class="pill" id="modePill">mode</span>\n    </div>\n    <div id="content">\n\n      <!-- ===================== HOME ===================== -->\n      <div class="view" id="view-home">\n        <div class="grid cols-4" id="homeMetrics"></div>\n        <div class="grid cols-2">\n          <div class="card">\n            <div class="card-hd">\n              <span class="ic-badge"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2a10 10 0 100 20 10 10 0 000-20z"/><path d="M12 12L12 2A10 10 0 0122 12z"/></svg></span>\n              <h2>Objects by type <span class="sub">Distribution of objects by type</span></h2>\n            </div>\n            <div class="card-bd" id="typePieWrap"><div class="empty-state">No objects created yet</div></div>\n          </div>\n          <div class="card">\n            <div class="card-hd">\n              <span class="ic-badge"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 8v4l3 3"/><circle cx="12" cy="12" r="9"/></svg></span>\n              <h2>Recent activity <span class="sub">Latest recorded operations</span></h2>\n              <div class="card-toolbar"><button class="icon-btn" onclick="loadRecentActivity()" title="Refresh"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12a9 9 0 11-2.6-6.4L21 8"/><path d="M21 3v5h-5"/></svg></button></div>\n            </div>\n            <div class="card-bd" id="recentActivity"></div>\n          </div>\n        </div>\n        <div class="card">\n          <div class="card-hd">\n            <span class="ic-badge"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 6h16M4 12h16M4 18h10"/></svg></span>\n            <h2>Pipeline <span class="sub">DATA → INGEST → PROFILE → ONTOLOGY → GRAPH → SEARCH → ANALYTICS → AI → EVIDENCE</span></h2>\n          </div>\n          <div class="card-bd">\n            <p class="muted">To get started, ingest a CSV/JSON file from &ldquo;Data&rdquo;, create an object type in &ldquo;Ontology&rdquo;, convert a dataset into objects in &ldquo;Objects&rdquo;, then ask your local model in &ldquo;AI Analyst&rdquo;.</p>\n          </div>\n        </div>\n      </div>\n\n      <!-- ===================== DATA ===================== -->\n      <div class="view" id="view-data">\n        <div class="card">\n          <div class="card-hd"><span class="ic-badge"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 4v12m0 0l-4-4m4 4l4-4M4 20h16"/></svg></span><h2>Ingest new dataset</h2></div>\n          <div class="card-bd">\n            <div id="dropzone">\n              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><path d="M12 4v12m0 0l-4-4m4 4l4-4M4 20h16"/></svg>\n              Drag and drop a CSV / JSON / JSONL file, or click to browse\n              <input type="file" id="fileInput" style="display:none" accept=".csv,.json,.jsonl,.tsv,.ndjson">\n            </div>\n            <div id="uploadStatus" class="muted" style="margin-top:8px;"></div>\n          </div>\n        </div>\n        <div class="card">\n          <div class="card-hd"><span class="ic-badge"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><ellipse cx="12" cy="6" rx="7" ry="3"/><path d="M5 6v12c0 1.7 3.1 3 7 3s7-1.3 7-3V6"/></svg></span><h2>Datasets</h2><div class="card-toolbar"><button class="icon-btn" onclick="loadDatasets()" title="Refresh"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12a9 9 0 11-2.6-6.4L21 8"/><path d="M21 3v5h-5"/></svg></button></div></div>\n          <div class="card-bd"><div class="table-scroll"><table><thead><tr><th>Name</th><th>Type</th><th>Rows</th><th>Cols</th><th>Ingested</th><th></th></tr></thead>\n          <tbody id="datasetsTable"></tbody></table></div></div>\n        </div>\n        <div class="card" id="datasetDetailCard" style="display:none;">\n          <div class="card-hd"><span class="ic-badge"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 3v18M4 8h5M4 16h5"/></svg></span><h2>Profile <span class="sub" id="datasetDetailName"></span></h2>\n          <div class="card-toolbar"><button class="icon-btn" onclick="el(\'datasetDetailCard\').style.display=\'none\'" title="Close"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M6 6l12 12M18 6L6 18"/></svg></button></div></div>\n          <div class="card-bd"><div class="table-scroll"><table><thead><tr><th>Column</th><th>Type</th><th>Null%</th><th>Unique%</th><th>Semantic guess</th></tr></thead>\n          <tbody id="profileTable"></tbody></table></div></div>\n        </div>\n      </div>\n\n      <!-- ===================== ONTOLOGY (master-detail) ===================== -->\n      <div class="view" id="view-ontology">\n        <div class="detail-tabs">\n          <div class="detail-tab active" data-onto-tab="types" onclick="switchOntoTab(\'types\')">Ontology</div>\n          <div class="detail-tab" data-onto-tab="proposals" onclick="switchOntoTab(\'proposals\')">Proposals</div>\n        </div>\n\n        <div id="ontoTab-types">\n          <div class="master-detail">\n            <div class="card" style="margin-bottom:0;">\n              <div class="card-hd"><h2 style="flex:1">Object Types</h2>\n                <div class="card-toolbar"><button class="icon-btn" onclick="toggleCollapsible(\'newTypePanel\')" title="New type"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 5v14M5 12h14"/></svg></button></div>\n              </div>\n              <div class="card-bd" style="padding:10px;">\n                <div id="objectTypesList"></div>\n                <div class="collapsible-body" id="newTypePanel" style="margin-top:8px;">\n                  <label>Name</label><input type="text" id="newTypeName" placeholder="Person">\n                  <label>Properties (JSON)</label><textarea id="newTypeProps" placeholder=\'{"name":"string","email":"string"}\'></textarea>\n                  <button style="margin-top:10px; width:100%;" onclick="createObjectType()">Create type</button>\n                </div>\n              </div>\n            </div>\n\n            <div class="card" style="margin-bottom:0;" id="typeDetailCard">\n              <div class="card-hd"><span class="ic-badge" id="detailTypeIcon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 3l8 4.5v9L12 21l-8-4.5v-9L12 3z"/></svg></span>\n                <h2 id="detailTypeName">Select an Object Type</h2>\n              </div>\n              <div class="card-bd" id="typeDetailBody">\n                <div class="empty-state">\n                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><path d="M12 3l8 4.5v9L12 21l-8-4.5v-9L12 3z"/></svg>\n                  Select an Object Type from the list on the left\n                </div>\n              </div>\n            </div>\n          </div>\n\n          <div class="card">\n            <div class="card-hd"><h2 style="flex:1">Link Types</h2>\n              <div class="card-toolbar"><button class="icon-btn" onclick="toggleCollapsible(\'newLinkPanel\')" title="New link type"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 5v14M5 12h14"/></svg></button></div>\n            </div>\n            <div class="card-bd">\n              <div class="table-scroll"><table><thead><tr><th>Name</th><th>Source</th><th>Target</th></tr></thead><tbody id="linkTypesTable"></tbody></table></div>\n              <div class="collapsible-body" id="newLinkPanel">\n                <div class="grid cols-3">\n                  <div><label>Name</label><input type="text" id="linkTypeName" placeholder="works_for"></div>\n                  <div><label>Source type</label><input type="text" id="linkSourceType" placeholder="Person"></div>\n                  <div><label>Target type</label><input type="text" id="linkTargetType" placeholder="Company"></div>\n                </div>\n                <button style="margin-top:10px;" onclick="createLinkType()">Create link type</button>\n              </div>\n            </div>\n          </div>\n        </div>\n\n        <div id="ontoTab-proposals" style="display:none;">\n          <div class="card">\n            <div class="card-hd"><h2>Suggest ontology from a dataset</h2></div>\n            <div class="card-bd">\n              <label>Dataset</label>\n              <select id="ontoDatasetSelect"></select>\n              <button style="margin-top:12px;" onclick="suggestOntology()">Suggest</button>\n              <div id="ontoSuggestion" style="margin-top:12px;"></div>\n            </div>\n          </div>\n        </div>\n      </div>\n\n      <!-- ===================== OBJECTS ===================== -->\n      <div class="view" id="view-objects">\n        <div class="card">\n          <div class="card-hd"><h2 style="flex:1">Materialize dataset → Objects</h2>\n            <div class="card-toolbar"><button class="icon-btn" onclick="toggleCollapsible(\'matPanel\')" title="Toggle"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M6 9l6 6 6-6"/></svg></button></div>\n          </div>\n          <div class="card-bd collapsible-body open" id="matPanel">\n            <div class="grid cols-3">\n              <div><label>Dataset</label><select id="matDatasetSelect"></select></div>\n              <div><label>Object type</label><input type="text" id="matObjectType" placeholder="Person"></div>\n              <div><label>ID column (optional)</label><input type="text" id="matIdColumn" placeholder="id"></div>\n            </div>\n            <button style="margin-top:12px;" onclick="materializeDataset()">Materialize</button>\n            <div id="matStatus" class="muted" style="margin-top:8px;"></div>\n            <div class="hr"></div>\n            <div class="grid cols-4">\n              <div><label>Link type</label><input type="text" id="lnkType"></div>\n              <div><label>Source object id</label><input type="text" id="lnkSource"></div>\n              <div><label>Target object id</label><input type="text" id="lnkTarget"></div>\n              <div style="display:flex; align-items:flex-end;"><button class="ghost" style="width:100%;" onclick="createLink()">Create link</button></div>\n            </div>\n            <div id="linkStatus" class="muted" style="margin-top:8px;"></div>\n          </div>\n        </div>\n        <div class="card">\n          <div class="card-hd"><h2 style="flex:1">Objects <span class="sub" id="objectCountSub"></span></h2>\n            <div class="card-toolbar"><button class="icon-btn" onclick="loadObjects()" title="Refresh"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12a9 9 0 11-2.6-6.4L21 8"/><path d="M21 3v5h-5"/></svg></button></div>\n          </div>\n          <div class="card-bd">\n            <div class="flex" style="margin-bottom:10px;">\n              <input type="text" id="objectTypeFilter" placeholder="filter by type…" style="max-width:220px;">\n              <button class="ghost sm" onclick="loadObjects()">Filter</button>\n            </div>\n            <div class="table-scroll"><table><thead><tr><th style="width:30px;"></th><th>ID</th><th>Type</th><th>Properties</th><th></th></tr></thead><tbody id="objectsTable"></tbody></table></div>\n          </div>\n        </div>\n      </div>\n\n      <!-- ===================== GRAPH ===================== -->\n      <div class="view" id="view-graph">\n        <div class="grid cols-2">\n          <div class="card" style="margin-bottom:0;">\n            <div class="card-hd"><h2>Explore neighborhood</h2></div>\n            <div class="card-bd">\n              <div class="grid cols-2">\n                <div><label>Object id</label><input type="text" id="graphObjectId"></div>\n                <div><label>Hops</label><input type="number" id="graphHops" value="2" min="1" max="6"></div>\n              </div>\n              <button style="margin-top:12px; width:100%;" onclick="loadGraph()">Explore</button>\n            </div>\n          </div>\n          <div class="card" style="margin-bottom:0;">\n            <div class="card-hd"><h2>Find shortest path</h2></div>\n            <div class="card-bd">\n              <div class="grid cols-2">\n                <div><label>Source id</label><input type="text" id="pathSource"></div>\n                <div><label>Target id</label><input type="text" id="pathTarget"></div>\n              </div>\n              <button style="margin-top:12px; width:100%;" onclick="findPath()">Find path</button>\n              <div id="pathResult" class="muted" style="margin-top:8px;"></div>\n            </div>\n          </div>\n        </div>\n        <div class="card" style="margin-top:14px;">\n          <div class="card-hd"><h2 style="flex:1">Graph view</h2>\n            <div class="card-toolbar">\n              <button class="icon-btn" onclick="graphZoom(1.2)" title="Zoom in"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3M11 8v6M8 11h6"/></svg></button>\n              <button class="icon-btn" onclick="graphZoom(0.8)" title="Zoom out"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3M8 11h6"/></svg></button>\n              <button class="icon-btn" onclick="graphResetView()" title="Reset view"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12a9 9 0 11-2.6-6.4L21 8"/><path d="M21 3v5h-5"/></svg></button>\n            </div>\n          </div>\n          <div class="card-bd" style="padding:0;">\n            <div id="graphCanvasWrap">\n              <svg id="graphSvg"><g id="graphG"></g></svg>\n              <div class="graph-legend" id="graphLegend" style="display:none;"></div>\n            </div>\n          </div>\n        </div>\n      </div>\n\n      <!-- ===================== SEARCH ===================== -->\n      <div class="view" id="view-search">\n        <div class="card">\n          <div class="card-hd"><h2>Hybrid lexical search <span class="sub">TF-IDF across object properties</span></h2></div>\n          <div class="card-bd">\n            <div class="flex">\n              <input type="text" id="searchQuery" placeholder="Search across objects..." onkeydown="if(event.key===\'Enter\')runSearch()">\n              <button onclick="runSearch()">Search</button>\n            </div>\n            <div class="table-scroll" style="margin-top:14px;"><table><thead><tr><th>Score</th><th>ID</th><th>Type</th><th>Properties</th></tr></thead><tbody id="searchTable"></tbody></table></div>\n          </div>\n        </div>\n      </div>\n\n      <!-- ===================== ANALYTICS ===================== -->\n      <div class="view" id="view-analytics">\n        <div class="card">\n          <div class="card-hd"><h2>SQL Analytics <span class="sub">read-only — only SELECT statements are allowed</span></h2></div>\n          <div class="card-bd">\n            <textarea id="sqlBox">SELECT object_type, COUNT(*) as n FROM objects GROUP BY object_type;</textarea>\n            <button style="margin-top:10px;" onclick="runSql()">Run</button>\n            <div id="sqlError" class="muted" style="margin-top:8px; color:var(--danger);"></div>\n            <div id="sqlChartWrap" style="margin-top:14px;"></div>\n            <div class="table-scroll" style="margin-top:10px;"><table><thead id="sqlHead"></thead><tbody id="sqlBody"></tbody></table></div>\n          </div>\n        </div>\n      </div>\n\n      <!-- ===================== AI ANALYST ===================== -->\n      <div class="view" id="view-ai">\n        <div class="card" style="margin-bottom:0;">\n          <div id="chatTopbar">\n            <span class="title">AI Analyst</span>\n            <span class="sub-crumb" id="aiModelSub" style="display:none"></span>\n            <div class="spacer"></div>\n            <button class="ghost sm" onclick="saveChatAsCase()">Save as Case</button>\n            <button class="ghost sm" onclick="newChat()">New chat</button>\n          </div>\n          <div id="chatLog"></div>\n          <div id="chatInputRow">\n            <input type="text" id="chatInput" placeholder="Ask a question about your data..." onkeydown="if(event.key===\'Enter\')sendChat()">\n            <button onclick="sendChat()"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 12l16-8-6 8 6 8-16-8z"/></svg></button>\n          </div>\n        </div>\n      </div>\n\n      <!-- ===================== CASES ===================== -->\n      <div class="view" id="view-cases">\n        <div class="card">\n          <div class="card-hd"><h2>Save a new Case</h2></div>\n          <div class="card-bd">\n            <label>Title</label><input type="text" id="caseTitle">\n            <label>Description</label><textarea id="caseDesc"></textarea>\n            <button style="margin-top:10px;" onclick="createCase()">Save Case</button>\n          </div>\n        </div>\n        <div class="card">\n          <div class="card-hd"><h2 style="flex:1">Cases</h2><div class="card-toolbar"><button class="icon-btn" onclick="loadCases()" title="Refresh"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12a9 9 0 11-2.6-6.4L21 8"/><path d="M21 3v5h-5"/></svg></button></div></div>\n          <div class="card-bd"><div class="table-scroll"><table><thead><tr><th>Title</th><th>Created</th><th>Updated</th><th></th></tr></thead><tbody id="casesTable"></tbody></table></div></div>\n        </div>\n        <div class="card" id="caseDetailCard" style="display:none;">\n          <div class="card-hd"><h2 style="flex:1" id="caseDetailTitle">Case</h2><div class="card-toolbar"><button class="icon-btn" onclick="el(\'caseDetailCard\').style.display=\'none\'" title="Close"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M6 6l12 12M18 6L6 18"/></svg></button></div></div>\n          <div class="card-bd"><pre class="jsonview" id="caseDetailBody"></pre></div>\n        </div>\n      </div>\n\n      <!-- ===================== SETTINGS ===================== -->\n      <div class="view" id="view-settings">\n        <div class="card">\n          <div class="card-hd"><h2>LM Studio connection</h2></div>\n          <div class="card-bd">\n            <div class="grid cols-3">\n              <div><label>Host</label><input type="text" id="cfgLmHost"></div>\n              <div><label>Port</label><input type="number" id="cfgLmPort"></div>\n              <div><label>Model (blank = first available)</label><input type="text" id="cfgLmModel"></div>\n            </div>\n            <div class="grid cols-3">\n              <div><label>Temperature</label><input type="number" step="0.1" id="cfgLmTemp"></div>\n              <div><label>Max tokens</label><input type="number" id="cfgLmMaxTokens"></div>\n              <div><label>Timeout (s)</label><input type="number" id="cfgLmTimeout"></div>\n            </div>\n            <div class="flex" style="margin-top:12px;">\n              <button onclick="saveLmSettings()">Save</button>\n              <button class="ghost" onclick="testLmConnection()">Test connection</button>\n            </div>\n            <div id="lmTestResult" class="muted" style="margin-top:10px;"></div>\n          </div>\n        </div>\n        <div class="card">\n          <div class="card-hd"><h2>Server mode</h2></div>\n          <div class="card-bd">\n            <p class="muted">Changing mode requires restarting the app: <span class="kbd">umbra.py serve --mode server --host 0.0.0.0</span></p>\n            <div class="grid cols-2">\n              <div><label>Mode</label><input type="text" id="cfgMode" disabled></div>\n              <div><label>Bind</label><input type="text" id="cfgBind" disabled></div>\n            </div>\n          </div>\n        </div>\n        <div class="card">\n          <div class="card-hd"><h2>System diagnostics</h2></div>\n          <div class="card-bd"><pre class="jsonview" id="healthView"></pre></div>\n        </div>\n      </div>\n\n    </div>\n  </div>\n</div>\n<div id="compareBar">\n  <span class="muted" id="compareCount">0 selected</span>\n  <button class="sm" onclick="openCompare()">Compare</button>\n  <button class="ghost sm" onclick="clearCompare()">Clear</button>\n</div>\n\n<script>\n/* ============================== boot / state ============================== */\nconst API = "";\nlet selectedForCompare = new Set();\nlet graphState = {scale:1, tx:0, ty:0, nodes:[], edges:[], focusId:null};\nlet convId = null;\nlet chatHistoryForCase = [];\n\nconst TYPE_PALETTE = ["#2D72D2","#238551","#C87619","#CD4246","#7961DB","#00A396","#DB2C6F","#946638"];\nconst typeColorCache = {};\nfunction colorForType(t){\n  if(!t) t = "?";\n  if(typeColorCache[t]) return typeColorCache[t];\n  let h=0; for(let i=0;i<t.length;i++) h = (h*31 + t.charCodeAt(i)) >>> 0;\n  const c = TYPE_PALETTE[h % TYPE_PALETTE.length];\n  typeColorCache[t] = c;\n  return c;\n}\nfunction typeChip(t){\n  const c = colorForType(t);\n  return `<span class="type-chip" style="color:${c}; background:${c}22; border-color:${c}55;"><span class="dot" style="background:${c}"></span>${t}</span>`;\n}\nfunction el(id){ return document.getElementById(id); }\nfunction toast(msg, kind){\n  const t=document.createElement("div"); t.className="toast "+(kind||"");\n  t.textContent=msg; document.body.appendChild(t);\n  setTimeout(()=>t.remove(), 3200);\n}\nasync function api(path, opts){\n  opts = opts || {};\n  opts.headers = Object.assign({"Content-Type":"application/json"}, opts.headers||{});\n  const res = await fetch(API+path, opts);\n  let data;\n  try { data = await res.json(); } catch(e){ data = null; }\n  if(!res.ok){ throw new Error((data && (data.error||JSON.stringify(data))) || res.statusText); }\n  return data;\n}\n\n/* ============================== theme ============================== */\nfunction applyTheme(t){\n  document.documentElement.setAttribute("data-theme", t);\n  el("themeLabel").textContent = t === "dark" ? "Dark mode" : "Light mode";\n  el("themeIcon").innerHTML = t === "dark"\n    ? \'<path d="M21 12.8A9 9 0 1111.2 3a7 7 0 009.8 9.8z"/>\'\n    : \'<circle cx="12" cy="12" r="4.2"/><path d="M12 2v2.2M12 19.8V22M4.2 4.2l1.6 1.6M18.2 18.2l1.6 1.6M2 12h2.2M19.8 12H22M4.2 19.8l1.6-1.6M18.2 5.8l1.6-1.6"/>\';\n  try{ localStorage.setItem("umbra-theme", t); }catch(e){}\n}\nfunction toggleTheme(){\n  const cur = document.documentElement.getAttribute("data-theme");\n  applyTheme(cur === "dark" ? "light" : "dark");\n}\n(function initTheme(){\n  let saved = "dark";\n  try{ saved = localStorage.getItem("umbra-theme") || "light"; }catch(e){}\n  applyTheme(saved);\n})();\n\n/* ============================== collapsibles ============================== */\nfunction toggleCollapsible(id){\n  el(id).classList.toggle("open");\n}\n\n/* ============================== navigation ============================== */\ndocument.querySelectorAll(".nav-item").forEach(item=>{\n  item.addEventListener("click", ()=>switchView(item.dataset.view));\n});\nfunction switchView(name){\n  document.querySelectorAll(".nav-item").forEach(i=>i.classList.toggle("active", i.dataset.view===name));\n  document.querySelectorAll(".view").forEach(v=>v.classList.toggle("active", v.id==="view-"+name));\n  const titles = {home:"Home", data:"Data", ontology:"Ontology", objects:"Objects", graph:"Graph",\n    search:"Search", analytics:"Analytics", ai:"AI Analyst", cases:"Cases", settings:"Settings"};\n  el("viewTitle").textContent = titles[name] || name;\n  el("crumbSepA").style.display="none"; el("viewSub").style.display="none";\n  if(name==="data") loadDatasets();\n  if(name==="ontology") { loadOntology(); loadDatasetOptions("ontoDatasetSelect"); }\n  if(name==="objects") { loadObjects(); loadDatasetOptions("matDatasetSelect"); }\n  if(name==="cases") loadCases();\n  if(name==="settings") loadSettings();\n  if(name==="home") loadHome();\n}\n\n/* ============================== HOME ============================== */\nasync function loadHome(){\n  const h = await api("/api/health");\n  const m = h.counts;\n  el("homeMetrics").innerHTML = `\n    <div class="metric"><div class="n">${m.datasets}</div><div class="l">Datasets</div></div>\n    <div class="metric c-green"><div class="n">${m.objects}</div><div class="l">Objects</div></div>\n    <div class="metric c-purple"><div class="n">${m.links}</div><div class="l">Links</div></div>\n    <div class="metric ${h.lm_studio.connected?\'c-green\':\'\'}"><div class="n">${h.lm_studio.connected ? "ON":"OFF"}</div><div class="l">LM Studio</div></div>`;\n  loadTypePie();\n  loadRecentActivity();\n}\nasync function loadTypePie(){\n  const rows = await api("/api/stats/object-type-counts");\n  if(!rows.length){ el("typePieWrap").innerHTML = \'<div class="empty-state">No objects created yet</div>\'; return; }\n  el("typePieWrap").innerHTML = renderPieChart(rows.map(r=>({label:r.object_type, value:r.n})));\n}\nasync function loadRecentActivity(){\n  const rows = await api("/api/audit/recent?limit=10");\n  if(!rows.length){ el("recentActivity").innerHTML = \'<div class="empty-state">No activity recorded</div>\'; return; }\n  el("recentActivity").innerHTML = rows.map(r=>`\n    <div class="prop-row">\n      <span class="prop-ic" style="background:${r.status===\'ok\'?\'var(--success-bg)\':\'var(--danger-bg)\'}; color:${r.status===\'ok\'?\'var(--success)\':\'var(--danger)\'}">\n        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4"><path d="M20 6L9 17l-5-5"/></svg></span>\n      <span class="prop-name">${r.operation}</span>\n      <span class="prop-type">${(r.duration_ms||0).toFixed(0)}ms · ${r.ts.slice(11,19)}</span>\n    </div>`).join("");\n}\n\n/* ---- reusable pie chart (real SVG, real data) ---- */\nfunction renderPieChart(items){\n  const total = items.reduce((s,i)=>s+i.value,0) || 1;\n  let angle = -90, svg = "";\n  const cx=90, cy=90, r=78;\n  items.forEach((it,i)=>{\n    const frac = it.value/total, sweep = frac*360;\n    const x1 = cx + r*Math.cos(angle*Math.PI/180), y1 = cy + r*Math.sin(angle*Math.PI/180);\n    const end = angle+sweep;\n    const x2 = cx + r*Math.cos(end*Math.PI/180), y2 = cy + r*Math.sin(end*Math.PI/180);\n    const large = sweep>180?1:0;\n    const color = colorForType(it.label);\n    svg += `<path class="pie-slice" d="M${cx},${cy} L${x1},${y1} A${r},${r} 0 ${large} 1 ${x2},${y2} Z" fill="${color}"></path>`;\n    angle = end;\n  });\n  const legend = items.map(it=>`<div class="pie-legend-item"><span class="sw" style="background:${colorForType(it.label)}"></span>${it.label} — ${it.value} (${((it.value/total)*100).toFixed(0)}%)</div>`).join("");\n  return `<div style="display:flex; gap:20px; align-items:center; flex-wrap:wrap;">\n    <svg class="chart-svg" viewBox="0 0 180 180" style="width:180px; height:180px; flex-shrink:0;">${svg}</svg>\n    <div>${legend}</div></div>`;\n}\n\n/* ---- reusable horizontal bar chart (real SVG, real data) ---- */\nfunction renderBarChart(items, opts){\n  opts = opts || {};\n  const max = Math.max(...items.map(i=>i.value), 1);\n  const rowH = 30, w = 560, labelW = 130;\n  const h = items.length*rowH + 10;\n  let bars = "";\n  items.forEach((it,i)=>{\n    const y = i*rowH + 6;\n    const barMaxW = w - labelW - 60;\n    const bw = Math.max(2, (it.value/max)*barMaxW);\n    const color = opts.color || colorForType(it.label);\n    bars += `<text class="bar-label" x="${labelW-8}" y="${y+15}" text-anchor="end">${String(it.label).slice(0,18)}</text>`;\n    bars += `<g class="bar-track"><rect class="bg" x="${labelW}" y="${y}" width="${barMaxW}" height="20" rx="4"></rect>\n      <rect class="fg" x="${labelW}" y="${y}" width="${bw}" height="20" rx="4" fill="${color}"></rect></g>`;\n    bars += `<text class="bar-value" x="${labelW+bw+8}" y="${y+15}">${it.value}</text>`;\n  });\n  return `<svg class="chart-svg" viewBox="0 0 ${w} ${h}" style="width:100%; height:${h}px;">${bars}</svg>`;\n}\n\n/* ============================== DATA ============================== */\nel("dropzone").addEventListener("click", ()=>el("fileInput").click());\nel("dropzone").addEventListener("dragover", e=>{e.preventDefault(); el("dropzone").classList.add("drag");});\nel("dropzone").addEventListener("dragleave", ()=>el("dropzone").classList.remove("drag"));\nel("dropzone").addEventListener("drop", e=>{\n  e.preventDefault(); el("dropzone").classList.remove("drag");\n  if(e.dataTransfer.files.length) uploadFile(e.dataTransfer.files[0]);\n});\nel("fileInput").addEventListener("change", e=>{ if(e.target.files.length) uploadFile(e.target.files[0]); });\n\nasync function uploadFile(file){\n  el("uploadStatus").textContent = "Uploading and processing "+file.name+"...";\n  const fd = new FormData(); fd.append("file", file);\n  try{\n    const res = await fetch("/api/datasets/ingest", {method:"POST", body:fd});\n    const data = await res.json();\n    if(!res.ok) throw new Error(data.error || "ingestion failed");\n    el("uploadStatus").textContent = `${data.row_count} rows, ${data.column_count} columns ingested.`;\n    toast("Ingested: "+data.source_name, "ok");\n    loadDatasets();\n  }catch(e){ el("uploadStatus").textContent = "Error: "+e.message; toast(e.message, "error"); }\n}\nasync function loadDatasets(){\n  const rows = await api("/api/datasets");\n  el("datasetsTable").innerHTML = rows.map(d=>`\n    <tr>\n      <td>${d.source_name}</td><td><span class="badge">${d.source_type}</span></td><td>${d.row_count}</td>\n      <td>${d.column_count}</td><td>${d.ingested_at.slice(0,19)}</td>\n      <td><a class="link" onclick="showProfile(\'${d.dataset_id}\',\'${d.source_name}\')">Profile</a></td>\n    </tr>`).join("");\n}\nasync function showProfile(id, name){\n  const ds = await api("/api/datasets/"+id);\n  el("datasetDetailCard").style.display = "block";\n  el("datasetDetailName").textContent = name;\n  const cols = ds.profile.columns || {};\n  el("profileTable").innerHTML = Object.entries(cols).map(([col,st])=>`\n    <tr><td>${col}</td><td>${st.dtype}</td><td>${(st.null_ratio*100).toFixed(1)}%</td>\n    <td>${(st.unique_ratio*100).toFixed(1)}%</td>\n    <td>${st.semantic && st.semantic.guess ? st.semantic.guess+" ("+(st.semantic.confidence*100).toFixed(0)+"%)" : "-"}</td></tr>`).join("");\n  el("datasetDetailCard").scrollIntoView({behavior:"smooth", block:"nearest"});\n}\nasync function loadDatasetOptions(selectId){\n  const rows = await api("/api/datasets");\n  el(selectId).innerHTML = rows.map(d=>`<option value="${d.dataset_id}">${d.source_name} (${d.row_count} rows)</option>`).join("");\n}\n\n/* ============================== ONTOLOGY ============================== */\nlet currentOntoTypes = [];\nlet currentOntoLinks = [];\nlet selectedTypeName = null;\n\nfunction switchOntoTab(tab){\n  document.querySelectorAll("[data-onto-tab]").forEach(t=>t.classList.toggle("active", t.dataset.ontoTab===tab));\n  el("ontoTab-types").style.display = tab==="types" ? "block":"none";\n  el("ontoTab-proposals").style.display = tab==="proposals" ? "block":"none";\n}\nasync function loadOntology(){\n  currentOntoTypes = await api("/api/ontology/object-types");\n  currentOntoLinks = await api("/api/ontology/link-types");\n  el("objectTypesList").innerHTML = currentOntoTypes.map(t=>{\n    const c = colorForType(t.name);\n    return `<div class="type-list-item ${t.name===selectedTypeName?\'active\':\'\'}" onclick="selectType(\'${t.name}\')">\n      <span class="sq" style="background:${c}">${t.name.slice(0,2).toUpperCase()}</span>\n      <div class="meta"><b>${t.name}</b><span>${Object.keys(t.properties).length} properties</span></div>\n    </div>`;\n  }).join("") || \'<div class="empty-state" style="padding:20px;">No object types yet</div>\';\n  el("linkTypesTable").innerHTML = currentOntoLinks.map(l=>`\n    <tr><td>${l.name}</td><td>${typeChip(l.source_type)}</td><td>${typeChip(l.target_type)}</td></tr>`).join("");\n  if(selectedTypeName) selectType(selectedTypeName);\n}\nconst PROP_TYPE_META = {\n  string:{ic:\'<path d="M4 6h16M4 12h10M4 18h7"/>\', color:"var(--accent)"},\n  integer:{ic:\'<path d="M6 4v16M18 4v16M4 8h4M4 16h4M16 8h4M16 16h4"/>\', color:"var(--teal)"},\n  float:{ic:\'<circle cx="12" cy="12" r="1.2" fill="currentColor"/><path d="M4 12h4M16 12h4"/>\', color:"var(--teal)"},\n  boolean:{ic:\'<path d="M8 12l3 3 5-6"/><circle cx="12" cy="12" r="9"/>\', color:"var(--success)"},\n  datetime:{ic:\'<circle cx="12" cy="12" r="8"/><path d="M12 8v4l3 2"/>\', color:"var(--orange)"},\n};\nfunction selectType(name){\n  selectedTypeName = name;\n  document.querySelectorAll(".type-list-item").forEach(n=>n.classList.remove("active"));\n  loadOntology(); // simplest safe re-render highlighting selection\n  const t = currentOntoTypes.find(x=>x.name===name);\n  if(!t) return;\n  const c = colorForType(name);\n  el("detailTypeIcon").style.background = c+"22"; el("detailTypeIcon").style.color = c;\n  el("detailTypeName").textContent = name;\n  const propsHtml = Object.entries(t.properties).map(([pname,ptype])=>{\n    const meta = PROP_TYPE_META[ptype] || PROP_TYPE_META.string;\n    return `<div class="prop-row"><span class="prop-ic" style="background:${meta.color}22; color:${meta.color}">\n      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">${meta.ic}</svg></span>\n      <span class="prop-name">${pname}</span><span class="prop-type">${ptype}</span></div>`;\n  }).join("");\n  const outgoing = currentOntoLinks.filter(l=>l.source_type===name);\n  const incoming = currentOntoLinks.filter(l=>l.target_type===name && l.source_type!==name);\n  const relHtml = [...outgoing.map(l=>`<div class="rel-row"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12h14M13 6l6 6-6 6"/></svg>\n      <b>${name}</b><span class="rel-arrow">— ${l.name} →</span>${typeChip(l.target_type)}</div>`),\n    ...incoming.map(l=>`<div class="rel-row"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M19 12H5M11 6l-6 6 6 6"/></svg>\n      ${typeChip(l.source_type)}<span class="rel-arrow">— ${l.name} →</span><b>${name}</b></div>`)\n  ].join("") || \'<div class="muted">No relationships defined</div>\';\n  el("typeDetailBody").innerHTML = `\n    ${t.ai_suggested ? \'<span class="badge" style="color:var(--warning); border-color:var(--warning); margin-bottom:10px; display:inline-block;">AI suggested</span>\' : ""}\n    <div class="detail-tabs" style="margin-bottom:10px;">\n      <div class="detail-tab active">Properties (${Object.keys(t.properties).length})</div>\n    </div>\n    ${propsHtml}\n    <div class="hr"></div>\n    <h2 style="font-size:12px; margin-bottom:10px; color:var(--text-strong);">Relationships</h2>\n    ${relHtml}`;\n}\nasync function suggestOntology(){\n  const id = el("ontoDatasetSelect").value;\n  if(!id) return;\n  try{\n    const s = await api("/api/ontology/suggest/"+id);\n    el("ontoSuggestion").innerHTML = `\n      <div class="muted">Proposed type: <b style="color:var(--accent-strong)">${s.proposed_object_type}</b>\n      (confidence ${(s.confidence*100).toFixed(0)}%)</div>\n      <pre class="jsonview">${JSON.stringify(s.properties,null,2)}</pre>\n      <button class="ghost" onclick=\'acceptSuggestion(${JSON.stringify(JSON.stringify(s))})\'>Accept &amp; create type</button>`;\n  }catch(e){ toast(e.message,"error"); }\n}\nasync function acceptSuggestion(raw){\n  const s = JSON.parse(raw);\n  try{\n    await api("/api/ontology/object-types", {method:"POST", body: JSON.stringify(\n      {name:s.proposed_object_type, properties:s.properties, ai_suggested:true})});\n    toast("Object type created", "ok"); switchOntoTab("types"); loadOntology();\n  }catch(e){ toast(e.message,"error"); }\n}\nasync function createObjectType(){\n  const name = el("newTypeName").value.trim();\n  let props = {};\n  try{ props = JSON.parse(el("newTypeProps").value || "{}"); }catch(e){ toast("Invalid JSON","error"); return; }\n  try{\n    await api("/api/ontology/object-types", {method:"POST", body:JSON.stringify({name, properties:props})});\n    toast("Created", "ok"); el("newTypePanel").classList.remove("open"); loadOntology();\n  }catch(e){ toast(e.message,"error"); }\n}\nasync function createLinkType(){\n  const name = el("linkTypeName").value.trim();\n  const source_type = el("linkSourceType").value.trim();\n  const target_type = el("linkTargetType").value.trim();\n  try{\n    await api("/api/ontology/link-types", {method:"POST", body:JSON.stringify({name, source_type, target_type})});\n    toast("Created", "ok"); el("newLinkPanel").classList.remove("open"); loadOntology();\n  }catch(e){ toast(e.message,"error"); }\n}\n\n/* ============================== OBJECTS ============================== */\nasync function materializeDataset(){\n  const dataset_id = el("matDatasetSelect").value;\n  const object_type = el("matObjectType").value.trim();\n  const id_column = el("matIdColumn").value.trim() || null;\n  try{\n    const r = await api("/api/objects/materialize", {method:"POST",\n      body: JSON.stringify({dataset_id, object_type, id_column})});\n    el("matStatus").textContent = `${r.created} objects created (${r.skipped} duplicates skipped).`;\n    toast("Materialized", "ok"); loadObjects();\n  }catch(e){ el("matStatus").textContent = "Error: "+e.message; toast(e.message,"error"); }\n}\nasync function createLink(){\n  const link_type = el("lnkType").value.trim();\n  const source_object = el("lnkSource").value.trim();\n  const target_object = el("lnkTarget").value.trim();\n  try{\n    await api("/api/links", {method:"POST", body:JSON.stringify({link_type, source_object, target_object})});\n    el("linkStatus").textContent = "Link created."; toast("Linked","ok");\n  }catch(e){ el("linkStatus").textContent = "Error: "+e.message; toast(e.message,"error"); }\n}\nasync function loadObjects(){\n  const typeFilter = el("objectTypeFilter").value.trim();\n  const q = typeFilter ? "?object_type="+encodeURIComponent(typeFilter) : "";\n  const rows = await api("/api/objects"+q);\n  el("objectCountSub").textContent = rows.length + " results";\n  el("objectsTable").innerHTML = rows.map(o=>`\n    <tr>\n      <td><input class="checkbox" type="checkbox" ${selectedForCompare.has(o.object_id)?\'checked\':\'\'} onchange="toggleCompareSel(\'${o.object_id}\', this.checked)"></td>\n      <td>${o.object_id}</td><td>${typeChip(o.object_type)}</td>\n      <td>${JSON.stringify(o.properties).slice(0,90)}</td>\n      <td><a class="link" onclick="el(\'graphObjectId\').value=\'${o.object_id}\'; switchView(\'graph\'); loadGraph();">Graph</a></td>\n    </tr>`).join("");\n}\nfunction toggleCompareSel(id, checked){\n  if(checked) selectedForCompare.add(id); else selectedForCompare.delete(id);\n  el("compareCount").textContent = selectedForCompare.size + " selected";\n  el("compareBar").classList.toggle("show", selectedForCompare.size>0);\n}\nfunction clearCompare(){\n  selectedForCompare.clear(); el("compareBar").classList.remove("show"); loadObjects();\n}\nasync function openCompare(){\n  const ids = Array.from(selectedForCompare).slice(0,6);\n  const results = await Promise.all(ids.map(id=>api("/api/evidence/object/"+id)));\n  const allKeys = new Set();\n  results.forEach(r=>Object.keys(r.properties||{}).forEach(k=>allKeys.add(k)));\n  const cardsHtml = results.map(r=>{\n    const rows = Array.from(allKeys).map(k=>`<div class="prop-row" style="padding:5px 0;"><span class="prop-name" style="font-size:11px;">${k}</span><span class="prop-type">${r.properties[k] ?? "-"}</span></div>`).join("");\n    return `<div class="compare-card"><h4>${r.object_id}</h4>${typeChip(r.object_type)}<div style="margin-top:8px;">${rows}</div></div>`;\n  }).join("");\n  const modalId = "compareModal";\n  let modal = el(modalId);\n  if(!modal){\n    modal = document.createElement("div");\n    modal.id = modalId;\n    modal.className = "card fullscreen";\n    document.body.appendChild(modal);\n  }\n  modal.innerHTML = `<div class="card-hd"><h2 style="flex:1">Compare Objects</h2>\n    <div class="card-toolbar"><button class="icon-btn" onclick="document.getElementById(\'${modalId}\').remove()">\n    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M6 6l12 12M18 6L6 18"/></svg></button></div></div>\n    <div class="card-bd"><div class="compare-grid">${cardsHtml}</div></div>`;\n}\n\n/* ============================== GRAPH (pan/zoom) ============================== */\nfunction renderGraph(nodes, edges, focusId){\n  graphState.nodes = nodes; graphState.edges = edges; graphState.focusId = focusId;\n  graphState.scale = 1; graphState.tx = 0; graphState.ty = 0;\n  drawGraph();\n  const types = [...new Set(nodes.map(n=>n.object_type))];\n  el("graphLegend").style.display = types.length ? "flex":"none";\n  el("graphLegend").innerHTML = types.map(t=>`<div class="item"><span class="sw" style="background:${colorForType(t)}"></span>${t}</div>`).join("");\n}\nfunction drawGraph(){\n  const svg = el("graphSvg"), g = el("graphG");\n  const w = svg.clientWidth || 800, h = svg.clientHeight || 480;\n  const cx = w/2, cy = h/2, R = Math.min(w,h)/2 - 60;\n  const {nodes, edges, focusId} = graphState;\n  const positions = {};\n  if(focusId) positions[focusId] = {x:cx, y:cy};\n  const others = nodes.filter(n=>n.object_id!==focusId);\n  others.forEach((n,i)=>{\n    const angle = (2*Math.PI*i)/Math.max(1,others.length);\n    positions[n.object_id] = {x: cx + R*Math.cos(angle), y: cy + R*Math.sin(angle)};\n  });\n  let svgContent = "";\n  const seenEdge = new Set();\n  edges.forEach(e=>{\n    const key = [e.source||focusId, e.target].sort().join("|")+e.link_type;\n    if(seenEdge.has(key)) return; seenEdge.add(key);\n    const a = positions[e.source||focusId], b = positions[e.target];\n    if(!a||!b) return;\n    svgContent += `<line class="gedge" x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}"></line>`;\n    svgContent += `<text class="gedge-label" x="${(a.x+b.x)/2}" y="${(a.y+b.y)/2}">${e.link_type}</text>`;\n  });\n  nodes.forEach(n=>{\n    const p = positions[n.object_id]; if(!p) return;\n    const r = n.object_id===focusId ? 15 : 9;\n    svgContent += `<g class="gnode" onclick="el(\'graphObjectId\').value=\'${n.object_id}\'; loadGraph();">\n      <circle cx="${p.x}" cy="${p.y}" r="${r}" fill="${colorForType(n.object_type)}"></circle>\n      <text x="${p.x+r+5}" y="${p.y+4}">${n.object_type}:${n.object_id.slice(-6)}</text>\n    </g>`;\n  });\n  g.innerHTML = svgContent;\n  g.setAttribute("transform", `translate(${graphState.tx},${graphState.ty}) scale(${graphState.scale})`);\n}\nfunction graphZoom(factor){ graphState.scale = Math.max(0.3, Math.min(3, graphState.scale*factor)); drawGraph(); }\nfunction graphResetView(){ graphState.scale=1; graphState.tx=0; graphState.ty=0; drawGraph(); }\n(function initGraphInteraction(){\n  const wrap = document.getElementById("graphCanvasWrap");\n  let dragging=false, lastX=0, lastY=0;\n  wrap.addEventListener("wheel", e=>{ e.preventDefault(); graphZoom(e.deltaY<0?1.1:0.9); }, {passive:false});\n  wrap.addEventListener("mousedown", e=>{ dragging=true; lastX=e.clientX; lastY=e.clientY; wrap.classList.add("dragging"); });\n  window.addEventListener("mouseup", ()=>{ dragging=false; wrap.classList.remove("dragging"); });\n  window.addEventListener("mousemove", e=>{\n    if(!dragging) return;\n    graphState.tx += (e.clientX-lastX); graphState.ty += (e.clientY-lastY);\n    lastX=e.clientX; lastY=e.clientY; drawGraph();\n  });\n})();\nasync function loadGraph(){\n  const id = el("graphObjectId").value.trim();\n  if(!id) return;\n  const hops = parseInt(el("graphHops").value || "2");\n  try{\n    const r = await api(`/api/graph/neighbors?object_id=${encodeURIComponent(id)}&hops=${hops}`);\n    renderGraph(r.nodes, r.edges, id);\n  }catch(e){ toast(e.message,"error"); }\n}\nasync function findPath(){\n  const s = el("pathSource").value.trim(), t = el("pathTarget").value.trim();\n  try{\n    const r = await api(`/api/graph/path?source=${encodeURIComponent(s)}&target=${encodeURIComponent(t)}`);\n    if(!r.found){ el("pathResult").textContent = "No path found: "+(r.error||""); return; }\n    el("pathResult").innerHTML = `Path (${r.hops} hop): ${r.path.join(" → ")}`;\n    const nodes = r.path.map(pid=>({object_id:pid, object_type:"Path"}));\n    const edges = r.edges.map((e,i)=>({source:r.path[i], target:r.path[i+1], link_type:e.link_type}));\n    renderGraph(nodes, edges, r.path[0]);\n  }catch(e){ toast(e.message,"error"); }\n}\n\n/* ============================== SEARCH ============================== */\nasync function runSearch(){\n  const q = el("searchQuery").value.trim();\n  if(!q) return;\n  const r = await api("/api/search?q="+encodeURIComponent(q));\n  el("searchTable").innerHTML = r.map(o=>`\n    <tr><td>${o.score}</td><td>${o.object_id}</td><td>${typeChip(o.object_type)}</td>\n    <td>${JSON.stringify(o.properties).slice(0,100)}</td></tr>`).join("");\n}\n\n/* ============================== ANALYTICS ============================== */\nasync function runSql(){\n  el("sqlError").textContent = ""; el("sqlChartWrap").innerHTML = "";\n  try{\n    const r = await api("/api/analytics/sql", {method:"POST", body:JSON.stringify({sql: el("sqlBox").value})});\n    el("sqlHead").innerHTML = "<tr>"+r.columns.map(c=>`<th>${c}</th>`).join("")+"</tr>";\n    el("sqlBody").innerHTML = r.rows.map(row=>"<tr>"+r.columns.map(c=>`<td>${row[c]}</td>`).join("")+"</tr>").join("");\n    if(r.columns.length===2 && r.rows.length && typeof r.rows[0][r.columns[1]]==="number"){\n      const items = r.rows.slice(0,15).map(row=>({label:String(row[r.columns[0]]), value:row[r.columns[1]]}));\n      el("sqlChartWrap").innerHTML = `<div class="card" style="margin-bottom:0;"><div class="card-hd"><h2>Bar plot — ${r.columns[0]} by ${r.columns[1]}</h2></div><div class="card-bd">${renderBarChart(items)}</div></div>`;\n    }\n  }catch(e){ el("sqlError").textContent = e.message; }\n}\n\n/* ============================== AI ANALYST ============================== */\nfunction appendMsg(role, text){\n  const d = document.createElement("div");\n  d.className = "msg "+role;\n  d.innerHTML = text;\n  el("chatLog").appendChild(d);\n  el("chatLog").scrollTop = el("chatLog").scrollHeight;\n  return d;\n}\nfunction newChat(){\n  convId = null; chatHistoryForCase = []; el("chatLog").innerHTML = "";\n}\nasync function sendChat(){\n  const input = el("chatInput");\n  const q = input.value.trim();\n  if(!q) return;\n  appendMsg("user", q);\n  chatHistoryForCase.push({role:"user", content:q});\n  input.value = "";\n  const thinking = appendMsg("step busy", \'<span class="step-dot"></span>Thinking…\');\n  try{\n    const r = await api("/api/ai/query", {method:"POST", body:JSON.stringify({query:q, conversation_id:convId})});\n    convId = r.conversation_id;\n    thinking.remove();\n    (r.steps||[]).forEach(s=>{\n      if(s.kind==="tool_call") appendMsg("step", \'<span class="step-dot"></span>\'+s.label);\n      if(s.kind==="tool_result"){\n        const evidence = s.result && s.result.evidence ? s.result.evidence.length : null;\n        appendMsg("step", \'<span class="step-dot"></span>Result received\'+(evidence!==null?` (${evidence} evidence)`:""));\n      }\n    });\n    if(r.error){ appendMsg("assistant", "Error: "+r.error); toast(r.error,"error"); }\n    else{\n      appendMsg("assistant", (r.answer||"").replace(/\\n/g,"<br>"));\n      chatHistoryForCase.push({role:"assistant", content:r.answer, steps:r.steps});\n    }\n  }catch(e){ thinking.remove(); appendMsg("assistant","Error: "+e.message); toast(e.message,"error"); }\n}\nasync function saveChatAsCase(){\n  if(!chatHistoryForCase.length){ toast("Nothing to save","error"); return; }\n  const title = "AI Analyst — " + new Date().toLocaleString();\n  try{\n    await api("/api/cases", {method:"POST", body: JSON.stringify(\n      {title, description:"Saved from AI Analyst chat", payload:{conversation_id:convId, messages:chatHistoryForCase}})});\n    toast("Case saved", "ok");\n  }catch(e){ toast(e.message,"error"); }\n}\n\n/* ============================== CASES ============================== */\nasync function createCase(){\n  const title = el("caseTitle").value.trim();\n  const description = el("caseDesc").value.trim();\n  try{\n    await api("/api/cases", {method:"POST", body: JSON.stringify({title, description, payload:{}})});\n    toast("Case saved","ok"); loadCases();\n  }catch(e){ toast(e.message,"error"); }\n}\nasync function loadCases(){\n  const rows = await api("/api/cases");\n  el("casesTable").innerHTML = rows.map(c=>`\n    <tr><td>${c.title}</td><td>${c.created_at.slice(0,19)}</td><td>${c.updated_at.slice(0,19)}</td>\n    <td><a class="link" onclick="viewCase(\'${c.case_id}\')">View</a></td></tr>`).join("");\n}\nasync function viewCase(id){\n  const c = await api("/api/cases/"+id);\n  el("caseDetailCard").style.display = "block";\n  el("caseDetailTitle").textContent = c.title;\n  el("caseDetailBody").textContent = JSON.stringify(c.payload, null, 2);\n  el("caseDetailCard").scrollIntoView({behavior:"smooth", block:"nearest"});\n}\n\n/* ============================== SETTINGS ============================== */\nasync function loadSettings(){\n  const h = await api("/api/health");\n  el("healthView").textContent = JSON.stringify(h, null, 2);\n  el("cfgMode").value = h.mode;\n  const cfg = await api("/api/settings");\n  el("cfgLmHost").value = cfg.lm_studio.host;\n  el("cfgLmPort").value = cfg.lm_studio.port;\n  el("cfgLmModel").value = cfg.lm_studio.model || "";\n  el("cfgLmTemp").value = cfg.lm_studio.temperature;\n  el("cfgLmMaxTokens").value = cfg.lm_studio.max_tokens;\n  el("cfgLmTimeout").value = cfg.lm_studio.timeout_seconds;\n  el("cfgBind").value = cfg.server.host+":"+cfg.server.port;\n  refreshLmStatus();\n}\nasync function saveLmSettings(){\n  const payload = {\n    host: el("cfgLmHost").value, port: parseInt(el("cfgLmPort").value),\n    model: el("cfgLmModel").value || null, temperature: parseFloat(el("cfgLmTemp").value),\n    max_tokens: parseInt(el("cfgLmMaxTokens").value), timeout_seconds: parseFloat(el("cfgLmTimeout").value),\n  };\n  try{\n    await api("/api/settings/lm-studio", {method:"POST", body: JSON.stringify(payload)});\n    toast("Saved","ok"); refreshLmStatus();\n  }catch(e){ toast(e.message,"error"); }\n}\nasync function testLmConnection(){\n  el("lmTestResult").textContent = "Testing...";\n  try{\n    const r = await api("/api/lmstudio/health");\n    el("lmTestResult").innerHTML = r.connected\n      ? `<span style="color:var(--success)">CONNECTED</span> — models: ${(r.models||[]).join(", ")||"(none loaded)"}`\n      : `<span style="color:var(--danger)">DISCONNECTED</span> — ${r.error}`;\n    refreshLmStatus();\n  }catch(e){ el("lmTestResult").textContent = e.message; }\n}\nasync function refreshLmStatus(){\n  try{\n    const r = await api("/api/lmstudio/health");\n    el("lmDot").className = "status-dot " + (r.connected ? "on":"off pulse");\n    el("lmText").textContent = r.connected ? "LM Studio: connected" : "LM Studio: disconnected";\n    if(el("aiModelSub")){\n      el("aiModelSub").style.display = r.connected ? "inline-block":"none";\n      el("aiModelSub").textContent = r.connected ? (r.models||[]).join(", ") : "";\n    }\n  }catch(e){}\n}\n\n/* ============================== boot ============================== */\nswitchView("home");\nrefreshLmStatus();\nsetInterval(refreshLmStatus, 15000);\n</script>\n</body>\n</html>\n\n'
_umbra_FRONTEND_HTML = _umbra_FRONTEND_HTML.replace('__VERSION__', _umbra_APP_VERSION)

class _umbra_JSONEncoder(_umbra_json.JSONEncoder):

    def default(self, o):
        if isinstance(o, (set,)):
            return list(o)
        return super().default(o)

def _umbra_make_handler(app: UmbraApp):

    class Handler(_umbra_BaseHTTPRequestHandler):
        server_version = f'{_umbra_APP_NAME}/{_umbra_APP_VERSION}'

        def log_message(self, fmt, *args):
            app.logger.info('HTTP ' + fmt % args)

        def _send_json(self, payload: Any, status: int=200) -> None:
            body = _umbra_json.dumps(payload, ensure_ascii=False, cls=_umbra_JSONEncoder, default=str).encode('utf-8')
            self.send_response(status)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _send_html(self, html: str) -> None:
            body = html.encode('utf-8')
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _read_json_body(self) -> dict:
            length = int(self.headers.get('Content-Length', 0) or 0)
            if length == 0:
                return {}
            raw = self.rfile.read(length)
            if not raw:
                return {}
            return _umbra_json.loads(raw.decode('utf-8'))

        def _error(self, message: str, status: int=400) -> None:
            app.logger.warning(f'API error [{status}]: {message}')
            self._send_json({'error': message}, status=status)

        def do_GET(self):
            try:
                self._route_get()
            except Exception as e:
                app.logger.error(_umbra_traceback.format_exc())
                self._error(str(e), 500)

        def do_POST(self):
            try:
                self._route_post()
            except (_umbra_OntologyError, _umbra_IngestionError, _umbra_AnalyticsError, _umbra_LLMProviderError, ValueError) as e:
                self._error(str(e), 400)
            except Exception as e:
                app.logger.error(_umbra_traceback.format_exc())
                self._error(str(e), 500)

        def _route_get(self):
            parsed = _umbra_urlparse(self.path)
            path = parsed.path
            qs = _umbra_parse_qs(parsed.query)
            if path == '/' or path == '/index.html':
                self._send_html(_umbra_FRONTEND_HTML)
                return
            if path == '/api/health':
                self._send_json(app.health())
                return
            if path == '/api/settings':
                self._send_json({'server': _umbra_asdict(app.cfg.server), 'lm_studio': _umbra_asdict(app.cfg.lm_studio)})
                return
            if path == '/api/lmstudio/health':
                self._send_json(app.llm.health())
                return
            if path == '/api/datasets':
                rows = app.storage.query('SELECT dataset_id, source_name, source_type, ingested_at, row_count, column_count, status FROM datasets ORDER BY ingested_at DESC')
                self._send_json([dict(r) for r in rows])
                return
            if path.startswith('/api/datasets/'):
                ds_id = path.split('/')[-1]
                row = app.storage.query_one('SELECT * FROM datasets WHERE dataset_id=?', (ds_id,))
                if not row:
                    self._error('dataset not found', 404)
                    return
                d = dict(row)
                d['schema'] = _umbra_json.loads(d.pop('schema_json') or '{}')
                d['profile'] = _umbra_json.loads(d.pop('profile_json') or '{}')
                self._send_json(d)
                return
            if path == '/api/ontology/object-types':
                self._send_json(app.ontology.list_object_types())
                return
            if path == '/api/ontology/link-types':
                self._send_json(app.ontology.list_link_types())
                return
            if path.startswith('/api/ontology/suggest/'):
                ds_id = path.split('/')[-1]
                self._send_json(app.ontology.suggest_ontology_from_dataset(ds_id))
                return
            if path == '/api/ontology/validate':
                self._send_json(app.ontology.validate())
                return
            if path == '/api/objects':
                object_type = qs.get('object_type', [None])[0]
                sql = 'SELECT object_id, object_type, properties_json, confidence FROM objects'
                params: tuple = ()
                if object_type:
                    sql += ' WHERE object_type=?'
                    params = (object_type,)
                sql += ' ORDER BY created_at DESC LIMIT 500'
                rows = app.storage.query(sql, params)
                out = [{'object_id': r['object_id'], 'object_type': r['object_type'], 'properties': _umbra_json.loads(r['properties_json']), 'confidence': r['confidence']} for r in rows]
                self._send_json(out)
                return
            if path.startswith('/api/objects/') and '/evidence' not in path:
                obj_id = path.split('/')[-1]
                self._send_json(app.evidence.for_object(obj_id))
                return
            if path.startswith('/api/evidence/object/'):
                obj_id = path.split('/')[-1]
                self._send_json(app.evidence.for_object(obj_id))
                return
            if path.startswith('/api/evidence/link/'):
                link_id = path.split('/')[-1]
                self._send_json(app.evidence.for_link(link_id))
                return
            if path == '/api/graph/neighbors':
                obj_id = qs.get('object_id', [None])[0]
                hops = int(qs.get('hops', ['1'])[0])
                if not obj_id:
                    self._error('object_id required')
                    return
                self._send_json(app.graph.neighbors(obj_id, hops))
                return
            if path == '/api/graph/path':
                source, target = (qs.get('source', [None])[0], qs.get('target', [None])[0])
                max_hops = int(qs.get('max_hops', ['6'])[0])
                if not source or not target:
                    self._error('source and target required')
                    return
                self._send_json(app.graph.shortest_path(source, target, max_hops))
                return
            if path == '/api/graph/centrality':
                self._send_json(app.graph.centrality())
                return
            if path == '/api/stats/object-type-counts':
                rows = app.storage.query('SELECT object_type, COUNT(*) as n FROM objects GROUP BY object_type ORDER BY n DESC')
                self._send_json([dict(r) for r in rows])
                return
            if path == '/api/audit/recent':
                qsd = _umbra_parse_qs(_umbra_urlparse(self.path).query)
                limit = int(qsd.get('limit', ['12'])[0])
                rows = app.storage.query('SELECT log_id, ts, operation, status, duration_ms FROM audit_log ORDER BY ts DESC LIMIT ?', (limit,))
                self._send_json([dict(r) for r in rows])
                return
            if path == '/api/search':
                q = qs.get('q', [''])[0]
                top_k = int(qs.get('top_k', ['20'])[0])
                self._send_json(app.search.search(q, top_k=top_k))
                return
            if path == '/api/cases':
                self._send_json(app.list_cases())
                return
            if path.startswith('/api/cases/'):
                case_id = path.split('/')[-1]
                case = app.get_case(case_id)
                if not case:
                    self._error('case not found', 404)
                    return
                self._send_json(case)
                return
            self._error('not found', 404)

        def _route_post(self):
            parsed = _umbra_urlparse(self.path)
            path = parsed.path
            if path == '/api/datasets/ingest':
                content_type = self.headers.get('Content-Type', '')
                length = int(self.headers.get('Content-Length', 0) or 0)
                if length > app.cfg.max_upload_bytes:
                    self._error('file too large', 413)
                    return
                body = self.rfile.read(length)
                fields = _umbra_parse_multipart(body, content_type)
                if 'file' not in fields:
                    self._error('no file field in upload')
                    return
                upload = fields['file']
                filename = upload['filename'] or 'upload.csv'
                tmp_path = _umbra_os.path.join(app.cfg.storage_dir, f'{_umbra_new_id()}_{_umbra_os.path.basename(filename)}')
                with open(tmp_path, 'wb') as f:
                    f.write(upload['data'])
                try:
                    result = app.ingestion.ingest_file(tmp_path, source_name=filename)
                finally:
                    pass
                self._send_json(result)
                return
            data = self._read_json_body()
            if path == '/api/ontology/object-types':
                result = app.ontology.create_object_type(data['name'], data.get('properties', {}), data.get('description', ''), data.get('ai_suggested', False))
                self._send_json(result)
                return
            if path == '/api/ontology/link-types':
                result = app.ontology.create_link_type(data['name'], data['source_type'], data['target_type'], data.get('description', ''), data.get('ai_suggested', False))
                self._send_json(result)
                return
            if path == '/api/objects/materialize':
                result = app.entities.materialize_dataset(data['dataset_id'], data['object_type'], data.get('id_column'))
                self._send_json(result)
                return
            if path == '/api/links':
                result = app.entities.create_link(data['link_type'], data['source_object'], data['target_object'], data.get('properties'), data.get('confidence', 1.0))
                self._send_json(result)
                return
            if path == '/api/analytics/sql':
                result = app.analytics.run_sql(data['sql'], data.get('limit', 500))
                self._send_json(result)
                return
            if path == '/api/analytics/aggregate':
                result = app.analytics.aggregate_property(data['object_type'], data['property_name'], data.get('op', 'count'))
                self._send_json(result)
                return
            if path == '/api/ai/query':
                result = app.agent.run(data['query'], data.get('conversation_id'))
                self._send_json(result)
                return
            if path == '/api/cases':
                result = app.create_case(data['title'], data.get('description', ''), data.get('payload', {}))
                self._send_json(result)
                return
            if path == '/api/settings/lm-studio':
                cfg = app.cfg.lm_studio
                cfg.host = data.get('host', cfg.host)
                cfg.port = int(data.get('port', cfg.port))
                cfg.model = data.get('model') or None
                cfg.temperature = float(data.get('temperature', cfg.temperature))
                cfg.max_tokens = int(data.get('max_tokens', cfg.max_tokens))
                cfg.timeout_seconds = float(data.get('timeout_seconds', cfg.timeout_seconds))
                app.cfg.save()
                app.reload_llm()
                self._send_json({'ok': True})
                return
            self._error('not found', 404)
    return Handler

def _umbra_run_server(app: UmbraApp) -> None:
    handler = _umbra_make_handler(app)
    server = _umbra_ThreadingHTTPServer((app.cfg.server.host, app.cfg.server.port), handler)
    mode_label = 'SERVER (LAN reachable)' if app.cfg.server.mode == 'server' else 'LOCAL'
    app.logger.info(f'{_umbra_APP_NAME} listening on http://{app.cfg.server.host}:{app.cfg.server.port} [{mode_label}]')
    print(f'\n  {_umbra_APP_NAME} — {_umbra_APP_COMPANY}')
    print(f'  Mode : {mode_label}')
    print(f'  URL  : http://{app.cfg.server.host}:{app.cfg.server.port}')
    print(f'  Data : {app.cfg.home_dir}')
    print(f"  LM   : {app.cfg.lm_studio.base_url} (model={app.cfg.lm_studio.model or 'auto'})\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        app.logger.info('Shutting down.')
        server.shutdown()

def _umbra_build_arg_parser() -> _umbra_argparse.ArgumentParser:
    p = _umbra_argparse.ArgumentParser(prog='umbra', description=f'{_umbra_APP_NAME} — {_umbra_APP_COMPANY}')
    sub = p.add_subparsers(dest='command', required=False)
    serve = sub.add_parser('serve', help='Start the UMBRA web application')
    serve.add_argument('--mode', choices=['local', 'server'], default=None)
    serve.add_argument('--host', default=None)
    serve.add_argument('--port', type=int, default=None)
    ingest = sub.add_parser('ingest', help='Ingest a single file (CSV/JSON/JSONL)')
    ingest.add_argument('path')
    sub.add_parser('health', help='Print system health as JSON')
    lmtest = sub.add_parser('lmstudio-test', help='Test the configured LM Studio connection')
    models = sub.add_parser('models', help='List models currently loaded in LM Studio')
    ont = sub.add_parser('ontology', help='Ontology utilities')
    ont_sub = ont.add_subparsers(dest='ontology_command', required=False)
    ont_sub.add_parser('inspect', help='Print current ontology as JSON')
    search = sub.add_parser('search', help='Search objects from the CLI')
    search.add_argument('query')
    return p

def _umbra_cmd_serve(args, cfg: AppConfig) -> None:
    if args.mode:
        cfg.server.mode = args.mode
    if args.host:
        cfg.server.host = args.host
    elif cfg.server.mode == 'server' and cfg.server.host == '127.0.0.1':
        cfg.server.host = '0.0.0.0'
    if args.port:
        cfg.server.port = args.port
    cfg.save()
    app = _umbra_UmbraApp(cfg)
    _umbra_run_server(app)

def _umbra_cmd_ingest(args, cfg: AppConfig) -> None:
    app = _umbra_UmbraApp(cfg)
    result = app.ingestion.ingest_file(args.path)
    print(_umbra_json.dumps(result, ensure_ascii=False, indent=2, default=str))

def _umbra_cmd_health(args, cfg: AppConfig) -> None:
    app = _umbra_UmbraApp(cfg)
    print(_umbra_json.dumps(app.health(), ensure_ascii=False, indent=2, default=str))

def _umbra_cmd_lmstudio_test(args, cfg: AppConfig) -> None:
    app = _umbra_UmbraApp(cfg)
    print(_umbra_json.dumps(app.llm.health(), ensure_ascii=False, indent=2, default=str))

def _umbra_cmd_models(args, cfg: AppConfig) -> None:
    app = _umbra_UmbraApp(cfg)
    try:
        print(_umbra_json.dumps(app.llm.list_models(), ensure_ascii=False, indent=2))
    except _umbra_LLMProviderError as e:
        print(f'LM Studio unavailable: {e}')

def _umbra_cmd_ontology(args, cfg: AppConfig) -> None:
    app = _umbra_UmbraApp(cfg)
    if getattr(args, 'ontology_command', None) in (None, 'inspect'):
        data = {'object_types': app.ontology.list_object_types(), 'link_types': app.ontology.list_link_types(), 'problems': app.ontology.validate()}
        print(_umbra_json.dumps(data, ensure_ascii=False, indent=2))
    else:
        print(f'[{_umbra_APP_NAME}] unknown ontology subcommand: {args.ontology_command}')

def _umbra_cmd_search(args, cfg: AppConfig) -> None:
    app = _umbra_UmbraApp(cfg)
    print(_umbra_json.dumps(app.search.search(args.query), ensure_ascii=False, indent=2, default=str))

class _umbra__ServeDefaults:
    """Stand-in for argparse.Namespace when `serve` runs with no CLI flags
    at all (double-click / VS Code Run button) — cmd_serve() only reads
    these three attributes."""
    mode = None
    host = None
    port = None

def _umbra_main() -> None:
    parser = _umbra_build_arg_parser()
    args = parser.parse_args()
    cfg = _umbra_AppConfig.load()
    if args.command is None:
        print(f"[{_umbra_APP_NAME}] No command given — starting 'serve --mode local' automatically.")
        print(f'[{_umbra_APP_NAME}] Tip: run with an explicit command next time, e.g.:')
        print(f'           python {_umbra_os.path.basename(_umbra_sys.argv[0])} serve --mode local --port 8877')
        args = _umbra__ServeDefaults()
        args.command = 'serve'
    dispatch = {'serve': _umbra_cmd_serve, 'ingest': _umbra_cmd_ingest, 'health': _umbra_cmd_health, 'lmstudio-test': _umbra_cmd_lmstudio_test, 'models': _umbra_cmd_models, 'ontology': _umbra_cmd_ontology, 'search': _umbra_cmd_search}
    handler = dispatch.get(args.command)
    if handler is None:
        parser.print_help()
        _umbra_sys.exit(1)
    try:
        handler(args, cfg)
    except Exception as e:
        print(f'[{_umbra_APP_NAME}] fatal error: {e}', file=_umbra_sys.stderr)
        _umbra_traceback.print_exc()
        _umbra_sys.exit(1)


# ============================================================================
# ORBITAL 5.3 — CONFIG / THEME / MODULE REGISTRY / INTEGRATED WEB + UMBRA
# ============================================================================

import base64
import html
import ipaddress
import logging
import socket
import zlib
from dataclasses import dataclass as _core_dataclass
from typing import Callable as _Callable

APP_VERSION = "5.3"
APP_ABOUT = {
    "name": "OBLIVION ORBITAL",
    "version": APP_VERSION,
    "tagline": "Intelligence. Engineering. Systems.",
    "architecture": "Orbital Core + Umbra Data Intelligence + Embedded Web/GOTHAM",
}

THEME = {
    "background": "#000000",
    "surface": "#070707",
    "surface_raised": "#0A0A0A",
    "accent": "#91A9FF",
    "text": "#E8EAF0",
    "muted": "#9297A5",
    "line": "rgba(255,255,255,0.12)",
    "glass": "rgba(255,255,255,0.045)",
}

THEME_CSS = r"""
<style id="orbital53-shared-theme">
:root,html[data-theme],body{
 --orbital-bg:#000;--orbital-surface:#070707;--orbital-raised:#0a0a0a;
 --orbital-accent:#91a9ff;--orbital-text:#e8eaf0;--orbital-muted:#9297a5;
 --orbital-line:rgba(255,255,255,.12);--orbital-glass:rgba(255,255,255,.045);
 --orbital-radius:12px;--orbital-fast:200ms;
 /* Orbital legacy tokens */
 --black:#000!important;--panel:rgba(8,8,8,.82)!important;--panel-2:#0a0a0a!important;
 --line:rgba(255,255,255,.12)!important;--line-soft:rgba(255,255,255,.075)!important;
 --ink:#e8eaf0!important;--ink-dim:#9297a5!important;
 --steel:#91a9ff!important;--steel-2:#91a9ff!important;--steel-glow:rgba(145,169,255,.16)!important;
 /* Umbra legacy tokens */
 --bg-canvas:#000!important;--bg-surface:rgba(8,8,8,.82)!important;
 --bg-surface-2:#0a0a0a!important;--bg-surface-3:#111!important;
 --border:rgba(255,255,255,.12)!important;--border-strong:rgba(255,255,255,.2)!important;
 --text-strong:#fff!important;--text:#e8eaf0!important;
 --text-muted:#9297a5!important;--text-faint:#6d7380!important;
 --accent:#91a9ff!important;--accent-primary:#91a9ff!important;--accent-strong:#91a9ff!important;
 --accent-bg:rgba(145,169,255,.12)!important;--accent-border:rgba(145,169,255,.4)!important;
 /* Web / Gotham legacy tokens */
 --bg:#000!important;--p1:#070707!important;--p2:#0a0a0a!important;--p3:#111!important;
 --ln:rgba(255,255,255,.12)!important;--ac:#91a9ff!important;--ac2:#91a9ff!important;
 --tx:#e8eaf0!important;--dm:#9297a5!important;
 color-scheme:dark;
}
*,*::before,*::after{box-sizing:border-box;scrollbar-color:rgba(255,255,255,.22) transparent;scrollbar-width:thin}
html,body{background:#000!important;color:var(--orbital-text)!important}
body{font-family:Inter,"Segoe UI",system-ui,-apple-system,sans-serif!important}
button,select,input,textarea{font:inherit;transition:background-color .2s,border-color .2s,color .2s,box-shadow .2s,transform .2s}
button,.btn,.btn-outline,.oc-btn,.navbtn{border-radius:10px!important;border:1px solid var(--orbital-line)!important;background:rgba(255,255,255,.045)!important;color:var(--orbital-text)!important;backdrop-filter:blur(14px);-webkit-backdrop-filter:blur(14px)}
button:hover,.btn:hover,.btn-outline:hover,.oc-btn:hover,.navbtn:hover{border-color:var(--orbital-accent)!important;color:#fff!important;background:rgba(145,169,255,.12)!important}
button:focus-visible,input:focus-visible,select:focus-visible,textarea:focus-visible{outline:2px solid var(--orbital-accent)!important;outline-offset:2px}
button:disabled,.btn:disabled{opacity:.42!important;cursor:not-allowed!important}
input,select,textarea{background:rgba(255,255,255,.035)!important;color:var(--orbital-text)!important;border:1px solid var(--orbital-line)!important;border-radius:9px!important}
input:focus,select:focus,textarea:focus{border-color:var(--orbital-accent)!important;box-shadow:0 0 0 3px rgba(145,169,255,.12)!important}
.card,.panel,.stat,.msg,.toast,.oc-side,.oc-main,.oc-art,.oc-models,.oc-modal,.modal,.dialog,.popover,
#top,#rail,#side,#sidehead,#timeline,#inspector,#camwin,#topnav,#sidebar,#toolbar,#appbody,
#editor-panel,#files,#userbar,#sidepanel,#statusbar,.sidebar,.topbar,.toolbar,.panel-header,.panel-body{
 background:rgba(10,10,10,.76)!important;border-color:var(--orbital-line)!important;
 backdrop-filter:blur(18px) saturate(125%);-webkit-backdrop-filter:blur(18px) saturate(125%);
 box-shadow:0 10px 32px rgba(0,0,0,.28),inset 0 1px 0 rgba(255,255,255,.035)!important;
}
.btn.pri,.btn-primary,.oc-btn.pri,.btn.on,.seg button.on,#rail button.on{background:var(--orbital-accent)!important;border-color:var(--orbital-accent)!important;color:#050505!important}
#stage,#gl,#ov,#tl{background:#000!important}
.hud,.chip,.badge,.chipbtn{background:rgba(8,8,8,.75)!important;border-color:var(--orbital-line)!important;color:var(--orbital-text)!important;backdrop-filter:blur(12px)}
#loading{background:radial-gradient(circle at 50% 40%,#0a0a0a,#000)!important}
#loading .pb i{background:var(--orbital-accent)!important}
#brand small,#tlbar .dt small,h4,.side-tag,.panel-label,.eyebrow{color:var(--orbital-accent)!important}
#search:focus,.btn:hover{border-color:var(--orbital-accent)!important}
a{color:var(--orbital-accent)}
::-webkit-scrollbar{width:8px;height:8px}::-webkit-scrollbar-thumb{background:rgba(255,255,255,.2);border-radius:8px}::-webkit-scrollbar-track{background:transparent}
@media(max-width:760px){#timeline{min-height:118px}#inspector{width:min(310px,calc(100% - 20px))!important}#brand{min-width:0!important}}
</style>
"""


def _apply_shared_theme(document: str, module_name: str = "") -> str:
    """Inject the common OLED/glass design tokens after legacy styles."""
    if not isinstance(document, str):
        return str(document)
    if "orbital53-shared-theme" in document:
        return document
    themed = document
    # Keep all existing interaction logic and canvas drawing; the theme is a
    # final cascade layer rather than a rewrite of component DOM or JS.
    if re.search(r"</body\s*>", themed, flags=re.I):
        themed = re.sub(r"</body\s*>", THEME_CSS + "\n</body>", themed, count=1, flags=re.I)
    elif re.search(r"</head\s*>", themed, flags=re.I):
        themed = re.sub(r"</head\s*>", THEME_CSS + "\n</head>", themed, count=1, flags=re.I)
    else:
        themed += THEME_CSS
    themed = re.sub(r'(<html\b[^>]*\blang="en")(?![^>]*\bdir=)', r'\1 dir="auto"', themed, count=1, flags=re.I)
    return themed


def _module_unavailable_html(name: str, detail: str) -> str:
    safe_name = html.escape(name)
    safe_detail = html.escape(detail or "Required optional dependency is unavailable.")
    page = f"""<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>{safe_name} unavailable</title></head><body><main style=\"max-width:760px;margin:8vh auto;padding:28px;border:1px solid rgba(255,255,255,.12);border-radius:16px;background:rgba(255,255,255,.04)\"><h1>{safe_name} module unavailable</h1><p>{safe_detail}</p><p>Install the required dependency and restart Orbital 5.3.</p></main></body></html>"""
    return _apply_shared_theme(page, "unavailable")


class ModuleRegistry:
    """Small lifecycle registry for modules hosted by the Orbital process."""
    def __init__(self) -> None:
        self._modules: dict[str, dict[str, _Callable | None]] = {}
        self._lock = threading.RLock()

    def register(self, name: str, start: _Callable | None = None,
                 stop: _Callable | None = None) -> None:
        key = str(name).strip().lower()
        if not key or not re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", key):
            raise ValueError("Invalid module identifier")
        with self._lock:
            if key in self._modules:
                raise ValueError(f"Module already registered: {key}")
            self._modules[key] = {"start": start, "stop": stop}

    def start_all(self, logger: logging.Logger) -> None:
        with self._lock:
            modules = list(self._modules.items())
        for name, callbacks in modules:
            callback = callbacks.get("start")
            if callback is None:
                continue
            try:
                callback()
                logger.info("Module initialized: %s", name)
            except Exception:
                logger.exception("Module initialization failed: %s", name)

    def stop_all(self, logger: logging.Logger) -> None:
        with self._lock:
            modules = list(reversed(list(self._modules.items())))
        for name, callbacks in modules:
            callback = callbacks.get("stop")
            if callback is None:
                continue
            try:
                callback()
                logger.info("Module stopped: %s", name)
            except Exception:
                logger.exception("Module shutdown failed: %s", name)

    def status(self) -> list[str]:
        with self._lock:
            return list(self._modules)


MODULES = ModuleRegistry()
UMBRA_APP = None
UMBRA_ROUTE_HANDLER = None
UMBRA_AVAILABLE = False
UMBRA_IMPORT_ERROR = ""
_WEB_CACHE: dict[str, tuple[float, str, bytes]] = {}
_WEB_CACHE_LOCK = threading.RLock()
_WEB_CACHE_TTL = max(0, int(os.environ.get("ORBITAL_PROXY_CACHE_TTL", "5")))
_WEB_PROXY_MAX_BYTES = 32 * 1024 * 1024
_WEB_ALLOW_PRIVATE = os.environ.get("ORBITAL_ALLOW_PRIVATE_PROXY", "0") == "1"
_WEB_LM_BASE = os.environ.get("LMSTUDIO_BASE_URL", "http://127.0.0.1:1234").rstrip("/")


# Embedded Web UI: compressed at build time, decoded from this one Python file.

WEB_HTML_B85 = (
    'c-pkRTaz2vl`i(qUy&+Wqbdmi^M0vna!&EmB*p8n*wUzbIyea+tB@)b63PUMtS&HO!cUH{!^dHt@Pr-qgToOg!VkwUe(<~XPxMQ?'
    'zHjXWGI1#uTN2eOZ0!49d)?Q{#5ccq{N~a7KfHZnjb<0)2Y0@~hc!+oXZQEA$sQ`QbSNJe*(|jNqqMBD+5Nrm-hbPT_v-3NdXe4V'
    'yUeqX)1sX1S%YFS%O=w8V?LaX?hmuee2{hdrDNrje3qx<ZZ$~9*?k9-%<|bdd+_Gr%jds){^qsy^v(Nc$FHnQ*ZRx9{U_^bR#ejz'
    'L#*dA?RcD@Ws^Z>JslVQ?3;T!_RcrI=yt95X+Hj#Pli@rS;cgg7ZVw@pN_{?I-Oe8>}s4(&a8emE<U15m5ook*lU_kvY}NK)@+oq'
    '>&K!zuPn#5e`yt`r!p!#u)1AY1#`%1hh<UBuDjj-+2LK=w<CLa)a_0k`I0(;8{&&AUovOt@r!qOSL$Owl`rFod>MFd;LDeEaCp}n'
    'MqU>4iwp|gG(J6*Z?jK_cZXi)o<{OzcyV|)%95au>56k1<PW_hkuM)*y3>CD)WvlDA-+UT9AMS?;oX59`=^7?cYb}{FFtjv{3ijx'
    'VZSJcS=p7E&v$U$oqjRAy1q!uvwU)BAC0p7Y&1K>>5uy9;QXvC=9A&!Wm@jz#0N)%VqBEw`|Q)f(W!v&&~c}q?m0a_;4PJ%y_4*$'
    '$gJ<4?{%uHYL;De=Xs|qz#V5@t>{$gr0P~#nV%jNmsxo#*K#<@hr?`gG?!{=8fSyq;iQ;kpYPn2q1VH_nvT<}!?Q9UHuiZrIzmlX'
    'CY9z{CYL&%Uree)Kb(HDbfeYBjy?T!U^%DdTIaI(C_QESXtNw&y6JMgVwz2^G4#-jwRToauQ^&*ICSoHouhhJr{nC?Q7ZU3>E<$f'
    'bvVcXilei1dg%DmPe;>qIK&0m7NFGxE>J8jyJuxO%w^F2U3=i9p53`?$ByHi9vm(2Y&I({4jtKSRgCkYIox=1aP(7GFhBcr=-IN*'
    'ewj{&*SFbNA{)8LCrX`%ZlLGnc<b)CI4iDAODr7?$XRaPg_MNCo0GREvGR+vPOGB2Jli#M(f^~|d-pV-9UAIfPS(F3XR{e_W10>C'
    '%AV_H7sNndcP41q3uFpK(YvQYN%cPa<6>}r1VDFd%;`DHiK`1?6C0B|VQccZF}DI<NcKSHsO0hnqmN}ey`C0T4$gB}W`bS$Wp)JU'
    '<H{{RRN!iFbNY2MyK6^|<2vTTx8AhD1>nkDFn4WBpvW50fc}mRkj`f~IccdyT(j)cY`LYw(_%2MuFd>g&RJ&Fd_1dGhfMpjx%n(R'
    '62dt2fYjscbS6xsB!unu$x<is?5{i7Mf$0}F3;ylYEF^PXT|bzc`mZJQ96`Hr7+8r5!PMXw$s(-tzmw7y#b)XysYH3(;_Ejv?%9~'
    '^J<o#UUiLFI|O=U-F`Ovm<g)_5yiaM#sY^U?6cFX>IuZJH~8t)YrxfDVH5Df3$zbL`Lr?|x=RSRPJa`9b89_JaD5ZtHxaM~5#R`_'
    'Y~Kxm)*w5ZSKp={I~M9$JIp$uKaOO_90KG71)1IUib)F)#rYCF3~@WBVLxy`YwwR~+3x>wvff{MdroNj_tRmkdw;mu-A%nffIpuN'
    't|{U|+o07v?_Ly>g1hd#$|mEY^Qf2zOw+2fY-sYJ4af*z!L^INa@_(wx&0E<%B8kkSL@>Or#s9`A!m@JN~Ue-&_sHh$l=MY)pElP'
    '%#N)7T!hTT@Fy=^ac7nd7PUxwCOlLQSIRnTcoMF0r!6S(1wnGO!BN}$R8reYS&b`bj{$OR3`hsN2Q<W$ldJ&3@@YOED+8)#WpSPz'
    '%J~3^N0`gh8S(1$qPha?cpz869W*QdC}7drdJDa3dQBnXv^Vv`FrB5{Sw8(yVQ_euo(jOOYd)3EX61g}=iq3QX_J%qV6$M~aa$z;'
    '+Z^7+tZ!xzK&?&UZW2X}c%sHO7>T1IG9PAJuGBgBGHtA@lDD9hmHuO|$iX(-fc^7DP3mS5Q9~+$v{}>q%*ou_sCWd^M@2nhMqAm+'
    '5hQw-1bJGN7l-rdG%E*bm2C$yPFE9rV^>C=8cJU$;KoehhU_#G)23((>lzFY7RpE|(G|6~Y9(f#!$UcB|2&sP2W2rH_tUb|lj4?o'
    'L!{A)My2@qrkT34(fp#nYd&plF=^NL?J(TbRj}b%dX{Zb0oQSIjm(+|SkGb&(#d7IP1VXLVuH)9H1x-&$=1?$Wwzq-+FX!W7k#1h'
    '`Cufxj&stqk{-QjJ~+Q#yGPW|ieg;X3rH$auX4HJ-e^ADvNJUVov)RU{lU;Xb=yD*!~lx>@oo5zzmxx%lXSC7p~=c1wX8BMi>a6w'
    'V`&pG&C7k60&13=N+?*SsjkTysnyi<Xs<D}X_>8A6M>n6o(-KLfO6lMU`3ZK!T$W`{jT&nP`V{+Sy@oa*{uA!ZO52JgOxybV4N5r'
    '-5s1}-sw`20CyK8Qv+WBV}TqkyFT%3yyY$pgI$NfEx0KZ3nd3LyWuaLUVpYl?5<ef)>~dTZ8lAW8V`aUx;(KmpNz6HpKWZa)^gm2'
    'mg6=}^(M0m)+Hnjnk?R!)u{hC@J;H;PD2X=d($%CuB2=o*3@0r1;yujzRk_t^-p6T+77!^7uV}jeNAex+b->C$9bAs6~_<L$(daD'
    '=4Mpq-Zqcu=eoxq1OwClI2-<WT|n;5t`2*CP~Z8a01XMJ&4%>W6yuQ~!47-X7%hfOZy?Rqo%fxgmu5RT6X4LYF8vMG<TvPuJZXzk'
    '<hbfK!WK96jmFum{`D3^U1Y>msIn+;I(mb|4HdB5Fu8^G4EE^;?OGAsXKUv7CNY4I-`2hl*5R-`yt8J@+bvsuo2sxpur=~luFTsh'
    'UJVrY)>+)mirsFTd!=p5_`&%Vp>DS}+UpOmH&mi_k59MP$+j@Pm5L^$bAH+Oo^E%TI=YclJx9$03_NK!ewLXmfr2Oxvr$)U>G5#C'
    '7!D6MycS#fK@K0#mhPUW7y0<=@OFB_M>%x2UuNm~A^(EJK?3=73wrMo`d@3-cstdKHcQ-r!ogP8hLCMqZFQin_>dq<;NPq(+)@gM'
    '4fEc&x4Hy2fhD-YO<r$uz1_rpORm>obl@_|b%KygZjxW5Jiuvg_1x;S?m`_qTLi+#$wA#EE6eL0BE$43&bM_a&V^O}hx6>}v`jCu'
    '$~w)jPs`$BDOc=mSMZ1ZZU}7=Ub*z*V?Mc+?i7SeCM&xBeh9;-6E?4s*t3Hu5tc9{8E#iWvfE&ExN#>z13`r8HaLGInAqa=%kx^j'
    '(eMi~kgsN%w=rzt7fdf^Tdb>fYw8A2q-3pfe3?Nw<2}b-x6RBl3|MICQf$Y<l+`FRUvlEj^$t6%6~&M>R;+u?Let6Q?{pViSh>?x'
    'lW*#1;g<qQwms-H{BtdFXZM1y6L<y%o0}E|WZk@_DYL9Z$aY%g)ec`T=Mm<0y<`r4Kge1r5!sNO<08eWZ?K3PaKQP~@d^%uyc~!b'
    'mCh_-pq6j{vICwr@M8IN#oA1Nu2Xd#Uh6Txn!G~8O?2yq#aO+tTAj@5jnCj{?6fKb5e<sP{>n&+)xxSfj+~X!vrarg9m6uv^z5cl'
    '<GL-r+}zEyzqF3*hIzEcfgIOO{NWm7ahs7ELs-p;ciFR~oZ1z416n8cFgxokWl!gBd^)sGPY;?f<}_B%37R0@8e!Q0nd8zwKg%yN'
    'th~wYZlt)>@!e4HDzt}Aa?muwf2J?L<)WX_&2_7ov)wRc{gr~r8LZxL)(C3^f0M9=FR0cCCYw<Da=k6kr+v5<M{35o!p01$@o)Da'
    'Y<CmfGRW9e`RWC43g$XIq(NDm-LG%sjjNUP>|?jgaNf^%?)}<=eo<M!zISKj*F+4?VcF#E8{B#WSN)ruz8kRqt327CWsjntmDNl&'
    '`Z^?OjGJCre7wG8P_i~E0yQdR<bz*dH~pZfvU+EjvJQUqW@opazImtihKpKevhvAvKD$l_7`X0C`Fw}1Kg_PC*?j=_$4;YSGQa3&'
    'WvgnMRu#;YA3KVr9SjnIn_hoiZ2#-rU6DbM+P&3|^EXg((_-e{HQ;ZyY`)YR|57r*@_>rUhr;c}(oM%lUvJ+v4JyU)mS5EmTGvs+'
    'd-P+I;C9?$V+@<>F<wKCx?#)Nce@a|F_Q*qIs9sW=B5H(uO8R_%a*x)r#C5P+4T(}7`o-q$x64lf_l{~ZSl-?dF6NkWa(YUcGJM^'
    'AoEB}y)9?B>mt=H{n``M0z+NWaN?!IvusJn`Gl9P{Bes5f0;5BZYCVul8)$&;HteUzqn<Vfc75?&%a$70?t)dRxh93%FiMuT|%!G'
    'cvWrK-4L^9Hp`}OdjnvNeca%A{=DqeD^5>Wj#T73m?kJ0s|Z?K<MZ9rAKXIYTTOMNzPHVnyxhm+x)B(m8MHkdxsBm0OTw+-Gw#h='
    'Nmt8j9H-MNJFE-qv}J}`vr%&^&`!4R#HiW9(h|KXq}vozesi&vZ_qUDoD3Sc=bf&Gmc7AvJ($;ORLsB{+w+lnRkkK*ze=6jKm(bs'
    '4!0Qn=_anZ>Dz3IJpT&;p2lLg%JN`{v$_q<mf18*XZv19i1&ar8-Vk2e0{unr;*v|nyYY2jITEsrL*f>I`kTPQ%v64@Ywj_<>+W@'
    'z}+NED0jH1&RV-{Fw$nu&J7p776k1wuVceSi;B(oD3<TduiN&cXNTz;Qx#DZ_G^zN^0Wz=ZZ;V<9EXYf%g>xJ-71B(ZQYOQrmnlr'
    '!Tr$j`?p{t>(^PwuftPsIMn5`cB(+%K6Rq)iDm3w?hx!qGe68{a{j^kqTAE16ttGy$Msqqz3+rS&pGICWLq{>_6-dL%MXfSc6|#t'
    '8b~BG+D*bAg2Oi`1-IZmPBU-|ftjqx#oZ!1zhp;l)3eM@jcje$!aMb3xssl!<?U<nkm>jHjMTUtqI12?tk^Y-*-Eh6RJ49P^iPA&'
    'X2(`9E7x-**;bW<zuRfT8&9JaaBJ&phZAHP7PIY$WV~n%C)%b%e49D~JTQi?a#HvRungl0>%9?GV53GZ)|(l(Kr=E>Hy^KHn0tCw'
    'R<-iw|4et=TF?$tey!83Wk!f)w;ie*GVQNY7LIDxPGU>PR)1~JEm%aJh>3NpU>Q@br$7{PZI*`rb7@zsoXt%p^7+nxxX6Ziy5EpH'
    'HbUXo>yL=QN&30@I6+7Awk<LZq$cb)eJ2Ok&Crh-*z$mUzVppJ^T3flcx2_n`+G%Sj1ticx=<XtmwtCpReKNa7X5BZlb{D+>AyP7'
    'KV`$EpL`keL9}GMvg6V^k=@9#_ia^qzWgwdpu)kX-`8wSVbxT$mQ7Z#7<8HQ*+j{fldaYDBF!ha?5df3*Sk9miVKroYqH_YZn2#%'
    'tfTD!YJp~R)apd-Tdw=1<*ZA1+#3A#H{w~xi!VPOe6F8EtLEh?7~m>RwktH2S6NfE$$cqduE?>j>LRUgTRrlUg$`D#vv5OA-dUy1'
    'WBI`#tEz^HEPPJ5U%njrk&^;H8on*95cO_QOonNBwb^trpJh!hY^qP?`e&_b;{lqM`Ne7?`a73x>&r~%Xq=|gOeMHl1Ll6ZTeOke'
    'dQ6v^eT@MdbYre-$qvl|qTOyVP3>{;wOP!YK~1w6q{lS)WiKe<vR}`aap=j3H3Q=Fa%{t)rVkALxQse6;!k5j*IG;U+k8M^$4L#w'
    'ZR0B~FVkjzLA>2C)PwdC9CW$0+BLFGXKNzT!DlmIS2A9!^U;^*t2He<wG%t8XFsfS+P;|5R&Pg;dFOVPh<?+C8lBo(;u7P$n$@QI'
    '_8e}%fg5M#w1HE-xLkYeXGO}ZOJw>tla2fuWk6K7a_@)RT#jFb3=xo_Ub9ZtG+(!R4V0N4tTw7jMI#!tgYv#27QUR?_!3rWD7Q)i'
    'YeIR=`O`k>G99<BrK4XCFdOBQ^~D`M@+ss@`|cVPxGl6<Gp;7sw<1OZ6I+*G`#ZiqMzz!szLIG+b%cg)JiHv~oOt;6tK+VkP#50d'
    'ziY8S2;zh0P6F3ZnXGR0W`9$ZYiiCtd&MD*&a{;Q;G4D!z(=WQqGkP*?$LUEbs=ao`m9=(=wM3?Itm+60^4eF7CZuMxvP9g-ez^S'
    'k~FsE)|`jlB&)|~O?J`j?whFH2F-ljmT9xvu$o9)?C8}tn$BU7<Qw~IG*>fG|CT4~rKU&gHpoTW{<FxfC)EK6n67}*OAJq2wp$~o'
    'vsU4*SG2VOKUiu5O4L2K#);J!x{|MVde7U2Ry&7mZKC1YZf2wF+bIX@kMFK;k$$KzBZQ0&wz|EV(k!kaus-QsduR{r{>}Q#!M5jS'
    'Hyq?<b_-8qWoyYDU!6?X0*<?Onww<vZ5Y(S3Kn!WZmNz;;jqh#BOu+x?I8HvoOj~})ts$^fuDP`^X~cejf$J}sIG6+eAs7jy$c*0'
    'o>=y;pEABXNK)5N6&&ecR$XsMFMpNG0%BT6EUMm=N?;_1WXM}m{p<OgVq0K$e*IT!1?yQaTY>=VyItQ)%M036)o<3H5Rsl&Ux52c'
    'W7zbFH+{S|H?>Lu-oRV6SC?vT7Nud5t_cNy`}6J1P)n@>h#b2ekJ>Wd=Ax}&PV?YyxnesP)9c2YLqOL0Tn2RT-&on?a=%JXvo4Y`'
    'x^(dv5<W2IOY!LoqW4P%>Q^2$-Z-jTr?aa!s%e&JuD5QprHS6!Ix9Z)hGlwoeJf*UxpSb?Fs(*QtE%{9EmK;yznY^>Wp%2JePj|~'
    '8jtccX<<XhTIYN%|F^%Ev!|Qe$g8>`W1!7ZKAYjqhscRle51tHIoDW{;b2B8g!PvAMu}}6k{h=6bFe8%lC`ML+N&oTtZDgXhb^dJ'
    '*nn<+T5QX;uHB-+-<lxY^?=7JMKZ3RxT^i$mmjyh#{^hmm1q5Q-|palz2IQ=R3_Y?tvibAJDS2|xLrbu7n=7Uks;jh=vnI^Uo^UJ'
    'Lr9w>v!N<C4znw(rIs+wuA6R^z*z8u;^x;|G>^2I$iGXm{L-5&zGw@p1k^nujCIS1)%LLI`Yu<lQ-u<OP)Li;R1L@1d~%wVc)Qv*'
    'pCx^~?V*AP%dzuGouI!N^HN{%YOILsqFjzNuUOk0*P>a$*x6OnkKf9#{hK81Z-%m#oY*!-sgg!*e{xT)<okxn=nqDXPVo3&ubu#6'
    'ptBR$mmd$dnWLMrY51vIKG3zf8_x-BNj%=bYNLtG&#t#RUDjm44tO=R3I@N-l(i3O)vQ74?G`ZLa$65MhkemUPWJL;cTd~Hvk{rG'
    '>diF)^x0I_&;HcuOk3WG!>oYSg)B$HYO0+$8^+VkcGJp3GcIIc1HfL~(CQrba<t}C@z-D2Ml`NnOPo!;`yKW6l^5$@O<MEvd#x*V'
    '+R=gQtwF+{>+;`Z#v4!cHq<My)CR!s^yDTrNB6H4+VmPNp=&bMb@Jx(#+JRF^wo2h$_b!$y?F<1`Ojw|m))&#+Rw(DgVrob8Vff$'
    'R%_ek>}<RikKBlD$Dziy4K;Lb8?bDLLzkhi?Ez@vq`wqctpd^Ej)z@wkF95Vmfc`B)CnDO*K6_D$twK1nwSUP0*Hq4y5dM*h@3~C'
    'w}hd=Mr!S{$!PSmewP07qt&(Wj){ZMpO^9dW`MsGt3>$ZY@AkVr|dnzYoC^t*SCr4uO)%S_HbnYXT#HYjafF{;CbT<JR7g<+<2s*'
    'xyN>_zkU@>ql2~Ujijwky)qR|I2(_zx5@l1>MY;o$+w&EPdk9_uD!ow{TV^^l=C4$BIqxX6z>c@hed^=<;TASJ;}!Y1}}!Hm5G)B'
    'P(5R3wyzs{A+oPquZ^=aC;p60o#%sdQIC0{$@(*0s|37_hlp0M>bn~|Nze~I*GGhU(@2-`wmpIru7b$qj;oZiQ|~myYd=<#Y2>WV'
    '0CdvCG*|Qf*KgZxY&%M#zP((@yyB?3b;L$DF%vBM;x=kZa{Ea**z%x67zU0zXgOk&ZGL7h$w>Le6rS&g!Rh*&M*`Qc7a#VsP{{ZT'
    'sk}k`fDrvKw}dJm<NNY^8qMbG@Tq?50qmDq+X6S&+<bI!?Rf&v>vKN%*ESw+ytT8V9Tj%Jo{EN!;(e7(YmVbKrqP!|H6}^DG_Y6B'
    'wE9X<^X=kg>ziCKpcSpW!AfuQGkqayE3-)_n|60Ry|^>l*}4wfN!@TWNYR+OemU9KJoJdSk8PWT&bu?%jg5|d`M&I|TF{Oc*(~2V'
    'yZ(L`eVOKPxaDOZcRkzpg}T-W^lRA<UvRqZ6&lz%-oBXkcfK7WUcDS5-nH>M(hv;YEZp$dub6VO{at4(0A^>|WVq|?0)|kOLfrND'
    '0n~=VI;s6UNJkAwH&ZshxcPPx=S{pkFhtlGo8OcV?6|FG+c{Rpi8j&B(Y<>b^oOC_?D8?4t-nw!?Z;W%>_bmbdmcL;B*UZSy9$4i'
    'U*OI8>15V;Yhj~u!{yVQe&Z=qe~=8KU<m|1Ke(NG{J2Fu4SP~`kaez*Y`<fbRR&wrtluBnTWRYHH%?YarG4!!Q#-itE=6diO?f8H'
    'VwgHLf-ZkC;IE9aHlKvx@oGUg?Azu!k+0HYJYgieWmUj~)=%>^Jn<XHYAIKN8zynE)N8tsDYtz%v3}o7w2EQY8w(q{(po&+iQI78'
    'gQKAr2d%epZK^5DDK|2{2~5}iqB=GlWKpe4Vjg|jz?v*Fx}qm4uB$W0U&-$q5#5?y3`W`D{8r2<T6=(dsV5J^%s$<GsHUEL+r#Qj'
    '<ykxFi8o#oUO#sfMExZF5^frt`qCTfoow4Z_kBC)uNj(6oh;dzZE>T5+VHQeupT??)-R;raFKZJ=Smzu*zq(|jn>K5iECHp*S`<`'
    'X#H8y+fj-uq&{q5ba)zVJn?_y8_70bfVulv+tOfLCRuw>^X(n@H4^X3B*ba*37C9QUTt1e(2PafD_$)_HiMqGu%+!4D>iay$HO7|'
    'T8Q0`)TW}_51U(AzGv}n76@JszKFFde-Y4Gg3J-VbGo)8L%!+KSJ}4s{B5s`xGVNj=w~-PiJxq+?YOnnrtjib?|s^upVFGt>R+!T'
    'V-uIxdn-zPi4WKC3*vs7tO4u>Q^aZhOo{rSR%59ZwN>bP88;47fAbv_7%Q`hR=+jdC-_q6e2Lu4NmN=lQ8L>0=q>EbLE!J^AWc?K'
    '+YJ8D$%1XTRu%JdkZoa^;ijl}+hdk5n1G%WXQ#^JhS{Jf)8+f5Z&=ex4aZp@Cr8Rk0KE08SOwK!oaPrRE=95Cu3(c!QQwO<42<?;'
    'VvcXG-ZmYlNgS<NPwNjV(~2*O+26vyXW#hCKkzFi_UZOi>RQLGC3qG)Vm5rW+TtSw0sqXry1L!#)9_NX(C!Zhe}}iC*^RfNdCPtM'
    'pl*gA+wqCIwar!<c%CJvw!szlYssj1m^ytU%BJ~blGU$=_nPlBYrILMfmfbG!*z8nYrd?_DE#UTmSu|NtX^DM`nDBO-%jznXW8e*'
    '>n63=^{i;bD9Qp3$bB!w`_1r@$z2a0F1<##aTM`svX+0Xp&BI{Puwnjs9Ro7yWK17#4Z16>k7A=Aq+IgwB6PJH6DF;Y3%O=#f~5R'
    'G836Ny!*=oYb}IT+oDarW8X-oORk~sy_HkdugTiL>G~e(XkNowUOI)F7Id`k?`d22jYzv|H*RU^1g{+<jYmqQWPaL@x#V}gsV>hf'
    '{lUIHd(TqrV37mv?`<%Sy$5$J>ziSATA?7t>gu9jjP)tiGenh(Jqy1I_^|jS6G40T<-a}cE&a_)83)qpxqH^&N<Yi{dv3C4;dfQ;'
    '?*U}k0)8Lm{+{`Hyt<-m_Urciy?e`Pr|E2D$sS&LuH~g}BKU7nyOjS2@s5d4x6f*s)S>%(y|}T&4Lf)11<bGcG}h2x`deSd*|v4Z'
    'wS50~o;UI@yCMDrBTxQ}-L7ZJsV?y~LVY5C90!dtO7Tz2<!ex_PLKp!m-1z)kr&<!45tO+#`%47ekbDj{oV=ynC9MtR%bS|d(aCx'
    '!0W~95HsrtsuH1yX7?1&r0()eK8E=v@hqKA6%93Yo^?W;2FI4&_;B^!gKt2XtRQke0M0-7W?p61sLW1f12x*puDOu>l@Sjx&x3FJ'
    '>pxNX&Aq-%0g3bA>614nZ;#(UKYnRFfBpW+%a_leK6(A<iS_^ezt->Eo-OmRn;Zi(@vrXC{JxMr*{#o>j??*MFcL5c2dQN5vx$hc'
    'J&Vs>?rDGd26xZ>y*J2Id1D?4w~n7%k7R}=$!<n%1RW-WaXvW5k8@6j#m8Pf7z6*|AGTC7mb-tj_uw!8+kfT?&yL^A$+?dQ&HXn6'
    '*BJ8^CwPaU)>&4Z$sR}fz~U@7oMY{sD*hny`omUi>{K@V-~G?lyW^8*@2%taFON@_n{MOA>c{&8A?RmmRM(q^#=1ulgnVq#u%xa4'
    'mC(66D#o&z`+FxGqjgos;%|xM6OlRcrAqnZr7WM0!CcWpGywtIU;gbsTh{)gSvmgA2@Wa1UT)7=-+Nndr|!aJ-W6LVk{i&YY0q?e'
    'oz0d|mok3j)Y4r1y$5f;{r2Va*G~+-e`%&~vus!`=X#l6X4WaHERFu{J^1#?lgB5Peaq=yzFN)o$~u|Nhk1b?k)5cXx%U9I@4tKe'
    '{EhXOfB$c9IqBQ0<)m+~W+TDTaz4QuUH2Zm{ll(#Fmyf}>^<mq5BcBs&0b5`tLV&1mM5vXs5BqrmgGC@Q_YG3DoLSnqxJ7DHTe<h'
    'xZAxY&uLH=S_k8z%9clZgm0Gg%Vf<z|NDv_6-k;)LA<Z9hr8nbpfhPF{N7N_G1Z)A{TYv=6%U#X#bu+Rjf(ZpQtWLYs=1=ke5g0H'
    '`mr4$)PMU=x9QHG!qMKj%%5*12J=fSD{?S!<PV_<e%{~vsVFX<uNctx@>LY{y$8S9;A-tLZ|1Z1ph7Ah{N=y-AKQ#&+mfT=BKw_a'
    'Ld)^*GO@X+9Dz;!*Eg&@xDw&{su-^B{^Vmm1D7d_KPrJ(`}{Fv>z?)GPjgyl>Evua7Q5q~^$IV7ofRec_rL!SU*2goDpsdFNrkfC'
    'zJ6*|gHr5SwmtaEfB(O%andcfu>28=z3m)}uae*1Hp{1b>v*g`o3OpVNjo+KX7FZwb}Q-5MMlo1V3)e)bkja$gD%JN68TjAYs*C?'
    't3H4I9BRPxljj0A!&a>)$M4=hvtGS<{N$zZ`nEPeega}-3HC#+$C%eouPZZr8}bUj8`~Vt_DqlAY@MoBm%S#HS9d=fKTHSb%i9;s'
    'cC1k`m$m-#AOG)NsMDHFkTP%2_*U$mdQ-50WUl}Hf0h4kHC=nEZ$A!~d;865Xa8kmD$PnWi<T)Ym2dR-z^%)4JkOwWKXAY`wRWS`'
    'mS%f*dnoPU4eg#S9pujqE5zu6zc<Vha+>g_K3!}@?y0?-dkTPCgZ8X=NvZvpfB%ox)55}+O_(;sENssDPV>oWvDDMnLr+U#cJnNi'
    'u$kev<Ma$V=Ko~z>sGnjA_AkaHRRH)C9qb+r8EWOfmQlr@%Qo1dUDavhQn-VL9I(C0B!B8+!sZd&otl}5(~c!!rzB~#79&icn{1R'
    '`pfWxGM~;G+TuOIc42XPz;e)?3hLke#l3k|-s|U+d)egDno=+E?(FUD-C5&6)}?C+{aWLKFTpDF;aO(wt0L2Z)`ra9p*7CMvMH}b'
    'sUKe*+>yin+PWul;nUSW&dc%rZ$`7(v^u<Zuh;865a2y}^X{a3Dx6%jHAs-tqO`^<<!%4?@k#e#$9n(rNv)Y$coRq^!w+=s@x?tF'
    'jt{K$e|Q1*Y*ZHWvyn9u99rse`(n7IqQP3&jO@j6qn<7Qa}FKX^AAMw4#qv}<m3qq&MdtUR<3J_iZm7zb<02Od6HEXM4*U0;qXJN'
    'f5qDodr(JPJO5Q#c`4UR2V`$FyBJ&hd}UWIHqYb?rf60j)c2iN0wpN-ckVodXB1~!o`7KQ$&~NrlS8Y%POCWkpcmGgUfp>zxs;|i'
    'Pd~hU^X~oqIEo`nfTP;%hwt9KyuTGJ9P#M*(X%HX-oJl&Kj8P{moMM^{=?gM&wqFP{>gotXrnnIgl&%pD+N1>!Fe{TzX>7;mh{T('
    'PxGvrEx%9GvdWg<_&`oQSs{kWA1mM)Bv3tH$I9W65_3eFFQfseUfsEab6NKVoU{F+>IqusWijcUWwZS~bLzd0wTFZ69UR;dytr?z'
    '_iMrfowtHy@1R#AZZh59ySI06N5Has)g|OGTYz<2u-meQb?{=Ky$1@nL|EK;_T-%z1?=w)^Kv5ev0r~r`xQR-KYRf8eE1*>atku#'
    '`tzM{fB*QyvnR)opS(Mfiv7Ju>J;z37XV_N<GJ8Xng2xRF)HB9n+&hI=``=2XIFCCJ9mVNti1Xl^7RrP;!#n}4i3o@XXVx5of^48'
    '(qPH*$J`svhkHXUhjpyi#UwjejlsWs3TW0B+{>pQOmQFMe(-<%!T#}}Jwo;~?X9+CVP#f~i(-mcLZc?1oPSVOwycxMfuY0pKJc&1'
    'X7h4ly)Wk(+p<rCOjzp^e!u~FXID@2{o8b0Wdbt_8ta)*_c$x}8#K~;m{!@d_wV1nQ>rjs3{14o2fXM6@<1@4c85G9S>JPe_TC+K'
    '#jS`+`Qbt!B}UXfUR5jR{e=Me*CGq629yO%f~<Q#C~Npp?irnX2FxFT+LN>W1CF+SX>s&wkwH;boV_t4$5+{8_(84F{k>y8qt^w3'
    'mBqMwjMqkW-;}usW#HAX_YS^x@T*L4Q%p1&{q)KE&f7O9?>leaz867t^7WHFV`KF*xAIo;tZQ5sm}Mpxzt?~gCjsj+7lF4(bgZKP'
    '#|G5+f{^=UaJ}LDVp{E^UAO@{?{C|c+|RU_RM|dy92{v2FXW~(tW&v2rg1(Xjo-uKd$$?<GMk*uM!=O>xj)V(``G=#!P?N(NZFFv'
    '-$!tw-p4W*X2C%#C<%}FD9VF@kw^gH=e*|oxMNui{qL_a2{S)9+TM3~^yBzUHn?}VB95oUY?NM*I6k-d(Fn|_!35hBe<@RP$7Tic'
    '<Ix7M5h-dq{4n}ahFmt7z@OxMTg>$gVej*F&~)$PP|JhrN2i|hzWH3O+G48shnEtpFCt&*8<p=WD~tK;zT?^lmMEm<CS%)zQe{s)'
    'a68cI*63BXz;`3^6@yuZ7ivJ++B?{>Rtu$eC{lMVu+V!>&$j5C>JG(Ry%2;OTK69qZLWf5x3R>>ksv48_9l?<Z!nrq&gD`|0d+cb'
    '_QN3X!h@|{1vSKw&=H3g-#vb3yVkcx6dci}mecXP8a1GA1W!{(>fy*wP{JLrZ6A0hyUw`lwOibB_gU`-hH|T0&u+f;h8c3OW#%uj'
    '4IF0!7)vR<<@_L;#-_=L1KaHg%OLQCTY!&c2cO%!*%0uwCRPk<SbQ)tXSWDkLe;hXHb{@QoVGQ$FunD8=PQmvMH!^d0y|RaTOC1A'
    'aLy`fi^gu*YlFsUCTqZPZ5zNT&IK}{2Dvlnl})ayDo0l>KU}I&OV9_bR%*r<6-_Ovdim<}&VA7?T-(-6)QoJlepvqf@TY2j-V;Vw'
    'UL7cUNgrA6hrPWY4@4Vm%`@EzFI{1Sor@+m7-bh3iC4tKK9&Aj`L9It779b#v<ICPP}!*{t^w6opw<|-*H4Go+urAmO<?}EVE{w0'
    'p=GZYKe+wsUTbwT)xD)stN^J*!OJWrr3t&-hckG?!gCJR_dLpRS2QhnB|CtNZa4`<QV)NGg?CXa*JgcViCuIn*(BJxm6C4aNLa-A'
    'aXZc31i&WW!5r?IwXq?OzbN??HY*W-3$;a*_FrF*4qNI7w2f^_4B)&)Z6Vx8)-QzMT9EntdGq|YRw=@r8bw3ult$_tS%VqB{!E2n'
    'V-2F)4+>6bUi%HS5*2%<`qjbT3!?_JuTh6K6lU)2U@Jm?QRMv`9iY8EvILd$Ev_)1D!8dZS-%|aiN&Ygz91TJx8iMtu2SEou;}q6'
    '8x@dqe-947y@TDNtTrWHzOsH}#{b|Q{wQDe_x^E@b(A1Fy%sYu&aJ(sMsk;7=zO5Qw}xUr26^kQ#w*_sM8n?7eYdwVu_^18UYbc!'
    'UeGO5SNyTaC;M>abTIcpOHxwStQ{X+mx8FCB(Jc`eX0Prk@3Fmx2_&@ox+vaWbTHBN&1*sD75Uu<JDFqZ$nbIH%XUHyx!RyE(nzM'
    'T#yq0@-4W;-<cGfdK#P$e;Y;Zi#R?pzQqj=zj->k2?bd8!PioWjKz^^Pf*Fj^TsC!+W`D!bgErmC-h+LHyy#f_ajW5PtIQDpPo-T'
    'O_wnlnvOAW7^c}pG5Ij#7#RI@vE8{N5d81~`p}0DR4PAwK;ZJj2cuRRAJ=*;!-Ow{du@1je>t?Q{Z+7_`@s5TbpUR-56^K&6j}p{'
    'mI7eTx4*ZXNPvg|B9Lldo}TT4z&=CYgQhF-MRwIM<VN_Wi*i1lHQaQtJifW7;hfvVb^e%Mrh5<W-Lq~L!TGK9wjAd-9qYG`Uod{a'
    'PLo2AT!?>|O$K>Z9o)HhPyUnb?2hK#9LzDJcgAaeZn&n?vg>t`oq?KmoW}J2+r(uu3qC;9YdU&SUKyCZn~OD3Ny|9ngZL(%XK7a5'
    '!J({#E3?`LRu6R;zAavJi-1iXI~f!gy=p$`O|n^!_hkr7S;*0sx=B$){Rr<pyG>uEgJn;gp_doE=Wmw!!e$#1+)j9h8*OjqvmK3C'
    '`?>r%R&Vw8#uKueon5|r_k3IB%f}h?o^rE|916#LG{*Z`Zs=fi{u_I!yj<%dhsNVTVt(~bOicBWey=url0Sb7G~ChlRw(U;rnO;I'
    'qaV-p5tw$<e3p-UuhQw3+CecH%uD=`M(@d|Y%mwhmwE3@=Yq}y4Xv-CwsoyhjatQ;2s;usZJEFwc;K1f6Q!nn*+1diejx4eYFXO;'
    'Z_3BY6}H9njy9)1VKBpDu<z#SZXNo|m{fT@9*e;K&3}cid)rp-7sWVBC)RqrZ_nB536iAaYVCZRk-x1cTA`t;?Drcrf@vQg&T~YG'
    '*Q{KT{0LpV%aln~`;9?$W$*Qycdw3L9`sDY<9jvw_G`@O6{jbBlUKFx1P2GbK33Y_4fP*>gqcb|{Z|JXKOd>WWw6Q2ep%#03vzyc'
    'xdNk876i!0s$ra5FHgVXPF7`rrC)mk;Vz=y3Cyewrm^4PF}R?Y#%WSFA1tN3Z2&+Zh^U{{#IV1l3S7&hbTG<>s`|VY)Yw00jnlml'
    'OrHc9Yu8;z^aQ9PYQ25xSoG8FUH{8oasDrRhlo0L{)L`8`SvgCt~!YLf7z1`##6^WZqH_2?W<!Y3?%A=d;hZcdGF?}srRn4M%#yn'
    'tiN$2)Z5K*<BJ;yZ5g510RGp8JyhxaMwOv2!QmeD!SQ6LMo4w&V5?#X*pNdBbk<eG72FPLCh+-AlOBk%G>4iJRc`g5iJ~T=1(Q)U'
    '4nenCNIYAbC9CikaO^e#*4quaF|2yKDcZr*+l|>7Lfr{OlE4}eI}{)4(=eQ#5yqMyG}Mm<xOp9N1FN0(uV$I>lD@zn<8cEIrAj#T'
    'nkepl_x{@tabx6;>(Y~dIq=$=2&UEgOnSC{Z%iYv(O;|(Yrm-`S;YqSJe0EtpRum3qK?0cefxO}gll0nEi-*0U=v+$1gThKLRtoG'
    'YVlTYh8mILne3*C_^sR61p*g#X4laU4DZ28H&!i>W(Abb>-iX`$iLW$QnfX_fmH^V7_wc026-+wLjiZvK3qd3>>0sqm3<?I>V}5U'
    '7R|I4OS1UE_CRBAc7tGcZIR5i1Ek?+?rillHxR0hksHw}%;*r}d;Pk|SGC7w1K~7zWr_Y$_bq;4a(}e8LX9k!a7<6;<FWM*|6uI{'
    'w$@@{{bE$(PMdasHD$j()~I7$u1))SJ@Bxv*Cm7Kt7+YXP{muQ71ap7l;RYmeq5I6RU2cKdgulbo~8VNP9wSvWoAU{*7ng<@V{vo'
    'I1j86moEAmQG8!U8||sn8pF*QzX7(^n4+aHY-eL%%aE3yd1>eGf&LD;yz8*<73C8-@%~Mr`;9$pBjh^6;1SbXs5z}+hFHA}hHKou'
    'm5E6!yIPOLSo;kKAufV&L!TFSWVN~De72iEZlGu_5ay>c2nr%Ad^-t$Jfh5*9PLOY*xy%=ox0Ct0-67T92HDh^bo^_=cjV~jx~{8'
    'qSl1_kJj*b_3g7Ia374U{T18E*7r^Bv(gmld55M*2i;Q3Q`+q@Yx~XVezr7d_C@srm-yA*!BP)A+O}|hHYrN1-rV0V7E7h@X9$y('
    'Ad>C}hMhMwJLN!sTIWE*Kb8BuOF#Y-eEcnSPzNm|&0s%AtyTY2bESh8D?GmxUihb8CFn0i^bdmX?0tS|ytlun_ZFTpG%e>}c@%m>'
    'esaXTZxZa_!uq0qfpzK$4Z{SVG<B`@jp8cTCp~twSL{HQV2LPxZBncd#RRGi4jAA!u6t9^HOwU|r7hnwpB`SlMwV(ryqSP88lMTP'
    '-r#OH_%GVFGbBaY%c~7r3<pNTiO|+dI5{_3UgneY?JdWXt9HXye$W7xw+^hoDz4rJ@z+uR7q1X013T}qR(>$Pj!;uw+O2|*FaGwF'
    'EGWUy$tD?Z5UyaPbTpw0rExg3Al#Nj<$-za&)Y0uscZbBRmTF`?T0HL&N^tQ18Q{S3wrHNu&vD1zZ)Z*?qq}tp*BOAF10K$0}kH1'
    '*9c>-dSkSOpLUimbR25vNtA+Faco|`VD11h&UBprlr>l5c*s!9A(BQ$Tq2oebz#oIj-g}#r%euqIY_s^pzBkJ_g%(^3kllOb*|>G'
    'lf*JWwUZ_cG~rK?J)f!?JI=_vaO4w{8ok=(t91H}*49?T14c7txHO3d2flkTUgp5nU;bDvtKd=9*bb`j8|rn7DbrNkW<E;YbaIA|'
    '{31Qe?wK#uWus2M{N|Iaxk*m40)(KPt!I8VQxKvj;^QB+a&<@iikFBy2abr=@T=ahKxd9p&Q?2Guc)OwpEmZesl0xT;tB}2-M4a>'
    'o0ChwXlc{4_IEL~KR2Rybr|o#onPT`P<{Q@ua55A`?Ws8_1FHxk~_kGPhLHI^7!$S$IC}SpFVl>`1t)XhP)It<N^+R^IKw-wLdN<'
    'opCx7C1sqR^R)r_g+TW-$0JUB<pJIrkk4|orFn_yK-I%!PcDV4;)m1DtbR5wJ~H}-a2g*&=aWnt6=Njr2qDLbc?p0tO|op54LQ*x'
    'JZr1lfh-kHDCHsEichZ4olo(wRmB0;X_*dY>DUsq9g3L?e<vsTn}F5&^}RbnBx0os&_298eoeRbohM>|S9yB)uic>Mcf7FYSltMv'
    'sOMVUxR;=0Tiv7=biBA1p)T(D4r;uP@1ZS{HYrJ)hc>SlSY1a;K1y!K57Ey>zo_R~T_2?wb&i%Il){dmNXf<kS<gaEVD}QslbXPh'
    '$uKUEX{-PROdsJRv|@DiWkMFDRSGf&TX$?!MKZCJyiO2GV<P90?lGzo9q3?pQt~awmru(H^?PVJI5AsXTkB%Wb+C$lMwZK^0?YN#'
    'F5i7Dgp*21W{WYFZHYkD<!5NQF+Ky!vpXSvhgaG|8?%J?#0az}vWB)`HJLZW`Lzy^mf1r5m36`Zv-)yyDJ9sId`9RiZ9e+i7=sgG'
    '7Ws@YA9Bv6<m&2j+6W~Fr9^iqtuam!0V<)MRZ2d9=?T1WvQS}|04_dCp{a9F#}Q7?!7Pcn62Jgx#VXG4SfPG*^nw!^AM|Y97z?gk'
    'c<6DMo<zW+XXE{aq3$M(aJK@-Snp42fLXl1$OdF1LK>??vMt<2<XE1Adf)Oq^q0>NpN{1_m@(w10KoEMtmJW}Q07JdP*&6$V2X!r'
    'qQ>mbx3wjb5^lw_d>><6e#ZD7;3P5nCc6K?)9*p3pP`N2$R~H@%BP;ow?bfOgr6IUKs*tsG6Fp0PmB^<O&#ZoxKnA16cSN_zP=R`'
    'LZm2u##Ssngka<wpl!<s$p#o6DN)6!!}YrC;{eekK>@+C$m7j;bs^@Sq>upIj=+t(b_6Kco8<(ysgc7*Kuhxx>d_tUFC-4dEXZUD'
    '$T|#(v5^vi6MLWv>28oCs<A{4OagM`#8MFKjeL+mz_mjBCa57)AP}h-1tIW|n+iBf5R?B%L9Sm|6AH?hoPd}cu!+n-Is>KkOrgVB'
    '1&{Tcj=*vr53l6rd!|Ovhy2R%$af;G0gJND1_UJom)~WKO-TANyZQA%AJ^!3!c<)r92C%Gqu}8-z=XkI<c2yPw;**80(Bu^KQMZa'
    'EYTIhM=@YgYPBwgv_M@TXy_3=$eGNXU`-w&>$+g_<TtLPMY&RkQidHIZbVKdyeER>0YXt2VIwx`A~R8dB3O<C`4w^+4_kKFllyeF'
    'nE-IXkvxZ+V^L4;cHG1?2OXD~C8Pb08<~x{f!UZ#DM0}tTpfGF!Cb<U*pJgmkrVNX9b6ao!lH{>>0k>_G97GT0VsmT07jfpir@)O'
    '!n&a2@W3_%n-g-h*KtT!Qj|KK2#nkT6VpKiyd8AN2!(3n4i9O2a&U+6x52a>g2Tp+g^{8N!RUCL#}>}Zg%Ze3Fj|zb3>)1JvD*f)'
    'BA$z4ip$`dL)OVu9UlN-$u--NNw@@{=CBoGUCIc|7jP^IT>8nX!Vjb|0l08QQt+{l1O(|g+Ms(ChTU-}?18He_;dnk>_9dqzSg-Y'
    'Nk4Glgqr|(5*J$pS|mUa-fY4vbgekSJ&`Z+>SAyJ*9N}?-dVASnSrLU%bP+U0Lclo#QizKadEfg*@@nTXGJlAnFw3%;mV{J@6d_@'
    '?d*baOG&!&0x@O8<pO2%f-Lfht>H7o7Fk1-69M4pu|fcn$D+V+0q~Fq4IoT>;I)*X2)dy6kcWg|2Ny+2#E*-cLMceJ4H}P9Nf0XG'
    '1ndo>1as_wfmne9>hi3BD?`EYA-;qPU6gE;Y?K1DieOB1Bu99dtsV=eBx<3JItQiD?1v>Fn}|^Pbg&O!$yV62XGY2(GcwfH1SOKU'
    '%mGExg&>3|P{;(aQf7dY64o3^=m+3<(4w%GBPE=egeqL!3G{4&BBH~FN>@HfEw+5GCORKC=LF^xh~twW<642>+F*-{dY;~*1-)E$'
    'Z9!*O_zUw30W(oe2*m)ZiH90#^U#JlJz@xMz{6d7z%P$H8l>m})1<+{Y;r3eK84qM=pTS@0y9KK^2~}c*e_QKQNl|2lsR2BEIgZ%'
    '0*Y9otXd^XgilwQyc?>xa8aUMa8R;UKDoY13b~jFB~h@!y(maroW=vjfGJ}(s^7NCA*o|2F|DDF;C_6l$dT@uDz^56y6S-%U0dar'
    'utf+%pWKx)6O4fBr4Qvv6iymHR6%{RF7A^hK-f2`vCKh{<Qqv0O!OTpH7bckaz#cwhI*<9O1RmNtiv4&T2VCGtRbfl6fRH%6fRgr'
    ';Rw->RUkiQU5hfwS5}K2xL4YCAQNNK#Z<_B2szFNy!EuRTx*Y-gv<nc(AJg3kfX@OZfs*Q8fhKE0(2Asy1rVQ(Z6=?9G{l?KrGM('
    'I(jv;@O+ZDq8^!&3`&UfU^Y%dZJa~`a)^{A`cNqx>fIzI5*PV0B&?6?p@;-2V#~f^u7RU+GzODmj{x>XLY3U|LG+xIJVXiCuBo)^'
    'P`Q^0x}a(xVyElt_To-ARC@J0-PrUZ$0u2L@q$vAL|w<&3Mj&K6EmVq_5uY=iogTXWmj1Npwa~}v_Q+H3#$ecok)>n=yCul-syBb'
    '8y07m)Gq2?*8_B@#C1Iw@h%F!5(f+D?AM5nB27b=BWW8Zm`x34T?YJ)iyK<#x~g!pNRu$;x!k%K)COEv6&jFDR}~tdTQ@<ge1>L#'
    'Pa7VmLZQ>O`CaapwLnf15~N~>T%X@!`VSyKRGo0BoH$ljbZFovZZ}fr1V~o>8gOAGXs0>{cy_s`m|hN#3KdFJKe|vefN$`7MCA8$'
    'ZBTs+S#W{07(gK{H9%|hQBi4TC-2rJDJ;7bLeNd5B*gB(4?|`w`=s72E0QUL8F#6Ev*c=>heHBOEW74;o-({Zzl%bH4=@Au{WuOj'
    '9c2?_;|^zV*#r77*6?VhKujch>mIe>K*fn~5eTYaQ_=Q-P99VdL0~H6uKF@KgUgxd)9^rrZltrg9Ge&cLeW<XDKJy1_JxnUF3Q>H'
    '_##toB9M*M7?e_|Hg=b`m$@%6*2rNktWKME1`9tS=)FL#>@I8~Xh|sf^=OCIa~H<1&YZ-oNFuebyNM6OwVTktfCiV}V`JlY<G@T6'
    'yC_JH7)}QH2w}^jAySjIo7n2<!JPDjNI~5soL8+(%p8Pf=71L-L*xW7gRqDgi`|Is7Qn9?(W!;H2-a$s8fOrr!7RcWn#kRV7Hc=6'
    '{n`zUJ=+cGmI4C$>Y<XZp>c(ELt3c7xNg9?fuJ;!UDTLuz@j!&)P+c$f88)qcOmxVz?zM*w7LreuIZwfU>{3&VhHBw18;RxG=i}y'
    'KVVM>g^=s|A(yjNR-+gAlkc<HNODX~i5S=OL4tQf3hbcXuD{xvPjK1B9U4(6x;z4yx)g0~c2;$I9geCKGI>Oe#vucuvJtXCvsenC'
    'XP!C=)Fq34PzYEPfkeZ)QMp*CR(r%NO;mvsR8ZpW#<r??@b)@NOaW`DB>F5;!;V=r$}{>ps%@hft6C0}iwy6IU2-fbU{0VV#*(%K'
    'v&jksXO%mkm}oO-##YteA=S7L@!iBz{uhy?ToPtNWt{*>XsLjGp-3e-V3B$;3Py!D%>=62g*p|rcPcAt8S1Q59+aGoA|7#jA%-O^'
    '`sCs~2zByqZ5K*G%}FiBX3jWP!!uwpQESxnCBu#bEh^+F8M|sz`mBTYP7@r(h(ad@#t=-gL%T61sfSv}OXn%0h*on%>W3livxE`2'
    'Ak-*AB%Nq^u`&4v#(8G-gqw6b1VJ3so4^&o0c@b*P&6g9d`S$6TPtONu?-+NyaXN>9XO15<k*fHQ&OsL1Kto^ot6l0@M$|#bCo?}'
    'HBLE0qNXRfwBr~&aj0athKKvTNaYO6u^OITM+LCTcdG4FWV#N+2Q&`r**&cdh-Aj!qXM7miW};DFbHdb9;ngF`Ka1ET8>m2LRvX6'
    'z&%g*l_>FIeqgN{U0vh2(tXt~F!XmpC(tt~t!iV1Whm=fqDJqjJX0=++6XL^eLa+1omseFqVooZFFS}|7<ov>?odY7k(n<1ieUDR'
    'XRG{ST`i{Q$&6KtifZS77j8?sT%`mdhtEi39^Iu|R7ya|K&5iv>1fLD$Os*JXh}x&-5TY~*Z56fY6Bf_A{t#fcU9(xCIZ7Th%lh!'
    '7%@yOLQ0}(oD}n>rqQ4)uoOa{44B46S6w!Us~HmnBEki&xMcjEnj9$7bw|lynnSV++sGtS@U>q^!KQ13v{xVi-Fhzq3gR$*)uaOf'
    'lZ=7888D|u2JI9*l*%@}aOi1wc*FErbY<&)s2{$n++8(!NbMffe{_biLWp}*|9SBq<W-k<qc%!X_XI#Zo!-+)9CS)(8gYQ&1gr&F'
    'i#ATzhi!x4Ayy`N_^<#%ZZm@EAtkj6h%U6|V3~9gDKyqiH{gyuGSeV57EMer`7C=>STHhFRfT=f1LKIgAzBjxTS~Okp$v6>RXbq#'
    'xkh_HJ2VE);)kpQoJg(+^K`nky3^?zorpULT%&2oI7MD+7+pnQ>I<e`v@@JAAf^Qz85jgKb4OfT`*KA>FQS!Y^bds)5r&RKxh}2}'
    '8Z*zV2!S5aW_1IWVCOk3!9FDe(Voh_bw?`2qL6p%8RgQY-KzqqON|6uizs%8KB^OURRsaWjW&V{rnmw|QYBG+l@8UVZtGCXq4}{a'
    'sWkLEF}x1*YF4IWguc~(4;*uh5lip8lc=@o>Uk0qwNUI-j!4T6F%F*5HNg;JUW}x4DY7-ZV#=Pv2}YC7O8*HxAGN*fn|j2@LgO8f'
    'k{K14xgxek#!ujoej*K}8RHsJA}DmAE62Df5HM0Rn<km>)w}i8zkr^4OEKGH0}TeJR)&0_&IOd95Og(K5_swdFm&h9B!u%o_9xuD'
    'OI;Q7d!!!W^gXTh>YaGHs$<HGYhgU$LMS56q+El>EaF^U4exlQCC^h>c|i>;4N@sf^3=KD6Q?y4)};V;j3dO=yQCmCH%vina6rpW'
    'vg8_$qpKps6B@1p8SfZQ0y~j=qGPU0Wy7IsPI;7+Yd?wcj`)qTOJQ?7nWg1mW{g^(eWbccv?_)ys;m?gSAj|vpz@e>NEM>fjXa~x'
    'pcbmkvMxbMRm)|a2rBtMjlOO~1FO?j`xI-2%2Feiz%1eE@|UfVvdS>g&&c$M0!kRtq_TNEhG$NJ%ZT7D49pe-9m_2{md%|w`r+ya'
    'hSHwKY+{H9Twa6brjW2>r0sECjWhE+goBnGmMlUmj2I|2Exwi_MeMMS>XIc|P#*+pmR<}TwgJzxx-*s%Xg6Ar+kJ}P0vM;0A@m5Z'
    'qks@mA3KCmO#53l5c4)%)L?igw)u^BoghLl=z`EXKgbVVlQz&rc7jS^Iz%YFjYolGr#8GF8r?^PD&x{vUV8<u8AqK<=c4wY9*h94'
    '4vNsQW3D(-qdQVWF$n^|C0x0j`eAx{nos1&Av8LJPfSwrj5!~=W@xBtl8e1~6lL10j_AWS4vlQ13kInSv^R~{CN`-NFsBSoCz=?6'
    'q3WH%7Hz^k)D1ovkF!b?yiE3(*!BLG2a$0)Dz=S(Ay)rL>~ZB-ZB3WgDC1+}3WDHyoLv?;dLqyYjIE7?2}5^Ur)zrB{dYND$iNIO'
    'W>lztYKOIV%7({EKlK)vkm0KJ5HYQS0H2&!n8FPVG!PGuh+XWaOhF6+*@$1Oxaq}o#=XXoL50}Syq0dASwVl5>cj#r{Pv+NV!N8o'
    '!80mrsr_Kwrvq<Y_K}&a2KNJ|lQBpjXyn&87QsM?Sd5X_peU$Xjb>Un91>}Mm@2yg2<!PEGgG_1L0=?9g*0(u&Am~lYp5nCBw0vi'
    'iX$eZtB^W}>zYF|#Dpv!CERrOu*{Kl%IvuaRuPn1?toKjNjL!_*+?@&m??m8p=rd)q1ps$RBGZ#m$@cgW~#aTro>AFivDRBF6g1@'
    'R5-r*410C&K+~^Wbp@-==+{YaT~F6c%pAV?^y<{Sy5#C+bq*?2zVX|62Hw85xBz%r1HAU~g*qv>6Br9D?9~=nY(5jU&Xm7vce*KA'
    '(c?lfd(+<Mcu|gI!Dq#!8qGz0gKwBFX-M#n3SNegXgI^-)T9+E0ki_3BN$~Msv8-E)*^!lf$AUXKaW^6F+zBWjoRXxxErE(CSXUU'
    'i>^G)%3)9pb0#LWg>fpX+75$Qn$zNi8bFP8bE?((>ctD0DrGbtM-LVd0_W#xJ}d+VzO9}_)t)r0$dDHzeST2e{8EII(&5%M9O*Oh'
    'k_XrQdc4jTS967~OK339Mf4?)S$9xmI<*d^zJ8C&EkhG1AQAwsFv`!1b6%2L2ag?%5UbYauc8Qa{)0oFq~{~i%qKV&az~AN=&Q~c'
    'Xr7Z-CqS9JO}!1~LIDfdhe@cI@qL<qOfjD(_o%84HzCu4+&ZPm)tsMZjRCX}Img?uG@YcG)8io1r^C=3GzZ#1reDm#FXulMT-&aL'
    '`D#csi=oMcf-j6)qY2?7(*yn(N0m@|9yOT>{xg~TRX!P}lN1;L!Ecn-*yLaZn(RZPgrA*o*`gsgAD#h9nJT?XD@;TGr)&B}CauT~'
    'nC(O7kptp;n~qZjsiWQx-zdh8V^Xyojmn(NFH$kI4*xZQi2+<rA`@VP%Eg6jHQ|sD#6T*FP^V1>6m3B?hA1XXD}s&9%pfx$NjOD9'
    'xFc~#NQ}_OTM=+^G;lO2iB?r;sk^WnE-$mo_!pwZbrBx4Ze)~p#BO=XE(*TtiOk3{edvlr_A~@;QBE>ki=A{FlcN=OmRVs-EnoA;'
    '6g13s>x3o~PH>nOM6793v@~=a&0E$4bkk@_;id*GS(~Hwk2wfj0PG9vixa9zV=~g{%i)RY)HD}!^8)3jvnt0`(?r*-JsVqa(J4{%'
    'pvmNSXe<(wnI^$(i>|Y@qAhhQc3p$}CP;3YeS_w{x|B?jsH#?1UG(cS#yVN78pYE&ej*s$#=$;gHTJY%prKinjMh8!ERpf~+6dkr'
    'npONrQNpc@XiSXp?A8Xc=Fn*ehs*#I#4HdQYVOrFwk=#>jvDN=aIqQ65;b50leF1YvsKZYytAw9*3$!f%;@Yc%~;3qsqsZR%0O=F'
    'oOMmo?b68A%Zt=$0?wFU6eW6ltCP9((=p-GV7f~()S^!(o(%nVT$EY0M2ni61?FJFwz|wZgc%k05};C<zZ6AOc1LFom=m2n7|LJ+'
    'd`7Wm54xH)7iyxMYUOgn-)AYbjMuU(6WzKh<JHgPF&$k!U+_9aA-xAEsn0;mnz6v_Qe-p3gU3-Gy<s6|Q_q;ode`(I=*>9eyI@Iu'
    'h3yTVEH|iHftU<kO}>dp5k5+ex(7A+*f<Cs7^*(=Sk?K*I&~kir@8@se>ny-VIGHquDVDkbZV)4MYRt<=HW=IzB&Na6~pnwQ9Y*1'
    'n|+lI)3dZ1q=Fef6ImP=sW85A<*ApI{wCuha*!S4(tnXyI+q(T*T(oXd^#9i<hw63S<tAHgz9}l9jU;f<j4p4_zJkG&!aHIAT*j+'
    'pqWG<DQTn9fS(7&$zx_~S#i%Ki<wL<*Gib8WSJymhdCmiV&<cwtmt8hH6$wn1jF@71K(wG33NJiEwh=Jg(MiNWSR>dFx^Z((dBAd'
    '&MRg#p~YJ1aU@^5iI|`RO-TA1oB=7RQml_pQ1PQO!{l~HHF>bQNAo@m!Z^?bPsHb34ZYcjg*nFG={hE6%#f#RYBhElHA0q-<}AaV'
    '>YHI;CV9nQ@ftJ6!PME<1gPVB65AB$vvz2NL`Ka~s~zb<l)@LO36{hfU-eD2#Pp0beNtnSS_>^>o|UuWT|OvaRz$VZ1Q$VQCJ93w'
    'nOJoPs59wgP|Pp0^0^wlF|*?}Lbi%tF(o;!<6|)s3&=!2rg@HW0WxY7a!%musTqd~RJ%)<M?&2X7<ifD#{~5n)!!4s@|P83X1<7-'
    'o#<0Ik$Hj!PgPK#R@cDm;!?D*@3V{Xm4J$YnaHsMJc(hcSEY8U2$P5+E5x%I0y8`;;WI5&?e2ijw{TC{Wj!5i@x(Z~V&wHi^>^;p'
    ')%A;$ybt+_)yN}Qi1o<~x}AMKU;?y#Q4I6+oPhGxI;9KJ)xeyuWm=@Z2JD!kLg)K9o6mBnj|{6B^N%4r2H#)@M*n)}^HJlGwcj7V'
    'fAWsctUVm3gYy%}dAV3ea~hE^pj7Vh(?KenkIXp!4V4FYcp!&Nfr)oM9_>+r53QBq<l83G(Ii7MP{}M0od=|jc|q8w$1-(<qMC*k'
    '^K5<8XcmgcB$g0KO!R6XtqDj+#$ggKQPSi}7edO%r94WjDM95Ul@z?!)!~6m7~!s&8xwds6>5nKOzQMC;aV6OuSGx+cxtBx;EwW5'
    '^GS#^A~FM$pBdQtP=%jpTCT1NN(gKn?~|K4Dgb0&UsFc$NubbmU8ZBfW0M&pSnJfuHkyAEAaxwy>7mNc(HqYKL~877oL?WSu@em?'
    'Lo<!*A~Tp^Dwyu-ouJM-&B`2#4V-YAJCyLr7)`+NV@<U%`9(3QKh)fmo@cU#n1_NZqn$Mv<!7n-!qAzXGp23$^h?B{f&m53r2jCL'
    '!`GB7U*lN@e`1pp;`=5&1o=i_J@ZoiZ6?=96FwNFcgUxsdbGLSxUTg~`c0sTyqYp%wqcMnq6^f3`$?I@x2d!137k3?35drUlOY_|'
    'GXovpARLi{A5$^Yg(H(DTu1rnVo+&=J+$1I9)pTDDYTc+fPs?kDDfm}8hDx)sw!$a5y)TV&>LN9BYf@=_EeYT6suw8QJsn{dLO#%'
    '5ix4G^wwoiXqey-nv{-M9~xw2Bs3n-P-QHKoQ%`UjIP(n<ie?`sP1Vs;X+4KOCpwJ<nQyzB%fwyz`hvLCNOy}8ktS>;W7HYq}g5L'
    'a}VFVGrw+kedoLCQ9Aj(?iu%)FjdJ3v_z~;n0*M_SRbS1Q!G9ual!;S&!9drC}BU@BWHesTMQLDT>94iWiFbAcVm<B7TL;k5M*&d'
    'HNMGB!1KI;iDdgxU0^;BA0KID$&vG?)j6Hnnra!Eq)VI5?(eEs*(U|J=EJP=bX?7!an#q;)#sq<a@Y&%Odk3WG-(We1=sk-P3~+`'
    'Czdbs#1c}&+11OwsG6F18bV~duGXInC#-kfI`teboqn_4#lu4Q3-y3!JmYMMX16h8)(!MYSXaFgk4EF;5(uK&ysOaz<Yt@jxo>Oi'
    'EwGyj0T8<BPw${x3TIXh8meX!I_A?nfg3@rBF+^!cvi_*o9+2z_-G^>k9^G@iV}T_FSa%DPZ)$NMp>+niX==#PT)*Ih?j_Z@7LC='
    'V$PQ>SS4NpQdvLX?F#xbYrJ`&V|~nrv(e-1tYiJ~!#JIF#>M2vUa$A#kNWeXcrj6#jdT3S+|^_@%Bs9-Kc4>X`1R8#Ab}t5{P3%1'
    '`Gu&*SLv@h4%{W3AAX=d9eF=?eqcs$Y)eT5XB^`bOegVJgHrV4k5c~C`@Emce%0v-jwhJG>%=a`d!58Z4_W7UGR!J00_FRM9}xCp'
    'I8?fcVT3YDFv%k<*oA?M>qD6#O4c$i8L^#FKMX=+D4z&HdS<nE#o#>0dN2rNxsbULm@Ht-pX1<;aWImml7j{4ys#tPJ4-y@BbaO4'
    'e=ndjMyBL&PQ>9*_EBc7qr*<}tSkkxy^uZv8KliNyE5wlJhFz+bSgI?k}#df5J46656#K_`rz<h#GcN7Jf7+if%`vTAE9m{q|=Z^'
    'B+Q%7pgv5A7p==O80;^%#)l3Q^u<$JoQA2MW_yp)`5>+4^@0F_Z}Q=|kg8@V>01YMvF}7l;WB0wrj1Jjp3lX(1PuZM0-#YkIT`Wz'
    'u^u0fL346ZsyTHh4(qcEk?4K6L|aj=VlJO_65H(gMOvokMVVemM|cWjASVq2qGzBcf?54pJ{itm%&QR)xz(ANp-;ZE)CtW6e4n0`'
    'g~1AvPE-TIqZ)*gD=fp+?oY=3dHECYq2nm2fpsV<1b&SMGhyOQL{r}yCw1viMaiK{NO$Au3<ly)<Z27iX}Jt=A5Rcy-?%OyqtWzE'
    'tC>C`ge46q@dOvCktR4wU}QSru|PDNRQ;?x;|Sd&!hjwr)U%o0X%2HTNGA=t0Z5s7?xHWK0(cg>23cWg=_+rpgxh5t7<Lr7U8A!o'
    'u7&W{njPhrIesld`g*Zh1aU@(7lBB<m{;7I+-i-NufI3M6LoZe4?DN!M|8x8Nqq>C@vC%LX6EiN!bMV$ZSEKxz(&botyk|&1nyhm'
    '(OEjj?gHM2c6QmB*;z^5`(c^>l#kJ~6YvmlYw00eme}j*T*xF{%?Cd!(OHnhobGs%&WbT{z=x+ESR_}-Uivt?_IoZe2K&>=d}ZB%'
    'uLu^@=YO0H1|&+CT@cU)dN_PXf!Wk=(`h;}AQjjtZZiqBCNyRi89HacNbfdOh=6Ab9O?WJ{+JjBs^JY~Q;G(iL@B`TFh0TSlA<BV'
    '*XpA-6zuY1u`;@G6EzSuf}rPCly``Wc8BhKbMj^W2v3ErGTD#F3vXpqgL`J6C`<+*;&Ug&xfrRaS_(S$vim#8cJ}8UV<x-R-MWeC'
    'sEHgZ40wsmeZeh;(9Zo@%AAjiS*B+(ygW9C_HlXxn-}TDV3f|zQ$x2v;sB4rk`H@AB?fzbmz6T(mB@#4g*^5c;yP`mR!CB1nZ?;z'
    'S{f*FWxQ5p#m@U#HOrU6%thL{G~M};iq2pxs>h74!0U^eV^o<=m7iUtFXf9CP-9e|AKPlo<9C064ud5{EkJy+<0viqxGO{p4Fqh^'
    'lj91wYXXRcwV@AHnoi`9NPJ-hM)kluXQbVH$CCmbJ)vVN^Z^<Lqt*e#Me3rfsJ%u~BLz(ah@hh?7s#L%6-nnss;wxL;L^R&Fm=35'
    '07F=TXTdriX9SOjWnyb9@g56=rn}KYkYj_B3%li}Y|}$laJZ)qUTJ}o8cBwTH4ZAc)N%(sc~97OaZ<N~KqZffC!(c$V!j|+r|SW-'
    'UGQ9w^ARM7-1)j%Na7aZt*en!;$mzCb1mHPbQQjbs<A-7(#>PHA@AAK-4Zx>GKUyXc#4inrv<=G@#Sb@SltJUM9>vGK*wHG1BloX'
    '=%mb&3$UoK6>^3|A<Qd7yfEr0ndvU^@`hM9>8n1|HN%4+70;o+F9y)+%d3T8`9iRKF)gO^F<(Ts|LS0c*N>jR|HB8obnE`VzAw(N'
    'ip6i=F5udZ7f5UflZ6)@J<i6XeDVDCLgZ}dEa2RA7M^<q&FO5E=8H$K7qHg71(Z@hl72^zN9lRGc=&jM)NW^iM{AsgD`Wore-_r;'
    'bUrQ?58o}2_#Ffb21q<KKT7kmSUh>Uz{49pXZ07Zb0lId9~9Q3e0H^X_0J2047~*enZscZv;2=Dkhzhhm)HvgPJNpr=NJ8yyO%+B'
    'ynwqqM#Gy5JH&B)oRbkn8JHYB8WoeXKbh%}*BLHok_HPWI)Z{H8uQ}qiv^s_;X=$}+gUi_(erASPWtol;{CgYXrxjp;7SCJGVjrg'
    'd{T|lDqTE!yuicKKC0bF{vN$d&x&gC`sqTJa2KAa6sUbT&n87>9p`0MEsh0J*rmNdMwE7VQH;;iS;}h>J`pY82@BEkDxKuxbn*7t'
    '!r>T-HyPs}LERNN88CUW2}JutG(DZmUH&vG<~+0qxbn#vY4ncX<@gOI>$mA7!}aju++N}=5N&cIba|PMiZTOOkkJw>BA@enN3V)%'
    'P<&jx`)&a@d$_=p<L&|x5y78q@{|0ZOUfCrAHQeIl5(T)5+NeVo0G*N;9ZcQ?QL4-)#6(LbBr5sMHtA)qld*=G5hoXv3T@m;rAlh'
    'ob17l(DGZk=@PIK;D<n7zLkZ89?AL>gC8F71Fkp@dMUzU@%G6A$=kNzs4OoSiRUx8x%1+D@%|YGMZgc6$b-g{tPmu4@eU`IYeBjO'
    'pl=_&mW#eh4S_izun;g51Uq_mHO$JipANYXxszlejKohcOa#(U==bTv1-zkhEE|_2w0ZPC8;Lr#c>azQo1k3=3TeoxM87^O7T=u!'
    '6$Rhvl=K#YkUa6(koOF8TXtv@PKj)AvZNxH_kei3EiJ#F3#r#55?+%hJ3o3RBst2hSNUY5wE4T&07C2%!m?m;^m2|D3NMb|ED$mW'
    'N`O%$N5`X!Y*-%|uXAugn!w|u7jrR7t(WtQ>AYOL`h(Df1Hd~tV|?__`LE1g6vad%PJF3<CRA&^kUxuOFMv*-%Y6!ZMu2bwy*<5R'
    'B>RMHe3xIP!_ng87&I-I19lX%<zad@8e)(Cv_M*uG|8em<4HQ1<pA=dmkXql`@j*q7e+$J@zDw1gwLZn+=6f&ZxJ0qr_YCrCvq>s'
    '5nUPBi)<MX9lbBgVltE2ju!~wVzLCJE|&GtZwmqcB&)=jJ6n8zyg-h*YlFWCVunX==MyE97#sv~?GVi5=y6(FS!JCFG}DX4`|pAL'
    'Q3BEz5{Lv~^J*rTB}f9_YPf(i(!=)sqgQ!)k+X$F3*WJmNQ*FV!H{$c!aRApa7cP$eaMXmf?ID#!g+?-cq+y|MuQpSBmrO`GabR!'
    'oXoUMjxKGn52OtQWZ%xu=Y?U(9?=X>g4+x7&yf&tF~3-xJSIc6fuX{fvFO9J9AqNmQi7E<;Oct9Vp9H`Q#Q*=g&z2jY{~-?2=)YW'
    '*59WUUJWUrupU3+&SLU5C3y7sgCLIp>eVaZ^SxL|h2Y1&j>p+2!S7Oz3!&xkT4a8J!#g_e=fgh&S)b!;2+l8J0pm`thLh}Sar_-o'
    'Cx#$!a4Q(~DjWBUxmXL@96^2}{GZ^sj!>!a;C{Y%0oK%W<vv4#|LAx)%td1Kg{T%!-U}bFJsc(S(KZndm_jspdU_W~BEknUMl6G|'
    'NEw{mC#wV9i`+%p*wO3kqxFZPJSQ))mweR$wuzWe$KzCoy1hvF44&czLId;@>s#SZgIojvdqlk`TJSMM!F->rGM&xF8K;h*TCmac'
    '7QW~llgq3$I3!1)Cpf{)0?UeQl7BKt<a5I=SeS@AkpeYRBd8-V$E)%}X@V%4;C-oM(ioA5Peovyd$f!(vsFkWUeHbNxC_XtXX&Nb'
    'z>7!UQ8>y@k;)$d(L`qvl|X>-yC>j%zKjb)=pfkYKh1NY=_ilKwWS4IT}Fwx6eZ}V#Y5qWh#SjJ!dMh$At=G;GOhmnU&NTEphX%*'
    'vfvYDu>vg}U#7#N)K*GHKItVYnGF865J5N2e$v50VxG1Nz@ZqV^U5^Hx$v~SjpMllO?H_NGr6fhP}xYJY=q#D4(PU;%SHbA|Cub_'
    'N;5Jp1+vIZj%8I}^sjO(dd1@>3&ccRFnJ+dS^el;A-d@E_n=FtWiHOjyAVb(VS^A@D99@8#ltn^kjIPT_Ym%o)FHtvL|Rtq$Hm*1'
    'SV07cOASk8+tG`w{BrT#@d61g0R@z3QKCQL$LquzT)cY&rY-6sUJhmR#*Swq1FOYT%4iYJF5!gbU*=U`u;=Z2QjUNqf$YIe9$!?#'
    'M25mhUvm#0&<016`5u<@s>;R!+9%kCXcj&gBbGXu6$7zt$HKXufb$4)3*kU55u|!ki5mR+4LOoS?Ljc$=$XuvPtNnjx6c=Nb7usp'
    'BqB~Y+tDNZ4DKjB6Q$|#3ushO)G0Pa@jiNt9}y9#%1RzK0A(j+%e(CA{Ez8ne!h5qvIu>kS{Jz{{z7Eo(f9K*AB+}{o`DQS=ET&+'
    'WZ2s>J)38XN8jUEHgrg;u06nam`(xSXWwBEHD~HaawDP+ROgF_f50w42h@Y0q>s-^kq(P@C%6&8YL{1rg&v7++!u@(q>ER_WdDNI'
    ')c1rt3YR_0g@G>~e-CCSK=MG+!orT;&nKb^zJE<7NDvB@34b|yU*^+doG)JffxHgF1Slp9^XPam5LWo~83cq)!US7^xD+0_IC+gz'
    ';_C6xT?B<(l>SKp4INy@UKnb6B<Hu@7au2-$OwMAxLUHdP_Clvr`m*ARS4N&yTq|q>2xkk;nnvfBq3kVT%cUNuo981-~XPgi^hOa'
    'fRJ$NIqjA2Uy&t1#>G%^fSNDT3pnx@-#wMvlxxR)pi8iQu}S2AWqv6OK3(uZz?c{2kZ@lWXQ@by(R^|8W<fm{SqIAU-ius3&nC0Q'
    'ci&U23R_QTj#2Jiq@wP<_#VoN)FJUswseG)lPd4$r67Q+{33+#LIalw|2xqRWGlj<+3b@IG5tJ|t%pb7iKa5?r()NL;`bW+#Ld~%'
    'lQI593Ipr-TL>zV{vkCPpAECog$UyL;`Lh~oZMf`g8+1oig9t#FBUIfh+q=o7x6-{-fy$vFjd9Rfx7LH4}r@HDT!5Z`~(URWIe4l'
    'fb_BGVvBz|W<6Ezz#~?@&&JmArLdysFR48z*rP~9q000ktp>t)PyRs6c7Uv|;@t6t?0WIrH@Ilgl<*=pNWT~Jk7+(rmHNf+p;36e'
    'H4%WG+)F;q^2Ph#V-L0(-GV=2mI#VWXnCl8;nLv6HJ_wYQQ2tR`=lKt)00Dq_IM>a^Oa~gix+PJ01&ZieIB&tB8O5Bb}K6(e>)Jh'
    ';q7QrT!>mV87*Fj4dkee>|^u78IRs(<!q$d3y+1|Wg2Q=mBL|DquaQoFr*UMo`OSk$5f<{j^%vt;=+iPQyk9+=kSd#UJL1XYQZ6i'
    'Nk!D}v+-EfIJW!Ljo2Q`UHh;Pit&6rr&jAgm&cn1urCn^lYyA8!dB6Uus_J(rzgS2d4z;6QoWA1#|xVEeEW_|fi1T4EJILJdpvzl'
    '!yEnyo3~9>=(k1n=l^T*=-q<)7t~(xQ{IiJ{nq0GzbRBK9={<I5s4qFqK4)1GpDbRo!gi7pF${s3*)^wdbHQ``TtMdyDT@3B<+Ix'
    'dJ0xwM1TZA0KAh4X_%5SQ=LjlEh;O!O0CWYNsvN`1egFRkrHKgR`UQe+gZ<U%#NK|%&h<OCjXO+e;$DgDJrY}GyRX*bXST%M8Lzt'
    '!^3ZJyIa3MWx-CEVfl=;hHmei&*#pABMlz-8(3gwNRc}kJK+j>HB*{>!eOS4h}S$wV+h7Ts{vI=+Kr5tDEE^)mUdqq8j6p?U`+|t'
    'PQHo*>B|LRxxz54h!KQv(mV{jd2FJA7!{U0^ewE-^AOjYMba;U|3GwPyo3qohM~(*Ad9`;5+5iE1DN_@NWJhYEL~*N2(Pbsa)el2'
    'Sk}Z}lmGsI_=pkIA-8x_Ee7eOJMcy>+eYkF@rGbzfcQa<?EG;kvJsi8Fp<d&0nVh?g4_pO9tz}yS;j5^q9deX>m>1`+go^%mmn7j'
    'QXH0T2+PU2Tdcdkusdji)Xj#_Uwx10=dIr#L-ta43XKUR@i|;fzj4qF)1f3@IidpDbSgqj9JL}3vSo@MBMq_er*S~5Cc+pNO!+1>'
    'PG3ZXuoB7Oa0N*;_*Dqcuv|c<DKaZCq#B*S60o5YurpofzQL|?a#lOPAi9t^+Eun_uosW~(#~H<aFIt3r<f&rgH78iskXtLA3Vqm'
    '8r3+nrpB88B%093LzDoKr3$;{6`>L>bSG@cqcwYrttNbLND=tneP<=&Jq_Ig3Kp9UB#Z9}?TZiO!NVG`*!YCa@-y|rTqv!&C8TN#'
    'Mj?j(r$so$+yrMfSz}iq;E_j;Y2OKhdy$Lfr%ete8ckL(AIX;YgOwBO!#b?imc^ory7Hs*NG%YGlITm_Z<@^K=R-H5t|YS->vWnh'
    'Yl#QQoD4?r3*KYo&^X32B1;SmT-W4H$eBW1tintN8x?K);7r-~Jz~4CR)Yv?2}_O4Co=pf0}G0(EXkWJ0LWJu+`2G%Ir3Ctzs3^k'
    'ztK4!dOkqja%PPODce^DJVs{*cM`Te+rrr5gpp6!lZycqkJ%X{8wUG-M17au*jb<c1PT!_oNr??0k6Vf8vXbG8&-0inHuYKp}Y-p'
    'J_7`b)`y?g?6$T*kqQS}#}1i(m$0IkkqlOO#4#k+hU7fnt<Sm~!i3sth`z#5oH}=8CY^G0vdV&h0CvtiXG#L+>=-sA$#X02q_h0d'
    'uargZ%GD9RLCmx!sv;^7a(ARv=JWNZOSbu2Y`JlJE5!4C1g4`~k3+&Z$+8Z^rP^c`{xl$_8wR+J3nBY;_pcm}05x%BeFFqAOvDDq'
    'E0>1wiW~wW5f-ReK!ON`64pP{34wSb;ErgJQwFx2AkcDw9Slg|mLu26ObncM-yWaJnSsx~H+P4O40SB}jao4v4dRo)UBieb8B7Tx'
    'O24+)UAHJf%rE1Ox*7@H5O+U%M6wcmb3$_fYhghUA&UW&jWuF&2<HkCaEl$pE?jwf|H<{;#|7C5>jpe+)DqwtNe4DFrBo^9c(7m>'
    '8PoT0x&ej^I_Q1)6)k#CW?I*9k*h#X?lE2?_-5i8+3t^!cENN_P7zi!QU=F0T#QZFP)O;`91^4C^kOw5z`KwcD^jf_YXO_Q@)bsH'
    'jr}z=JK)M-Lja%8cOgL_m}KGsnKNAZv?5`&MsDwcRF{u8lk4{c>eN^Z6u2b+lL$~J*@A3{mAhNaN6@%l6SoY=Q3~&fiK*`@D1mu+'
    ')Kja9mv3uCT?FbqXEF40U6P>$lKQfW#N+X5Hivk|aH989uTKINVN^gT2hBwc%pyqzJ|J6jK#Wj9i~;W$j_4d@o_SOjZ!PXz677h4'
    'a3dFx=ccS7URJVh0&Dply^`6rM&}$|<_-gxOa#>e;4ZyPzy<Kb&}7Gd#O4{`z>WS0eFhOl&ONHbp7@+tivlkVZKZ0QsfUJ_FpwII'
    'e7t)GdY!CrZr~%yRPP)4#^4l&{)@wGTY?oNz~c%jXHA9;Xz;U3l7eHG?0!+oIZS`V{Fs8H@hu_CeFi6C&76JV+{q+k-C#EIhafX)'
    'Q$an9BoTsTtUv(_9nzvQjh9J4N!MUWC$0WS)}$ko8QZH{$77a4XBa%rJa<llLnJgs-GT2$OdFW=z>mhJH=E%?oHfX9S)#X{Rm3A$'
    'NP$meMNEl&)YcY{S28LPCXQ}F@)p|l`LXZHreZbMnn!VRrVkutLZ7>b3`DuV1~xu*QHAL=TR1u7iRBoGd_eIql;pq_gt6BK7bj!S'
    '8|2O*_tp?!HDeug_{7oNW+udrSx2rQ+-5FIC9{HT5!p_1YMd9tj5E<!rD_T-Nk;<-3(DXg_G9=ajG?%=8z$)_2pFj@w@jwOsiibB'
    'i#!;~<Yf_{o+~({NjZm3==J+?s>zXgN`AkXjB>#!7mIJUxGDXuvqJJ)7gKR4PR=;0gkVTO)N4s=m>oqr&%GqgM-r*p3SeTh2Pd$!'
    'sh|+Op&r4iL>;o9DD@H=hsu%nT><hR7Q-m;b8jIOiR#T7V>m(c8GaKbsg2~vO*jSWfP70z6Wi!SB4$sSbZ=e0bd0}+YHl=BRL-%$'
    'g-kZg`7&$BT^j;%FesLRuLGf8Pe@6|>NQoM-IGgP(k@l#U*3I$IaFt@MlNaRwEH&<^j1}b+pA{h{PKvyq++(NWpuh%r)=|9*<GxX'
    '_4@7$Vhhq6Gst&*cP=MXMdZBM=^b|=UpOd^6tnZ`go70bB4ci|)%p2nj@s0P4_mKve*Wo_P0yB$c#~atEaup&JjZS{I`1z(^JG0{'
    '-C>cE3HZygaFQ&Zl&+Eebp9Tp6N4uRFtL5|NlczvY`d6b|H-K`SP<CJ)asmmxP<pfLbZfgVCV4YJy5~qIT@;*cb6R3MGQ%=H9Fl-'
    'Jr2Dh=F=dzs(ZwKQ-hUmz4Hz;ztT}5tG{#7<G3?vNDI>-o!(F9Y^*jwGa~rW-`;W<r-sx@y>oQ_f!`ZIscv=-yC<+6iJ5V1vDx{{'
    '*;}4^V+oH64lk}m<gWn(uWocs&wH48L(rvSb-G7KB36LID2&b-NBd#0W8#;3^Y|2SXkdUk2GQ>m2T@x*TiEElJ-y`FQUm!7q8_IB'
    'c)A|feY84nKYm0$)-D(b9d|x_e9se~Cc9iMvvYCGOou=NW*M5Di=TLs3YI>01)_;O`C4i5Cl#Y}0=KQfUJ=gjuXfHZuMkgaP!n;U'
    'M62`R><9@M8km|PmizfgP@&4RSj;}BJaJWT@WfTK+Ub52DTvu4B-0|?E=72#%Hg3_g8-j$V8#-GnHCZ7>=4lyjxT@>jLyf;r)zfQ'
    'Fda-ZIeh;SvL2Q<CY*^U2ng2GncPCd>Rgdifq0w=Z?xI!Tz$w+my-+j;e_MsCRTEo_0Hj^GoI>|@#jwW@{HYe#G24+hvYmW?k?6a'
    'kh5|8ZjA$GTI^8NE$UWYUD2$IIjef3bJG35k&LF8VZ}(<n4Ka!zRQ6WqbUO^wa&%W&zQk$$Z6nzb~5XA>}1i7ya71h$*cO*nJJOI'
    '|0K#eb`)o>^J+)jEcxWOoonMp8w}{zyuodH?V@vS-C!LYo+>xmESTY`dh`6OcCx-e&rV%}|G|1?eP&W0)qK}RwVBGK+_bau^FLbO'
    ';MMvv70uu>Uy=^630$PlLvM=P9T`~p?@_TV>Y8Qhn#FZ#NnO`Pu8OO<0q}q2#fgXKm&bfn;$lvQmblr_y(bSU*I&@%%nc(ln(&S*'
    'U0p3Vb_24j$f=7KzLp!{uHXNJD+m8%E0Gr3!(gx=qjs*^`=R~~H`n&uiHnV4N~CJJKfNr*m)h$i^68bWFS?TneU$Xgk#%W*a^|=C'
    '#Yq{bt6f@0HvN`mns#|?*DDx1Mzg71bw9_23zqijvt4O5>$q>IO0q}-988?)%vSC-N9z+J_ivm7r+vTQKj^pbwcNxFDU-4^VCfW<'
    'e#ub_b1nA}Iy0)*p4j_}qD=l=sT*psRy9<9!ohEG1rhawgt1f;mYLgJv7#&qV41;chGxdhlbaXj1*KB53Uf8tHReVGaHPE2HL`8o'
    '6nv1+x1;oG^z!xIoBcoJZ^~nBK&U<C_ww!h9@W$#)_jBK$sCXScpUTNAMp5X5#Z$y`9ILhA4!_$pRWfuYGzCfZN=9nwxuQ*_^M9H'
    'JzQ|9Otid_PfCxb^D`75+6EOrTTJ_Ih~o2rZ?JYHfV}IMKKJt4)7105>0<g07h`&Xf8>q5dDI?iQ)js=Jsqmi#3kZRi7GzX_!q=K'
    'UgRnv4O@49<xO2OKb26MW*BJUQ9}qR<_j`~$$!sYm|LmSNS}B_NlR<dN27($Rp+LQ2{j^IRV>9(pJXq^xr+MatZk#?*iO+{){m^W'
    'jn=!`+UQJNbT!vS4Vfs;Kb-yjeOw~3cGS+?o)^=+`9J2Ahuwwix%!W}<OD^gn^l$m8fv*}wW_Up!)n!^pJkigE+YHsw*B<1;Ywj`'
    'q&_LQyHvluc5m$DX}!L_p&naAx47RnZo#wWPDyaN+A#Z-C_4(mV`o6ciEZcM>S?45)n~roTUn~i$ic+b`PyP7e@&97oiDn@{7s%X'
    'o#g2=aW14@iT?LOB#G2SavUAMvvHmDz2`o(pQa?N+WGM$=(~9q)|SPR+A_2u0cqo0@y8&Twn<YzYd_!;>(zw5@EvNDGs$bYg%3{2'
    '-%aUx5Cq}y-E`j04~O*1w+)A@cHWIbFMa=|T>&I=Q3=!b(>TOc*b9O>4;QXBzy+`3QC=x4(^>e6=ZVvIC-Ry6EMjVh1ekbt=F>oa'
    'F$u_F5zj++PTsY6Ud*R$zSW#yhJ#5ARNT?+%;jqk_PzLd6a@1bac%rgrA`G30**s)LT4n=9yn7sbY#(or7RN@gWm)xo%sik$p187'
    '&0O#lI*54-Rnx<>hBEKNU@>dwBN2y;h>lVO^}M(p1Z?EG)Yd1$q!$j_d1o;X^1$l^vo-h51U>rT`NP#mmpUX*NKTH>!TCmB^H+lm'
    'T8`I#>N^p2^6h*+YnRItND|x|-zMLrTD~{)+MNIb?wR0W?oMZI9A`2Qg1BSEHOq0Q`nbJX_RwS!JRE}Y1oqL2xOGZkxcYwR4aY=|'
    'ML21rW;9w4LJ~;6=K4;5;tnMf2-y75Fm#BS2f>86Apggz>zJcaUgKSpZA%+@lSv!v5(L?aY)`krf*8xHYGMFH4<sD&8vnFwhM^Hl'
    '9Z%XMKAga7=P_3DTIdWt8hI7N5QqlB-P8&1qW1L-@isL<JPoj>Z+hs+*GVuAKq49(L-*A2$L;)VHNOpfnM8Tm1)7RKHypcAV(Jq~'
    '1w{<nyPW6eD8(Bo{p-7%y*;oDdC7PoyC5I*e<dBB-`o39=yxyTUoNcf?K#<RoXu}kSs|rrT)abk?TS)(f0pvgiDh8VR+Ln|M)qHN'
    '=Vv-watc3+3&Oq8N+D50>HzXg)DdZ!vdmSzInVjx-s}@1ppp;9md;Wuuddhmr{}yH%RyIticyK4Rou4@k^eQiCvA`rFLLf(QV}$$'
    'oiNr)R7CBdTt-uI1Ay2D7ST&Aw5=xfs6kTm+J92=e?*1DcN1q!Dw#Tm6v9Xcr_0O9?fk$0Z~rS}HO%FU(40pEmDS)$?>xRbUg|+U'
    '^p0eC+TLfaQZv+;@I<5w;!j%%v>D-_Si*W9R>^QdAc$}7U_MEU#c6Z52B{X$fY9#KUc8I!EI8T3iG3I8<c%nC!W;=(Re?|NXT65x'
    'qVB$)+}QV7j-ErJE7NGKVdBGv+=y&4-V8M{(P9HtAK;7t_jrO(E#Wfs?g<-8o;Xo-Msn58Gc+P5U{Ow%*i=Oaox(*TqKY${x!9lW'
    'O@_)`?QAi?oSHHXz%Z~|o>PQ}!Gk{uoFQLwub~DFx69l4*Y1+ftBHT|T1y;ihoj$y?#TXpc`9?yc?i<G0@ip-T3ES8bvK&O38?j1'
    '#fLFUHc;v$mGpz*YNM473J(a$JLN@tpHOk=-UoM?iUm&iDkjFWMglNP4%FM@8|sxP93&=L)(%uc@{2<ESJXnoAi;0bCCQ6>?yrZ='
    '+$j+#`w#gd{S@<mxS??_!4jl|-=bH^DIgI|$@e5c^pBnZm)e|32?WsyCcm%&#YQRN$}~R~Ce=GK4rqwZ18!`N(IUDhwconVaD&do'
    'FIf_i84hi#+)Y*3Rz!lH&V~^L?bJ*7W9r#=(}JPbEt7nw*fgAaZ_EQ&^2*dJ)T|~sIQiUYo^Q)E4FwG2z-n_2!FzsDiJvl|Kcz~_'
    'rrxYsiSY?Q{#5g)SwQp+0Le0U(-;dvkxGfWBocR1?QY}SJA9jMf0sIlidn3rUTHnyWfibYp>7(RxJ|X`W)uJIzvZ8^1?Wq{z}iFs'
    'g;Gc8^VMPEps<*wQT-i3Tg?BG&$v-XSHJILoD-UQf%z-)>vDMsEV0355Mayne(wfsdQT?Sy%O(z3~e)}&&;O80y*B~{ZSS_4TMiK'
    '2qI;c1U$mRppYa_R4sXrJYT#gZ!`6Vt(AL=-20`r(jMd5LIL@9H4El4XT6Sj@|yD;KoIWpV>#4HL^o9}Tv|t($eugCrL4#Y;j~cH'
    '1iyiu@BuuXT)CXPCH+S}iSJUE<#K4biKd%yIN05=R5rdP6-?XVrq3*Uzz@TjJ+n$PQyWffWmxK~NR=Yu)=ru_oRuxLP_T+A#Y{D&'
    ')67y+vJ5ApY|MmK;qthUwwa&E22@PZ(&!s`-nS|lBf>--rwx1+>6f^!GPq7QG1HdzORTy7EVY!r>}(HS2wv>Q?&z8#LM4cohz@e8'
    'gJSlhwrG%AuXEtsrZS>QkSmwRvNhDwErJPt%OIs@x*|*bOqqFNP)#g*Qp_Nq6raEH=}gr!Rh3?#Ajy}EnwiCHDg#Q&gkR&~;rRm+'
    '^sAlB`IO;K2T`vkPPrc0X4z_C7NTKUm0G=`^=-v0jnsmpo!Sb%ECEoK13sH}(n3WP=6AfJW)xLb?X&gWVwNb@$)FX*kkRPRrm79%'
    '1W*SFQ4EwzSSVp-N?0m~P-v{%r_}W6h33s|LyLOapoeYQ+Q914zuqTN>oADz|49m!J|nP`6e<!rQ7<cKsMbO>0eS_(s6==dkTjUE'
    '{Y+(T+mNQf)7`XfXwIX_e@W;+cLqH>5?>Yv$(J2M&(1Io<D8ffT{|urP0CTPL+!B5Qq(O(-45DgQ^LWZSE76Yxl9RdLw<f}kIH7f'
    'KuHCqS{%`zQUz~BeGrL;%e2EZD^fQds)Z4OEhvOg@vso}3JPkV#{oT-%pze+@B9a{<N@ny<aq5fwMqc0?wfAOwD$IjMQ;v;CwrRc'
    '<IVSNB*Z2d8Tk^?g=I66PQfYl3w=a7>90m@EiNo-LZw+H<c(IHUI~{*y~z(1%P5(RT46!sMAhEfC~H_$)T+snrX@-?s-<c}l*=;S'
    'uxGzbTl%(4pYCXE>20|#UX@a%Sj7iXPn9oOnk0r_zaZ#X8um8oBX-F4HTrdn|F$@5gBevY(&qQ(*7xy;MG0sNfWReX(5MVkiMdpv'
    'KO54Pxt3C`O&QDr2NuG%61f*4#6%Xw*|CzkCm)Nd<U$)-maFIFtZEX~C&`q=q4y#QzYHQC0z~}HD67n_jT@l{@NC}1x~-q2<5{H3'
    'J{#KBwgzRjnUGguC9eK{B~2o_G>Jb@SwIZm(Aa26{=epVAD;HfvPd_TNJ4fF)pACG5SJ%!qpdvIl%?G*?8cAKDZYJ02Tw?-u6BOO'
    '%=OBboJU_i#$QTB9~YKdY|}1d-hI?I4Y=1$Goj<g1MX(bk{r2X+th1uhYyE#hN)trYUpeYy{wYf2OLQrUl4HWEMxm<;Cd5fI4n!p'
    '$v6(|>zfY3SkNt=ZFIahw%_rJMKuudajrIHL9gs5`Z^a#YsHTcd6~^4M06u}xT^(RQH&iG)hB#>$X4Bo0C3>9{gSCN9`gIKAOMkw'
    'KEC#DH2f%D(NzEJ-^3NFov{puNbGf8AFI#AmOl!>ajWn#)o`=b6cKJtOfT}Oe7jZOXu>AGFG;mwyLkl~#bp56CYl3hEL5KWDzc4)'
    'GU0Bz_*qiS><|R_Mn5qDI#JP%&8Ba}52YEH0%M;PMKNVlDIC-^>06wn#@<|_?jo4nm&Y`^8D)W3rkh`4|3A>LGh6oOH#^&-Xprb|'
    'h+*KZp-CFh)zCs!zniAvM(#Wk$zk9PfuTTcN%ql-{yh>7KrNocNvEr&Kxcn1sYLB8i}pRebyoN_Z#s|owJ>!ZduBopq%K?H_yI`B'
    '^V~c(rjc^5dC{pej~jez^Xq|fzi%4{`LldG-^;6Q`Fc#RU-D|_-cGvVUQOgTr;R27(e_@|rrCGpzC@-sX)rCalb6yIe`C%Y7W4o1'
    'U-QM8GgPMJ5C8jr`EU7RL@x9@Z|M#dGc$!*<ta=Q`9Jf;TW-l>K8@KrjitSAY2O*P-fFe#67|QxcQ>#lFs$avby9b+e_;^jC`l|*'
    'sAJ-|SjpPvu4R*bXOY6tT+(!|RVMA>S}}QcxJFr}b7ni`ROjKttPc+TrCr&H5zi^wp-mNK{TU>7vkrejnUp5Rh5_`698HBQD8m+|'
    'dg!TME!FT?sFcZYQwy__f~<107?-G6#cEsx7G6gCScREN=4(xsgyr{I(JB=s&~a|XXk^t`opLvDJ+|+R!dXG-!aBYxl6~C8XZ4~|'
    'Bl;JvidXcnVHFNbwPwMEN~HW+*|adlZ{UCIl$`m1qkJl!6|xjmx`l4p0<5cIt8hq`<Y7TnQ7v25qEa^jR#Z|q463D4F_LQP<px#5'
    'Mg?{38$&(wi?-=DviSEM#H$aFj^Dli@RyILpUy7+dfB`B{L`1e<*!9pWP|CPc@aF<<OK#T^(I~m1E$jeOLN=Dn%_R-^R3!QE+V;@'
    '&*g>43~_;%a!h06cr)qDr?j)YFxf`aR0m+j!5*#GJw2X$<#`B1-bgy+V^2XSk7>l;VcJaPO4DS3!fc$Hd`?3$&%wNmgECk5o7EU5'
    'y(YuEO7JuSNN_S~oowydA&wc97YYI3laFhv5GP2@O0twz{7K;N`XunP((d_(?DTlF@N?zd+?#GsjQ=|10N^w#H|teqzM@sF8a13r'
    'U9ze*vsSI?$zqf7G@5gHMNzD#p;zlh-E3AGF!S|RvsSM*D)qY6D*QS`C{e6dNqhhyJ>-1a!sn>qj7B__j7>6Ie5j3W8gGPx)hY_W'
    'hG8|yY-LgO&E~pmaULoy3=w|#Ry6e%jp<}?j@2UeBW8y^*=Y>LwH01i+A3A_x?5^U=-H7FI`(#G1`^86jQ-P1IOdc*t)V;E6(HLD'
    'L`EF~GEJNkXo@y>@U93cE>{()f4=H|R*U$9r;<$G@W!aZHvMBG7;6|HrSW`E>DOtb$Q@*Dc48oHM;=?{Ngg`~ly@V>pF45W_-)!{'
    'kx<*RA9bo$o7wN(K+nc|lQFR!U}fVeqCZ6#3G`&*$-<L$lL@^F`|k1g)(;zvi;AbfkF}kBUCM@xv*Bd2G5l<HHl|0}yCZE`7_&t7'
    'WuuX3T){;P(Kvb{gNxJrB+X~L@<qfl^dh(C&UdtVXk_(%X6&kk_=!0T5O_{hi`=<*n1!yi&o=sVNa{AWE~j>_Gks&5BnCRuqMdjf'
    '?#}OuQ?iCoHAE<&zrjUGmCD|pyKl#jj0hv3@?-j0{8d`kO#lFC@e!Uf-*6*bDN3IJ5e<BPPESBT#0o_FY2L=HhVBOsimHY5*fzD<'
    '#97I;6yCjDe)DzGp1C0rV2b@!vOIOcoTn6@5>xy|nIVz2#ANw8>BwLBdL!Yupazwn=5~sSSZffM0Y0)!(H_nV{0LkV6LT&c+2GXU'
    'dHw{l4ct3PdE4wH05e(Hn#EEOm*vfq%$-J^6k=wbjyu1^j8G^Gat&dos1lOCH23xrwItw`(%RHF6)?u;IxS2fMWl-&*9ix=TiWP?'
    'bA@8SdWl15cja3;mG+JNZ>$q2|KsmbK`9;leOOcu+JD#SS3OWE?ce_E0dlU-dVX}H;`v(3b;>utQT+Ie`yh({smz@G<8&k3D5Au6'
    'aVi$|;-PYba#NC1dwb=m?CEoOsd!gaDq6~DcvY0FqU1wbvWk*Hwq(F1vtRDFjP*KOU>_EK7PWY(vom$ukh{W8A|y4eM^kxy8^1$0'
    'XgtH7XR9f;t301c{EgJ-dY#X!az!#z;oFX&>p)7}YzLw6ATB#dR#JT9C7BOyc<4l~BCTYWOuUv{=en2n{!;fhOA>2M)b&~{0RPQm'
    'a>;h4++at!B%b_ZsQy;{SO^o&qc0vg=M(jJVDjRF-+=G=gUMp(M!yq!w)jRnUSWh#_t)!CA8_x7x)j%VBB9MZK$(Ms{J@*9@_0VT'
    'J6<>o!Z}%wp*!{hU$Teq@^MC~pNj753uV$DlJC&!q${=t*u;dErv@EZk|S)f$`~*<1D(wR4sP~`>Jxz)cKY_<IW~~{2Twq*-Pi7>'
    '?f&q&jT$$NTHl>N1mRuo)}4@KZs&$x=nm$&fB&EVms~Kz481eS@lq$bylzX_oRLy_5;<K~1<A5PkvLQq$+C~0F4FWxI7t^n|GoUD'
    'vX+N=UY>=)a&<ttcE0HPSmO5i^5ig>&dA;I=LAVuFwx2%U`dlgCB<?VJO68hWpP++;f9em7i(8+3!3iPetO=Rh#LpCfU!t-2MlaX'
    '-*@}ec~}z^29t>!rmL5N?ImE&fMf|3CiNvN6U)`&FpR@zz>HkT*@gBLBNlmMB50ew7EjMYLWFv7N9rpK9&(wbB_FP?F34pGc|qAC'
    'N_`@<*p_WR5H*E5-W0VRzhW^E=_(ox&SbLMT-P=aSf9udkaUY&BdPN8ws`FxgBu6&WPt3`aFShJN4!McKFOg4i}5WM!$>wNl%Jou'
    'o?RdTB?SUHY@@Qbm#LQdOZ{!UI)aeybB0@Hybj~(wI2FS&ZPdEV43HW>_BFe9zW}{{||PgDHaw)waE>4sUuu0ir;RKjlPe27SAa~'
    'UKHiAl`MW?E8|(-1M)B1wQ_ZQdD-P{E5T?q!ODwc2iriC+d=f)rGuj-$Y6}9$K9Me?YqOFJIvklTCE84LIFTIe$M^2U`BBK@nYhH'
    'xy$!&ySbsW%7Hx>p_@~j$?Vq2+42&Sa-X#HYU)x)sTu(o<{Uusz47h5G{N5}{#4Ih0Ki{*TFwt*F{b}ZH_Rl9lx{2W0vHJH+stNx'
    'rB-QF8+EhNs;K`+lUG{3-n8m9tG<!^sF6cp)mt^AYO0+qoZEjWx7a~YQ8m+QR86aHHX2mqA2uh~W2fl$#Rh{EOTV(YOlRq3J)EVg'
    'tu_*f!jBsXkHV!ME$wA#>1m^ty(+Ef_tAbVJ$fBVA1w>?AMbe?Ey>wg*`rl~{u3!HN_n(Lj|KWqq&%{ojf1kFqDM$jwW`(^uSGLX'
    '7$o_WhJ<0JgiLa?Fp8$CjW(emX}k#sNw?dOC^1EBY1;9oq0v%XTK1r*3`+y?R<YfpGAg;^t!j^p%57=PZ!6PYnnh)4m6j$YthAM7'
    'FDsN#EiEfZh)3#*O0BHY3Z)*iOW*oa*<)IeOj&4-t=F_UmL_jZR0LvfA}ZQWA?fH2c{@&r`m2CrZ;Cici#kobv~;UOJttmpfQwTg'
    '$jQt^d7i<fA1vQa79kdCY7g427AEU!r!!WJ?<RpWuUKMfIF*u<DXIo7``rSV+YO5*$Q?ImMGacLx$Ugd$(Deye(1!rHgUl_yA*cr'
    '-jK(1M@6aW1o%2AD#~5)LH+ZCnofEx>8s_Nht3ip327>|ys@M5u#@>}Sqw3UL*JE>q*7RXC|I1xnrbJ&-^2?wCJVoAOLA%xvz&%@'
    'r>cbq!ltvc`9#0#73as;zJRr2w7E<v&1BfCQYbQ>GpjKPWW2QT3MUEJPhZ-WQEh4;+K9<(B!1Zr)L5z>-isIBJj44A#M5bj=Xf8@'
    'HTGlPx%@D7qC4?TNLI}%wfI>1^E6!OkFgJ;=Z-aJIuo;UCv*0vlO89=xyHnru{i}FE&5_3-Y{KbK3wwZffCOz4_CZ=pd_}2x_)+v'
    '&~QoF(za*YhVtJCMAqx!eto^Bg#9Xcg9<)>Q);&M_WJUPT!_?bL{;#3$WhFA=lwKQ<-Qa1tNqwCdzLlJrSat6!|W*OHMKx=C{X3v'
    ')V^lmMTS+jO2bu|(hGMQqf``==2mgI6v;Ooq6iUWstqBv@G=E;=;b*}x8I!OJeg-FIRR(ae6^8I2QTIs1FFBk+GR4(#~Y^f7vaW!'
    '(LRWW589dirSL(UE$uJmN<E%{oh~u)W$!1mYlYcTo31b~Mu{z>gaAIJi3Xt-MK>%he+jb*2R$%P!WxPG{lEP0`Hh*P!TqaCy$6ne'
    '??l*?aIf=@9{UR(Z(T6H{h<?2;8Pm86Nh4_k&?H_<L``h?EUFs&zhb8Be@ZInRH3!3=KU)qegEa!kO5Stb{a%CSczz5K2m@F-ey}'
    '=(--pTa^*WO&36nMv+ZL5vw@3#)Wis<ED+t-_%tM;3}e^N>%mA<MgpdgWQ%dnNn6}nwO5GB|+qPaWTM(lj%wk^UB`ASO<Bp0$vW%'
    '9_v`qFW;U)4dx*UT{KHcoCubWo)nOoZAZ8p<g|Ns6pwlA4YQM-+e)0xTZcC0uZ1K*aV@i_6U(KFN(A;Tka2{IkMvqin$)q>k|UBn'
    '1(H}D!h|(%_HpB4OWi0g3Wu+ijC+(iH2=rZXoLwNw0B1{`9|FDw3G9HZ$oRDhE`0`(5gh7#jwPC3qvsJ>ln(rEJc)5%5}NsWCK%K'
    '4!CZxw>PxMyxR)95s#d?lMDjhJrVOZDTkK^!I`=xlFnENp)g4x+Z$ech3ZY&s?|gz84CUg1ca-``-l}1P(nVKS{|W+#T@b>x^*X`'
    '+#XP+cN+Z8#G9{ZNV=2ZOOY`#?bzZ$C1`|3hBp?b$>bN=rllsoo<DiLV8u}5-|rw#vaJ_8RKR~4U*jltG`>VR9Q?MFBdaTxa`d<*'
    '<wDD*#1~>Nv|h?NnYJnDC=q*ooe9TdB5&@V&)kqVG}(Ff%-oPag%~+>W_F&ZpOd7&1fHLyZSiP0h8#;Tn@p#r!ZEb`1AZ;mRCub~'
    'WHfxL^`Mv44LQfw1>~C)b>f|5EH-4?52SDkR;&a<n-CS0y>y12GkK3qn;<YuZ9~IfN+IDF>dtV8lkURaJfJ?+^5MAekgH$Q;(z&K'
    'RLraSmxaw8g$;GPAI9NEACQsi3}NfhU;0<D#9tOA#O(_=Hao7b$=H{-KM{-Z6+^f+tya6aNfpBN!<4MD8z_Ykn-#<0&XxVYqajK}'
    'ri+T!#69_id5o#|Fhyck@nlys?NmK!Z=fSc@kpq#=AqY3)sx_;@W!dkkQk!Nz9W%1M$Tb{-z||uamb`FBa<YMc&v+8DK!Kumdl$L'
    'l(loX9^DDOA&DU^_nuxJ+&P&qQPy(#9b<Zsj_JXRF+Ct(b;p<<>=@I7U1NIiyT){ORST82m40mA(D!27EFjH8$B!nw|7oeP6-ySL'
    'u$VbN!l4rMUb*3MM>?&KIco8&ro(XX$}j}h;{WFBgD_tt)QWlH+x~U+X7?B*_j<dqg3<-Op?-hV#vkyA9c+!*EQN8In5kKs#l;Z%'
    '4?^&-pryQyE*U3%dmn@)y5?CPXr#u~j=WfHS1Citjr^v99t=Ud?~I3R*?>$X|K+gwqH3g%Udh_>w!aAHIG(10e@%`~`3shome|M_'
    'E96kqHTk!hg#aB<Ns=m70b~a^IjM}oXV0HE53$U_9m<hgsBSd-=(uNJTV_);Tc&2>D$?HZrxW|yY#F$tQ!@=pdVkra6x{h%v-pnU'
    'cjuS(bxqy@*Syg#yC-KhZUe-%?DWCaXL>bjhQ|LaD)E-Tps$-6F3`L@Kl})gRa^n7@eQ55v-2+mqk;=@EA+2*vx(>Ng?){5uJF^z'
    'k$v6L2zm=Be>gsUN8i>NArlxJo_Bj!_H`ZC2~skyl|4B;rZQB>s?a|ww9%#ZH4l#)Er_3Do6K8Y1?dSnPwal$O5#$hg?Wd4Pg_Ym'
    'YmsJ&Gz)1K(l%VqFnEYA+|ahFsY2%fhk*!(@#X{lDcZ7>bQ|MuS8^`~f*c<-Di;@vReKsOSs`4qGPB_#_>JT>Dl6u=4+Weuw7GkT'
    '*IN=ZZ|pIWi4H#BSUVP1x*h-7U~$i06}}Y7ZxyB~TxVWww8i$FBxW&~6cX-7*n-{@zSoA2b|j|6IRZ}AB{;BMGrik4bi)+eAbHLW'
    '$7W{AB#ysnb0BdDL0YAH#LpxD)X3B!!`)1$$E`wKx>jtVbPZ)|T2(EPr{P-(FjH?7s|HHY6Urc=LFF{R^40daOpEjJ_mTdpogL_T'
    'p-uKO5vwCY=ekiV>Q=Ro*(d3RfUOo4-{eq<Ua1!e>jM7iX04#;m7*7_#Y8z5a8%oly2cYk6!vSay*(`CD>bV8@TO#%dwaYbuz?T|'
    'vT6-=Z|_H5zgchSHTi*6-`$3RYjaT?-MJo5)C03E!5!!g@mQ}A3_z>vbqURE#no5!+JRoJwGDL(K6NyKyG_FZx5A~}D0C~&p}G~i'
    'Px4nt43*j_8kraJy=V%nWk*9swocTqrE9XTx}UMet6Vok?0;$#X$vEiQGAPggDgpUtre((5;Cdcl5SZA#S2T+Cbg&=_0CkHI29=F'
    'sCrIJh=EsbTBX~9zKtI^{tbbp!A26vCZUc<$ABaeKbv^A#ItqNVTq;;Ski0LGQN9`*8>rls)T~<1Ps5#aQGzyi1dS|Owlg2teedZ'
    'X!RH=DwIIOa|{g68CaxR7*<tH5fcC?Cjo%x7yzC#0HBMs%=iGXIuNsJs`|Wxwq%tIZ9c<{j2p81NjuENY7)xWH`EyLbYHI=kREH3'
    'c7qK^-b|c@6bS*hzg7uAL2qsKWP%{+zPNN1m!n$REfsIpcJ_Sa2M?!Y;oEw%&K#sLA3$ED1=0~9;Km<m@k5au{#)|B2X2Zq6fPIo'
    'S+DQgdW&RDf#em*ka|(C7JOJ_SU70=KKFxsu*Aa#6d{*Qt5v)$m{vWT`MfQw-{`GYMpW~e?7K)|+7lCsBeLv?g$MspiqblZ(mIP$'
    'jK)9=gX0TuOd!Sqy_k5h<V(Uc0n7<a48h1M;6ieYLp8}}`ywu2vT8s9?&7!%8ys=Bnz;2jLW$Zdz3MtPcO-;h%sEYs`d5oJNWEC$'
    'HgS_kai|4Ru2F}Tg>O|H#~>wZ0tFmZPk=N4qEWN}q(S~x45VJyi0wq+SZ}t)(n&%pVfO&$Qru+M(Qxgsx|>n%iBX6>jAp@qWWp0O'
    '+%wVTgC!nbNUXazHtT2}-9a+8gJfjm(@xAt^^(BGEKwg-L<cmRLO#Se(;&SQEc!Y;$#FIHHvqrFuyW11O{$_pX7=^3H#X`M&!jwT'
    ')G6OAyjk&E<;LbJJI^sZ8O<W4QYVeEGRq%SMD6{dIG>qMviAJkUM`*27on}KsMrrFl44^4ng8@JJ0H-hihv*dRKU)z33w4M^M8kH'
    '?WeA_|H8HQt%2?D@U1ERrE?u8ZhF^9{g1iVRQkbAkN41=t>_6aE9c+|8?A}UjGBHcboCp7s|uVYN+~+OBXDKFB{GB?yh#x9gExq='
    'EQJVMX(57E1#5H4D)h&8ChFaa)y*~T$u2b-xVxKgDsO2``adaCaRGZ1_qU6;3i)@YC|Ko7)N$#0rGfjk5e1`GRZMaHc7?Av$JOMx'
    '6`WXB+}%!Dr7GX4&hYBE0GuxYCo2H8RoK15UG6%Zz-xkS5(<`tP$fs79Kz(n^eQfKZ*n%S_a;EN?OSA$W;Pf&=b0_7)M`n{@`7{A'
    'jK4H-d%2mwEmhzJ%9dE-+WI<UVb(LDy}rE<7E+Skw`qt)L*OMAf0?z0^X<ikVQ7;PQA{_a4d&RnDii^x?Hp<95k-q4uS_i_s{vsd'
    ')J}=KIC0MFBtsbYP0gY2U(2UPIf-DF!*63tVN+IAXsDSvc%yUo#vk$&e7uT}7>Z|H3uM=7!(r;=iHX=^<}Yp+QR7VrX*-L;<V|+|'
    'QEM69bYCh}q85fjEMOK*NcW@5ta3WJS4np^2srZm4e3`bH?|;PfU9KUtTs|H*u`cuZ~4Ypuf65I{e^y3{Ic4&KdjfnABB7BEpMP1'
    ';>fU|xLC<dYyh*K3?U|f3QwaTC_-GOK4-+QTp2(TP_B%}M88-L&%&6bfmjvB$2jIVJHK(j0mBie1VpFgxTZ^AvCc1<<WaMW*^({v'
    '*{yL(a_9<uEOusMgNIn*|3&??oPS=~FL%|+d1ahIEQ)`?_B!!YGB>xFF$Gr=YH@k9uh+!>5%xKEU{Bg9M&9`U8u55RRgB2Bl47os'
    '16Yao(Bzzb(`p_lPKnG|f@js+#=m^U;QQ0_x8k5{aeS!;g^fevaOS93!<QSnH~`J{2dmO3bluz+xBvc>hzmo(4SChxx$ovii^-%E'
    '4RE_pF1p2%*<9$XN(0Q*@>;`acI#r*U=Ze}&MeA}h)&t+RI%=GD87ymMl3TkYqBRbVVm>u+KXYN<#6b$fU4op+c47q6VBXz=ek4t'
    'Ni5^VF|F7=a;M$PC7vQ3ry+{N^>in~GE-$UlTS&!*EY7}Jgc}jQs>iw^Ek&fuif#iysY;8C%aP3?if6DrdSTtBn|$dU8ldpS=cr;'
    'kWsGV8O@g1-^0nP>7Y$~=lJbp^DKcZTdL-_uT2qbblcZt4d7|f=CGrQW9XyybyeiwyOZ|QlEAEp^)$!#ref{TD8N~+;+e-;<UP6y'
    '7M~GHk}zNF2O)nx*tg<=@@)DiHh#~Bd?IGDW4@>3v{g|MEwb-*$fqA|TOL!K?8m;>(;eCOdU9aeEW3ePi)MCayV_=aaVxSYMW2wJ'
    '_Vr*^7)%Hpjw_00Hv%JUo5S%%69i_(wpOHYQT!k;E=vTouLU%CBlo=cUy}*uc7hcr++@(8ezXM#eV`62i+x3opRD>$s3d7kJ)V@0'
    'cTN&moZu{QB4!XRo{$1a_#r;$y;>Avj44YtQB7;scmjYbm(i4@ni#)~o+LB6rin(7faC6+&4x;{bs+v05JfJH`S<bSNi7%*HWrr+'
    'lKqUDFCKj@-g&1j#KR&D)GkW{xw4F84a}w?mb|j#BToq!*d;ilyxoxeQFKC)98%DpRrBNEjcvN6+NM5ZTC*cB*cn^S35qMBxV+Ts'
    'aZrc}BK-Wg)40ZkEW403E>PpfH_1j8B0{of8=6{P|6r#k4#68P0d2Sftl?v<O8U0KQ4z}Jpa|u2OoU35Pc<U07+Tyvh0Jrw#97}1'
    'yI<&+27?3@r0r+UXf5?i86+r^X*S<C_V(s)PD>THRNWxlbEX+dZ@)_%qhNc;<HWp-wk`3H7Sm6g)E`a?F()O+3L(MgO}gPAIdO9J'
    'JD6Rvx^95m>2JdD+a0+o#Y0F<5D<f6s~|xv@emS6q--J^FU+GR?U!n9b#D)kZ{(AiCYqd>P%a^yGns>U8>4??fNhaES*wJ*8Vq7y'
    '0<c~iIMYY_y(dnlkl!o+p~EMs{-gyzrOTu@MVGYFC%i-I<*6qd&6@D7A`^`7AURVegI!!jQtM&T$&%|3-*YAp&MK09LFP?PnkynM'
    '5%@Xf)*B8v0jIv>Je?d?S&1`ZVZ%(kX<zLm5WwWbhxnbWa`#^3^(XF2Dg8V8>E)JjO>~@^O2IqZEN2F=HneBSKI&P#k6P>=hj2@W'
    '^uB!;YYL`Tdh!hllMI$;KxBt*vN-VDlB+4PHXCZ+RyMvYu`Z+6M;kCotjXwgl3mjKZArzc2#btw6LE;w69E*`9DyqWCtpl@d5m8O'
    'dje%X$7_kQXRO>6?$q+PNk(6aRxyHi#c#_3X%1jV&ntem`1z5Zx0{-7_g(lr+@hrxtzMWVI~1?v-oQ_!7fY@pK`6yCOR8?@KAbrz'
    'H_`G@9WNvoY#t>(N-Yss?sBHY;-{oUQWky4f>zb|SOlDyhNA*lI0+jHGHLf`e6ZJxV?MU=I$+t@ZW-#XotBbQpR<$yFkN1ffRvp!'
    'TiLsCLDqK^Jud`W+9ko|QUT9atX#ElWtRlgFIgjt4C3qX(Powu8J5gQY=UruO~WMtqECn`mSsDn=B>ofBmZp7(<in`p98OjP-@*!'
    'YTfV=Dpy!Th5KEKR_fR{yN+{wRo(6^ofVxxrWh^@a}DSe!xcYK!^6kIT+MV?Tgp=GhK4*9JMCt~aAE=ewt9xpNmN<lL5nfK9AC1@'
    'G`RyiWo$w#jh)<QLMQxOw8@IOOE`5K%C6DD-~Gn$fNga5VlarK2Da-J@OD_e9Y$tzNDHL`WBTn%8NHAV8)88i-3es8lt-H0(0DUp'
    'j10I!mNAP;VmcQ_Lgv>sv#QFi>GMmzeu9q}&#DpBb`S^i3UQkiKB-sL^ron=9alo>dabNn9v5O~Lgl(lEQ%FXO;(u1c+vm3Gs<Sh'
    'xleXcGg-t<G18mi%VI=(pVNJ}{8@m{eiSzo@N))G06=NpCTOv3I>~)eUBJ~P`5P!?1M`E-9&EIRYZnjL3(h$44|O%pIc5sM*|ncg'
    'in6ph`M|?PNL5awHLkHVG$$NL>QV)WI>LR{so$gz%PunGCKAY()}`XZ<H|PV#X9ax8P312aez#EK3bC0am0xk9T8I%*ic&8(Fxh?'
    'f&<saoYO&-*q{F2mP<-z!Glt=NHtnoMJ*?*GQ{A(&0GX5AsE3GlybKRNnD7OUz#N7SxWQNf~%%A@CZnTFxQos?D88P6gcipo-iY_'
    '=0P^YRn;P%I#S@;X3^29XHr`<zMjm*(v(_9j?eGcj3V2WiZrUPto%kD*)2?W`&ibTG8D6eY<<#}7^$QlsZTc!NfG=MGr`EtBtjj@'
    '&DLpx5?@S`=}j^21e=VY1f<Zze92D9m-Ocd7N7LYc!|Yx%%7WwpD>fF`?&OR{W538Ik6?`_?d4C!+F`PYiUuDuysfw7*=mtn#{|5'
    'ZVx+|Z|$MjTP*`;KlSXqGoOcEe=&El)7i>7o%_HW=BAE^yT!(nuNTq<uqnH$IGUkjIFrbJPHqc$*ZbPLJhcBg3*7-(`q*0Rjc;cp'
    'IRmokepvV(&c+e&7ng3-iBq^hZt;m!S|?Mgl3N@)Q*CjqEk0|DciY9U9KW*(^U(FT3tf;>-UQiO_$e+Cbv1Rpb(C8iIV){(#^Kb('
    'xj)esUzXdzDEX7OL=OL4xglZKolgU8!83%~;t+vXZE?icYEcPqN{PQ9%oN|Kz>qFZ?22wy&05Q<*E&Cl#9Jr2RT#&a`ZTjgxN}aK'
    ';a&){Sut9zqE6y!MnkxvCx=VQLe#-C>eiY5Sinn>Ug+N=85GYFxF6s?5{AAcp2x3e$9tzc{63OZV(+s(DvSzBMK?;8ZWKlsvdN_!'
    'OC|ot7<;NFev5#jaO6}~wGr{TmKGA3986WWKQPk|Ml=Sr?PWR2OEA0u<VC&a_v$rw)N5|kJ0glD1RM3INoR-@$2PERg#L=XVB`VI'
    '<@MF<_GKpYjC#tRiS5avHZpNqWc5|hiB18aI>~lrs+6nZ5WT219Liq$CVMFy7Aj2x15R>_&5ijMzehG}N`s_*y{6s9$$eR@*wEA6'
    'kBm`Npu&|}(ZK44zN!`krF0T`24sjB+&^T+zz<@a&1{kf??PwHXZz^ORf$?t;1SIzpLJvtYzZ<!8or%;3Vcy2Sj-2Raz8+3vLtw8'
    ';22{>&xf{;Gqom&p)cMMV=v1}TqE^c0g|AwI0o16%J|F*Cnm>`{23N2L}7``AWg&{%$^!DEA>k{KP1t=H(-JFy1$QKvGkXl(jVKR'
    '2UF0)sps4B2w%W1Qa36ktbFT3g5qR%QE+TS+m;l3fcn*fg?t+QtpbafPEyUcEIGahbK=eIXc`3bTV@UFrHY0w*U;Q=8YH2dG*9|-'
    '5`;p)_s0d|S)(*o<p|O(i$1Oiz9@{rJf=m=(`*)~9#yc5;IGbeLT~ohGOpU$4&3LsGl0~6dgkAm{-}Wn3{)I@$S%#9zS7QUxDw97'
    'Gs5}ElnKGlQg2yifiJpBa1kGd4ftGW#Z1D51O$QRYHHZ9WKao0pt?~M#mg3B5SOy4U<v_HAs!hwbl+-9?iD;M;-8cT6S8X(Tn<Eb'
    'n=IjGwJI@9q6-t4u`fFVYo$Sbga1$mZWH@Vj3Bu>TrDI=I3_8{!HsgUICuQB9MFq<d~Yd2{!_8Cf_7b;;B3sADlH;<#LR8^;sjV='
    'P6NWGRbx=VldKSVe2I0W2z`2=j(mTZWky4<wg8}J5<BXSR6&DaVh{Cj+?R4d=+S+a1ad(6wve!Ag@z$VNUc_k)2vFISgnz1G$|mu'
    'TU3TVL=-1m1)x$8N;xeN1E}NkxUf~r7LKVkTnK8>cV!$sKzxdiw4tP;w2b(SU?I|^#6EsWp5kz!>W+5%<z-e$W}WTIy63FkE`Z1q'
    '9a71;4%yM^h+`%x$x$Ra(ZE7VE=$GcxAq_mqDVQ@@MVhnoehnO1v(~L2cpQY&iWbnXQjJ>qTC*rZoiN>LlBC}?OExzrxqBvngaBP'
    '6BfE>LJGyw(pkN;*{njBA8g7l6J)jwjXqV|kkBzK+%uAXgy;%G?hDY|H*G_2G>ed71(~-+6liuK9-C^+&lMJ+U=egFF&S=<FU)w!'
    '$y5VGwE&D?DlPu_C%Y651(7~vr5+(w{3+4eWF-*51ZnMqKo~2zz{f0uncQ4ehcGI}+Omc5CuBh(n(;W0JW8E8$+CvDYKb$%&|)b5'
    'q#!L55VldJKUD+EgBqe%ZW{ByY#-aUpz+?GFn8Z%#^qpwy%jWoDtc9D3^slXU^27D-U92U4i(%G12wL_so|y@Ap@j2!0lqn6XA^-'
    'x4!^F5d$zRoZDMbK@#Rp`qc&lf<tvSV7bKXv6wQeAzxAs{age2OjC_}k6X0SIy33Yxxk1ZF_ks(&@}jgkZa;5W#ACoF-9|y*4RWa'
    'FR<F3^LB%{jF}2_RgNe$WnPRshO44#L=SKE2|%HZu@5ZqPjMb6IIG!yZZ+7tOUV|a(_nJoPhBmJS@>yV)KZhkJxd`^`ZmK_>?tKu'
    'o}6^)BozXm#gJrkELh15(zsjAS|MitxL0BEz^-5tHslDC<2~Ee1fQ6>z>tf(czJ_lAY(916xBnv3161nf-LX{z^1=WLHK$=>g6z('
    'jzY*o7<Hw?n1;R_$Q7u7?64Jfl<3q^$Oay4DTt@0C7LTOKBD+bTL9>>`v2kipRrT<9t%KhG91K;li*G+cUfRL4z(0N)U@_f;7{5H'
    '?p`+J9XH-w8QdqAeN46w3wdz+<4In7a{ReR;>$@ccE&<!`Apt^<c9a|QRqB){`l=;G;%|EZ?d{xZ$Tt8$ql_JA7W4v;KeC{<H_do'
    '0&xw+gj|hmta5s1D{~FEP-br09Z%!};U2H5!j-0!B$in9f<-vM6}$Kb$%9}z^Cof8D6SkxinI$Sbfzv&%!o8fKRo|*adLY6wRhFM'
    '`rK2uZynEmdE$?PQ?eqX<e0w9d55A%JC`rM@=1EFMkhH`P|g^IX%jEPU`+Ta+!kj(cLukzDYH<U-T|MVjxVo{|Ms=_p?h?Esr`hj'
    'd0#F2?y~#-)A89=Tv~*1#1|9Kzl*Dzg;_$$)Ra;Lk8(~=&ORn|+9trpmvOT(Iftqik(;e4p0ga=@#=tNk9JB4!DxaIea|1tcY5ny'
    'UUq-}`u6j?chsW3D8QM#ZFsxDi@m_tVuN!<lfO4A8i#hB9DY5z?0!jZ<_iY4XjYelXQ%R7Zjgg7wxvvQ*5glZNbE04iAv~O&cDy('
    'Tm<6AAIj4#)cNl8yn7`kWI3u5)8aZ04>zynSs3A$Tq*n<<IiXOd51sb{&J?vKjgCDhwKmhkhzE-HVyDVVjDkSmhy$9o_LoJklpx&'
    'WMVMTHw+zS0YhYCoy*by$1lw0e7b_$xA(=I<+Xn!3HMn9*s_%K)oeRoM>BKigD;L^03!)_rl%w|QJy^J+Fi<u1p{3P6(EPwVD8-~'
    'Nt8fC=<4(3u~GCA4ttsV)jHBLurnKQs0^hgBgEVKDD(E|<m~IalhZ3=MKOksyO&($@BO~}{{PkYUoN{BUwcToJia*YUj2u^y<#zW'
    '+Wkb2=U<PH-XFi918>?VUAqa$;7Z@W?P?qYOy21C^I7lY{n_!+*S9}k9c#&6c{xDENeMpR#sLO7uxhn7j$(LDYUW-E?s(x`dg$n;'
    '?A~7Gu)Q!Va_1~D__}Leyh(2vWhqsZ=Gni&sKh(&@_fXA{$<=oux{eM`Yrkb`R~w|+Z8wYkhc(tMsL^#|Nm+3s|}_0$c67%o2^VE'
    'Z63LU%)<8|UbNqN(d>A^g_g|xp3=j_S>fp8!9B|rCY}8B!Hy4R({AnLU^bTd^f3<7<~a5PVzuc?9Wv8!J9p7mlvCY9JHyr9-ide+'
    'TNMt>wxO1?r7`DZb&`~arTF||nSS}Oyxj5a!%}?ugB+?-d|G7Y>QFHPyNq1r3@9BfU4bB$A0HU)Gzll;=BX|#`*CG-kFODCrGJ=%'
    '+mU<BdG3y!&z!T^%t6LGt%Mw(C+x(NnLJrHFYza}$gnWUzq{$AF|~B*bh<#}1t`*~qA|0ufL|={eu+A%T#f!^uON9*v4AIMm^M21'
    'MWtf;DcgxJn~15YQyMGb)bpKr5OT-AD8_SFr#iL?>@FatwVnvXB6KFaUY^GCfF4av>^W##&(}RYLb)3(pWNLpF)wzii;W4p>yndZ'
    'r}~f|b{FCqH6FCPD}u?vJ(5}f5l>WGa>0pOuJdG(T%Mp*OJc@ZEmxAg#WC<9c{QwcB9=CnC*8C6r^h{PcH6o@iMk30O3%r;$PF@E'
    'Ih8MNzx2rs2j~XQj`#rj?bD;BN2+d}L4So0_`VA=%-c_H6nbrOf`9&)o^xM<a5BuvVV>6(;iRoRVpk+tME|^<&u3A)TxJI?#H9S#'
    'iv*%@gv#A;@cyJ%#u+|b#v8a%nIV3a5X+yOS&zRi1NHKso*tj+&kBE*&;NW*ChO+GEZBkA6(#=*u>!cSgwpRuYv6?Q1g}H9<c^&1'
    '4%ZA}gX$}oIXX@)#3me_0StydV>YBuzdDmiT;Ebus?YrKKjpQt({bif02nUh*h~>yR;WERW`0dQSC0<?VnSmzg3htm^UxdPFgeE$'
    '{M9sAM0v^~;snmn#@YM?Me$TlV=G1`{;FhrO^^iVCwV$~z4qccd$oXIO&6!hzw@yq*uO}xuQA`edDME3wpFVaVih?3?ajthxz~6a'
    'Z#3>bCdZFXUv4wTYMddiCN#9*F1g3@*PtKas?Q%@o>b%WNi~~C4Eua!4nE4>m<sBnVX{kAeSYiuiZ|usN->rNwY{mfEKno075=K7'
    ';I3GFR&`+~f}l^&@>6~Rvc+PDNVT^|e-ylz6~Exa;@mh1QFgXYJfZ+M_L`}YxV`&DNZ>4x;$RRgXsGnv9D3Ou=9Kt!dJ-6Y+*9NZ'
    ')y*y7!Ebj;AUlQnB1rqC9G?kD&UNszYc`KMVnW9szkWnfTmmN*y<9OXHV-6wHsuC{Dei>--X;X8a<Snc*|Jl%3TREXCvhfAa+*l*'
    'F+QDI9s-Y>t$UB`T&(y(o-mSJ3Y*>sCFPy{ls)%ZT21op&Rw<hc}<KXbXBrF3&V^BwN65s)S)!oNFgSvIwUth*hzLVdHN+;B#8pH'
    'O@HNrCB`PUNf~!+x6`r5E>GN!OB?36wJHyM^4c^SxAUj;2+fl(;;eFrzG7Z*8jcc(eWWzLM8>P&UV&^ZA@DISAxW{+X7>JXSI<y3'
    'uW6hWa65Z3|K~i$3x_N9)YXvQ0~zNpHsmHWp?{s%swUq;RGn$=V?IM&+)RNZah3eJP|`9(j<<G(Qd&N^i_e+eysJWBC4!T&-5=K='
    'lV3rQ<g~!g)u(P0(HAK~lI?N}-?=BF2f-rVZAzc6(1(G)byWp#N+wt9!3q6*c88?Eh;Yvcd$jM%lGrrG>|wdH)865#5L9^Sc>Yi1'
    'pz!Wg(s#RA=2yuvXYL$AM9C+bbLQzd72}>ku+p3@`V((ZejqV*>xL!Ps(iak97h|G68lx>+V=M3gFeFq<a&M0CxZMqif?FsDMkH2'
    'Ad0n6MBW7I1aqIG@H+XlL|(ydK#9NV_*t(Lq%k%I&fwPFLOs73e0*h`q~^n)o&fmyPfw_uS}?zT#<j6q)<W4Tn_o?~8F0kr%h7-s'
    'TrwD>2ol5Lm2ON1K>jkN1Ti(Jg#EM%<AZBkFb)k|4SLc$@6AKLI7W}CdtAjdHB9~Ff5|`Z<o_6vtr76Be8K!#+`h;AUj#?U?#qk-'
    '49KMXcUk>kz1{oW@$pel3_wDEGV$gvwo!ZGAaq7^Eq8c$^^;EJ5O>6ay_}N+^+{v1U{QH^=Hyv+xFROLJ|@CNC<Jm?j)yasjKr=f'
    'XEuxXUI8fLG5;AmwR_#GuU9``9QW*}^NTC8ire|~8M|{V5s4d!@!I)6)?Di8YW`X4buYP;U@L`QRZ(JKG^?Wll{h^A#3c@c>69EX'
    '5yp)~p@!o$Mk6Y8*8PbKojLd3*by7a-k<e)64<EUvMK=f<!@Xp=8Livd9d+B$x3xtX|;gZ)fpG<&9fDbMnkh+NA}@~$R2pEKX3_B'
    '0En_wwPE$CRHFJpmiL$EpD%i18#@5Duk*c`L!U-T4SA|Gf1}-d(SrQn>-^i0Pq`rgibzvY=J15dNLfdPWLqfb%ik!&4;+V5&(6Eu'
    'IEf5;o};2<(cCxzRZ=%mkw`QHIEkmEqWpLkm4aE6r@Z$Uy<8BV!Q((j5Z$TF*qM;L3Q$5kB{>M)BwwGNpLKh^B(Lv!!(f4Cy53Q+'
    'NYb&w4KqVPMm|y=u>s|gS^VJkDd*gG$?Hwh^B&F$UQA18$A7y*Whdf2$M12evB1#{B*`84vodcsaeQ}9*%$nfJ0<fnCC`i;Y3?xk'
    'jmauvj+EM+OmgBSr;NOix{L3ej6o+{5QP0hl9Le*{+er^k10ladV_1$4itqF_FMJ6J^FpqYT+0}WU@Ft$oG2Zd9u5X&+}><$*93N'
    '$bX`QHo)yysx`w9pHv#0_a1rq5BMa;Ac}$$e_&G~dtcblSiY5RMNlq}i<F6@E-E!FC9R38ZxcRt=8^q0!8VX<qKYf0gJ+)alaT{u'
    'fXiZ4ExHXJ{I-E9(RQ8$Q(n6=ve%$~b=&c2t0aUzicm1_Wz$fPCds3Pj^k^yTO98n@GW$5|Ha3tEfCdwaxr|l(47|ne)?QiD8Eps'
    '#8(vnTj9VxdBb-8qr7{YlZD#GQXOa5CP?^Quf^>yn<(9RK7D-WVl6ir=xwS4+j!{*n6~L32lD9ms2!tjwDFhIhj^kIr~|Mx0XIgo'
    '@4;8)szj+zMw=VTrG0H~v>D4QL+m;Z`|X%}66VpO2WmEe;&;6^G<i;h_SiP~(nW)J_!xYM#0H57Z53ihx*bV3Nk5)%E9v0^&ZmS{'
    'aGWJd*=uA)k9@Ro5eLrO;vyf#8+E!Jw_<GAe981xa%^F*C&mHyti8W^cE=MDsx78T0%;n4BvZE6%PGHfFMsZ;Qdnvk`CPROt!C;t'
    '@t2+|hV~@-)vDF1Rk8^Pz##x!opjGW9PffqX&GA8)T<3~MwgL*s5Y&J1o7eX+qb93Ipss|Dwf7tDl}`Anr1Ztp^j6gQyh$1(|Aq}'
    '=*r{X4pIuaW?pL;HLXguHSrIpRVA6NBvWLi^O26d|B<i35duof<BTA(Cx|ooZf73md?Aji;pk!dQ@PQ4J%tbwT;p6<Z=O{(rETx{'
    '?CRv~__Sno^D)$(%hy4Wpl>wmF;sd~wHA&s+W=^_40v7}kly}YNIOBjz{~_@WFc(8tG6mztErn!P`tGTsP+OU^YFJ|SdHHVQrShK'
    'rdb7$dX3M#u5JP`32L@Yd`+NGB=K2LWP`ZjJ+q?dcLHY710T7zfl#FqW7PfY=id#55Zl10ZY1sceE#VqcXn~{9Z*e+TNjUv4N%ZU'
    'N#m}C?U6Hydz(}*X)==rBlw!rEn^c{nqh8aApO(v)%iu~Eoj>i>1H<LFq1(zWG`uOc)mU!BWM(!vKQnE3yCx<|F-j=-1+%Tj-O=6'
    '6um-2qkrZ$e;Vo7p$30BzdSwq>E!rJiP}(Y)d?kFnI>D*7obIx@07@7REYV|gofTi#>MIJN%!cumjkQUTTBdVGvn=MM(^X#Bq~aW'
    's2GQ#H#U>4t>laIt6U=k;Z>3e?uO0nh69hxcQPX~#IXz_O|?R_X*F<Jyp{-Tsg=Apl>@WhuBVK#d0#}O&O2I&``(?NAAT(5i;7wF'
    ')VSgeBdmt&e7rwb)Iu{B9oSh*gH<M1nuLfMzg1r#V^yDbB4IXTBu);Ge?Bh#jj-Sw52b|QRH~oacTFVZergawZ?37L8%^;Fm4?dA'
    'r^i}FO({Y7Z!B4RD)={RPbxp`UL2pEc1v5eA38Jg4;`xCs%hSv>Orm2CIsr#)@lu08B<;k!tGjSRLks5y)(;1ws8$#^rqH{M9pMy'
    '_pZ8^IT-d-`>aqaMvMV0aSir<p1K;UsaDfwI9@j@G_2yRU{-ckR@qTmlPi0o+TM3hPsoB5H8nSDiv0$wVp$eZoN9v>kEp4ruEv5&'
    'dJv^gJ3++mh1oJm`PZv@a|?*UK;9mo9G!nIRdSzp0Et}@%dA;V(P)BDtRz4zBXdPm+HkA7qvd8brZb3)wQJ1gxSfi?R*R7;JOnM{'
    '=hSGl)+(sBMpY`*!DX|mQu&%*`Q80ne^KuRx3w<Y`l8Z0iwF>%TUuuX&7Jj`)~=RXagFC^$6t=$mbg08+Ndvf*-WUACP}=wm6h*Q'
    'x2t)k8P|4ld2)2}nc2Y<R5deHl|CSB4yv%OSL60oEWLrk^_^8VzeiD=*4I7dL9>IT@A<r1Xc=l|l?(!MqGlMalBSKV3b%ltSKj76'
    'U7UY8X5brrMWX+_Ld0ttbxYF?oDLW9LD!inoA+ln$@!LLnzfc&s=?j06@RMDwE>^L2<a|gD>c|*IC+VEgyPtMn@84a`~6wQOnrZT'
    '+$)*&oO0Y{bGOu}2}L3@nmOgmvB)qh4XK!q&!KrtQb@*T3h5&8@rRR7-7nqClTr&*GIaj(-SOG`pFf|Ks-*c$qbd?l&hTaB2$sR7'
    '`AcofDECdDKKBrZMA!n3n?pFZ2vHI*B^(Z0YSF(s{iE(F5nGgq7faZFLUudOouyG&uj8;>?0_IbL6VpiVco%)G8@f|_MEWx1Xl37'
    'OVn$y;1h{1*<%CC0V!9~ZWA@TItTMS?22Wgoov|0;ZF9Z{q_qVmV>jsI0lHwsxt}33pc0u0aj>C5Pt9|G3SbjyoiI4>~xA_mb}Si'
    '5zP_Yxp&q4#*{9?`0vADF;m9LbsqjGu+zBK_4sDJz8=e{(QC->nhrQ5e4?w+xx>QcVt#uzK*YoGVQ&z6v&=*Qrp$khhVI0>4|TE@'
    '%KmIxPJ*hG^*_~gLpRD;c#%mbVo+Xw>%`poa{k(c!vF{pUGDTC9GB0|FS|$On1<!?OrPD(4wwjbzDQnRFmyj(p75E~xJi#FR?P3c'
    'JHPzYy|U+6(E5a^LOYK+(fsok8mBfPqDM2rR4M;GJovj`R{46%$lj0ic?h3ejqh808w3*<D~vK%!rp9O0K>LM(Ry<#8D(z|_pXX('
    'jv|Sj#okCcy(V7Ww2{qRUftV6hP9btQO3r7@b17)Nj!fD5P-HQg)$^yO@QI~YDyI=B)4a65kIk!OAnKPWs;A}=8)tE<>W?Ggn-2H'
    'HhmfNL9qh<WDluNu9)S}&sDw{w~^-~$S<P4`I;}L6p^8zm*qGf)TZQ{^n&|;7&*S+p2I|K3<%iAKv2ApbP{2sXgsUtHEIJ5T%gEd'
    'B90w7lQ}|3rOV^37>`Ipxj4@A{qRm>JDihnZC-O{!Qi$H68?%H0lz-u9$VW=7p^`hhtl(5hzUh@E-JV>J?1F{In9j)1^FU#E)$Hb'
    'FGJo1mcs1Cgd-s(r=B6~Y$5J;MVcaa!pC)NUJFb;WXF+4pqY#g?z(K$&rXG;95GbxM`fely*>Hi-X8tvBn_1WlA5BCLIPthhORtQ'
    'gYwja_^F*9HG>+`Z=zu83LLX7KFCkKr8~^a>9tKkaO>Q=Ni$POTaDe81TR9Kx~_vpndSrVb~9zouL*6Q{CiF1Y>DsOzx`ji?0}+_'
    'fFpYma(eGCs`+$!?o=#B*(#sTi{)?@Oh!QvlgWVv<`NU>nMphPFnTewzPnM|?03L_Hzqny5zhyszcy`{wxbtgoWmi)8-=JnP_v6j'
    'ESFGrR=lmV2@!WmgvK`*W+Y<76eV0?L(adu15b$vRe7poq(jy)SV)^#P0#K#a(Na8GiQwHS}ZmgXvysDG!jRo|2Vr}uj!8-AIG>}'
    'XI==nI3+d^_iLEqLJj-OIZJN6e&)Q)NBR;6I&tA_>Pn<qo2idT#jT|GI7TKIc=MIYC(2~cipyl`OD+4h+IUNku?#k@#+%#J-V$k3'
    'LoLG@(>~de{>doPfG7;-+Bv;(^qvwpY>&i&m!8cT=_2~>r6(B6q~(mhb<#6BKdIU(lf(xVshMMKm$S6&xmsGy3Ii`KdM?jFjZ2BN'
    'Vy2Y%PLPq3BQI^R;1G8tSwtIS+yB(2|HNTk9E_)KZ;$2q#2I#qug6TAOkZn}pSBn8OTJ-6TZ!vcM0*N@;;In&0`Jn29_f9siIq6t'
    'Q;A{@y|sHfvFHbH=*ogW{;1sQ(5crE|Bz(~H2ml~;vaq|Rk^pvKa@&;<3w*R-_`6X*VCjrCW2_Y76=*r)#U|){>Ba55pH%!L|*(g'
    '4T5A{0>sVUo><kNG-|z$FifOISg*xKGoBxlQr8=*9pY&(vIC#T9C>Dm6_l#Wt?^76lPEzbC8L@5ruai#@lHxaeG)K}n*cU$wv|1+'
    '!4AA`kb3P$n>+Fq0Ff^GnNXHJ9qEta9-a7f+sx2pj$kV&;C1nlp57G*zCmg^6jO>3A9j_TCTJ=0J6xzJ@-a=RggBLtq=H{8J`1v9'
    'ZqfF|nTc-b1w-(XWU;I6=Q54sXDwGQ<RX_)97b53kQ3ey-?Gaj@NHZvAba&no+%ka(>9qTxfoIy*qc#2+ZP7(#vm$sWxsI6OJRQR'
    'cuFoo;0u%nMZP{M@@agPIE981Ck?dM$uAG@O|0JQl=6>~>{^E4D{U##Vj|xpTSN&26L`$4>qz+y?qa%G)z|6v9a@o#ouO8I*5(GO'
    'crSP-%d7M3DazmBvt2FD@S652ml3Kj+B^z^dDkCjxGJ40H*xkHb0!XXR0W^mx**4wd`81@sC?6KBui6$`euLA=fP?4;D(3fXe*m1'
    'D{q;m5w8#2ET7t&-&8d*uW^b?_IS0f7iOmAlS%i9Sf(l60&)ht2?~6j<6eTz8Trjw-<af?>xHUT)ymq|yQhP9gt@J{bTRp|POYyE'
    'JHz0~vAZXi7w4B(*O}F{p`sRKa_oKFbo#%$<j{6VDE1GGc5>LHBM(l*F_V3M?u+w8A8x&gs|???3}d|>?wjIp(5$%JS~mcK7Cmj?'
    'Ot3QNbN7_&&m;c(w)=(tcHbdpe{}kR{(kOao9th&c$V=5GjxC9l7|;~{_8vZ?H=Oq)rX(y@5fU_hq`A-Iiz&VFPQZk5!Bpjb+gq{'
    'aq7;(C-1wRR}%A)3}PCrWZPa}XIg!uU1!>TbEAcK?V%QoMr{BaYSC=iwyataZ<QLK$=P=Ffi@4?efoi$=_F@`3Od4P#c(yW+u<1Q'
    'XNZ*^-c-!jtIyvLW;tH?9}Z>_=Z;3+083TJSc_g7c;R5;=D594uJ6ttaE5rkxXBV^dnc>os9J1@i{iM}3%dZaD5L&ITk1bm%p;Q6'
    '$x)zpQ(K`FqGyrPXTyRrFUescj7$Eb{&}Q_cSZaWk3?ttZd&F?aqPI*mp#(CNsw;wBT1`KsA}JSvsC8B%TZX=4FfA+My!BwcsL$O'
    '-{RnKdZeCXfc<csIg0!np1vVwnj9eeKCpph>26A2K_RErm=y!dEF^~_=?*8gz7NzwqlT*QL)(Zg5OIrVY=FycQS;I$wZcmP*D}OS'
    'giOqRlgz7;KK6%+HzSUbb#aU=T4re6D*RB3G|>e(ni53c-FSH@7iS3=GE+c$PS4fs&StRT_V(mMVvvD_$sYTEn0veC#*r;S?0tR('
    'N_|@(iXix{q9}n{byam$&6TRkB~|y_(a60Z36W@l1RH=Tu_QU}iyhvu!yDoC&UJ*x;Ri?T^E^5HJp1k+(Z9ey!RI40kpMwS)qN+t'
    'w{M9+B0o=_JbCiu`QV8LVmcsouUq-*rc&$Jl_g{ULRg3+4HjF~1$)7zHAS$cZnJ<)%gneuXf@EjL!~Cu;3BPvqu_8Dp$aw<*ddmd'
    ')@hl;S~6^8_v&coe|JZIfqN`L!m!Kt_DIi!k3W)?+gq8rCURqDAj*(7^KKMzfaw?H0n*`lB-0_!2-EMeV@QM`WuJb7x$aOqbGWKS'
    'Bhxot&F#J=om4}fLAzJtms<~Q0hu(n*v)RaUu+&xFlX1uH7I2B2-$Hpy+`7EG_Q?AF*x?pIu5h(1sJlphwl4$v;%rkCM!seaqNTM'
    'ZZXxn!PIrA2;Hble+3yWb?I>F4u%-^NQBeCXZtcIrVTyQI;ib7Xo}0e!6)Q{f#>)hWl<Fjz9E_)3a{jGf^iq;Czq?r&l$0-{7l;3'
    'cX!$5&#R6&IZ+2>B0`^_mc6BOI%nN;_8Pstot*86XC>*T9XCN@MB8m8fpvR#XPTCffWsk+K8j5+L5&1l$$hK~krbc0l%|q61@|tf'
    'tu0zSpl5901(}x8js|HBe51WFIoqXY*yJF+NzXu#`p=#vXT5XO(^J$><EB!JHbmi~#>yahI8KHc7%_0K#ylyYd7~V_Ja^z_9=x}='
    'z074dgUk~k^PH)FBVgtM1wifLJls4d#y^xzK#!74lZDuxlQJaLrr%J@x||d6kaGPr^x}vtwduTorrMS41Gb3I6F-_El%G58MyE%x'
    '_K=*7E+w>~&?Mn3-DU^=hj6c;tz;bi6a%FATcgo!^k^DNTgO=eh}J4lG6BZmr$xk-5`wPJ4Bv5G;DuBri;yCiXK5Lwrxi^lay*T8'
    '$Ms)b`7znpNcDb_4~iQuW!H7$hd{0H3mhzh_#_^2#05X0DYmZ?f9#rO(LiQ6<kJ@ue_e9GRRTOBShvaL%7pcz(!8rQGWDyQU)<sF'
    'z&s$L<eJr?pifnEn`oIxibN6;DV58+;an<-C?a$f`z~BeYvg0Y{hH`yZ4PW)6!R^cw+QM?I_iMUW)%)UdkhCr8CHY2&FluFbm-#x'
    '!q44qK=-z{wagx@$`T;0IpSZBSkSP6dg6-UIB0ta*8JdU#Xn%mgl$97u)b{7DdtVxM9V~tB3DgJistzwIIx%sD6$fx0?EdFW_Yv`'
    '4D7X~f#@r{20SzBVIdE^^nYImb5(8VW?_m-4YAm8!4$WMiR6w@rv&43BrYb(V=||%o$4@8c1<I0UpB2~aru$8MN1n;B`-U&Pmm&4'
    'x|xeDh*cIZCM2DKK46GFYDmAXc=|z!ZYmC6oz%X|8TnOm*AN!l98Dv1p_Um7$+H!ni^$X8gK%IAF#iIEJT)$$A-?%rYv$7T7uXD1'
    'h4BrBJQrS|Dnhur&5={4#zc!p=!XvV!qo{&230`*80V9NDhMX!a^Gon575A8c+u*ZeTuPQe&e<MopzUAU*Nm2>gk)`v|8h~@0+^t'
    '1i0KJFFm=Xu8jRzq+}tl+_N(iT|*?s$uCzPT7jVEO1Ed%UbIo4pES3Bgp&yn$^>?8<GVN*Pf#Vi>2%RuBRUvuHA$`IWEu>wR-W+^'
    '&GE@5s@-*Vx~OQ<-gREU_C~o@<GH^wDCo8EHUgA0;gHmJdflBKhBJ0r%`Qf1Hcx4~k8wZuf;nf}-DyFlp3`ZtF6t+Lb@{Wm3@(kg'
    'UOa?FWTJ*#v)gLhwN}&FZBx8v^JTQ~M&8hydr(cQ<?Oy_qJ~V{Y4#|<v-#?3=mo~H7YCT7)pZ)ZM%V6koo1&&o#9W$cj&zby4Y(&'
    'HyYUK-6kmxMIlD_dILxWqkiG^n!Bu&<8)s1sDh7y_vMRcoOmdAi$@V^usWS~rwz;5X}5b~IAb*r(D;jPdlzflX*GK1dKky@Yv7SP'
    '7}04C7amSC(34l0F3*^BdCG)9l(!nNGJyH&_3;NL0b`2i102#AkI~2=jgcoMN!%+aliAyoHP?b%L(DBx=m$`><S4=<^W|&}j?nAc'
    'lZXH{!x3bYLUY7gSdM|$t!zvv%)g9aPU}5!q*&x9Z#=GeaSVeQ`k}g_*?bvIpbW;PH_uRy2J!6XnF}Z@TIkS|rbrBT19Y&O113`s'
    'LyATwX*YIJ(QXMnk0eGw*RVE74~0UMM$jQEUNvXj<9s#B8A0bJuEcWw{hwYMuRfg0HU&@k1oP)>e~67c&|o?nDP~F3V`kBff6jpt'
    'kTXcH#{Tv;oyI5PMOf&<j3jKhZXvvh9-Ee&V8(rD(5&LrG4=~%c0~GWRz2Z<RcnIRfEcaBcd}_`gdeei`{y{cVKIB~jz9MjpBNu)'
    'Re`#47YTUR?qxG51%(nC!q&b-86Y=5%7j?2w&b2)P8u#KvHg`A66*%?a2kVN&6CR5x*faKu?(j&b{F0l68D~tGcQF|#w(yWW2Gwh'
    '1f&^VUoTqDI7*!noUo#09rxt=7^(qAZ8S=k^yh?PC5y_X0ewy@#lv$ymgVy);>V3UxN)$wrQ;i-Suj6g*E+~i<B7?nRGe;fdY5}4'
    'IY9u$>i;$Nx$Yq0s;p;lMptp{&r@=0@cGk`RX|dJHVx`0LRIt<C$TjY4j|RTdmVk%$2B}wrE&<JpNfrW{Xoy{Bn3pD^&c28eusJg'
    'AsG7+j`iTd&*V6Smyqi9+=tD6^%1qM?yWo{ELT>3Bns7wxK>zbzj=YldN-^v)$G?SG2m#&E5)g?0~9_^)0aQ`E4pWg4{+|~c3z_('
    '-B`gkX#9wIFrqq=RpapEJFLNAJKhRKTgS*Oa2%q_&?keHImci&^u7=|?C~YdjS5<B;55-8=r_2+P`#2n18oP(wtR(yJ#g6md^-$a'
    '=W@G^ZAJ<>vC|<|9opJ(XtOC%JIPTZ9M-nQHKZ$1%O*@r5ZM6>Zl^wa{Z0C}=1q-yRD)jB0Fc0g`>Xr=GCCqUm=kqfyMt?mzT4Z^'
    'jPObJB$pAd`)j%Gug5F1dM&DaC$^|-2NrY4i~M@S8o%DS#B+F2vU3%C<Sb$z=kV@s?MphnnhodZdX5%oMQao_l}JPfi^{C#zOa0b'
    'KH6jte~r#^2p0G&oY<{xmDKNSqomiu>RrRTuV2Ti+A^;j1i7cJU|bU~uaY#%8ylDNgW{;n`C*7B0AYN@6P#k-M{BHm(X^NdIM;D+'
    'k1Qz#9LtW3fRq5A<C;*rS-lFzl|oZg>&VJvf^r0V3Gld;4UD3u8L;y;ngKNQ->Mk^{Y76p?k#y|!UHaf=yq%r-s8P3YQ`-5c?J5J'
    'i6khmL;Xzwn!q&75FW0}4>Az#UOvAN#qiwWT?RdjLiAvhWkWMeQH_eYdJ74*ANDtS92*BqSOdV@L5HVd!cGT}D;ILyz0~nTXbEN*'
    'cXbz`o|=1F-`Ihhm@!gxP;a3J+d#^}`ksj*02?cNbYUU9!wqBUh2*YHcxxgtNX4={q?Ae03mR;o?kfYg0MB>Gk`#c7kbt%W6<}7u'
    'MT1&!zBlsbBR@Qx193qD@jbfWsiY2og|7@90F8ya20hU&X&k}6sOfkUoMJdl5teFwLyH5zp8!QG8=;a-GK?<-+M$4=fo)HNTSHt='
    '!s^gm7G6~=R~hn}2dD|X4TrV^B!WM|zLZ^wWZnoWN+2|H33fc^s8|=jJv}~h&3(WUgK)sz8hMMY!TxXnWG5L_c=bT#`}N^qKUsKl'
    '{ws6G{%8xbRz~WEmkyi<=E=Kb=-01*`S-@ryB}VgR09<^_B~??2;gpgvqkc)+Ksz~2)Sj@mg8=nMw3bC8*h(J#EF~OwJn3(m_i3p'
    '%+>#9_hQ_*xY$EeklNTEMeJFnKab}A9(9O|9hlIKaR8I#t>`0mWoz*3KmK3)b+5cLgo(xGE;h6URsGX{#Hz&b_Ui!4fez5wJXMvE'
    '(?8Sz`F4-J^3n5_C?)SHaCUyd`;QYp1nP_8+cVKQ>f1S-FC##LV07vF?%>v^{S%h^EC0f~3R8)nyrf8EAj8^*OZTDb5#Hx4Ar6;T'
    'xO}u3l1aPI_*XbN#?2RS?!NGf_$XiU_-M~cJLLf6@KFAgwR`*6;)O445HZsc-_&gYal<8towu{K#UbWTBGM!d#(QLuQ43Okmh?wH'
    'u4jEx_ax#BUo?B&y^ClL>CMHBaTU~N(L74ffzj6B{RabmU>_ds4`WzbGcODanD@fp?GAUg)Pe*CMsPiVa+qIY&%Fw}TUd=&=1TBU'
    '$CT17w%cws_LO66x7BFu%^Yt5``!5E6p0G@K$C7n3t>diS*4u-591>43A*>Z`JyWJVj+wYr}@~scGE=pUA@MZ?J2fsr+^p<-HppD'
    'zsr?75q&=jkOzB%8iY6mb~`^+F;_h}%3RF>t^8$$H7ZE7V!uR}olYwANf~(s3RHVmy(NU?(2|2}4bH(y8ZDsye;ZGRl|S4z8`WOp'
    '`Q=^X-u}aFt5I#X)LRGMUhtdsZ%gWE$~v%ER~2jL-nv<pSjhx=nUGvPyHKHc{{(9!^H5%*bBN&27dF3X44bW1%iPQRZ@u2Tsk+UM'
    'M3Ny)eS>t`b{l$QH}<qPoYv5ivt<vb)m9^4y|_MLFJHYLUKq&sFqANS)qKQKRn5-cY9DHZALu~C!fUCDHE?z;z1eEZUfFHCvtcmz'
    '`PAmH)oJ(4Jd~){*EaSzuV1;NYt-Jjl}b8$-fldv1mCs}n*CbSLMIjt>)Y$<HT=nS0JA8cX5=Ofm$_MlShItk6<XHw9lM84sW<3%'
    '<^};M;#FGRt}XvbZ=K$JjGXdwr?G=ZJbGLC4A*x4eQLMRyJ{X(qYJ-%aY41f!gbAN1BjENOtSV<TG6nZe?B@qef`QfeSLCjd^|io'
    'ef{Y@%YiRu>F3jz6}hhL9T+x-H%1EW#y$}BBrQ;HT=Td;JeEbu2-fLZKwcDqvgJuNCmS9`FW<teXe8Hr7eM$Epc?*si@d>ZX|$Bs'
    'f&Ds{9GIJ%oc+A;CuYW;ZX%`VT~vB^rWQ1J(744E=xDGuO07-UwM^^ouEP5(iv5_YQTOXmy_?T|KyCJAPNmefsk=**fteUUdv=uq'
    '$tL}br6XY{-|;zlM{;gX%8z2HYf&sQ*1|_9aJpLf6%+D>!uMc(IUi%W5RS9}P3Wj;Sxa_=4S=Fs)F<03<7WSJ@^6}KrHpUVK3Ve)'
    '4c$SZN_6eK#q&S>af0OJYJnQ9KAcXiTfrOn*9Lqfo(8L;UT}CSL=ut8ahi_(ap1v_`PLWb6qpU^pc-HEQ~Fed0X`J4#E(Bl0Irp5'
    '&ZC-4GK)AAWM-0dL|{~2LoE?cL!7p5^%Ipi@}~?VK2xdHMWPxs&>_6jj$|cln&>{9!mMJixK`}hy|^TkXCt-Q|Dghu$eY0&nHvvG'
    '*BrsX5!@F-2Kaah<F&8IoSA#qn+`bB@s>Er{Q8%FM?OP^W6_FmZ>Kj7bXGF<!>crn)WK(%&W&Uy4h`NY6~_jYacm7<;v-TaI5klz'
    '#o(9Ez;$lg5XhExC_W4Uzi!VQ$H_{c>&10pffNu}e|7JxAAWfK>FDrJq@>V#g`xT|WC9s<5fe8z;Ak9^$J8JF;hQ6aLXYej3phUn'
    '^U0nO%okVbzk=h`!^OhARSp%W*b9CfUByWhOFxUFOOoLbooDGyLO5JOthZs2i1mRs%b0X<D?i+`buxNzRA0%u%uCG!_|BgXgP0YJ'
    '(Y`~otffXwTiHB|i3Q%ZlC_BaAf-eR=qLObC7A<rWfVs%Bq>qaja`ze>?PL$5+SyLgYsVDQ#bou<SZsmI3`XwMg>5WjX)k$SlO6|'
    'm8&@;$~61@6r?NhNV-j><z+EECCLoNJ3KNud}OM`%7}=Sc9qM|m+wyh^wY_QPr!A!_$=gfmXly~o{DD=fxZu&MYO1S_*Z%A{P2T&'
    'J6iIzPlUh=FRp3&Bl4bkZV#_65}~Z30xj}7TEcNg1UM`^*swejcnLBYL-zYNGku6N(+6r1dD@%(7_F}3v)1|c_D%JAfUn!zD@bl)'
    'avNW&(*eGgL|NpDgx<So@;sAx%5YfJ!HJ!sw`&_tj<y#Dlevwo9sGf9jF?Ph^zaWHAn7bhQYibxpG3a#`JJ7t5}2CWRbVIHJgFsq'
    '8~}qTN%h2;`Cf7rQ>-XB#PdN>UYg&y)FQ5nk$G@ayRNtTDkY|r{tdee$L>h$PlBX(Qv)u))&wrS+OeB$D-Q<__ktl0{U7;k3d|`U'
    '@-O`y%M7e%vtv8GF7d{g{cj`G!erG}RffB7d*~ND$I}DY05IS9I~NVX7)u6N<}N}V>7H&NE8<b<!KZ$7*&yI8{l3Ls_~|KL)L~ql'
    'iik@@hga<xJ4Q4@9rU0ED~A!hLBTl!EhUJ&Wl55iJaQ%|s~TN}J_}{lYh^;)?U8ep&iE5NV4@Vz;_*6Bxkh+BA*9lDQz1VLqZn_m'
    '_>*|SkC`432}m&MG>Q<B`Km`XMN*Wk2vv&a!CWIg0a^oy_hc|#Nru-lP*JHw$Y0?t8v@_Eia~hXCyoAMghQ@~6R+mSUVMo`D=G0L'
    'm~p(JDA?ZCUZ5621sQ2*>W2$}feI9aw~^@bWMYT7C{wmIf!*E}5n69lkQHH59TiTgp)_RCPpb<z3{kR;3yNY~q3KCxjsy(}HGNbx'
    'hYu}Q(vN`QRc)`?I-~mlf4;pfjbOI7m5~LSebyE?)_}12Ih^LRYRLP6KSv6K;_=fcGcvXIFdMBGnm=Bag&b_S%K~rIsUcHigqJcM'
    'mw-W_prv)grb}k37%lQ3L4)IU?6#hZuq4k#0I)Li$_D`}&rK4zFG)<4K{z6`T3XPZYITprDP--PGa|aFy3jo)d)Q;x0RV~_5O3jY'
    '&ApEIZt(BD#BrH<aZ@W~u2N?Fdk-VN(PoZ{XmfBQz{`;0+n)R!h#dD5W*!ObipIgX293KrITYqgfDu+)$zm~P;4H>jDJ`ZKnhfc-'
    'Q1w<FvOdQ+^*iXYH@|EYVbT_kPOQorRl)wGbTIW7E_~T<I-P@dqmPemr+d)s(qr$S$!V>|0jG4j2Q7MNHX8@czSETzEd<9!<JD!v'
    'q1SNL=xVzSJ)jM1w%3w{RmYxK&*?Al9?i`1PnH<@aA@QL)j|Pj0SAlMO%?;U*Hsa18!o0EphZ%@&~P+|hBaHQR;j6$-jE$eO|DN>'
    'r+O95t6y204kQdi=Zdg%q`)M?(#c(!H}R$nVdeb{r&_Gzc?JIt-0nfU-&Ix~vkc%(n=`;{b^5wbM}Zu0G6Mz-7(BpgSO`OZ63hiw'
    '=NSgfc~HTA9Wd`e9_o55ZgV;<%j~a<;heT*T7A9LZqIJ+^!Ve3GR?N;%1M%+Fmhos_rho&ew*-HrSYqCc5>`yVVa_E2}0I>)35E&'
    'IXgLi=DN?G;UJ1mz!qtu`wj>_4O@G=fQuOK+}qC(k`kMk2z{9G4D5FgoNgbZ)mu=XU_C<*5XKfZmYA%3T(My#ZE=up-4_SzxzH@N'
    '3N3L%G}wGFDr?~GHr9Na<sjib4H7v5EXnuxP@JPi@<}X0ln|7%A(Dt(D(c9zOZ%dB%N(dB=~<M3Z?Am9tJHs-bu~Fq9#Cilz}G=6'
    'vAJU1=i-iWZ&7RK$kj+O$9Yop3HK765NNhIM{c12QG!AN>69Z1U403m1Mr4G`(F8K*g@9(Z=SRia@Zl)zyKk)y-iSVu3^hH?26t3'
    's2LQnBpMK7gaCnq6M7V}WYk(bE~yr-t*ZGi|BPBh`;7zhN3(xDfZx|J2-6~$7u7axmbEq=u1pNzK>~CAHqXwa=LJu<U$X}8?kejj'
    'Ul{lrvWrpL835)-)&t{(w#0y;PcYIGvmbgm<oCa0$Wq!Uj}8>MSNZ(OP9ix~jj?|L>j-GJ`TCbDjKXQ2+h?t|(`oPQ*yd>*Ezo<x'
    'h4B)vf$3wd^y?xHMo~P+3_Ckccc<O4&BGWs9^)msJfNc4r+Mn-zn<eB!8%BEM#E9O@^B^Y*j+^!<ldFvPs%pC0}cO0NCc<b&94jG'
    'bvlsVQR^bVYn8DhS%_m~2$(})mO!!rz+>&u?k+y6Z&m)bhcH(H#4$^N%Sa~KX8b;)nbYzt?oR7#zpW8KYF%5=8)#v+x6{mFVA6;J'
    '$IJ7i;urU`TTXSN*aQk%P`Mr`=pvn7Us_}79ETSTpjdvIyA7g>ypGVBETA4OCzioz0v8w(FC{*a-#&;0dk?WWSr-t?2m?Era3s%$'
    'tsOqUz!~YwzPkf|wb+u8i>Oxp@|-r{WU=4tYNy0(wrT_}%Nh{My?C5YflY|$W3NNxvGdhCVSZov0t0)f_qF!#>OXXNZGWZhwcfLy'
    '_o^Mc_5vLs7k42VM-g+(&!^~y`%8vB8tybP{zMxlZWnQ9^fVeQ4^<?pF}4jMm(h+^QixM}teOURiW+p_q=v`w#GM8Qr+yrJEc;3N'
    '`pZ#7Ou73EGBx=yh1@xvvs!SxY8Kr}EK#Xi1%Xy)58<j}sd=d=AZ7`D)DgLq1~(n-!IOzK9s`hA6SMN7yWtqnvvPVvq`^{&Z8}7c'
    '@zN0yaOTF&Pcu6C&sgS@+_()pS>c~A!e3q{i-<E(gnr(U$@QJaT|?davPYXRY%MGCS#XXRL%+C0lAEgg3wfPe;RAY|`+^Ux^Lwdu'
    'g@u=`Fsvju&>!dxNBu=-!C%`g02uZQi>lA)rB`{88j-gN)kCeP^-r&HmaRR8luMpcC_5^ba}jTxvuw`fQmTHoCg(kBM$a=^xT5yK'
    '3?o)n5$CEc$#`rOz|CDX-ZEFv?1C+KR9m<(oNwoAa=0c+iC`#=O%k{NpG9pvK3d&s_lw;D$+KfC+dHR$#fv@kF8%VX+F68DPL&M!'
    'Hn;b-90mVPd{)=)5HGQ5g?}a2MWnM;!gY0+BXe*o<k5*vtMLuRrK;R&hGa6aa0h4F)Sg?`Cf*}Qg|A>+H%JPu5nw45zb)B)#o0GS'
    '#`c8e=LF0k70xn?yAfVWZgjasS8rJ|YP-5_kRnqLKMrXb;<ZP|_nH?MrhVaIGG2WMf2U5f*B2?d>A?Qb70}&X%c@qOav-<eext~R'
    'Knuldmcq<KMP3vfob`aw?w_3(EM68-xWX=>mlYfkzE7gLd3UEJ#(2q^OJPT6`7~(7)D%^;FEf($=X29VOXdz3`v5$LCgUv#-FdMW'
    'keUT1>n*JdsNg)Jd1pj$zUX%y3^Q?h_}MA}A-=Eke5k5iVDW(E&*5pl-6A2Wb~T1ROT{Q7WfPm1L}+Gmg1v#Eqt+)m%AsTBF4xzg'
    'A#!*7h>QRmiG+|m-tl|l3-QdAwTU?}cNz_&*<Reh>c;C#vIJUVr)_e)tlg5aP5Moreem`P+Ht?xw9`H>7QFKZj0ZNn<bp)UIrKkJ'
    'h8~y+^-=?2pe3#2<4ZD+mp&rVe*<o0jHwzTLB8Fc;zZ>L5|%}Wz9TQKoZ$<UJ-6&ejv(pG0y%!uQ8m8IGpEXd-8zGMF-u?JUJFIE'
    '6OIrIJkFA8K?NROHxDg`c77RDo-m=UCrl_EKElEZMbs})7xWZpT0jyRmh&XISXFq!ZDu1#-Y4&G*2$18E9P3^3U)brY0^uK+g531'
    'MCGt5R-wSxPiTZ5q#}EH59ykWI;dUr0TnF*T^c3jFX1rPgrf5thKs2OoQO_)^e@f(2T(Q)6~cyL3A(a(!3QfS6cB@1C%AHyH2Q4$'
    'EqL`kgoJn|MBmd-z=m9s+>;8byx%mu=8Ja2EG3*ef$r+cyu<)1;oFYAlZ|@AcVs66=trZpQ|rUA9$P%UlC@K`L>;*~MIOXK9kdze'
    '&!CkD=b<P@L|m4FmmJA~ca7AnEzW~pAH9)f`-j>um>|){&@2<KU?IN3K>UA{hU}EUA-5L@m6+{qfo#&L5^DuzM~B?!T2sGq_T<hH'
    'oZCb7jA379n&(n<|BEYF2k{I$JA063V+9jG8gs-aib6QVry-sPoXeR`(RXa6(f%Y+!~NfsF25Y}%jz8(<E!*NZe`dWr7Dw`La5t}'
    '&DV*U#)we2!u5-ihg~b<qeEn)j}E_keRM+Kfir$aN=i8)Ito16PH%fVbmnRjI~(Ne?8}c8+=_t5@@e#Wv5>~5rDC1zMx<qFIE!)7'
    'P;hdv+ix~twyS2jfKVgjkp0Euqm9hpHk7r_lOS<dN=Rhir987)-rf6bqDDa)_)1}F29!SHJ9{`E9yD2Q)B(nqFYMbaP}(6m4t;7I'
    'IPHET#|-lw6xuWFFexAgSUbQAaz*z9nNlHvXM~!A``is{82jF3{v@wk4iS6`C$HG08V1eAK^wZrFYSXCT>$RxJ<QX@Ydnq4C?Q5R'
    'opx?UMq);)vACS6w&8$ae&c%=Z6bciD03%z%pTKqPSxBnGmkP+akYySkaRtX0*-Ja$gOZK=1jKAGqtSsWv&)>K{XCZvn#c`1bn}f'
    '+T<6yhv`f7zJvkPPXF}r^@&ya4qdt8ALh4}8l3c!l%!lQK5@JX+=d!T0b#xp?P7d{0f4Qji&oGZ%G@I9bUbnKgH+0*kPt<5i7qqA'
    'XLij(p&o1s>HsL#mml81hZ{&<!M`s;-{@I%d3T3Xv|sD;!{Em%JvC)g^L+3Yj&Q2w?_?+to?=ZJ^w{Ln=0~A_aORVHoqZ(091+#s'
    '-bQf3Ds60USDqm>S#5~O_+a<$E>W8|Mh(xszkHW_|MBlAs#FvY@$Jp)4;Vu&0Ro1*c4lMGi-CRq^Lprt)nF^EP@^6_;p)=D5mc-9'
    '_XUlT0-~u68*z=MLwbhDz^zlJtTUI;4=Jqq;v$T;w=Z#w7~Sxo)d%8HAQpL)^E5eZ%bF194_kV0UQ52zTd=PqzrfGQ7n0~onv#p('
    'lZF2xeCOaQgjfjRag64Q_^7!U7_Q!p-C*nvgkOdEnBy%d`+KS%ib^&c^Qskrr7OZp|5<W(CzeI-1{lx&CDWEeHVQ$KAa|{E&7D%d'
    'T0fCEz3xNDXo5l^ya{>>FUa+BXPg|7#)vh9n*}bYB}AF!w{h9-PnU5Icdr;nq<G3-=fCcC$YDs11sv$oENajtQ@bo!2L_2Lmr3ZP'
    'X?khDXl)eQK6t+Q-J*<*XFL(`hvNJVRCJXj-ZTi271l|oS1MuA&b~=poP4MKkQgq16fQxN?QQJ}V-uNIV-QiI5)nM;QB?0d2=hEW'
    'dC@{jva4NVAmD??B%4B1NcTo%LPEg3%?n4zOVvhxZoDvkf-Gn!<C`9pe0Fs#+O&JHM6&k6<|=r@c;F045=Cj!Cix)cs5;|<SpB>p'
    ';x8O?icHWjn7DixX-Nuv>E32;TF-zJS58{#MS5tZ7vZE8UhbcAIe>OQ2inyDn=%!4K?>-B=1m;WBgY_@M`D0Ulx#{*u_-;trt}n>'
    '(kn7Zo;$oe!=~7oE!Ak9Yg++;CyRbYp({`q)lQ~aM5w7{kEU6`sHwH*Wvowi=Xo*}$KB_nDb0Va18KFk)8Pb^O~Vr<BwCJYF-Mhi'
    '2s==%ky?{mXfk@`-h?n+6UIHphQW{zdi@SEW8_yDr|II}D)K5L<W+{38IuB#96g0g89kZv*wJVJG9QBP&?tdNfodteT}<zAI_pwt'
    '8t3<URz)x)h-S*9P7|vX*StXZl4ZYf$5GXmNfWtwj-jGpi9XsgF*<%Hs^#;+8GkW`iYWKI*^|L*)CpwnQ}M~Da#kn}K*8GW=GrFL'
    '*~mk*J9ewtv|H^SoxvX(D>h9{$)))S?@&gfONOg0^v9_6?q7vkqmwEx48?+K@rvq|6YLFKz9idu6&dOFcZ3nV{TSF`T}{R-yQH;8'
    'aNu<T_%m-o4E3?MSf}KBMbQJgKP#c2MG=D_oDE4g1=VawqFE%Fmu`iijls4<OU7z=QLRwCHkC@}ULTGg3vz_Ww?EH(>(+N~Wpw0_'
    'whhdJ{_8GnfR^u|2@76o`Od1!oQUs)(vKVC3zm@VzpuFexr-Tv``{aRxv67JKB%Wo{?F#ToY!#&O&E8x&`3R2TMeU0t1`Eqx2&=o'
    'QOR64?dERNZtvJmtEF6IlwFeYcDlFeKv60B8@agfcfDTbE`zY`fiop!MBF_j6G)R~<T;zd`CxZ<_n<Q8RjJ%YHm$08Y4+!6$cfS&'
    'D_;?Xp)uEw?f|m5-=s}KU@~tMFa?>&S_=_0!pY%CFuDf`;l1md-Hz8D_SmtB1k`W2*XXQ?!06<9Q`@muwGO(H=~?TORB}lz@uKyF'
    '>+sU+ZPBE*C*9QAkh0_G*WEX;S+A$HoUSaJ*ETF_n4-wIAg@Cv^9DFfm`qz?ktULOicpRxw?UKZ%``!rG8fnF7Zp!0_&PErXU(Cz'
    'yCMUK;+^$W<TKV&=^iA1c2{~U8|)B;;UR7l1qXezq~2*XzJ<Ab>c;TUCev(ITUn^z)GF>dnmVvPD!K^pR0wr3YZ^c7%rh|1D{C@*'
    'B!hRc8Fe4rj5eMgXy)=prg?>VC<o*ZRpRroOUSX+0%lbU#9NpFbb~e$$0{BA4@0q3*M#nbI$eJ=G0o%}u%352tXQSbUpK$9wTWea'
    'n{qQI4-snn<<Y*wH1~EaTvskqcu-sJVhp=h8Z2H5=MQ+lL~4N<7p(kd;Pu<m3$J`w4d>EcQF6EYtplNl%287Bw#>Py;e8n#&gpH%'
    'Zz~a!3f3nQBoR6e*g}ptG#tB4e^=w7i`LnA_cuV!x>n1tRLX=*^*9%?8+vhLFQD}mt>N*$yKv%adwYAlKO9@P(B62DnqS;YM+*2_'
    ';@N=UL=IQrNgAb%mMHUkjc)yp0C4^saFP8v`0+Tpo|`sp=u6}XK63I)ZvoBt72gs0-i@U#H_7f({fiCEg^xiVA^q=w$&k-~y0`Wa'
    'TfKQOBgoO)5|-JGE1y=<lAYFV)<W<Fg~d&#wBy9x)P#+se=I_{hI*z@&lRTqg&(6eKAM<_Fl0;QiI%_=-IHR4l0A<T*(_}=!e0{i'
    'Z7c!=F$Svp@`pf-bqEj(R8Yg5<N?W-*48Z`gsTR!2Z-TjAl(40f!mU(mhYlc_*jeqp9T#JA^#<cX5X!3dR@&eBAV{jNC}mNdy;WN'
    '_?c{P`wn}(QCrbi>v9bs7v9)ot>2Wyj>aWeg*q&+fn3=eJ6CRH4Z2o-GW4BUeqpPYi-;V9DRdK&Oc@i=u40TGlczQeF}IEw<5X9K'
    '##m|C`_$TlpXH59f1f+u>iDKUPM<e-;F&(H=+lZmt#Y42eL@Ko8EEJoNK15mpNBn%PDfuihZ=w~*dXtovs}JfkP}aZ7-L`>(!wGx'
    'o6zF2YXGK*ok{^$I3PljSl$(-%d`ehhTc8~6we3%0dX%Q0|dEyx!lQ5jKs;t{o{-5YGK+}3-WEbF%Nqg<$RA;82TPATXHa#k=AlA'
    'RY=;|5fOL%q3W-vKK5aQv(<HSDV8eXqkprgut|!KbDMg9!q`Bh0Zn25(5uS5eT$~DnfK?1Ix`-IG^N}hm^=300b{Xl`4Mtd3Km{)'
    'F4jV!mLLOb`-B$D!B@auliq(As`!W@OBs+t^_$g-7P}N9tvl_mjl=GXbbNl^a$3MX^>-VMd+Wh5jo6dV%%5Lv1aoer;)#%>qUshN'
    '<<{%J^jF%ZDU9JKE&u|KZ9vfBXYyVs!&(I&=FqP1jM6y#qrXBLI*P`8N6J@}WnIO+Jn?~to0_O)I=V`-`M{+MO(WZm92Btg;uQga'
    'zVx#c;i5|Nh}kaUW875C@j4lK3+%)Lz~MDc=+4fqlsAj48af1vau>jzpjW!RwQS#czzNZ)x3|}j?g~JUh1Q_4-dq)is9s!C-`$)S'
    'CGFO7S>W($i366Tvv?3w-th9MPVRxUwXQsK$sJwti<F5fbd@3XlDM*H$^LiA!yMuiAP9QGu9zu|+_axP%YadyZ$ZoT*|Wv=ww_m>'
    'eDcY}xTfd>S*o%u$b}eYbW(XXv{E;wQ;!PShj(>}e7l&X?<?da40W$BXJ$s}xef~7hjpOzZoSm=w$ti0dL1l%k><XVB-PpNwE630'
    'x>h%x++YO%@Bi^1xM$eUwM;@9LY-KPSB1{(h{_phWZ=ZFH-f4!3<V7YBYs{)3wnp&s(HLtmJiISTZzTNF{aDyd^8!}J8)H!pRsxB'
    'rhA(=l_9!WHP<tQ{)HA`oCJ}z)=tB|sWv;LMpjZLjTUZYr84jWdSpKn-s=Q5Ke!t5TLzPTkwE3)wB(n0%3ND9B)YI}HPTXanOdA{'
    '*(pY8n@!$O1{X)cxDv|1M`xPs_1t0+=?u-mLM6`p#T`J3;`nAaWu|SvP&L1>#VGG^@?7ceY;VtQ_JIM<)hS|2I21tQ7Zo}BzOXIk'
    '&EaTEq#Qx|$r}ei?zN7Q)i-SNygfdiO>USuSPEGO%IE;5Hi6IDD=fKO=Q+z?-P`2phYv?5v^?2zs^ZP(QA$o^6U#P|t9a?J>LV`('
    '+829^>B>MNnb^iG00t+TV;v$=C%hSz5mH=l;v3rrIv`7e6lw|P$%5Qi{wsK;Bqe9}mZPIoBIVm9bqg_7f^nbXq=?9frp<oePsqU-'
    '--Fs5H$WuOi;bcfnS#$G896(**+NY4cc?WcEXY`vi0amBfmZ0dipT_A6pkDy)<uwJ?q6k96dmltg;d@~d4?sw>ESRkY1_K}nWZo1'
    'O<fWl$*dfTD$@;3Wg0I_U4X!Qx7iVUn(tN?_Akh$=Pxzilipq|?aTdGc=jSAn4tdNvPD``*u-Gkxr(ANa?j3`KJ~fH&qID57N054'
    'dEr*ILmlveh6G4MDnYerecQ?WI>t<Am1g~I-VQ{W8;I;V^2XpOnw`ZOi<i$YJpN@sww`Jaqb_=K+U;@-==rgAkZG`IQ<hDb)3y5I'
    'O><~9ueYr8dxego7)wl3)GW;~A#!i;pW59>YKD^aG(F~QcuGxfGRuyL;ww^Nd{A(X95~emGdNAhB{j3OccU$jv;}k5W?`?`Uc9lX'
    'cylY#{7Cj*y2V2?Bl?r8^YrjDB}&*w!fCUx)F}9)l~eIl_;aP2)x?4M|NNhZ*{=u_!2|It_$<_1wyM&QK{=e-D<5E1`G%^hX3Web'
    'RfnTw#Ych*J4<{*B~bnlCxeS=G*cNl638ZgG}9n9a?y6Uiu6QX^zB%76^V|Pa4!A#itz~tzQSUZeeJUCBR`V?qVTGFiv{}fW?}@('
    'XpEN!e$pRhD-S6cRf1C_>Y%yFSArS=9NsivlUU}&Jz4k48i-v0^D^lxgwAE&6SOua9|eUTbIDvwXYu*{J@*fnNq_S)`P~f&1j?Ft'
    'x|!aK*6(UQ=lGbM_(st7-=2JUUy%`?L>=Gz9*W#wMxnUrGX=L04Z~mw@3l#kPQ6*pzd^_LrhUN$lD^!Qv75kq3@Z5=O&j=iSpR60'
    '(Z8iS1uApYK7ojWCz0mj=$HZ6%AYQ0eS(8n&i!Z4vbAk{QNRiCKm`JsAD{1STq1rNuQ=4OTrl^R3TSxY4lW#-OI(;;#L-N`=x08{'
    '&XpoR4mxpvR-|DaY6m|%3NmZ?%!9L^&--T&0Z8lh&-c>z8ytP;EP-f&4Ewn*b_M3|jf>7|gyrG0N&Yf#K6CM04s0~jj|B%_#0L}<'
    'Sr(EMNfstLRp6D*&_fne^ji=M#*g_dyR0PsFbpfGY^x9vwpnX$Uaju2?F&_Wd=;jFs6Cfij}wUFsysk*?qS51s8tE%sd|mLtaYB~'
    'lI%M5INt%pVsw&T-e<k$Cv|)ioqM47AJ^zyt|g@BqLa9}#7c2(dpl+_0tgqM#p*KfoScEjOjXvtp+|5OE=X-C4OEig=Aaepkh#}q'
    'Q}p_Y^I1Z%axkHq--xB4tuLrwERaB}{zg=PgEdIsBeYmmmJ5+3Tk!UUldU{;KsM%rQ2z1wsFFqQN!$SjbV=kD#$x6ou`9Uc79?g*'
    'Uxu)_kchxHl!U>Ti6RS())sx*r<cLL29beT%|r8N$Wk$F<TUKYeqGPHU+40fgeYr9LqgG3mNM9f(r{{mQ>;H|?$@=q2fL!e%jf!J'
    'TH@W{=wbODYORWH%8?T`4EB*xh`&Q)1TS8_gCZP(>l5|!f!@e9@mo41tFNy$UYGrnfk2?AXj+Q&Z?He7U_RBGiek(pONH%-uP{D*'
    '%ZkYmYO=zEn^|Zq{TKxb?pD)jY#IK16k$YhckA=%_qE>E!C?OqGC{^U#uiD_1qPbGX5q*LunwcuK#qFLX>ASmUx^qnqK6;E_HDeO'
    '?c3n(TXj(1ycaVGEQVE96IKsh*CLmq@Z{C&?@9Uqi)iS>*4{T?D(G^eX-^@MgrDAgbv^ZCAEltMz{iF*6SndB^w>6%DD+}u5hVc$'
    'RJ{3^V&MA7-3IB(VZK*#0@xn%*?2dgwFA||GDnc6!3glwcokg@L%+r%*t)^7r6Ctz4mgIo3NTy)CI1fWV=(XiracSh{T4@`#lXPW'
    'ATs7!V}e3Hy|rB3ZI(SC-cjXmFlbMW`9e<Cn!5H@bTydl8KFN(48CZ_1vK`PVDyzux0EMzYWb5lpZM&nNuM&34)BzXflwm9K`Ft='
    'h_ey~UfYf_69#4xQI$#3EoY4Q1#0M6unzikQPrNvWmKRv2G|NxR5r&Nl?cre_0jo+szWVDex)ig7!-x6Fd!wmwz2qJ3g4k7R3a5s'
    'z`~~*aEUWZpt|(iCX*p55JFW=d))7=nbCyNf>#-1NZlA-U0md$i4#C`mLGd$BzO}8Uzx2IP{2bD&p$lCgoe3=bR8Mdf>t9`8pU%|'
    '7~^utchhS4@J{qgEBBQ4N$NWEN3ahkIQ1-0HE?yI9y2Ml!LrYqBXGzj7i)n1z3VUw2}8FB?k!+(rVMs=ZqG#^7gRmM0K!sh0rIhp'
    'qKNDwFDiw=TjdGHN_`2PQnG3Vtmd3VlJ4L{@E%dot*U`;<n=m8%L+<NiG?WF3@ELe+J!|Ddzs3PAm?YYxpUhWdR(dnR-UnL{qVt9'
    'S?ixKLjOh>%NJq-V+i0eUV3Gre=%XIBKewC9n8up(>`nQ5qq<R>wU`z#_m=)3{!k2{}0nB9Q(1mMFzwMXCmD^kyH$r+i5Irwgy6s'
    'lM6sRk5Zo^5EIO@z^G3O*@f_XML~S=Zx*cUDdor?akw>jos3jLUJ-mlooU)={5xY6<(fl>@q|~o6j|qJ#9mR47_Ot*lx*)M#kf}='
    'wOhC>N=6`*yI?--3~7S#xxH}Dq=E(8oTw{dvf?$F9pD=_ar+};I@uevGg$iYk;>h#UB_{)%F!A7dnq}i()wMTb8S302^F~+S(|Fl'
    'J7-JX3N8pnG7On`dvCF}C!hqOl)1Oo4Y4=nd$Fm#oU^aX#lmein@)4Lo>}q@8T@m+{(uY^Idr{EK5WV+NfgpQYuYUgacXy&Q4ZX}'
    '@OfaBg5?vj0Ty5XG&XfM^L;m#ZtqxSOChC<t(Ot4g--cQ-U|9+k4RuQ0EUloqM-7_0yDZ1m6ZvBnf@xhCN9YH03MC^okmx0|GZSY'
    '5RP#f471T32yn^`jsU8)ht4(1zy~`N01vlF@`=S_EoJ1uP<5KE`~GjNUpNy-tlhMws7c~kIdPI;hB7h~n8Hq^MUD$*rgdMAjC^<S'
    '_>79u>u5+Z>58MWH>|}^)Ldaqg^rCK_9&K-J(P#4a3-OCUm^3zYnKc>h0y@jgBPV1LXvxojmQ)f7ur%TNuRGa7SVO3nG4Gzjfa{I'
    '$c*>i?y~NS-dAS(O$-pzpHZNg7W}?|-)_Izu%3$$UqiLiON}L#M2eTkh%fET!T9d(8U14@<wSr8Pc?2K`$S)5wr9D6XTjYaE}Uns'
    '>zxHGFT#|jmeMQ+<=7vi7D#?^=_puEuKDO@TI+O@Sa5l?qlJT$S4y>ICE3yv4yAY}Z{2H`Y`hBa(6-*DVk0-TM2EfgW_Sg+q^4fJ'
    'EpZREz8d&Ax2dU5TuikkOitH^!miaefNxXfM^vc1zv}Ms>%k+>H`Y49nPE3IjfCF-{U_2<R6lr_zGZ>p))AFYZ7N{g`clglSCI_n'
    'J&d@SW?q3cirf!BIMD;4A3BB553Nn+N_mT!i=2z_+!7aYEV1vS?QKCg<yOs<U2}e)Q&HM0Qro;e4-7@x{pwyI^G+%Yo;5PcBSf)_'
    'M_eR6=%^5l9(Y`vU1;5w><HRsfP={UunVoKPAs;!HAj1`gG{H8E@strIo{1%Suhi6GYp%9=H>2d?1pm-^Z`a|dwXQvekE_D0m-t9'
    'PFNl;8khKr)ezxH?p1Pr8;kRmO-SwrJ^pI}wv15YD$wDG5GnXPy<Ov8a%<)M{&xaJdN<6RdgpA_q*x?VG6QB=D4E$($ILb^!WAYa'
    'wvk+}3?yU)`?ix{=HB9cBuO;ltN9$|e!?|<98EY>F(6hYQ+Xkpijx)*VFiF;#fqY<*dXE#8IN#Fb%JAG`EfsTn8z1qIn?MA;vv(<'
    '(nQ(s@6{$Dh0){!3XUiNyMUrDu>2uNOCl4OcnPIo16q{QGHni*bW=2gWh9|R?U{phH@HGaVXr{ZVl6yDnFeQeHnAkjT^5hP)^Etw'
    'oq~;kLEoS(5KC6`kpUA~$s|!?TJyUSP95Ls;pDQT4glqCO0hZ2m(vKNh({b<+wkTFiq|Nbqft2)*thWJerP$c*si^JUObvfOws$G'
    '8>|6(!88<h<Xj}bhWio~j-Av_n{L{uM$R;XZS;8?*0v9nf0$&UD4_F%Wb})4Ec9lscp)b(i)rABO!WTRJ*z33UC3-@Q3mM^K>vQO'
    '=Ya~W=lMKkAJ?nHZ$junkvLFKKzRg|Ja+=zHYKtOWhDVhE+T0o#$Ec0kUYfWlt&kt-$OJazM7AHSQ!4;WbL`c%eJUqqhV2tlqebe'
    'gq#rv-)4aqwK8=qgT_|5*+APJA9*A@oh@99V~rq!y>2vxWk`OlXl-4}wUv3Gz_^GsY^B46F<UA*S9|D)PrM$(>p{EG=&O{sn9^)D'
    '`fOuVp;oInoAL9ORfn3E=r{R=g%@3R&)#WR?1+MTBxR)bJTvK(3Xv(`)n2;qrp>)n2G^iz@JBuX(oS)-Diqd@3va?L7Cxb;{4ey>'
    'LiJD0YET6?u}2dTtOwGb1IpsAm8|Hg2~S_>sdaAEW4qS0o0dHnCb$%nW;7xHXqg&-G-*t3YFrr_GbXDV*JqEvxXG6qS80z!y-Q?X'
    '2pKFC;BpIytD<vb)w!|i+&JspION`OY@9-Of_V%mFcT(2e&{dF13w&KS};fJ=<&X*O<B%H63VhDf%Noos%`;O`iV`xCi<!E&&Ti='
    'DtZO=*g!*}LO-;<FXS!+rt}^PIgrau_wWgGX0`}21)ys2XRIKj$12Gdo|&QFweI%zyjuOX#Ri9%#rq-;w}4tAfjMLmE-&@wErj7~'
    '0m0Wa88^@0&qV?}0DVX3Re^k2-@+eg@>~mCAej&X1g|#X=!8se1QP3h%<#inMo6z#FTdTP1$>*4+RM7O#PehqzXR#@uDt+|JoNoV'
    'r6E~PQNJGc-g9VfYD4~&t0P$A0ZQc8`FY842g|cyndz61r2??iT+6;2l4~jpf3o=rX@A7&l_$xi0K6#2AI}T+roan9bFep$uYl!}'
    '{jOF}HM)k1(a3JqD`~TqvdbFQ!|)clz+l38_A=*g6*CES_9X`ss#Ssmd}e7#A8NGjvs}<dMOAT7fPu`f_nn57VE0iRd*cpnsK4<t'
    '-?b)mjkD_Aiv@W23%TeNPqpT`9vB^%KKB-t<I)D~t~O7b9W3EAy|lgM<P-Cd{aAH9UWexpp{Q~&6A82S##{8W@V$<MzyP|2>sopM'
    '6=)&?+bqzZE4ux($k5kDQqpIN!aI!3ghUV&I|Z)TANMtczSoB)cnuC(RAex6?_<25f@3H%JtvvT#weOC&_uZpXAaTVOeje226EQ$'
    '6-gSYESk}!xJJu@vllf-$*B2Re0TROM#hU6<vd?jJbrOL<ZQ$fvd{EHN3X|32t5%!@+tm@y1(-rr-wh(&va!&D4y+5q>~R|sKhyW'
    'pZe>*OeDllE?4AkLaJSjmgvRcB^%vV%ocD*_K%p#CM<99aq0(?DID5v+#l;Ld$e-j!q2B{`}onu(BZXahn&WtLJ&$GkoUnaYjACj'
    '+wE?*D35vJ?{<efne(RI{4mOWH4!?W?KXgyvD?UM<$PR~c~TkOzyRz|&nvr)ns3#28zpXNaD&_5g-y*LG%U>>luz+k0S?tRR8rF_'
    'sqR|$8{Ha>Zfc((zviw8YLF=^57n5<11Z%{>;7@H4w>(<H&n9Lwsg-`=85=H{Zwr>@}FMQ5I$9V__<K*NBjo0$#3N=GiQbzJ976U'
    'p&6UA7e!SIjX7wQd%B@4DiDa53&Rt;3~Xk@JeG9r!j^y&n7U}(L&udH7e*GxIX6Qq7vLk)kXuCc!h_6pl)bY0nF}g-yDy?_=J}XO'
    'u=IXhaPIn|TObv!2V4{jv*l5;tZbrxnfjx6P{$ctD11XHQZ)?F<sa@~KV79G<OS(>d==BDpAy^{ewusZApYrchI`LX$bRz2u|N5T'
    'IT^_2HXAWiqS@J~#Ur+C<0kbAeRBvN1C8b1oqS;ZM6{L5z9VB&_^QXSrVKS%4Le(dmXIS=mKU6YJgDY|jqhTY?!eqKtII0<wKDBR'
    '`S=egVK4YF5(-gkevByHCBE|XCPhm>KXY4zuIJhBrMS*w4G&eDDI~R!?uYD68#8~kzK3o<EP8^9uL3#X6dMb%`z0Lcr4@p?KMs~s'
    '9pZ9{`W7BRCkE(9)ezKS&Qvc{VlzuL^BRm$r_h)frg&f<;+bNU+Fm@dM;OdQHeRNVfuS-WlTi53l{27kqZFsBT7jC_u;;)O8R7|M'
    'KwV*Y#DYSn1iDHcAZ-^`<}joh76V1uJ_#iWo`VAC;3i~3FD>isA;MO9HO)C)gM$HDuK#cUY;b?rMBLgNqP2Juk0>9oO9y#<m!UVF'
    '_$YMT8l1d4{(N+J`uY_Lz~>SA3JVQ#W-j5~FDn}cOMh$d^7YZ{lhaR!f5gHkZ$5U^9I=)OO#j)L`ToPF!&fFS4f81W#sKVJ|NOsT'
    '9BoqOGc{-Xv7lRX{P<F*9f0LDI)spgUq4_Eu}<h}W>Fu^N7;I8QE+ltN+W9QFieB=Y77l#jsxtba5#V&e((XSDMW?Humn_UafW(A'
    'Sx&BoHKEditR3V-<$Pj@P*#OmJ_0WgjYS>oAD>bxu~i2afEolKQ+02nIQRlM$s$y}jP$A=qtrm_<B30q6P!U(8XP@697taW_#!g*'
    '8OZ0BP_GiJ^dPqgrP`C8L#-)7X?3WjaxyEfG?RSE0~JHo^6~_=XtIx5TmWb4CD1oG6C9YI=a9z81=W94&$bEag(}SNL$t<*Zx`XJ'
    '`0XQY1XvCpiXRV?OXCo@P}569zZ99sT@oZYM}@SKe*LHaUM(baH6a&LFnhuRdct}+diTR?<M7o<?Yq*2^6ur~hgQd^8}D98ga^3c'
    'ynpg1kPPSo%t*EtuI6dH66?vz78HNRrKEr3`)9xzw0=6^AHbDg|GWR0mQEV=)w(QODg_@Km7>><nMFn4(1vNie&df-@pUI0g#ErZ'
    'COsyR3!NV~Xw8b{7*l{ISRHBBlV$w8xx3@^y4;VtTuL8>O8Mr6`C)Ew5Cnw5WIjGHSAar&*y?DRtRwjMq<*~t!yiP?ug5^)K2muh'
    '$<y*Ogo2GJE;?LAN{^ZXOP{v0fvg8M0!vf4)G&^f-8mQDcj^f9I7q+uQ7N2oj{8y$$PWvDZd?#Tm}t=O5(oPrD6yqrehG`tE9y_O'
    '3nX{zr(x*LFSlT44Uv#xy?(r9OwlvImK-=%LXbF#uHumoC;o}QU-t&W4EJ}<7<qKbB1ND#%{WMW6pCnYvc=5@9PlqLT#coquk~j4'
    'dB>`E_K^1c<=<r!kF%~#(@S3J2<Fj<=VoywcShkj#yEcBLil`oY}zVLG<~)9dmXZ|ze;Dh{CGIX=)wtEZ=}JD*W>5YmlZL*su~X8'
    '=~(KhMGLhu^SwEmfV>2>1wahk#(`PoNr2a?X^HK1ZYZ`N7y|$)zLvr>=jvFH3@Ct80F*NEVOOanF-^&V=&N|u`^IC#F4l2HK@KRX'
    '<%hTO>^PJSWaA;iFdiFHZI$#_iy2rk(<TMa-%nM9rloSQKsHLKfI}8Hxrw%)fWm~O|KmRzq_8X0IP-Y=${z(YFGQRS@jRw%(yOLT'
    'y9`vPTdKpHy*fT&R2|O*GO{>`RF$=Kj0{1l9ls5Q7lgW%&mT`Ds>K(iJ;0&6gXGBLMXAain3!ZBy5fo1Kp|#`A;3S30GR<_fZKw3'
    '<lQ+8{0oB|n#dYsO3U{|=S+=C<JUj`ho+5IR3je`!eO=uyf08cY8B&@cwe5f00@Eqi(fI&<a^ED%e3bQNb%+lS%1wf&9@h+hs-g!'
    'BqaVDNYjWX&hs#y<c2Bgzy$e-j+AJq88^JXUVqn`d>JiPDA|Oc-@jbh(U-bf6)F$xAS340_fP**jycGDft9LB#LPTs9Df{LZw)rs'
    'Rs<<lsZ1zxOb8y1b2b<6DXXY;vR*Ce^2vJPMXR<FuZ4@JJz79VXHQNAZ-I4IS^f-%@XFzbcNT9RkfywV&@O|I{4L`l@uU!IYJGIN'
    '6gnz$lT=C^*7>;<kgNE7;`k38I-++|DV3=#Pz+<vYeh4MAP0)kQhq=9vpO)6-;`Xf%9~1|Vpxz^-KXrt$ZAxM%&48&D&iENxl@UY'
    '-c+`?<6Oj9V7XFn82WN*Q<#@DhJVw+kw4k5!!JH#qw3}Gi+V&$OMa<CDU#VKUBxE5xsU;rr4Oc9My*}CC1GYYb$=<yq3(>)S_l0d'
    ';i`f+PLbePGTG3+EP;$R3lvcMT&ZA&R<+sVD_yHJD~;(sFMlFvm7bQR^%2k%IJMQ%Xwlyx10;<|{CyP7HgXG}F&<E2(3J`*1s1=*'
    '4e*F&PT{Bc=@t3qg^#dj;WyjF4S0+eo$*&uDIqS**>p|YN-~#jGLyQ|g=rL~2St}#ga7=O%s{G+6=}q2I7Z+MRS)#b)cK4hnM9*Z'
    'TXc&qLgq8;c0O~WInf`N{OK~;av_<>&SuwOdqT-+BqXIstMb*4LTeNjYbOHcLb_f(Yi^}zPqjhNcXubq{WBrI!#I`loum*2<t}$D'
    '4742#SG@FJhd#bxZQk~_oE&sW>jm?q;;Hg^QS4vauioc(WZsF<k8C3W{9_fe#5O!~;ed*Y<Wbf(-hO^%(~$uw(7%R<yq6!|ySE(d'
    'pl=>GTShzFHM%wWSL+(^@5^!9Xi_S^;mZrBD_>0;Z=bnjvlVtB!>+L#);dPVXu*G-TIaagHJaTJo@y=l55643w?^2mwU3)Gj2HX>'
    '^@Yt^6TRm6W2_Jg?Rrg&?_$7z%|@-+p<H^J0cky>x#M-AH=L_?+}tsGS%T5yu1%c=RL(97p>`a_5wzY8p+842j8+r+T<d%}et~0!'
    'o*z>){M3d{!h>m(t3w`at1;b$rkt+PcDi26X&U$sn`|3xsIW;uXc|rY+j6=!{PV@Mh03acwFkg5up#)@Gx(*^fU)+z;P)3|9Q3_m'
    'h(Y1^#ut59UI6v&8tr8ZfsH@A&;fp<-?p(k#lOui`~Vbp`G;O%3Z~7*ve|h1;tP*@+F5p{01R|KGWMbBp3w^d89LB@hu|B+LycY_'
    'jRxAmsP1Ws%$~r8t_P6d&ewJfeulmqJJ8Cm)4>c)2LJ{C@Ph-rb9$lEbebMw4qkNET22q(3XMBW_<t^c4RY70ke&vQ-5*+74IQJg'
    'EGY`822)q8&uL>zg%04qaJ_w}jU|dzz&yWgtKyAXXIdymS)69R9M>gBDNAQ<uhjuPeY=}a!^VHen#OS#iy6f+GYG@AW+lvvaN{}p'
    'VYfIUqxn{YdBXtgSqC}f`eG_G@{fn_Umu;gz>G2Rfj#ty9*k|?`RTNS#09<xx&6pnc*7v1=;id8Xa$x8+D;p$!6{UfmO2)u2X;+L'
    'UuYG>hnJb-Qc4#~6TTd;>6KFkFTl2rjg$0h97MSBQ*{yX5g%9S6pFz4>u*o!uebELBVt+5IK(6RrxMz|6LgOmT6l>^w_l2NoD|Ol'
    'Q-5?hj3jF?#KXXXIDf%Sgc&zcr>c+#knty>8QQdMG>(I9h8onk2grf!gXX9VGvv7vyzXOjeqbvPO!PIh@#Zgg*B8*WB-JnOBBil*'
    '$!(<U^N0C&c(S_{2;u}Y57@7j*<ZSY<@WYFeuZPIhlam0*Y!<Vh97UVEHX%_%!r`~FMRav1$k5}#Hz?T&>zc6Xi}-zKq70gEBC6B'
    'zyE!;5H4eH$=d_4N?hG{QIulpDR2cbc6k^F<B9M1bL6GRoaw!v;tkTI0<8GdpI4$wR?|3f^0~LSpGB9JQ2hFiJ{j{UHAvlzPBLDK'
    'k`Y<#Dn<w5$i2WYfG3$4Lr*v<3D5)p3jT8CC$wr=8~z@8I9|kB-(w%O+bWi#1vt=8(Y0H-B;9_ST`#CZ&V`GTayrRhC1jO<i_fqz'
    '1!J@eo+T6UsC>hshYA$r_fZ?ohGpF6-q;9S`RvDW-yC{l)5gMp%J*j%)QW#j4&O@d-GOufm%T0$&@ULq5kd^Qz^8J--scbdW|e(f'
    'Dz^@6w-cf#eE3}Y<^liowRFCj=35JSV<F4I00<&@68pSZ$N&c#g}}8|cAJS}iwg%}%GdhvJXiPknQQn9mNrG?MmZ7EgbOFtGND8Z'
    'QmnqdxQjj__^hNh1!99W=OXBgBb|l)TQ(b@6;sKS5~dwEGABNeE8a8UOw@rkfR>^7V~)-PQJiYN7f(ozQ{=Hnlzb{4fmX$r^pVAm'
    '@JYxd(M}48wSB@W95xbjQW?sQtJI5+ar860U(0s^HG*(+XumSv&?7biD+D)^*YJZ&#^KG!k5R$z7^9$|stGkp(KSf@6B|CpjV9mj'
    'hdBvXQ3n%%lNjr`v^AI`88OKH@7zz-{8Km6Nu@|$VV9CxNQOv*14!s&c+P0X-fqUM^@;9k3i4g8d+UpYyjrN;OH>XYq6I0N3K5r|'
    '!~weWhy&xtC=SPlAdLHU&R5KzMvEwy{}d87Wv0D<Yd~AS@d~EhIQCM2OqRdS-Q3jOzZW~({AyP4kJ2RnD24XgTZ1ocToSE6Zt7A8'
    'vUD&@=Z_`5kW#&DqF{#;9M84y!4$-(0D;o^PjHAu3o<|6G!MMSPhr~p+0Y-4aU#Y1y#|O(c@~WzF}&~^@d;;m2rG=2-d=`i7v32C'
    'P8l!^fWL8#u8bH<yx7ln4@dT2M_O)*PuH-6tfOKUbPq=Q%3B$AV~z@{M)m={V0mE;PsSL)4+pGO;H5KU@DAZ8S&&b)3EoBL@{Gdh'
    'ikQcb>IT7}G#+a{^Vm<}uuh!eD2{4OCJatBk}2QB=a**2T?QisxAn13P=#-Fh5MNKMm`%=BaNd)FiK$PeD}h7&`G{qSLqCjeLg)l'
    'zC<vG6WF5*gT##;vi!i>aP*4Pja+u<T^8#bM)8<=apC1Jz-5o75n*r<_~QbYN6d)>C(RGJkHmq}N4|Z979+a)5g+o<dOc66j&%UZ'
    'BY-4Ig=R<v1~ZUKld*sm0WGnrf<dYWMupcBAUgn)v}y|DKy{%-jIQIdvqqK%)v3S*uuT;^0R20XL(M2Bd1zB3)lpM2pMak7F%MLZ'
    'ih_W9dHRD4k|I><4YD6o^0A}LfQ~dqVe7oN0V4E^S<o^2k<z(MFjN+1J4;wq%&p{Jg}WoH;EW&(8MGJi8S6buNS6%0>u;RlUWHcS'
    'P7b{|0oE=cvn4p{ctdnmV28mhWAQNJiU`R-?(_Vl0(q^Ry$u<ypj11%AcH#Y?sj)A)Ogh+!Z{9BL&q539r$EYTE@;{*NEp4nJZ_&'
    'fu0wSMgj73z&QixQD%Hbsv5wD!U^c&qT~n!`MxIu!~7u#i{Yg`aagQZAy00Y0&sy;jYG@#6Ay#=4F~!(ufurJZU>5eyN8@OBR+fs'
    '5X(mDfn@h`PP>Q;Eii<o+M#kfO8|(x<`#0dqGzbtUqkM`-xR`n;ueqOH4k&Vuw|q`ZI!k&IhWzi;f)uhpG>1`>LB4a>g8rVB{ki-'
    'QO-7VeqD2OU8|=glhQ(itfXajdi2^Xa?9oed#dyY37if)(Zl%{E*k4b1c&(Of_78l2+4CN`CH5j8lqTim`D-@A*u@|o1_4OJR;s!'
    'OjaGD6>P)tE>i@(Ja^`6DWt=MEF&wYYV`;$LR{%ss&adB@}Y0SAER<|HLsy5^)v=X_$skX`{*@%gFi;)2!_gAIaL7Pj`7<uemnNZ'
    '0We7U&u{Sa8~psnj}nd}<HalZ@)p0q9~>-lG;k8TJhv#epZQID{G#pmio2_>-kKW?5)_k&9}ebHRI=0ZdKeeDxg##I^Q`G(&gK9m'
    '55sV4fOrYKQTTK>bx`s>dACE-kuO@p8hsz2_McoAG_DQT&5-Grl1pX7cP5VU?&QQa-h6~VfJ7<m_u;R9{!ilEDhk6PTwOpXqj)R3'
    'Zo8?mIZ(gZ1&($Px4sMDp8DPua?WMFehH%uqsbMpVx%a>{eF!9hfbin<6^6LG%joeh{bO{eL&q4MWmNZr1Ok4kXT;eOQ8iXnCSvh'
    'lbrSX%)x%IPaVn%fDUX8j^Ke*P}k-T_wCrHSvU!1bZ(><xuAjP7%AWolN>5hr5DHWoS44}Az}L9BnotFYw*b@*P&5an}rUq(=8=A'
    '?HexvF3D-^T>|FRVcewKidyNYW3%ukB8Zd1PUq*ua*Pjre&}Z>ikucau#Z8A5y6nPg{Br$w6>nuQpgl4Z^lrWZjNBEC|9vM7w(Be'
    'DP{XOkLC3e&#IWofL4GQ6Rhz_L-ZDQ3whW<*%j`Vj`1CUI{`}l^24VSBfg>o%wiF)_V{p12n3xBBNP*`49uv!jO3M_g?>m8J~u0a'
    'tU91=UIU3v$<;<DD3uU+Rp=5E7(E5~dNzp#f+v~9Vhwoh39KY4MI*a=aS@;x;nBsXWQ!;9sHljNUsb&958<y-K~>a~%N1dUH%^95'
    '7=`>2#DMp6G!F%sTbqu$sAig6!jWHA^xjXeBRGUd^Kj$&9vj*ksOIX0#tLQg2j_B09W0p(SU^+5Uy@vb_jsMo!s&jf_%|I~QWU#|'
    'RtWA^4}O95+-f%(1$U`0SQ<c8Cr|Z-3Jtu+UdsN>qwA;dG&q^4QIC2L3X6&qtFVjW2?IkYUJZeN5oZl!&Xcl+tf*y;w<hv@^7T{;'
    'YIy&rms<n)W4!usnsu%eJ7LM8I!XbsyDerc&&XM)y<@+ydv>#7H=A~|#r9(3vb|x9d&5gu#joi3>vxB>p+IF~Z-6IQd-LS!lLf_J'
    '`7>Bp`1b)Sy{;ODHXATK<05imJlxeE{Z)Y}_z{zhAN?V;m>7p2-x-(w%BV=nW)&Cz6FN>+!X)}$OwN=Z?fz5H!p9>H22xcX?SbIr'
    'Yk#yF)RO`9OpqN%w>?V|h9zbFLoNuK4GF&<VS{!yvq1$KJ%+6p_PS^$meLv{B<>H&S-R2ar+Jy4;3EhjX_crV^a^zV9oS-5Gh5z#'
    '^+@5USU8&J3qLvuqqlwxeP&lyX<P*U#-U#oS|+J4Q2XP*{rLI~{JuRpF)Gfiebuv2yBE0)<MXGZt<8+4sQB{X{f*?hz}e5e1sp6>'
    'mU$Z$oaS20ba>-_Hv4&j*QVS>;BkC!wkhj01hm94a5g!VP1%Esn5O<UjdMX=;xwyduPbF`*Cqzga|>~_I3<NuF``9L%IFJ8ys<4s'
    '&&4ewm`!qGFcJx4#5S3Mgx5dna_b`h%e>qN*wm3-3r2w#*7N%l`e})gnpFhDV*{<Yii2ck%YIoThQ>P&l&|_@$H27-7|iEOx#1D7'
    'xQebQH_Z4nLVfMABt7uQGk*Q^Kjqf+uYdmE3ydmj8sx8~h)-apGuAv<BL$R78<}wZZ7c7uHv3q#rB76LSj~G|x_&K>^KDkMIKQsz'
    'rW<bOvC+I#D&-@Sa&Lbwyv=XCpI@IVIDlM*DNFuQm2Zq{mv|>9qQ+`^7Lsee4$`TL%wbf1d~;Ikb&MYZik`8ujIjt?l9XN`ypaWg'
    'Lm08#WD})*qVo3Sry|un?DISNeiL5%9w<F5l>V-?^pm&8_0<codN*Hg4P-nQSb{^?CsCQ?=^G?e@+$VAN&L(4Q#S35lb_)0R(_s!'
    'a#1b|`&ytU1+blvv#ZAdukTqfabF6RcwheIpUau?&6SJ`bzII0HT1X!hQJdi>{SpWf0v|qWkrqx(dH+Ecn;RBrvaNpUn+zU9E~xc'
    'haZ0>qw!NvWHj1cX9w8m_O7$Di;$=H_Xa1t#uT&(+4_yxi~W3q*RI@OK;8>Hvu$9@o{oBWwl0K3N||!A6U_`PB=y3q<rPD=SL~f('
    'lk5tG&G~Z(VZ`TokgDTd;S_U)-yUW@0M7=;KE(^FT+TN08Nn9py=c?`=a<SX*qCt+^}UCUjI<h1wfpN1#$_YS&~4K=DNfb*v-IJi'
    'BJ&{(+>9}7%RbguK8i82@UQ$y4bIrL#2;<Sca`FC_w;z<wYk`!>C(TF#d6_@-Fw=0O$2e<5b@3Zhc;_v>?9&r2-o77yKWV)Ksfj('
    'hs3sW`TbwWHf}zosDZQmG75pIDie+f<0Lu#S%`F5l-%Q#m86(hLUhs;qLUqYzGxPzBqV%5s`7n+!t{q5X^2J~)r!+-71}}HNaf9x'
    'kelO-t;s^eNtb9=p5EZcryMX_?UDngFmu5=@KjtW<-ax`uMIX<$sdn_VITuHJRjrX{ju8!AUP3G>$(bwS4tWm<2s-)Fl<``5i<7a'
    '><Se8<1E}7{PFncEACt147WA-_#Vz<BcL&JeE%x>3ZR28EbnFue(^>le*twnKPS=LMjI=BxSVB(quqQqHC6#PU1a8Eg%o}XWzMJ?'
    'l;47X{qui<ZFb=So*DvH#+1&|7;}=Vd3^lP#woNR=Z>ly8%5aX=b6sx!zj8$+LmmX=5khIcv<8mz7zEr^Aa1!QdBKmy9_Vspn3u)'
    'iH+hVZki9O(je?IzfL6a&sGrmSIw_kYvX0Y`$(+wm7kKn>w+(Mk@Ong5LPQ)D&#}wNeyP<fx8&@`8P;RgY<_WDJWB;i%8rLC`d6d'
    '&C}?*j#g}Rw+&y}b@GAv>tFr{G~NBnzh|niWUbo0IZca1VUEqvCoa{G_e4Ais!~~;UI=s3To+ILu)K>xwV@>br?H;^BM_>lsja0K'
    'S8BEK%wkP+wp&G+EM^@%Rfry>uQvAQ*MIttYZ7s_H4220h;*xFQ7sL=e;kqpruncI@B@&|BRlZL`My#=|JVOkSSk;t1@TjdKfGKY'
    '{-Z;OsV!Xs*~s&YO6V;V-QlC#@ptIfTe+zxKih#jILo-Aj8P)~=p5Zng;#K(uLO)8mL0n%!HoRm2{MJwyryo6>d7ne_)U)43!xEh'
    'W5mweJp)DKcyEt)>#S74-c&gPqr5B0?%mg82vAuWMnJpS`{a`nFG}c8HkXpL`H2UJUI+IH+3i4ddjpRx;<r4^Vk5Pbl2?vPS{2T*'
    'vfGX-Pf=##QM@M!@=I5)T(NK=Va<yC(Yur<F`Q+<VLNScG<y7&4uQnuE%2D_Mx(Lyw2*@O%0Ynh(EtX!nNxc5aL{5yAmanmOwRo^'
    'E#rcA#MzGBY}u`j-Rapc#D&+iY$B&Pi|D3GID|N@C|4G&KgUj>BJ|#i{(PrjJB`Q=M{vfCPz+UE0ZIj4I9ro?m9+9$4IUk&+vaQO'
    'u?D6pxkSD9NUFRCGokYSBp3??Y;=*MoUn7_2j(Yi)gWMymrOz_z~19PbD3jQ{^g%7UF+*HTq|vgfBPo6Xy(1L3>P=ZQa__hWlb?o'
    '1PcyVhA`NXF@G7HHQgjmXr1xV<nh1?R_4kX=#O4Roo5{5klZ{Q<SZ=_YTi?wRI<WhjWumKTrCQBp_eq%Qtb`HW>j$c0~{dpPs}wX'
    'mzMMRk}8)n@g}P=|H16j6)>cz<A=0>JzyW0;~){XQPR<5{=4*eJ)Zy*4w+8mmhkI8{@;1#Nm{YwitF87Oi-nCT~||czk+4)4nrz#'
    '>MEMl!@bP6eVj=xl)Kf~NgLMQwCWa@Ans1gF+VB{M+c&Oj3&~S^A{@onF)v9!l_Iy>JU5LwhEp`Uy5B*Pb_2bqDx}%&<(&c=P1JX'
    'Hdo)FP`Va-@MG0_qZZYR-BXU+(Y4O2t2mdIdDY1^ckJDu>-z#QRC#vjUM$3}6pId5ouaSw3MQiGcX-ZLx0N@>$}a+?TL+bly?6s#'
    'k(=ZY7YYRkPNUDKFQqG9r7qoGvj#)AQsudOcC%SxJf=q>p7?0vMJV~WVcCz&gUPLka2N^=;{m%+RLM<|OkNeq!F>*92B$p)vJ)BP'
    'sU%3T_oa@(j*(g=ydO}AZXqqsOr!Qk-hAmLEH}PfEw>C>$nI9F)7Uata3fv>DhltueNqG4W3MG7%hC0+ziGT^HkucEY-mvv0baWe'
    'q5<6G+Hk%XY$qd80kbUQafwJUdzrv;e|hqQ?mQ%qO`AkhrMeHBT-*RQC|5QonG&mXdV|tL@%%dcmw&Eb&I-P6@?OS!jhx3D^jxD*'
    'JuD0mmto17N4d2@TSVo>TKBCdo!I0F3T%eu9>FulIP;#p?n4LYMb6`Ol^kB@vK3uj<LA22mS@M<DnEgz%xg~0(~MNlH>UDdTG*QB'
    '@1;+oi}c!y{Y_iMaPZ-~qjx{N`|#d)^WpUE;jyu7ISpF(YfJhBst^4d%E<687Zy*7_Y-)MftjE9cuh&_?n+BEXJw`oMqzg$MLyDF'
    '!ne%C9$ti9edXgS8V6(F5*GG=u)zWcC~fWQBBL-=-h5;9wHG~tulz*zY5?UV3a?n}yp)9>FXH?uO>y$Y;~HyKZo1rPZVj6M`7cK0'
    '!b{SP_dQLg3)!45`UNV_(b^icu$pA*#f#r{9VFoJSG)0g%4OG6?z#R7WBRM!alLx@TI=}aH(zJv(D*2)k}QzFPD{bktmq2P0c>_;'
    '%$hIKRv$QV*q$a+Hut0g!X{0W4ri)hwl>!b0kQ%yOGug8DnGWZOOYjnGY11-tCGkiKLRa)BQ}XpHVBMKWK??pyGGmIph|r<FxKg2'
    'h5?f^4RBI_7LF5uESKu5d>4E3v9xr3>g_`qO``nu18Jt!pKrc$cnnZjC0PqdqXA5K)I{L(0u3QhO)56f@CpkFEjg5n2dKwSHvqz1'
    '_zDi3H9S|(0OMvrc`z2vm{sV*l~oEMU?RP*xLzu`-6DesveDt8k#L!mk;YW_1J_)KL$uGz8MEUtpwOGlcA7V_0M6;FIh0CBWy}*1'
    't7=yZMiaHYE!p-K+F;9DI1!`AF?fa}wGH)zfF1Ba_PDn3-?SPHgDq=qLm1?e_;H43a1Q{RtP=9%!dg@psAh(?%V^sRQ-ShObaDoT'
    ';mEm~`DlA9Oq5ZcNtVl4ADdK%_&0HkcPW{DQ^Y5z(14-9Q7;(PN4gy|@7y@;XurXVZ#DQhW?aB(Np+mN_Qj7QsZCB;oIpdT$fUr8'
    '7F`!yuy9B-3smk0NbCSGo0Ao9K@{x;nW+Bo-RE}>I*dU7Dd?9c`-Cet`v@heI2t5Wf-zkUiRi(BxxLLYI_JX>_!1z*FQ;B=-IgRe'
    'RK5`K6CJvdH#~eW$qAkem5r`*#v&RWX)9-CRhD49hlRbx0+>F+J-m*fz~JQm8)}r5(*+Q^_y9sm0iNcmTVcma93d8Cik&six!JqB'
    'vvcdL$-Yf;4(|5;fHk5!I)j(V8Lg|uxtWFe8M=d^)*V0z;QcD7o?s6h%$}gf8E(ni%lmnuI5<4qTQyD!Pg^$9*vC*k*<ioAZ>oa1'
    'S=yCCG?Ag2tYI`>nU<Z5+@S;fWfX>|(PD3?d2i&n=zv3KavbL}eD@FmKD73<qHZ!0L0+OHRgIHMaRvH5^7%?qR`qn}h0mz;_O`dZ'
    'o$tHu%W!+UPCLt;yga^RZlWI0xw_&xsW(9dbLI6gkEys6?(Xyi@^n@1B9S7<AOvCnw{?q?#uGI>H*HGG0(XVV?0ez*p+cUay>usj'
    'O2MK|?1czJnMEZQ?ypP>T{hy2KX#uzTXH-^U-*)Am#%PDWA>MMJ9K~P)=4*n0CL9y-8*ScQD>lt24S(_6T=5vKYjgor-z?jADRay'
    '0oCk7hp;je+Q-HDdI@ub=!cH<EB=z~PH*wv3i{=ijpHC2M_(T(_0i-Gh$QYSr%k=&Fa`b@Rs-O;JX-*!A5;_&poobOsLB+p?<;4U'
    '8HjC2vDTe?;yjwR3imp7*%Q~<;(Twqy*;f^DGd4LQqWy=zi@ZAU<6?<*|bEYC4nH@+rp3M_ICaQV2&jMW$_vjhyk=%B3>4uT88aO'
    'l$YmUc<FlSFD70ZikBEw&as2PSiclKk7i5x7lwz5S%&c9;4z5C;;Y>fLWtz|T=?#-OBE7LqM&gxsAO>BrFl_ClDm;hlvMW7D|B|t'
    'Af19I9PFofoxXMpexC=p^ol28K4LImu9ghsk%jVX6?xDq6laHg7SE<9G%*Tu$`1K5OHXno%gQ(0#)WkO6UhtCrP$t;%y&fUa>UjP'
    'yz1~Vb}xrh1iBorkigde0X230AnBf#k07anegE<J2v`nOo9Ro<TDsUm-j*)G@p3?}in+^Kp%BKK6IHO*4KRJ=S^-X3=y-};q)=2$'
    'B30{I+3PrRjY3bSf`6Qa7sHmBT2@I-BM<%6`Ks?i-RA=KNgyYvJK)TK-NHL;(~n~)!M?S!byt`t<)tt`4e}IHG7s7m#B@3FJ>>i3'
    'd(2YAkP*)fobANHirg4C;;S%~G>1%WkKhYBgNw;O-eH1gfzO|gw0T<VEbL4c@p?=&_A*SO9ZK+e+ODfGFCW>BZCy;U)mS-4%_k0<'
    'eV{=Zk$}<DNPt+Tqo*&^k;AS*zE;s?G+NX27(GeP<!>_2dnB!NXNj81M31sEOE^{^MN{A3ZHT?!K$?=6VkOM<5=niBv(NT1N~Fj?'
    '6H&Vavs;<fi$21QDf$_?xSEp_HA7!p`3tZQ#~*Q70E+SY_#Re`xVlJf6BmB{W){Mf;?|3i&d1I#S8#|pA>Jp7;fPo<KguO-S|uTx'
    '=QFpm$d{^^<TxAHg4_EXzfH`v47Ti2@W9Neja#fG!QghrD3dmslK(gS17EM#fg#QCGG+lMA)sJMwXQazM5JO2L`r*4?15!TG(AI4'
    '{Pu`~(~=)O;lhQYz!S}OM-f1Q<C|EwOn>l%LGFS2O2-)o-Jj3wMVj=_sJ?q^Z(gn5t03J}5ysi&IVi1-6{PjLMy1t!6pBF>vBe|h'
    'RNoq5h#pwxYc(rXqO!{G6>R7C8D?oDM@HnHC`yNDGs)2aOg%97gW1GDhcR2I^owb@ZF`}Rscdo7vgKs3e+2{LAWGjvlNx=j<AR27'
    '5>LXGXpfHMh7(Sh0EI0pY(2H{r?q&Wg~Sw|#R~y34>1@f;Kr9In!Q7HE{s;}&4U>q&+rXDeYdJOJ3vYC`NLKEP`)N*oJKPr^^io)'
    'i*R)sRc=Es?YCNJ(bI1=Y_##}cc{*O(`n0isjE@wAM?>&>Xv1G6ou<Va+Y|$2fcTMU&KmuR*4)6A@c#foGQ<WR<&t;+dk*YW#*Z6'
    't7UO#M6l3_Jh!vGExuyk_MKfzd!?waV*65CDj(@Y9A@bvvXWpcO!kw9i*W2wge!T8l$*5B*RdCV3{+}{c3;js0-y@2EJ8f<UN!-u'
    'XGhtgaRj?*Di4ilypNZQfN2pc*1MCCA0R<oXF>`;$%@@*Ep+tWgjhW?1g%U$yTQS)vo!2V1gs%`u|-?9Y{F8(pD~biPAQ_<dXAVf'
    'UZ7gRT4ZQFjx?&E=0X}5Z>&@ZoJ`|M^1w1)iI`BdFO!cL#VPBA>T*r%7=S8`zJnP;iNo#MF}(nB51{2av^0U85ntK24YD^w{5p=V'
    'nM*PwAy%qQqIBxbYGxHL)_J<Crn3Or3i(OhxFU~CX@~(saE;M00rBL3Ya))={r^YZ+x<3<WP5_|`ByM~yG_!fX-T%TvZSJYogY=@'
    '?ySt*w6m)lPPL1YXj^4TRFaZE%F^IIU0|OEm<8^|46u(oZwp*tf!ST`+ui@9|B^kwb0UI4O3KXY?ipYcRTdeH?>KSdoD=6Gm=3?a'
    '?XSvGv$D{6cyID>jM~S=GYcGwS6?1+W2amhYb-7wGVxB^*xWP`rgW!@5&7Rh4a%+xJ7E!Arf^7Ox}slMPBa~IC_`WIxNgHO1WO>&'
    '1lIuTh-?ifJw}(N!x!lom5ON%@pps#N~p%i+F-_5-E`*j6^S8E8ehF*ADXJ4tG9>hM-#P!zJdE?^9x0eq9BVMr4Uwy-qs@r9YXQf'
    'MZg7ml(;A~SVqGfk}-N9!kE1=pIHH*It$IiaAZ=POsq<y<0NrBPv!cVcKfB)d55iZM)XabCz>~5Zk{8OT9L0+f4O7uL%k}*sc)zD'
    'IR=Y-5D>G!f(VdLO9BNnuZR6>0|rlY#<wZKQ_v@DzaRV(J!!899ZVl<#^+$TyB}~c&z*NKw{Qm5!oBt{Q8V0MtP7Zm${SB9Q)6$j'
    'E~F*$)EoPh=}CRDHi{y0?V_Spd2|#zWI~soE`D|BEX+(sNQyW#gkaGMf`{g5r`b|5nGPi|`^U@#aoXXOx5s`93_-geF(eMAqTB14'
    '8Keei;`V~ZzVA~v`<QZ}9pb4En>|L;AR2@jtk4x4=?Ihsq8$ls(HGj{7cF3tV7JRafz=OgR13j$G>Oh|cu{?6H|MBI!(sEryW!1p'
    '!zTq#NjjTGXPv+Zvz0ia9w~g+rbFA4Fx1m}d-~0^UVHjv4@h@&lgetz(_VX8i+~R6L@xlulU_oL6HL(+eaQFkB6_1SZd0Ey)c!pu'
    'G$a8-{)H2olF;k~#N!GE&WY_KCUP|Ky#C#ml&|&gx1?aL|I3z?@MWp4?k7Zw^zWz%s?-m*8$rYOx85~h2%CIBa3+Fl$gDB?hqyHj'
    'My-VS40;W_(UgBjg-cF;r5^bO$xme;Fbk6zp*p;^^+YOeUvF#^AzgIs#Pzgg<m-62lKP+jH>Xkm_kZ(SqC4gl6MTqA74+Vy0>x!D'
    'puhan|6=J0bt~~ViFBYrIIOi((%AX;e=}?~H|w`J^gDEP$3&Vq%{}64*Ptkg7=^>(n3m|8FCjezk(5J4dbJKUzH72TR;p1U_Y72*'
    'F<5&oYsW0znTZe9=?D*H)gO-M^U^Dy1ae|wbP$bu?hjHQktF*3kQ67z<)?ilr~rU#dKz3$CQ+k7DDmqZZ0*SeQ60LGY7eVHIkvv4'
    'uNV_^o-0NK^}0dptPwN=b{5sqRuA2+fiL6L;R!)aw(6P(k$8k_POou%Gq_}5okWdIx@nyCH#b)#hPN5vRVGotES{&CK}#J4eHoPJ'
    'Q9_w{%v^|7h}}Ip6Dzz1!%ZQ^)r~;!F;}*2G|Y>^<t!7MHf<1NH>#qfDOyIiCA#EHyR|JE=hMuN#8mUNpg`T$*?|2CE=jxA^<uR+'
    '><luBwMe8z1GGH#cFySI<4VHkc`^3(DKjhuBY`yKRk<ZzmIqUMSbT;V6!)K=LhYiFZ@FVOE%1GS@ypEAu>aYPs_OzKCH0|ZYyJ~o'
    'br&7ng)AHev4m6KEFqyJ<$*BwOT?l?VpHxfP1os_{dI~bWPVh^ML<ig>LYd1_^H&@P`h$k@*9*z`X`WdtskT~#RKFOaatCEc)L@n'
    'Us8?uo)dgZ2<5)VL^^wM(}_Lh#?4c%Cbb7T$;fWcbk<vW;SX@(rqlcU{OMls9#QM1$qp?WintbDJ|)ca9(qB)#i4v9Hlv|Jf*wEj'
    'm?ByDWpCNUTW)v5esPi!UBzsa@_I%GS0QQ|a$|RYFQZ0k0uCO_qUpO(3#Y9h?MVD$Ik`4JxT9fx{vK<cNuzS8&fr~9CQ<#iwo}hq'
    'kJa0$SKdzSBeBQqR&i+e6#G?BtFm$+S9$e>UL{h$DJ1I?oJ7(kcBe+*BG(n?!`Lvug$%=-A$w|x;mB<%pLN#kDPV+4Fs}%3t;&vd'
    'QJTW%w(Bc57{*a;sV6j!BGt4T%yfM-lXR_<u5}VKWV88vkiU*!d&Af_k7;o+_ZrHI92tl`0@2cq`Jj6L?v)8Mr1fZcy@)oDj(ZOx'
    '84fV%!<c7$m<F?K*qR04ep=THvs;VnNqr8Bzp*7shA&<iO6*Ib@{N%)yP^#YuzxJ@BEUp|r+Qb#@TLdcjQD&q>l5n$<P3-`@;f(c'
    '08(lBbJu)sYgwv%AX-y|&X42y{Bf5k@sbh|Vm1u>%13XW4sR0Y2s6HuX3n$FE$chkfoB=4V+QFiKX*m2b`==}wl>d*^Dr{;&a7OW'
    ';LOU`3Br9jt<K|abVkUoBbOU#Dah(dQ>T|hqRsMj(1&vz<7{k&!A~g&uJ!c<!9>Kj&Q%PXjKMfrSN^J6_;@^E{rLD7qOS`7D5_XF'
    '!tSmLn`>qHmYpiEFWmf8;U5Nl<$S7CPK!fFAeu)AlThjNx2zuM{G;=Az3yC(cCJ=iM`5mZD9e_TDOMflYjB1wt@6X5R?x?<26V0Y'
    ')Q!|vfzWPQUNg}037Z2DM|r{m#9iF&GyKRC!%&R)5jwRYsfy{5Y!Z>n5pyKT!#GDNZ~Q~E+22hPm+*y+@L6;c45k$dN)LFDS@MSE'
    '4VoAGH~vMCC_I`OgxS|=eUoHu;ilTd`4{Y8R!$WUWYrBkk<AI+h@2-V=gk@a67(VRwzie!%&g_GshNhLBG9x7@$e<i=&G&{ChWI8'
    'z(a%M1%7LJ2{S<SU22Gb>UzB9GW0W???f%VJtQpc=cP*Oh~6{2B3zqUOl@_M;cTr~Wm&zRg@7kZi}#wBt(RVop;=sAtyyH`>JzM%'
    '|IO3ALoCB=I+B!N!U#3Yr<qtfmKITrm$czhH#>OoqQ#<(RV?bH!lJ4YKb*AGWlDdfx)CsqOZ%skPGH1$1ghZs(;rZ9wlvL#9GckV'
    '&=W-s>8Umjj0A@;*P4xVxNcVYHf|>magAJd_7c@sF{w*ItydH8+ynN;Vv&c0iV9a3wBCd0U|>;)+7(Om*gSrkrDNA6Tz`o-Uf;(0'
    'icVBTU((Sp#Ao8jiRND4T6xu5EA1M|4OoFGXPtn-#l0uPnWkF5$qzWZU&9YvT*%XriVe6!#cN!i8WitOpKR@VG;{-9HIzjv)!mHy'
    ';boe_NG*ZRJ_^)WJ49BKT_r&$IlF)Om0DR!MQwUFHG6x7n%3&oS<>AaQw0O#q-mx0mMGX>FVpMYYnxnW-ya;TsPNpPOhp?Ij1;LX'
    'cD1Qv>q-<GvEUkHH(K&{*_GCvcz|2<mUW~41)>W$zVQZy4z|^|vq7hAU(a{>$HEz1s)F6zpaOePI0}f_9S~rBUdSWfB}5khf;6QH'
    '@M&=lI~ag0L+t-ONqe5(lmJy(vi9;DH$cuFzANn{B$^&Tq+QIyM7zCFrm&cZ;@(ynlWsrZs{-DhTK*%(sMyNYJ2LY{Cf!&{QFm8{'
    'h-Hw%#ZO5-kX|3UpEl?J%fJ3dZ3UIGVTU3BSxse4!ERp_grgxT%fV)GLfHXl3v$wJ&n84LB+svijyKof#;l1YcC2XVx~o(S18pQ!'
    'IX_-z2ys}p7;;p&WMfAgz;S-=^SQ#dOefP6?g<o<2DTs!b=j2otI#A$1r1RK71Ea#?+UH{s?xa2xBG686dGj1C<$rNFKMaxJ{joZ'
    'Ow&*uML{IPGJ$*n^7+ittVdo^-+V~INtU417s*9D8-m$oEqjwSyDVMPD5IC7W2$m<lYgo;udH-s&M#;Ps+-)DdibKo*5qB)9D>ss'
    'ov55nh2B*~CF+C|qX&YO)>$W@bFsDE;Nyb$w?aW(w4gb!(LERCR#rY=vASY6z;*#*J3;7UpwEt#B?#bvQv@P#_ZCtL?rV>-EWLe!'
    'Ps*Ss*Oz^x!Prxl85;9b?{yv=0%DL76CXe`w>+6<LCTH2pDZ^O-+6UY_4Z#=^-D1Ox?<X*y60yr8t^--D#&~Bgf`nlCW=;}^1=}D'
    'J)BFk+8xeV+ga<Jub5_Jk#!+RfsZEK#Nl;yr9tCq9pMC5)HF(GM6sJC(~7I>_V7UM;J&{!0kysX-9bkqIzY@v|KVfwQK^S&sSaO6'
    'v&DlkXHb($b>UM9I#*9siOKjlL>uX=^j16n&`PeFzhN?nFRG|ZA_z6NxewEpb%*5!ka99BJz?ccxxPO>{gW1wu~2nfZm;kP_i^YK'
    'QtT&%!Y-96w+LkjYU>WJZ^69Wg}oj%$sER=A#CoLrV*Bq^(SyFT(s^Mw5G3)o{8<;ukF^}+HT#2*Q}}G9_m1-bR@n@E(ff(iq3wz'
    'i<x9ypnE)VN5}8pzIk_A>SV9nNotUKw|1hA1{sK4Y5t352#s5|F~PoXUt*OiH-0}*z1XVY60DV@4&2q)PN^=U1Mh-Wi#Q<o7frR*'
    '_QmqRRBY98ORB{+QR@OtE1@iR-&(C+6^N9e+kk8@9sy|8<eNQ3h1v!k)=QXADVy-Kxj-%-4^_lc!Pti`JCSi)dTUlK5RsK#qug1p'
    'C<Ucx-zQq|0{@-xB(3^-=+Yk(FW&a}bjK0hjeL*qR<MVr_EpO&kC}wF?nI_{r|FO{KsWaBsgN|V$Q|g_6*rWUUgk;lX>f<YT;(zx'
    '6;0CDm7#^DGW1Q~`fw7H%E)9$^1E;%9mCCZ>8gkEjiehL$Vp-62L$MrN{A{}uu9~yLiDssCQ?+d@WNp;d}5_?pAH-0Zi^Myz^5%2'
    '*<CJBZ+*2;^r@kazJLD$J~WBa4jjbUW^-*#D;a(I5<#vx(_|VI3K8iT_5p#qUb-T-gLc5UB=VvHhwhu#uZ~~8B-niO?YI0ynHY%K'
    '2Gd1Pz}j+N_KL19e$>q=lt|B1Ks^bHC-KT8B+c!e+tFADF;2fth(Q9SKFiOpJ7U(sggYihg2k%M*tX4~dRO0yJzM*tEVKLe<;xc*'
    ')IAifxjXv~qR6_GYsCnV$2fLxKhpN8!;xy@)eqnvM&$<JcjNT^i{m$_;pjL7O9t1zEq3$E`ByZhGU~PzOy8@9-riH%<i6a{+drWo'
    'NNPG{Cimr5DD#R|tjwyVMHN5@n7rarmBny;eQfmZ+M*~&jGJ7lP9rT^wr{y>?uYTo3_cs-uy8gG;k?n#5f~qrwsq0J|C__E^^+`%'
    '!$JNkrenaa_RxKG^ct~$e>^&U`OX;XnJ(C>e>K-}JWKt|ccH&W{h|hLj5kOzBsg@BhEqqmb)v7>!$c@=y?cpju19W5N>u%<Iltge'
    '2iw;ghEZa-V<JOWMN-Y#YMjo+J^4~xVVh6b8jOOkX8mo(RC&dZz_b9&>yc5-+Anmowye>zJ%*@$_R?IYYwJbxo!@Hs!K;!E7uB`Z'
    'Xw?1SHhQ&#HwBcr*p;F`MANguVcw%1o8?nNF2jB}rndgT7ux!U?G<OK*l7*Sfg@%PmWjbFTNb#*!17c~Cpa*OkmB@c?rX9L5C)Hx'
    'CrMfHLIYWwvfK9~g)dXS95Dd8s;pVrrn;`{9$>kS<btoLApYgk#T%wLB<v@%?sl$1qR?T}vTYuyvPqg3USRu4FIY+x5SOaP7&|sj'
    'p7AssDh)~XTKG{!$0<A1$s{*DS()ig=cO}7X7}_}^Z-($)!b9Jh5?JWTJ@lJ!$xZX)XZCaeXzuS_imJZ_)R3H0j}acxel#>yDdr7'
    '%2v3m;f&6v#4=p%-N44>831H3zI;9$5b(dlY3*C0x1#DA@t!@-^v7-5Z^^~f-^m2jwoGgOqD|E<vxiDm#$pg}Q2kp;ejZOCJEjIy'
    'zT>_c6edEH?9iD6x|W}+AL1w@GcXnSUsQHBu_P4SuH4@U`Ma{@?Nx#}C}?kmZ07Ux99%@}CpDOkB5U?9ib-ypr%05Wi^b+WpWIET'
    '+I}*e#(&xh>vh6J3eFmPTS^bR1T@ppwpINicz_U=j%oox&9{~;QC5iX#3=;NhJl}VaFJOvQUIlqVOiUVx*t>1eYqm9f;pi}nn9T)'
    '4zChi6$#&q)fPzb+xh(QRaqR^pJat>s2M0hTR*uWeEgPB$nYId)_mR&HvUE?{&5uDZc)+soKnOTijuC7<Ui<4lBI2O$oGXdACon&'
    '+K)lV0xdh3w0SVKg0j8(#dp4+W6;2d+u*8j7ohg_Hx@)#TfDwMpQ{`Pt8;w4?|&JVnAR<*3-U>1@&td3rbItdsk%?R($=lo84Ap`'
    '-+FP~TQXeBF1xYU+;0SpuNwr4L0JFF*M@97+&_v}R2uXj#S!YZPPtNE6|{jyGRdQ}Cj`J-`vLzn_BC+tYHa#MKPXu51RMZ|3kxF*'
    'Q{u@^{!QblKcA~y#y}5_@toOUdz6mh*|C=d<_Vp~iasN11x!KYPSc4i^H7*P2sMxlhTgQkgI4`5{1rQhd;+40Qx&M+MSt|zJ}{qV'
    '>2;!w{Tfeq>-$g8Vwbp=F?%jSF5o!gl<ov%&<lRMDrzve$MT#k28fm|;aADm``srcb3%0LAX3vYpKCX_-@_|Ai&pBJn>z7_!FV=J'
    'RPrGl=^mfFsW{Tz4~W`nt^S6X#ZUa;uC^OAOH0fVV$ROo6QW07y*fU9>AXEUIeB^F2F)gXr=PqhX6d`{Pn~~s{&4*AM>p8#WaxDN'
    'c>Mas8%lZF>~t!l-HV^ZUq5x*sNG0Fvgp7XeFlYxCqV|ol7?UGybK~%b*;5*F^|R5?p2vt{-!>k-yPg)L}Yhkjb~MRBiseMdw~%F'
    'H-kTlJ5}rl-HMM{T~wBnci4V2XkuRXcY|<$-)HH`jp_41k5=ut0o+T_7Acx*1W0Xk&>DZG&wgofjH%GLz^k{xE-vLX_z$9bd+^P;'
    'J*d@u<EDh*ey}s%$|rO>tRxL9;F%oM4>i`<r$N<&ulE9?ufpB^nrWEW`~=<<hzj%FR&uc2XsSX_D1V*ct1k1<l2pPJ&HZ4X62C5E'
    'A9U?Dc(NDV?u=^<o?dIr<Mfu+*fQW;+NryH{oSv>b_KzM<9`w7SKb+6q>jIC`%+b<4UG5l7OvFRF+40l&XD2Nz9<u6)XIk?%=p&z'
    'VN%8+le?uJSk<gHMP5_y_I{=2S~Vf~O0T%~iL->V%ov66=$9{M&)nY~y><il+n3Mi?+-`s=<m_ncl`V(`un^0ulX<ZWRKo|hcFB;'
    '-_qYV&rj*^>o<R(zb{@scRObWr4jb0adcRdXA<|lvY&6!@X=}C5}E!d)~4ZPMe!F#*G7!!6_&m%P!RD*s~~|W^<VxQcvWLVTyy{5'
    'e}&xPfBi4?AECeZCof;Pmfp9kW(1`xylbgiE{}@-<-fT$2{#yDq*dQ}8HWOBIjdZ_%R6(_B0d#2Z?Jy_qh5%}C<kBU?ueOe3RlIm'
    'uFJx;oh>K&d;ELE7XfU$Q#fSxAjUj8-ewn$(*b;Rzk7Ld>N`RuicdxfKMnI<I#1YxB9z}$l;RyNwb_R7oE=7DezrLl8Ii$5xH1nU'
    '@YPj3b>1I`sKIoh<-8#Bf0#~^49-wlmy%<;Iwwg6vpugbjDd4ColaUiJA9FTl|tLAxx2S>Lqs|%6mPZ81{}$5z|t62ere{w*9Gj3'
    'hnDYKpS$pPnbqPF_+lJ+EdK8&%F#5T=ShZvv186m#r^SNpCLCTdg|OjKeZl~t1v-QTB=ye4gp-N@>cN(xuj{Ur61tPaltp5(%HA?'
    'kv9#jzD(^lTm2&E(eXKK+fSl1*hr5(_hNW|K23o@hW9+PD#SKHZLGrZVhoN4Iq^<UF0gh)kh~MiJ(2^bOFoB)E$r4pm-r`?Z@oSD'
    'Tu}t0X5JQ6QvMAc-`Dk71qoS|tGmE`MPNxlmEaqVqWmo#U+RzXQ1YE$kII>}_P+XV1s%y}*#-JB7(3Ua0w(`MbDz#|m@)=>dWcLu'
    '=V8GAvC^b1O$<$xHEIG->@2il+`nGNza-OXl4O_?7FMmB65OYpxtzuAm_87Xd2V8kz97(`4shsE1cQ+eaHpz6(5dSMYbKWF&kt6t'
    '%n?N61{J{0f;Q)v7lzuh^ZH67x>Wr6$%)hBh@tlUftfuwfxkGCQtZh4PIq>3fv#UrlEguf^=Lcd{Tj}Kd3^9N9OoS3>&@|BIX*v-'
    'CMrO(a&&Pz;DjzA#3V+XvLE8>gnOamo}nkQTBcfS#dy>zDy$l_33U!X5`0Q%@7XMOk?q1y8ZX3IM(0|<N=TndQzKa{N_*ZtJ5zhB'
    '6NF*daThB_ivCNZR_9d=`g0wDoyK6ot?M*C0Cf0qdYIlOhzoR^I?509GA@7`<tn(ZV1a4+1(`6vl@&S~<|&I#cptDefVC-PsOSP^'
    'C3IJemWa!9A`^ITow7??EOI<?IFYK@NiQx!=M~=amUBsj$)GnICV?}Xjso$yY`ioF#%(jtHLlH)Y=k*TGdeV<qcniGk{O&m!;NL&'
    'un{T!UZm-Ck`34&G<|ucipT0cJJ3dJfp&=;IJbAQ6{urn@Kv7POB2N7*W=W#;LEeXGII{oHFdhg*kckzj!w<+gN8W0I0=DX>&zWP'
    '<26Pg<SBei_4rZTOuKYUQNvPoxj8!HaPIMW$!!)1Xpj|3SGTv)6%@CFLX~Dfl&J=kRWo)kQXP-j@$IKi>J5izRzAKq#;|T=e<tiU'
    '3}}$hA^L+7OM8baFWS4rEcTLdaxNNxI5DIioU0PYi~SbJb!s3m2B_iSTF^8cCdx?}q7B06O>QVd*EE7_obw_Y4$i^>L_$S;9B)h;'
    'GXcYya?7@-1inu3g%H$OmXDqtrVpqJQJluat7u}pdHJafX2Zc~P)5TA+Glq)MK5^)Fth-ES(vuK_}Cc@ZMVYTclTaV8%cN>I>#p`'
    'K3ZoT<?7t?dD$sXOKj9XWK#6IV`ij09YHY%Ab0b@<yezAf5YIpD{8;$o`|if^ZfbgAB_F!nojYq{zUaKC_UHam@X)OnnJ5$fg74h'
    'Zvq$Y@zCcv{nCldW>mY1<8@A325YxIKIV=NkI6nc<Y=Ga@(CxkBjBGa&M7dZoZk{^E64Wwdmrl@L$N%AYYuCcHlM4&@9>bv`*y_f'
    'eTlmxjw9Q~!7^6ifK3PpCbmlRHsKf?C_fu7hphpXEISXSH`2=uc+;QZ#JPzFL*V2PPVw)ZfrQLM)96Ebi>QA*MW|zG1$%<_9(4*T'
    'KYB>7)y)}u>}O5ZQGUt4-C2IGKK7>BQ1052EF-R#b;S7&+6sQFLx3FGI@zI$`QYt**!j&)zzp%ua6}xO+d2v3L5OOWGl?&Weqj`M'
    '6+O6${oXz$tV6uDZNb6DAPaUFg-WlJd;cmtn$gr|gI_pH<UYejLU=lzrCo}I#O{K1^Z+j(5JNu|lMgMkSMGz^vw*mASJ&`6GI=!d'
    'SM1g{Z;Ai+KKrfa`<5(BuYJ&Rw+=)$FS87n(BGe)zGWeT;BPIo`dKxVaUgN+I9?iwyq{U)lfCq_a@Qz2V09$Pm0rsYAivORK~tg#'
    '6Zn|N&Na>FkF9D8CAuPq?-$RJotJL~sM*Im%)Mxb$s^xae&8kFSzTfXC=GkIK$K}!1}%k1!USy)O$56!BUs^gFZZ>DwaCGYjf@(+'
    'xSBJg_l$)M^bfvex5qeHcom^*$vaxbpwtn<wRVM<i!_3BNDxQRVjQ=|(Xk>~xS|9R{DHU=GqAt>(|^t#Rf{$da4Z3Z5>2=*)6GxL'
    'Q%iS|h9(w2!B;Tykhv(SShXd_MZyLJY(>J+Kxjij?hGSzT3Sh?Mfy`Zb7*%+2+m_VcjMtb><Tn<N@J>cPbAdr?7pz#d2KJp^Aa@1'
    'F}n)FqaauLc*l_xI%vN~oErohI6}}5slr4Lf^LZ8i6A0y3T`)WEbcLIs(c9>W(e(0lvJ523Y-cB5;)a!EuiK7uYTzKs3V#Rw#~0|'
    'me?hz|0*R?4ST}0jwLR_MW>?#fldi_o*%t><(z*1(qZWe%_>cQ+y`$fOj#FFfm=w-?rB19**LeK>iE;M5si4DAV<_D0YC}ON$A+V'
    'fUuJNq(?l!kbW<-1mvFfh~T#ke<nGvM?^ziXz`xW$5N6#M0=Ty&CwHZ5TAQlSr8FaP2c(Hr=NhS99BoAStd64L82tLHe|&%f{i%4'
    '%r{yO8;t7d!)bbbpKdG`5@aUjDRQ7t6}sj+iJ`P77sGze>Qf)akO?~{&tJZ#zo$p1FI&*5su&U;y*(B^JzPO(Z`4ZTHp|)D(sR&q'
    'h2Lo9rHv5&?;?2IDKP)fk!8?lkTfyb(GeK!aFFw__p^WabL;HqPMbcNi=?!07Y$uFcm_=g_om8CmY0Tl#y2;MXR*5tFlAH(KPW=K'
    'Y!bvTg@|x{Ev5iFqy}a|y|B*_`CbUv6xHxj%Y-Y%<$a;^Jm|OFi|)Bwn+@P_t0KEJ4Yj}$KvsjE!v&%cAcuHwRn`b;gqyUyxTUlk'
    'EW^je!oKZbV9TSkFbv`KhVsBfYlnc(J8S{|{KF6VmUs3c|8UaTI`rwo&ZXaJOF6S5bZ}vjJ@_$D_7T2d-NF}~28vOnTJm<j!NQ$m'
    'R~!^geDh(aNZt{L=KfOcM(cOy&(y)Q4`&Y@Rm0hb&Z0wUzfoaDroNQce!cyLf?evGMWrNnNzc<0pW9Rl5d_hLY`In(9bg-Xu5cXk'
    'zMIdr#|(Zwj6+*4D&98qx7oPQQKI^-QZ8D2BknY9PzuXns2vte66_ibtux8n`ksj7soaM+6d|Jey0UMaLoNjPpLHJSrsZvY(*=7_'
    'ZC-cE<S^eJKaSy4&FUJxiPVXudb({qqh*$$1uC~6R1YehUB6Qi@DNmh&bydBC;Ndp%S`2XVP7dY;9?!WPjZSlM&;xe%E`a-y^y8o'
    'OhpRiWVhIX7LVvGct%X10T5J0mcia)E!11AN#*1<oiZsH1K8R5ytz-~5N_HJDhIUb1d^$Upve+fue0d)H5J?Jw}BFQElM=@{lH?R'
    'bw1^Dky1<-s&s>?Ql<ShpeM}fD$ui`pL6Liez3%+nl(}W42m@=c+r-il~_~(g-KwJ5*ph|IpZM#&jN!j;!lBqIJhY!2+ZYjz&D~5'
    '3|Wi-bc*5)i8WJrOc)!b2u>Y%OUFP6&NNW&6KrOMkl7igw^QlDY<xXNgh8NQL{OnDl?F^nPtMK<`&21arZjB~{XL(f7Z$F~6JmCl'
    '{xE8i;EcgOQKH7vMPw|C#WI%r&xO4K$yo3_ayy!)Im?oH{#fo7F8Qi5jVcd{pzJx$+sqBPXNo~2#$BD(SxOt<1+D4^Jz<+$$hlB_'
    '0V>m~1UNj(`Y2CqeH6|2ih^M}ny|ZN&DF-2@nGzCiGR9Y6f?}Gmx_>ZkGg3#WrkM;W8tnt!VJzSpQe+Ea8a%tln+HFhy=N0$=5;6'
    '+o>>eIw+T6q7I2rEU|WG+Cz2GJecO{dRVb%Ug=8O4{V-}xjwlqSQX9mM8UZq@|AzViSK~HU+$dxEW(wFsk*Ro7X!Z6dMH-j;%gy|'
    '5#NZ`S}saL482O)Z9>|=k62hfY!%=cs1D_=GX*fh4_Y9@+Kh^ETy#K*(;9mPw26A!_Fmm5RGo~Nd!s{58bLxJdIYV<vMuDT5Y#YN'
    '=Rcr-@*HW>v~AMPX_HVZk&CF}DvGr=56P{=5C-WG6fHQa(C0-q&`a1+6D8uj2e4@=k-2Z*oSeGBvM47&m#Rc8(&&&JT+)KIOt(Tw'
    'SQLtJA_1y|qRMmxs?vOHZZc7+#VS*Ob5l!*4x&AF|7`MVxKJ*28H;4e&mv1<{HXaj-fYCS^{!;&EGukO@s6`{<1aoZ#bOnosj<U^'
    'zMB$Ia9kN}KSWRl1`Jlm3P@+&sMz{3<A?w1`ej~F00<Mp6R&X;e2z1~5J93tO9jLNGkAd6dy(Lf0cfBT-PwgD7X$KZw^dya{dAlJ'
    'ta`oBtJLR+Q?g9>EcmWXwbUYN1O^iD5F&oJ9u&kY*Q|_H+qYMQuRL!MQ5h3`1hzoFe-PD8gc&HwB8Q&4fv*j?(c|LFpe9P#k5NK2'
    '9rGWFBbPXTEvi)_$I@Y;6~!c{XquW@F&?1kvlnk(zwEe0DfIehj*C`ee*4xbs`D-kJz=!chSATVY+8b4^LSS8l;1?@p2yK27Hy+b'
    '!%)GAv_lUx(<V{yp5RT7z((UM-|mZ4W4N>2$1<z!*JF`O>8o0T>uB1O1$r#;A@ysk-sX&F*PTc|5M2Sb*bP3d*@GMfgY3Es#($`|'
    '@9V1IWQkMMCtZUO9leTRz?3Q_*P?31N@bQjV7UhKtz3;sUf>_kuVwbSB&pVHv-f2XppQfrPiWLI((5civlvT^thIvZ`!gUQh4`=S'
    'VRLh{X9-HGv&vAfk)cAY27OCiA{{{7p8{FikP0b9H&RyKB{`GM#r{>gg_wamdeLp0b{TKjDz$N*Pa}0e!_oxo;j}oTt+`^jDtGj;'
    'uGdF3)+DOQG0uYtkO6*F4L%q-&u1XJGKChHuL2>e{9$3aD5y}a=%JvsUMaYlIN`B|C1hkjOD9-*C0?llgzFLcF};VNbVBo(_-+w$'
    'vb36-xnNRO8S#{iHN-%@IH<rnMtWWkxvExWb_*j1WuOCugK{E%XXzM0JP<5DTR3+8#My$e;-JJe_Fw+Xe|8YmuZ#|G4zCiq+3rBB'
    'Bc6pyD;Cs9Jg0Zls8SzQVfow;e^ce2{qz3;YT&M*2bxdne$7LQirYpBhkVov?X0F-F*3bi3a-VhoB`)A;dtCLrhrt99f*l_?aGfe'
    'Tw+uwO&ojPh19V2V1R=fCdJRy8RhI)(s%?U*Ea*9t4ThFN!^;|VPkc_(N8xp@N-VPQT$+=v2cIP&MAScU<`}=C(`x}BuJBtsJ3Y!'
    '1ib%HVNRFmxPmnW-&9=5?a;eoP(}45>AU|UN$h3D<&&(2y3hU`Z?kmwg_!o^9#*ut)Y3O$w64KQ5R)lhbRf5`(E49QCwpZ^px8`J'
    'kj?AvgB5+g>L|6(PPzA+A||4dU4T3B3qB<V>r_M<k?11uqQuaW7cRrt7w<8Tt1QzfpoXOvj(2qIOyCsHw*(ob5EF>Xiu$xO>sj_#'
    '#cEy7ro3p4FVcwRg~{-QH{LzpaE2_LagTVB5=LVPV4Mt9q*SfjCs&COxIm8Rj1swIqudaa@wL`u7|(Lng{Mt@tuJYFQDW!Z$GGXk'
    'jodIzui=3X!A(L~U&O0!pwMUEj-d*~7(EQrODI<)N}mF14%3kpY$zEL6Qu9H)%CvnjVK@iUPeT(7dwI7w8)MWV*^Kgxo?QCmXTk?'
    'gBB;%Qc>0ay{cZ7-8fLOKD5jV2bUm#9BgD!i;avv6B3}GPHjgM*KUg*lPo)QyRq*42I6^d3`dlAqlj)>4k{oyu!Ar#UElMv{y;H<'
    '%i06FUCfC*`Ym>)YY?8Rd=o1-HZ>mPis7-NHitc=Y+(B;C&k@pL+Q0_l)KIn+N*R(I4{~*XV|czn*DThIvRbc$?N3)Q!Uc|fonp?'
    'Gumurvyj2%IHd#28BG0+RY8R(*}(S8JRGS>-#AbY)kwl?Cr)5iEhR6^Mm01tN5CZz;GCZiaa?r9nGU9KAo)%law@PTkpAcYXLbLk'
    'mq0Z_%tH?^nOXwvWqky%dO=QfWlhx~2M|=@_<^?0bwbCU`K~UqS<jKMiYP|l_QX+NAT(#g13sG^Ib4eJMkLRg%+QJ~dJ1(^OP#Ec'
    '?fbmUasLLFN`URPt75s|WUKAglltUt<KUFeR=pW*7|dY7UIIXz!W#(S9BtG$5DF{WXoUM4Y=|6fg!TObxRYr-80OTdVDnP+jWvNo'
    '4o>V@p&m)mgKsc%h#+ToMP_hA3}iR<D_h}J65qh|0{j6@oYBUa5v#aOYrsprEsIYFfwYLu>!vUcHH1}Q&PGppFB5cyH+x%Ckux!*'
    'NgY;#;4?;<FwoL|PYZhyXE>f-rQ<#=Co2=4-1o=H{UM;|igJvk&&MYxwwf$gU^FqCdsi#8F+~gWG#=c><3QU~?6Tv2D*WTspm$~I'
    '=n!SJMg^6-!V*QTL##EsWd$Wj)Rh9$+a!j87TSw5S3+!gJ>{3oJ}KZWh<3QWz2gDI<7FrCgW_oGS)N~ugAHk)#zO{huuAb@FxK$W'
    '{3IUDuf=eIz;E0q#>H{iKcy4#T@m{@xf)zdYdV!kKuF)J@Us%huSC0!^unGGAdn5!Z?sCggZ>s6ZmFJ1aUu$-2>t!yBF}MsNVpz9'
    'Ux4W)j?M{@29uU`$bh-}rh8!STG*Y9HUWhCv$+dXIc>8*&g`)*8BR-|^QdbY%8HvBWC@*9TkuWi<Tb2Ma%I^FOuyZWCtOTXHQxVp'
    'o6uf(HH=5`_HNjy1<nsd^knfcaK2A6qOC;@><vITHwXhH-!>y|&6hg3q!`7#3x@Zls6mr7XD8y!YY&xcEjUn?TOA?{4WF23J`q~x'
    'ULxu#s-UlaL$ND8O_kFLlk&YCn_2wN0=9+b9{7VW9V>^iQPp3p_*vcDe4K<iK=}8`{c5khy=f>gh>Is9^y6^la-h3P7iL7QiLa9g'
    '_s|cPM(IdJ_7U~aMcdqUDRx8;o;eXcc*Tt*n89@cm1)Xxm53R!oRAUE&6kM1VJ_dSPzOllfUB<D&5imrCw#No0)A1?Z9UKNgcy`Q'
    'yPNV*Rq^H1Ya(1$zwc3Va&fEuH%AXTX;DA}3kVXU{VTJfdB21!Q}V7v)g~Q{@P}h?qHhnC!Ri5)hxD0_E0;6GNhXD7W7AQ6p&`nv'
    '1KensZ?>y--6igkidmr6y6-8`7}Nl-aXCZ7DD=X=;bcqk%7f+=r_F!k?_37nD2M@HoK}lsHBBz$F<OHhOF8w6N})LR;daaaFg~m('
    'jiI_>(Bq?tfdAkd-0u*Y>)}k{=Wlk9?%K6^XMg_b!?;uPQGqK(e$!C-?VKOBK5S9uEzXP=&fn$C-2-#|=J8mR4D_&sTmj3Op_3*A'
    'QiSMQ&B>ipN7%Ig^uH_b=ynZ-W7Il(fl#Q4IWN(G7iD4NjaYUw@nWtY<myd4zKbv7zP-CX&)!K)!MtQh|5tNw#I%-Kwz51SQu2g{'
    '^_U4tkmY6wR~5UY%!A*RdGNbm!-L;hJow!j9$bZOVBBXS9SGva;Vxb7`VZYutJk1|$lvZ(ClslN?kQHDfI{S|z|`)-l0`iK{`l=l'
    '^fyqU&Wn-}W%&1{O68#b?@XC0!eIq%+J5wgt?ffxw_J`rI_`o8!(vJ(UTrACAtvP{d{}+tJ|2|)Y)zwqj%lYu)VoHOHI@2AW`{(6'
    'LfUgt-$Ek9$C17RBP3f~P4sNCf*oY`Y`=ppS45<A5ldnkF)W<b2Id~V(*LgCRsEb=-7J5>rKbOPc3biG*r_?s-@JIq3@nyuGV2l!'
    'Gb9%5t0|KX3Gn7SI+zDOaU28_eWjSD9AGea&wBKlLna1U%saK=RiG$3zV%5V5@dOyQS<rl;XZ=8A3cCH<by%HBP#{!J4<_db<n6g'
    '9T#dz(EMKM$BBwAE;9_-Fj-KUvfBEc)?Q=Fy4sx%WkpX775(Z?2i!su-!k59Zn7hAxg{@GU>p+H#6!4Lp%mV6OS#nHXGHglvjlzR'
    'rA)vIz2c9nC*fl;vO~F&l$ce)D%Z$-nJGSv7cH$!h`WvpxEsVoeH2WrRHlP2(Ev=9sCwGP`ot^OM{a&a5!!E4sfhc~rm_+Dq1}tR'
    ';x`%}YcYSRb(Jf;csPxEhqYb{9wsV|o&)3DS=<;lYLt8D-OHd6*6a1BL1WJsN6zXq)llD|EJ64*V22e8JyoW*lIr(RQF&TR8-ow}'
    'rQwTj0CDT^cbE#UE$Yta69pS_o2!m`D`rUL?x`&O#rhzB<<RBYzkvc}u7<!+#UocfD){ewe!^<jqEKE;*P!1TAT~~*s!|bGl}fqH'
    'Q;?KrDpPY6r-Q%4Ol9^2Adq)|)eKRtp32qdT**R5^L)@=`o+aYb!M{i+&q_TywRc4{*ZF?a8^D|Wp?1ys@uJ2?jdL#98*PMquCa#'
    'mPpqF?-#4qDfLawMQn1OV$BS$nR&~MH&el<p<J(2>qW8tVLf1ouMG@ddD8%GH;E3;IHF*{;RHK=c`o2n%v}WwOf#Y<@S7`d9(|(P'
    'RVcfK;`)d8m+AP6`>68&+HSs8#a8qb@+RtMlRJtR)lJpG!rp)&nXL>~17`5ie((B$70=ZQCm4L>=a1|lm>C7D%Fl-6v?}TZXI52u'
    '`+5df_~xqK`>4{o{$Ce_)4oz?2PCEuI2tjv2ejBVgfO)ts0Jp!D?p)UqSvmQ5xc00(R$ubE?bqju1!CHH0ivQ1)jm<Uz#<<mHF-N'
    'le+C1TI~k52I2Ehsg6D7H{2_nh>b|@ucsHpnTaUW*WA$g1H#SWSXAUN0$X{e9>u)`4zxCOs%YIuj~}OF!*{<KKck~sITp!7slU^{'
    '+T6VIknxi-*ord?Rxdm>?YRVH7wV21wk>MJpK&!(SUQhaOogxqqZ#O6cw6F%=DM1>ss!T|=6n1leHS|%)mO{JW~4j3(pO2*(b0;I'
    'g7q~0<nnWro^x4&?>w2R$aT6S>@H;_{a`zusgkbE=TjU_1O;?1iCetO^woezrphA!`E1&2Ex8;lyDSZGt)+BQ6#Jb=>=07)n}l_c'
    ';N7ED&<J9X>f;W&ws&pHy}mQ_aaBJ=olAhk(j73Nb`^F|;c*oy$-4DgzlGPdEt=C_&WZ(4+shM<A<<GD;uzts<;sMyRVK9PIHhw7'
    'FZdNIwD4}4DbJ?kpyXSHvg18q*FW?^zX1S3#h?|8fPgQ(7dF<gNjl4=eFg(QLfHvT=3shHUvreEce^l??^!9p>#n%hK&lnsl~N~3'
    'Hc0#DqXB*NB$^<nc$vRrqo#%*<hQY$lv&7+^Es<N<moKyVUF^wXUu+hViA_3Jh6q#7VUur^Mk-W157NPa%ncW9LTJ(XBL@enOw}u'
    '`KtNICrQ#jzn+#q<&*waBm8=g2x^GLAX+PZzv^GoRN`Lv{9;n6_9okEeElSRy8r8DQyYr|sbwIE0zMY0|2U5h<)`LuLwkshBxC<o'
    'o;O5mD9@XA0AoX=J?~5$&?A1h!<k{3xQ~mrRE+2^m6|1rmZ~>UvyS=i1(S55TqqHI(0+gwS{733swRSbHa<^uKm>tn<MmeZX6qsv'
    'l!q^2b6O_ssp1orjL5Fb;1L;%inp_>bHkW2l;VNd)dZ^UbIe9-ytz3J@e~T92C52RPw5tnj1e#XZyNN%9yF6QYH6IZ*h-B~hdOpk'
    'Tf&Bj8+ehVslp;nwK&wKwZm+o;^#sDoYNjRhRN8<>I{x8izDOvIG;q-*b#r-iBfom#cnyr_G=YhU;{KJ0m^DOEBD+@b<go(D6vUO'
    'Xmcqzi?w*=*es&L#Z327A$)38gR?Xd29}8dMLz^W6P;5BSJPNUC?Z2)U3ZiXr}zVFJy>S7jEJoeE<y3_91fJaXxfB@DZZX7q#)mb'
    '7qm5PC0va8piAI83TRW>Y7m)#!0%i<5tgHD(@e~|9D+nGTRwpyP3b(sy5;5A;yi^)-rmyD%FMYQz^hfR=MqTsC84DO(NHQWQLk29'
    'C-I`=om~eP9iO-?`W5?Sxbz;zuv<1R;abXX|KS5HzjYK|dRB1@*@IQ99GzEBgfS1E^k}p?52f0Bn?Xv^D}`+|n<EFxbXnYfMao2Z'
    'zuvCwxanvTogpMby~7p_!^l7d8y~1zbhs+D%T#hDnBy=SY7oq$11~QW%X21A)FUv8dL%k!ZG659f7yBckY^tbH@KHcFS+n?jrK5>'
    'LerS{;nn>loqCiGRv14G`Du3e#8pA>bA&hL)SZmBYV!qPNqr-{-1MxH^$zFIScws1ZWC^~O}NQmE3{f}(`q~iOmdWIFfUVRLnwn)'
    'II4o7h&&TYEw55)YV*lnwa*%>J;RIIuH)6|=5wS|_V1rV0T|3b!G0WCb!~U;HzQ}2Lh3G&flz4=YkT`&1FQ-_HIn&T;4>!pge|!a'
    '5~<XyH9g2_pNC8}NP$XJ`Ctgn*btntDCP^r6PGE@Sm1+~I9_=W#nppoi8_sK>Xg>M^ogj`m2_!r)1?5Kn26C58E(;-G1Hj825_|7'
    '0s$T<s(&Hetb!HoXhD+7FtWP@BWg{Glf@V<DH|l4tnKlZV9KY*%o;C6&yaNz{f)`qo{+u2W)|#VaDVeGh!YDoJv01h5j~X$)$j>D'
    'm6%g~ZSgv_?oio94RoEfGlZqMn0Z;`C3g#aIU79?ZN^R_&T<}I&hj?nP@zIoa;E`$%;5)1C$J37@{nPVuNM{JRV(A`Essw*s;mqS'
    'e%X|wn93k44;dE+UG&{W+m6@Cc9t5uqhm>5!^{fMP{Mt6*;*!9qB>8k`luy8&t`ON(V~iYF*o`f51bEFO4UBc_yk#X$C8Ot%D>mG'
    '0aq5)dTTEXREGXS9{BHk-rQrGbPy@x_^z@%N4B5bLGHvum`LAiH+gQ!f^L=A_cK=!9HPe4Gv&MNZ5tD5B)sbS0SC>n6*ig+7Rr?_'
    '6Xe|*mtHb4r%|IbR;zb*R3;OoR*%>k?*)6GaJAywMHcaP8cg3Y%jB6DG1*old>SC?%G%4ki%b}Zi)>M`?V<rcth)D5k-5&rJ&d@2'
    'vB-S*3`k%;CJ*)}XjPmm8ucz5=a5kAw@=ZkcNHo%h;J^>l}A>V0NsU@@=g*CYo7hO1FOK2JV>}Enx6AZVhu!qbcgBsE}kss4%n*b'
    'yxLEVPM`YvcEl_Apq4}ol4Ak-qh&5r#|El!nf+NN+<580m5@T)y39@k{o~$)R~OEGg5JLz+H}0HB=X4})K%#$fvRZXE>*U}G&LU<'
    '!C++P%qv;J%II$jEtLGLl|0n7a%0d{wE<L>LV;zql^}6f!z7tNRmkX7L=Sw&0e|t$upZWFH%<nvqqoO_czrqvE|V13O8_=uLOGx|'
    'k#*n;g(+0-=y^CCEt?X99_V~w<3XQ*bE1;1qhkaZR#7YdbpGtkn^Q#x60?8%(<7NHm`Ma|j6grIj0<p9T<Nbr=Z{!pX(9?9;l;(k'
    'QJ<#iIek4JIgu0(e_#*0a4hS=<F5aRst(2NZhnT84rM(bJ?bYH&bh29(TpwLuX#d~FwMO4QQ%yJ=jQ;s^K*LkZHn?j%Kq%7s+hLn'
    'qke}t&vNhQJgl16`o1cbSIhAbyfkq7gWmL<rV2uwB#Wq$W$xF1^zQuS(Yw>{X%tU(zk<fV)2B54ut-)<j~@M_8Xq?-p5#0}X3o>>'
    'Tsx7BUc*a<V~I^TMRjpwLwSAll#@r_fyTV9ZFfI>@-%Q7yI+S-z78B#PM{+8=xClW5Z35XXmhC#rRHg(${jZ@>OApB*IHkFp<}{1'
    'D>W&7h@w@wVc*yY9JvX%2EMBL)#X*;)s3CUQyH#qOlJGnG-nrI)0R?TC^}a78MDTS)AU=u&tBi=XKUhWs_olX_ol&5w8HrT^k+l9'
    'VfESadIGvnYU%i@o@z^#JNPeYOc(j9+EWDLCniiXREjAH>iS~Zp=qU9MNSm$*8}C3{&T>xBw|wKs!f!6`(M#OMJTYQ`Vu=B?bbgv'
    'b0yBPQjf(@t*^n#R0YW5_S_*9cZw_APk>`7_wriujr6CxVr8mAtaV8Y7kr-p)Jo23Ka}@IZ;+=E2d?<k)ToTrO6YVK!}Ik;D|AkE'
    'X6bx8*R`bGpQ}fpuBA)^@zL0yjV3vlsnlr{FMxL%jCk-jo;LZpsoI!O;-pCj+=yv9LQL^E=OTWvl-86ZyFa00bx38X;5OG#&PcUW'
    'IvSMxSGszL9s3h!$7%Y`)|S(BYLbp%=aUAdS+7m=%B6-yDSK|3lt~}bDmx1|5z>*4an-Z@Bhe#Qeszje=$$W_AT{7Go21Xp$9-u&'
    'hShO%o;#hVGB+rKx!JZ}*UlVXseXIHJpQ1(UdxL}eD4G2&i83WpgH6G7C+_L>Jz`DZr81&teag14$&8CvM7~EPMWP1leJ=As!3Fv'
    'kLqZ#HNnNz8UU5WH6t&N)GxtP8GcGRff?E18tNVDQZf&w$n+BxOmxRpyY^~Sm+BMKKLM<ilZH)<Vt-Gs0aXosrV7G=LD#v_uyneC'
    'Gp19=g4m&g+M&$c#IvWF+Kh2M;KY#eJ6(S6B37%~-&Ceq-cDv0nUQ&F^ZS3zcBWxsN7#i`+v#jdt)F$YgCJ)Bf`V<Sy)iY=P=n;p'
    'lyd<0D~}4NX6St6)LWLPGp<w_rFquKeZTE!uWBayQQ$nYx2M;jj$WYieRS4>hoE@5Sn=7^h@E^?nv3$(U>0iB==v=@Y!<cMf1)-t'
    '{OQ^_hgI7zc5ND$Sj80xKUy`B>k!E=YGULj>Mn4IWzdtg7VngI2{lsyya)xE%qsYG<pQ8YU(r}ZaAna~OC?I}5GUzn{;H;o3~~k0'
    'P81j&EFv~*?kyeq)joWxDpd`Qo>}qqQgh&2k2sDQxNRNYh6RW%XM@&<_>K)xFC6n88Do$12jH=N>;dTPkCop;2(`S8^9@Y#Pujle'
    '<sZ-A{waER<bF@|Z7TY4Zp#uOsBWZ}k6?DInAPV*uBIDhwwAe5WGYxQlW#+6=b?#N$%e1S1<OaF*3UNNo_?d_{}eoOzXNJhyqELp'
    '`*(l&=l}Hm>lbVK2GmEZ?(H|iy{`giyB_ZC1EUfLy}vIU^jA;0cg!5o?+VOG#~pQ*nqqZXYHY(AkGB=e#|=UjR%#cc<E(0(OiaJ)'
    'QHzEy!Z9jPkYT84tBb9$LCZB@_eqKZDV5MviONsI@O^6)_V&@`!1)@2Hq6*b5wlF2d&Q2@^;tP<8V+gZN}`5GC=M%q%9n6gEdFPg'
    '<$7?C5)I=~w;wxs%PEbo0Pp+^VFouk@<gjnsP?SYsCOO#SUEl=nrfND=F97m1CFQs!hN7*a0eTm);G<)g@bp#V@3kK6P$9I+%;3;'
    '!IK4u3kMDZXts+$j1T?R!B=7Z0-s%;)gx_22QZ~<gI>ORI$3(40?r}$oXP$u?#a*$lh<fs5*5S@ld%`~01d`sPkA@t$YWk{9ZA5E'
    '&qj1`ZJ4x;4)6OIMWhm+KoLp3K(K+;sqi^A7_NZTUd!$)<-<`5C9QNcBHHe$CL?5)Hy(O4yH6Jn;{`QAQ<>v@j%8Ly<%)oNtS<)+'
    'Ejf~?kX`4-C;=T}@JIpv#q5QW$3t1(GouY&m*?6XQaq0haz_xZzXsTgQ-M~(pyK9!Sl=bMZ#KexLL7|H36-m*$<8)Jj1JIKj{*9K'
    '`6~qf{Pnlys6a5bOC5+!a#!vFxBz}-saRA(xoinO0jV`n6IyaDpGRT5>n*9?ZArUAp|5A7w{%dvdijQqvN5%N4`aWfjsv`6p2oyP'
    '-Xl2dm<V{9G>ECO%DH1UY#AHCc#2P&V#gtqw?T~p@t>T$+3-8SG^l4h2|47dccyoAQ7@XJZGAOB0MMj=nWzFtNH4Q^1bjgIsyi6x'
    '5m&^d;P%%*fekF3FSB_?#ZloegNbL=Rt4syb+Ctx{_p?hgrW10)OPDdiu2(9gG;mz@?J4Hcjr+XS8}O-M|?YdB+{Hv&DBES5#CO$'
    '(BYqiMLFmMDJ-3Sk0fxA1+5@nHjaT4h-PxSvmvfQwT!Ofpbb%(XX2<*TqYedp#TC$8t@HpqZ$9F!q%B+f#01h(E>loiE~QF{#*EQ'
    'q*aB<oZtR1E{;L-Y2#Ts{+TG54Sd%`oEfBOfaGo7zl7r1|Az!^rG~J0>|9@tq-|n%+Wh=Y<e29gJrf!G;FxYT_th!E2Vq-H8(+@Q'
    '8HtpI>B<JYQg3kkuk{hBHKtoXDciy-vgWZWV^>%aBjN{a-JR&bxeK-03#c)k>bsE99>0%NilyPe>2wGwvyhDs9|#Tj?Gj333vV$d'
    'H{Du|zcwV-2Hy@a>Z<g$a#4~6tcc3A1h>iN=_Z=8iXqK$i1mu-=F<!3j2qbplEn31$LGEX4Yl_)d`c_P40q`-HItcv3Z%$lm2&Me'
    '99a-3;Vz<w$-UftLL3IFNP7SjvK%zi+k4AZ<K$i&B&b*81x8g+`mEC0XzcxQ2tSVQD@j{t^UQ|T|DjQLes~5?iQ>O;mM1FUSTAN@'
    '@hZYc7m8m==37qL?RF!NN5M{BWIgfWgd<IRF1+34t(~1-e;odt_mkn^CJV>ObVpsz?cCJE=96%5=Ypn0CsI!10djI56}77Fdk^e*'
    '<o&x>tzX#y?7}AZFe*8j_Ayfr-IyKYxAN$~n!wz*GbUNKHlqq(qE!p13<o#Cv>)-jsB28+afOCM%UKTCXD^&uFt=t`<hjMYXB!uk'
    '>Q<J0tV}(q(y-baGg4vU#(#3Z@PVYnd9XN1Db|gRT~@TMfyD~`R*u5qei*;kevl}OEH(Rb^2Fs*dT{}^gkvVN#*PNN6eKCT#HUAg'
    'Oz+D4Da-K0STUAB%u=C|$T1u@=HqOTDBm$OrSPb1V1*0oZM7!;%a;y!u~2i=izo26U_z&u1!u^Nd)M$f`z^7A$GliM_tGe_CV8|D'
    'LhO8S&0Mr+c_FsLD%1_kpijJxgdnJi$5CV~L^d}i0iQQFAFJ82*ISGzl^O(PHoE-}^m#Iyw&*7iPsT0uU;N^;e!Ep@QHjT?J+G{a'
    'uVaJTNI|bXy6q>n<7EXJt0v}f<s7wKcWGiuYreA0y;7US&`ZI9Xvu!3R#c7f=-Wu$w_hgHw^=$(p;7SWLeQZJr$}gh;j@-7jixtE'
    'Gwn+}CCnLyA)FUkvl45!Gb_A79NtwOB;WbE?`(^ybnVhHdz%g5g13bS8T`uDOlgJ33h>ryxEyEYThD#-9pbNE(jRpk(-RXVFr~Ku'
    'UHgSDymJIl80o>_2ie&QFtZ`mUk1wRDeqgm*vf5SjHr>`H6U!o0@s7RWvD9o#Ni5~2O<_)9Gzq$2Q*={)(OX`dPSu9eD3P_&3V>4'
    'Nro+YcbEM5PDMYD%Cd^{Rg@=}-r1QctI&?y3C`S~;dit^p`0c@M=1T7#2EVb|C5od+vx<;fI~T-#$78o3Y%}LLPpEys<!NsPdkkw'
    '3K#ZrPsL}{8_=rp(Af`n9jz2C#I}lYG#GQlBqFidU8fy6DP*-vTv^`TgV=!El!9Xb+oxkDX}5Vg$i3L?wc%bIZo=a+l<TOT9-#^x'
    '8t`kST-EZqN8QO_<eDXY?OCs8=9R(nT={CDSDsl+S>V3u5;;Ki$Xtd$>xpFDRbE7bVg6;Wk&`UZQ%0$UA5VILKJtcg{`G~<8*ML&'
    'RKttm#=(p9c8t^F3w<wAspskB9)5Nw_g`2>=HV@^2OPNOQ?-s2$BjG$46Vx!mCL>xmt9n<^zMNGZ;SmgilZ}u>s`lQ0_`fTo1qNA'
    '*Diroa8|60Dg^=2_;Q$RUw}*)#)L<S1ODBM-#d*)%}1TjQVuShPl;3oH^s%2TjfUcD=4akjn>nzo_?jPWPhZ9S(TZ|#}NBg=g?8x'
    '2N_&f5yfXbI9lqg$z8<TP3`4F7B;t-&1_%Qq9sS8<t?{8O()oPWk1MhKDn#7L0;*XJGqPDQNQAeyJVuD+=*7?b>X&5IUu`U<ABWa'
    'wd~fs(&*gJI$uWLkBQ1+hukW(-{k(#P*$uM{Fi_Ik8aCFHpPu7FWUl+%5z%DohTfNmOQkg9oh@pNo!+|W_Ch6J<;R6>u7^by(_+2'
    'mj+{m6(2PB2AT8b$5}dUv#y#v`qUxA+^zV^KHY40u79N?R}AUhY`k$mf1JPk%m3wg&!^c?JjeQ9xYbdI?VQyS+NHYHEvyDfO5vTD'
    'ic<m>PkG?Hz(TNl!(t(pu)xyHzDo#AKUZr`$Hk9H_bAVkQFnM>IN1uF(<{CE(o4PT)CEvaBDm#+x9zq=n`L_lXR)dfQx&=#vl(rN'
    '<$+Ez?S<?bY@2xvbb{A9bY8<MfD$yfA<PI-RqVb_=>E3N;|k{sPv}m3K`TKNR6j>-KUyUS^|mLFW>mPG(D{zKOfcA58Xuxj`+-V+'
    '^PNd%zt(iR<>sS^cSgCd@&rP6?g%l({=bvH&Mc?AL2iO3;P8$GVbuH3+EZedLB!G&bfEuW);jXoO=HOgGrVofmK2|vHI+yCSeDI7'
    'RFn}&5V7Rz2k~1vH59wJq!TC;k8&wI3ROIkQdiok<%Tp};eb?m&|RXimgpaCK!ldnsVyzv_%|hgiJr=_t$<&s01ijx+Zj0$m5Rn`'
    'odna^3@&H48|+LY*8cvcv2u?m<RijHX)=<!J3W-wmbZMGoRx%?9XVVoiCPE~hv}I8vTF~!s5H`Tx2-m(g|FTC6JCIsvRvi%R~so&'
    'X*n$D6k-3&#YpvoA-Z!&B!EI{l}~mhFUNhqy;N&d$r9zYy@d{?z2vi)QV`MP_sKmm0K{!hV|XuK>%LfFUe7Pb7^kycuV`{73reRc'
    'Q3+)?##m=c<nb)6wzrNt@XvIaPWua%sjYLfdqprRE8J2lR=_KmdfE|Gg<YSuHx7&Rmd*tKlg53`n4=^v0y94kUj*vfzRQfK#LUsb'
    'hTsHlt>_}mxZIkt$*34(C>Uupg2vYbK)$qR4X~JCzZ6Wkr=o!siQw1OctCx4GEekP3x+}nJ3TCGWfHW=j8}Z2>d<aDRbNyj$xooV'
    'wBmphmfehHyx7zt2~oVf49qcjMRdYafp%Xp5=80ogwQcu;(=N#S)ZUlde<c^7r1!YAqon<Ke=(R9Mt?cz8PF17DCt?4kq1{4#dsP'
    '6^Y?(HkfkMI}5Xx`dn(zZ<}C3lR?r43wQ1Me|J}+5WKRi`*r~E3LKeV1oD~ijdnKOo=u1~_&7_(z2xue=#yg#^8HX$Z$C1@LoTuy'
    '?w4}^;gKz8=}#kN`abAgD>F?*&+z(Fc~K6({WcqlsyE|U19sHaG*BgphA3lKpNk<AK=fIfPQ#0?&%f~2_O0?|Pp!Q91E&<VnK*1b'
    'q~AWFQPzEF^85EMB&4YNw$I;AUr7!2mp%FPa6BgZo$#3&Y&j6J<gL{fk1VNTQAeX$=SuXY5DT~9f!r<!X#p|6N8^F`i~W{oo#)<P'
    'D6tQQ9X*`K(^fs;BKhE#!jDNl6(V99gRoHh{5CQce$<U1pJD?LIRA*KDSmLZ=ChD8e$by}L=n*6!y5mHxfwKio65E?>?b#b|K1Mn'
    'lHoh_d_Hfexj#d9E{CqqyEwgZ{f-G6&?7vhoZqM}iq^sH7PaCB<10JyiWAvMaLD0aASAw>&wJq&_Y<!OP$?hjQ(J$bbZk+8qnfST'
    ';0mKszTD&MqyQn+A)=Dk`s?q-<C_>)J(NkcCLVWw<P_DYBz>=z;4;Fe%S12<p&Pf^r#T^p=2BIEJfbB-a4t_(7N{BsL`u=lCAlBp'
    'E91xZpcd^BsP#keSZ9MyWOC3;+oabTr7!eqeQTD#HSKS^ov69Lzkq}PY0=9;A1*u8{m?}h<Fg5q-sh(ehR%_D(WT=^ObfzZo&y)t'
    '(U9gWNo&P$xiXt3?ZG%t2;|!m>4%WPZ`(4_@~ndHY%}GQx5mUhxovAFgead)pCvSxiPtm0X!_radTp`a7tc82+fD*qb1JM}ziIf^'
    'Ths`f`amG=@w->{Wenr*8Dv7tsWo2|AvfUQ$P>9>Z%TyCY#3)n@VVeCAUYMmz(#JyCSCWKHzuH(euE$R>Br!E{{6nZPpob9BX6V9'
    'wz0l`&tHpOv{bOzR7<568q#}9aNfSemE>s_k8_&;k%tb$<BR&mcbG+=u-wW0hkCQVUyogt`VL+JkedeQ+aNZ&jZTl=Z(+O>s%WIT'
    '`}Wu*5jP%vzti0IzOHYpg@fMv){EvllV_M*Orsx>N#{t%?6T6%MO_&H@=r#DePP`HQhYj!k6FDxucPfo`}&)R{?uyzB_AZbVLY{D'
    '+*s{;YjlgQ1@tqzGTul|iLD2v#>Q61fM%jhr6gf{1*r5C(Nvnxn!4BCmW;l{=H_Fw0j~!AeloTRpmYpBu|CdUiG)eLFo(d?fbcv!'
    'CPHnxsrkG~bJ8%tsr@aA9~@A1-w`xSs3&<m<ws&dS$_<nG%K`e+iJPZJ{HFJJ^k2=hf{!x_m$s%olL_Clh|#0l)M<(y?-pf+<Ya='
    '?Oo~Xk9Q_&B<{JGi1L`4p`^)Vc>gNBObySN(JtnL6c75^;_cDvm#<FD>E)df3S`%y925$xFyQFqv_4bT+%Sjo<TJ5f@`)XrBA*cN'
    'PVJWBw&WAN!MbZJ69F34*Jae5WA36s-+G-6CJ_hP?%GuTH~Gyaha-5F-bEXAr|vZO=)aAFZzcp2P9Ji~<L7T)(||iQcVh>!4sR|G'
    'T&g97i^tw|WU(V04U=71RL9UYK}Q)g5Bf=OnC8IFE2`m7o)x522t#l|o~9{$zl44Vc?km##`;P~q-4Oz@FS*i@=bz^O-9G*cz6#C'
    'Oh=#_hyoM0OZ22^P>zdZNG__0C$wXGSCZ<tiG);7U>Dyp$?>KumruL_m~z#G8x3B*dDd~Ywx}Ub%f%oPWN*>>K-0C$FyQh7`WPae'
    'aDzNL(6lTj#6yf_Ag~NXzk=EHLJ4RX9|1XmH_qS=k5Q0L;XGx{5L&G>mk|gqTM0eDN9-WaIU+Zm|JgL9U)iU~F{5GJ+YV%l$SA&F'
    'aa2p2xVc}~H@?zL(TaF93E=!f{zB0VeswusanU5K{OJddJ3Dq1D>YH@&T}#KtFt#4O)^|1YouEa;G#!ZxIEENjv&EKIJwMnM}?A|'
    '_!C9)ES<CP>49c|YW<q~TZvRr>4yx9`(YqLXHz73-0!~xG4zUWoCthektVBR<rQOy)EJ#AT3?4qkKMp3Upkc0^~j^M4UKRZn@JaU'
    '+N%dUF{5m&fIXLPiR0G#7$XQ=-V-iSuCNwWg%+V+5fQNu3zJLh=6#9fQb^+^0pgWI#{nS&C@zbel#&*W!U#|K)YF(q5K(%)xoJpd'
    '|3MOIUodg(&R)d#Zcw4*gCc+1<bTfOFqL=>vPzd3<K_8{Z{&wXQ3;4uVp?P}_#oyPI6(j<K4Yy{K3n_ADAmt67N5`ZX^OAbL96U%'
    '*0ZAJ@W{ONN-*$B;unb)6n%Q7mOq`ua5qXgrh-3Sndn-eer;{Nf-b6PpIISoMBhfQ&JvNs^%(EaJf8{x-Uu-B!Jr%g=?KipsGAVc'
    ')OQ3(B*Y&_`7t{GmLYp!Mfrgl0}VzSi5GPJlj2yZ4Bs4L!(KY#8<989ULF78_|0qQyEmubAN}CmG@(&J`}~pvr>4;3MT*=xAPo!&'
    'QusdZWP;cvl$!IwL|t$LRuRY9CNZ9Q$15tR{fG{9*5x>O^o>05Ra@HIrtcdES|vtx>ip>4X|y73K9|VndFx>j<nU|ruvlnRq6K^J'
    'kE5j&D#%mNGTKL@VCp|$a~EEvR4L8~bgT2azWoIy@s;<wd&t|j#VPr$2R#i}qJ7bX>^{MIFg)0ry6&0onDhK9o_1V9Wy`n(IVs&5'
    '-*@LPj!uuF@+*x@h01MNnpK7T>?YE~J3&lwqg&+S?gbPXU+rk!t50QC4p^=1*q22KdRZ!@-E2}R6OoAk*%TrKQZ1uBAKFE5n3^)c'
    'EY(8B6P{fPnsI0D^Y`!Gy?lMT1n@r`y>*D<Jbn4cQ-a<fh(wb}SuJBX0dI+~XS7W-@pwmdTaK9a=ulyO^ve~Q)A4d<?9;c#HvtX-'
    'PkiJO7c-N11Gq$N^F~vjSqLENh3<GKc3YCf*(Cb1RybD$@LDN=B-Q*M#Nn+9YoNJ^YCMCX?PPZd@48lC1F7g0Yde9f8T7;hm~y=f'
    'kEij}ic?p(<jay?n)UNGWr?xII)_1QR)$_Yvg%M??bLU)k0TI-0Fe%C%|#~&^_QAgdBkl@zd)rsj4?Sn08Aw@aS8Ac;b2(7aNubn'
    'cZHplYk94fH8Rk_p536fm2GREyZn{?%yQL4M-MIr32-zdmd<x?PeQlTF6>+_mAk42t|M@$LSI)DZ?#U}=4MHC6c}PHa+N^KxH>Q>'
    '=Vp&jBRB$N^dlqH91M+2v<-5a^KDT_Q@U+(i2^$m1f9#{i)45Ys~*+`(5HEhGr{P(h1^08Uif~AS@O8r6FNuX&rZ}0OdxiIG2>w2'
    'yfkb#G@=#E?uC)UJ%VT9I~R&{P>UqqLu)Vosxw5D`Ay{IK}H9rm(Ayz3HC#FgLJ~{P4peeQ60&{n+7q5#WX(F*Ral05wfaVD>k0v'
    'J9UGmW7=qZAuro^KBtFB;^t_Rb$sS~EoS9ie{AveH*HPFT`M!-A7KXU;`pMBOLX?Nx=?KT!Hqhj#vm4trZkJh<|p2DfF6MKIdln+'
    '_=~d+2qFSmucuJVS*O+W4R>=VJj>l<rCLo7Y5-$xLVj1o+;YZd*5$<IBN@8*baoXdcX8+vnjDNTQhV26;Rv?3>7PS0bk9&paKIqt'
    '+-7K%0Bw>DZa~g(gpeHv8cQ)}^`)qZKKJS*dbmuc-nE>d+V!mkrw}~CVH;&x+Pun9H3D<c+({LsvbipcDc9=!aD`c|Nyq3wh|lX4'
    '6$vf7)Q?30$iIL2r}Jk=Cody6?XqLLunXV#0n+Kz`@>1`0iM$G@Mg~qUcCJF=>4lxDahLs+Y7wnH0`Cs5?n#8(DgSrcmC`(nqPeg'
    '>-=A1&i%Yf>B#xb4m(^d>Om^I_Bk|3Dn^C7q@;*w)~?xSZ>eX|*_lfN<_Pq&3@rDl{Z<c}LD+zb>olF5Pw+XNIB)Tx5rp-9{pDJH'
    '`8^k@(^q`Sk_oKD2}a`~qBywkIKeRq4OB0+!2Xg^Q_gh5ozgCIbXwy{u-p9V$y0hj_FTjVC;UTAHuk>Sd%F8%?<;D#)3#Bwn>&a('
    'l=7g!DP%E6ENwdk4xqGwe*`<zIzZRT8PNQMj*eEOLU*H>sA(Z@o`eN}zkT=S+v8U+PolF2I_g{Q<z%{@=J|HB-gN_%Yc&G)F55cO'
    '->C2S+F1muNHQA5+k4xMrY_Pfir^a+z_+5naJ0P_KDpVxAY^r=%Ip?ph7hD6!*UzRo^E4rsSSMVEII~6q6a{D%ZA~AmxNW<by!>p'
    'e-p5RBn-~vm1ub6Qs=^1C*VE753@{p=gcoTVKV4l^U0A6<pZ>F`3u6#O420G;Nuaw*aHRX?sMz_df>1OE(atH)Jd;I{o)o^4@fb$'
    '$Niiw4NekfqvYF+j(1PvN`*6e+5KdihBRCKboBoH@e6MSc`@j3yEP6yL;%AoCW@-qed5<dYQp6!pY&M~H0r*MbJethtRU1tsIkSz'
    'GpiBsMHKtNWfeU!nxl7U3KFC%>C5&>LQ_mE`}W(E+PF6e+2{q_Amr9Fh-79qUvtN^^8Vc`O4hja&Y&tBl8jTJ26bmJ50VXzap&{$'
    '7lXQh*X}|PdHR!!1Ssy)uIpO~(<_~0hf{<bHW{u6;Q3`8hJR$-T)#TO(c)>m?FTG+?LWI0J(Xw)8{0$tYmo5fW>ICD;g-&2q{~sM'
    'H#duE&nfF;uiPDKl2Np-KKFh9Egvya&cwundb77<o5q-1V+<q@Oit9j1HHY^h9aZqZ&rx#o!W190z}O=&{vpLh&F+NowA{kGaPwX'
    'sQ^lrQEKt8SN-VWh<Nr1ZA^=o*@2riiS?L<kgWPw{WDhsEL@_xooKlL2iy)B<xqj}Xg0l~<LwvD5xLJ`g^W;gDodO7V6@TG%^?0C'
    'z0RAPYPxB*qo{Hs8{<4C>fh4rMW%~~p1VUhyM{USTlmX1hQ_{$@7zq?HLH%`VU*CM^jm2t4@A;^_mbFeIPVAhcGV9s-z}N;!>aFB'
    'S&SmqQvjvEcu3jhAs~{wPir)Q&arE8Fm#9{7lh=KOt1`M+-~b6cVQt))}z#W`lw42#xdAj6_hPe_Lyb0Ln~C<^LPv<kVt<-+P+Fk'
    'ypt0nBz!S7Zs@RDXURrHnHn>#Wr6q!-_SsKSSFHK95~5fAEcsjhprzyj0qR>apEr?;c6=j(`zvaokBYg3pP~?ma#P4J}nl=M+aUs'
    'Z5Igl=g9J?Oxz5<dq0cFn~<z}DmYV>;QM$qsZ*<!Pfw*5_n;li)Q?`P#(tFKTQ+U=IyLFJ-=Chobr2m)#k8SGk*AhU!rbT(9vTJB'
    'IGB7iiVjAbn`bT#VJ6=OeYWc(1|-R#5eLOQx$Ll`5{ml+b4){Hmue!WGZfO|j4xh5F?1y4o2CCoq#VK@s*(}JrbUR6`0xt0&X;cR'
    'z${<OCFY(=u*qF3M!*cv7NWYc`y^0`E4xn?e(Or^fR{?TaW;sz<>uaPxqudT5zru1Sn5L;_R};+ri)`}R*V7@DINO8Bgl;A^HDhH'
    '<1desb;FgT`*9wXgKLjMnbdRo#FDGrKU_|0SrG>jlEL#z4Vh>rBZ#-?h`2x3!L+L(O|-fEMWl&eiMB9_4&bGnfH6#HXWfH+rIw1-'
    'gpV@4lD&As@#SeNjiAvVcL&446n>;1mXbnve@Vwa%82H_D=Bg@SIIohVxY2fVxrG+hj=~%!(S9d8l*C=QO_IXuXwT|nyf?mU&+Z1'
    '>b&9Aa6i(*e4NFE3*`W6KPrOY(mV$EpTi1NClDXRhj~GOf{yX%gMaAiE0>n;#i8CKbcAYYl^f`FJnpwVdfwcmKLkwr7x5>gsbazP'
    'Xq1`n9r7^2oefeDh^@)R;p8F|CZ%2*1ZpR#bnp#KeA~0z!bAo#`>pcCA3lD(a@k50JorxTP(M28V>1NGIOa7+WH8v-4JI>U;_|Bm'
    'rqt#c;27Ae(E7N!snFU-AhncnpL=NH^%D5DypQ}F;ClVpJz|&<UZLmnE?(yIx@H?*@w%^`V9IhaxU9T}s^GamjL#dExY=?tT9EMz'
    '1Ar0n>$#v@j#$5VB(7<O!_$%$FQj#UAPy%tp8dTnO{bfi_$%Tnh@iM91o*k<;)>73DRCBtp%I>yByLB;q34E#w?^#w1`3{eI!e58'
    'bTB5o@?0}_Hm=IylVUbZw7QeN4dX8RZRxpnOIG;mz;S5}!++4DRMswt;H<mJ5##_s_b1phSW^{Lj_9k$M8gtK$Pb#~^ySQ@J;$D1'
    '5HrPebU_5MVN?%snb+c&^)##sMOzeSC4r)LWqVMhi2B%srkW$)4)bS&DK0nJ`ws337~JWk237FLKJB@q%C#X;(C$t=8SLCNcH|@j'
    'niUVoZLa2Lb;9AWhbj=RVF+QB$tw6+KvRVa31$^O+3F`+ly-`isYTUbQ?=8y1m%U>ip3*qewYz!gGS=(BjQ`6x`^W{se2GQ#0hU>'
    '=MwM_iTL$FM#~K@up!Yu=5ys66w`n~aCZ7_Yk_5D-i9*w3&k|4#_6cBvq~o=Fa57i0;q-PB66rH#7S`Y7KTD%lS0|%^T$Hjc&zcF'
    'rn^gYxm^K|Rq|EiIB6`r-8GLoP!VeJxw#0B2s5Ka(P&zI@=QBIsC{7rVt0lkpQWphmLZu_fCBV0e?7$@pfq3II_ZQcm}`c}Yhn6h'
    'Tp&JX3`yh-dk7-RVx$B64aNl(e(0P+gu$02<~l+Q_|ws3CK5Ly@-tXP7PlY-x@u$UR%hd-cHeW7)$(Cc?2)>tE_zI~d~rM@h!B%U'
    'M3oB(8kvK-y=KNrv(#R<&3Cvl!?(F_-<%M;#ypzbqO`bOC=glwq4Wd+sHICw7!QD<pz+ht>nqp+&9`D4>SjPMl+Ym|t9!{sJgq)&'
    'tK#Bi04rB2V#p3fJRMp|t+V3gxZm;pwUeV(arN}*D$a@G8uS;76%$bzfK*o<f`vuDe2S%J3tkQxu8Bw!Fk|w$&_=4dq$#+m#$MeI'
    'l&%B%qGd0_)=H3-TyB8%wToA}<%2xXUzX~@p6@w?tc6|4a4?GAs@sTFIKo)Qb(KX=|7hxOo7C7!E&AU?>?9K%Z-6*wgMKg_Oos@J'
    '$G;->J;o>X6v)*b)kJCLIWYB8s(BW{FcqaAZfK+$0?-CoIs}Q0AEDaDQ_!KxxQxgu`Z?|kg~g9n(<7^C?$~Rg*UfVPlTIYij}k+B'
    '2)Z>)_%M`lUqlBN9Q6;N04mQtlpui@DjF0~mh_Ati4iE70@f(ektSI}z-OC1u}qq@K3$u%z2NXqV5dNL<WYrz$I|<4c7Np=c4m(o'
    'sBdoKt4?hA5BxeIG)|<`%8C|`q^8G~xRI~C0!T7f)dtr%G$@vT_maWTvoh^8{k08Q<R)vnDR?gEnb?+@SQ1|D4w1a>Sx4E8mU-mZ'
    'w<tN(8pZl}COGaHCZZQAeQ*(uY;KmT5vcUnZUD8sY9CN{-jDgIZ>@8qS@)NBhzeN0a-Yz*H8!lPcMvQ^zNE0d(F(e3WF})&oeYz%'
    '_FL(rC%cjlW5QD|cp;qtSrm}>)Kzo$x9#br$r^pxc)xJZSH&xw3YiK&=&1r8FjI12M4UQ^qQ({8@^-Gteg<1;ZD~OerarvcVme7F'
    'M76Z}OD_xCag_#gBH)RyEOt^M>gRiX==8w8*V#UBUcC9Ca(DmxAETWQU858-=hQjjoB2(g&1E~y2N!ct1aqPY=8Prg%#zN<F~%Iu'
    'Zsyd<ITMX@K31_nbA-#~?#@|gIS1`NXR4gnb`GcXb0Sr!diE<nXBj|mt~3wkY^Bnh-=svz5*g!v=<ZxvT=Uhi<Uwu8Fz|(X{gw_`'
    ')+Q;u=S4f-hn){QXMg@M?rhEfLH$zF*4c;r!%1iB@Wa-J9e?g^c!#YIAHw<BpEo{ypiKVO#@sb&u1a&~Kb`&gr_R<-RN_PTL%)U`'
    'A^rM?AG(}I3IBhYW1l8jSv3ZuwmKGQGiOPd+$GAtpsz%D?E2_n;9qE66?|1_a1f~PbQYNJSDp*!A4ae`I%{+e-Rbpq&!y+4Jm+}c'
    'm1mZ+UT<H!i(mv{5@CLH1p(EMQTbwJ)4mY`Us&hOfQ8Q<;~Nb&3=F({HD10gf`LD8b!vFvcY32muF2aOfl7y7Iv+fbeTC9O3n1lw'
    'r{;g~%d@vMdDEqtqps)yOjk@Ccx=p(osZ@aV})V_K4~Wh!FB_}SItIZHY=qF&!mKBxLmVi?x(k#<#M~#a>+=_?5=F9oHwSWy~>gc'
    'TEYEJpf0%G^X@PnU*kq;h-)McpPNB6uC9~lQNjrGGVgWFNm}=7Sa#DczwqR|x$xW$Y>k#6V%3!TwwP<w_YmDV9Uo;=0|&6*Hd6oo'
    'AZxks0t6SYT6><#SXZmr&Sk)~UEv~7ue{zhgKu6bf=IVAj9$U`m#>O=Z3#AZ{`}KVKY1T+xBMLe67X<Z*f6_b33{#8u2xBGFqc$!'
    'n5ftHDZhxo>9tnt_*_yua_lD&z89L5`l<llJs8S}nqfk=dK;icClkz&GH0`|Mrd2n;z~qb{aM+LaY*P-yLe!XQn=5k`f@N_U0{FJ'
    '_1FrZu3@_TMSu$K%^0ux=(=2)0+`PXBB}=%zaLl$XJ;<FxuNYFxTqYV8~Px%@2<Gy<|YHu;a@j3T$U>m$CuP`)-pwSK$vs5D$s3j'
    '((&P|heg80cB@`e31VRI9ZoaaO=nkq3~eInUKZ-m$EWXi#MvinOD+shdjIgy2zD3#hrH&6t6($X8Fg!ngA|yz6^aFZ2@*oWR&Nsn'
    'jYUg4ggCc8%tQL09?X3_tH|*eI*(iPZNj+r_g8EtFZWhv``)quaCw)gib~sr#nqo_fwG}evz<C2QEAZeF(}~AALjE9^WT*5z#O)I'
    '1Ne<lYMNb4lM=zVxkh8Dng!XQ(1M+2oHIkV6}}km=xa8hGZ6xb>6L5dx~Do8-1+TkR#F<Bb`2uTSc%kHj%n9lu@>Ih_Eu+3q|1j8'
    'D{mIWIAF;7kxU%2n9pjL&4$!T%5vzYL+a%WHo9w8WOYMoc@$n6U_yq2VyL_f*8DG5gQW<D1HV1fHm)Atupsu}XT!?i9}m?m5^R)!'
    ')WXBVb%@x44#vtJq2;-3pAY$bsh4wxJO9&&TN^84?-mnK#^1rDyrdKDa+y!FLhh7bCBvbi{8@#DzH57wWEy!yAqE#?TO<27oQ8bN'
    'YmfblG5uLs^tTxG`48ojlNdfX?QV;z9&>&4As(`;U%or%P^XqlA=Y-sF>A<ohywMHxC7SF4axxp<PzsGe^wo7S8mH7;8ho8Mcw*A'
    'X_#vZxSJ%qz>T@9ZuZ-{@{qmRvz@g6!1G8AUEv<hU#z~5D*DQ%($&r?5k;l1%Fgarcb7X_s4pqaxqsl<_c=C5cCR-KU$%LCn7D3G'
    '=r<{SyqZZ7eY}zmLvpLe@s`bMS<m1tOBLkS1qz<g!$Qpr-!;J>=(=IT`gR+4`=!~UW^rjLlcj~4ntoE}{_B*bpnV5JWUCfYZ@2Cl'
    'i`#)0EboOfC99Cx6|#{H*JDXzz1-KXTMJ>Vb)!(Q+|bH{o_QgcYMVK-?^6X}9<+J^^ig1_PWwbC0%HhR+8ScFUg}!z29`(Cby<`L'
    'zg7|*@De1U5a7zg+(Oe23L+S+Ga|blfpEv7lxPV~STLz{wF{EL>{*w|CE4%{k}Y=<^UYnW?lkr$cTS@|xoayWiPpt1xocm>?5|c;'
    'xPnqr&Q0Aw)reB9#yZ+bO*fHCuajFx06th-akZB6d_O1FBc8w*23Fy5R;JLHUjvK%141o%F1_4si_*~3Cp1i-1wjbsko%v5cj1^;'
    'Au7poae)hi!2QcV{ogLpWx>bb(F!6DYwHG#Y1PZ(vkUUnT93<Y(C77d@|pEmH~DgvgS&p}t6VQRo0ekpuUU%HR9h&sz2sKo|D)~A'
    'niSc#G_m*m6@DV?CU7ADXC_E8n<;>R0D_swlXc5+oEdj;ccvK3>a8V{OeQn6sU=gj)r+holVq)uwaH4>CeuUppV0ID1L~ikz1H47'
    '0TG$!RP{YKNbq6Ldrf<-Z#e^sC<q8gi}{8)w(In-S4Mo^uUE`UJoF6xSc4l!7KLjI3WSXDr4b&J8Db-2C<XLQSZEN>D=VBJV)&lR'
    'p*s9_CBUG2ps^tCE>boZh~=zt8XHu5i7UX?qYXT5yRNL?p43Y%ac+jTGMOy@`L}|O#r|k3IG-|i!+-bpc8bG#V{HMnzq`&z0W&nQ'
    'hg1k1uxJ}PGqQd2+ZL+1MsdavDCPTk>!1#d0ykU9e!gCO7LLNrC-KLtG5zO+Sx~LM!*@6&GFdLXOd6#+&aBz#uZ=ZL5EV!?c+)8D'
    'wjvy?^Fh&mJ{U;EB2v^atc^bNU&&$_2}jq>=yUw5s{tw8l&!|aIdV}WOQ|5J%Nh6z+g+VVGsmWRL!mgSCQUQt&0okZgYA;9XB>;#'
    'S|;d#^UrqvX`L4RGKK>dTvtw0h^70Foi{w53p(2(Z45IyG5nHFPdv|)^a8u|wh}*4VFxe3X7&DqfUDy2x=|?m^a=l==Q(g*_0`2e'
    'f-F#oi28{(vm00N#QFf@G#NZMyx{SfV7@n}V7?R{*W-Nt)lMPpHZ$L)(=lAk=2m-;1T`fPNUfGaV<0PsvTmr#T9{B_&EODvnx?LG'
    'v-ccAk;`Zb&Vc^ulWyvH>_*zS;yAra+0NQ&jKZZM_P|joE?-K5eCS+f$4N13XAA!o>Dk}>SHERAs2Ka>;kYFGq9kh{kPG6hv47a|'
    'XAUL5urB`ONSNX;rR!#QeXjrTuYXHt3wTWN<Ib9xwYHO3O8PAW!MDHsb$|Wc3kI4$VGursocK<TrJtRS4Zq2a0lj%F7YODF^0sTk'
    'CFh0rk4E2dZLlA4!qK1)b-R$qcOGU#+35fH-vFyZHQ<7Z<s>z0Co7}u(sv?Tf|QSZS8-}0+)<(-@<)#Jl4)8P<aQFz4qje1?qE(T'
    '9;CuPLLO|ei*35otg=y{5fBi{2E;tOREF+v@WOYtyqII54T<>G%xNT~?FSWGpHc0Nj3as35+Qg}f+0wfZw4~XDP|6|kT61JVQb;m'
    '<HMwoww|7`X4CNUmTMtH6@{5YF8OTI9@s8qn@A4AWA}=cO-C;fT|pIQRhYUk`dux7Oy5{;o?l(eNtk?xbbU78Z3JyFE3jgYhXy+b'
    'gMf{l53NjIKk&UAI)U|9UrkRhY&vt*0|gk9o?uz%nDyuX_WyCczT&u+sC~w?e}Pqk3vd!)5=YEDES(&Kw>rgQ`Ww(5SSbe41OZrs'
    'uwijZ7_G<xs9W3B3etJf97KYy)AWYMngN^*iZ}#d8IbuB#3GbS$*7`~^WA=kjZOWLS*3xXGigfTQm0JkZ0>Dx@LLubz^Z1(CL@@V'
    '&72{%(z*Mforzu-<PaQLP&y!L2jC(6c;)NqqbRKU%%~g)!*RaBVsgOo0f`xy9(dHg0Pk|SoJ}B($cK<mGnqz=`Kh#jnP4#~8HV{9'
    'P|Pk%-`aL^@+kG5e!Z+6!sD+#STsoC_4JqDsqNY!@nJp%W7w@k2xRUt3ObG15yoVd0Ut&bL0tf{uCo&y$I5ro8G7~126-lf+q+I1'
    '0{%nJyJQTVQu@owFXSTm1pZ-<D|lCWw-^w6`k54RO2AAyR8<uCg6WVg8gv>MNNE(R>AJ#Ue3Bwd05HSBM!cTMM(7~yT&o<4<A^bV'
    'bmxPP&swHI2sR<m(sJx~nXNV=2cDfg^F5>1PZ&~KM5EcR9cC0JaY3q;-@u;1a&}DyW~NaTW=l(t1;wcgLMEU@<Fvpy<XCCx-{Eg='
    'I@JiHV|sPUwo)HX=ar@vWgf(?1{noHDk+c~Cf0%p@^kl0lHw)`6&%QnUYxa~vLzEn6kfmU#)LomYU5N?{-vu7tVOUKXm#Wc<BBM*'
    'RB65+i6erjvWLWRb}x3s|3Rm9SRFu^F|iMsFHm_fRWo6rN56whp4B~t<lzb}g8@&NtQXeTO0%aKG!#lALjKG`!^l31mwx)h{KZ!u'
    'q6)$yq`IJEAyV1b_8@tvrs&4NK&Nq~!uV6a?NfV@`7Us=cO1_}2FP#vnNUvtOWJa~_h6g>^VN4MmsUqdif+jPgh0FOaR(?PSWWtB'
    'hzo{?zpXMeERT{6XD@-G+5`xP%l4UDwy6{oHONE*x0EV}lmiMC>S;D5jBtL@VEa^Yc$4-2NQg335gIjVTLSi|fFBAFrq=pHdp1o7'
    'aZlQ8KlXXg@C4^g7HayG_L2IhTFd>}El$7Lok3mD64&?i<;&D_8_!Qyo>zO4*KgF>W|5{(vcp?a%Hq2fHjF=w*xR(3MuAQOxy68+'
    '1V&x1`5W_=&${SI0Zth<;(2ugi2uHsPrfl8@GVHg7HPOn=HS(WHnX3BP07Gn0nNiB;&t2;8KYq-lw`KQ!F2l$-#r()Dy9v;GtmR7'
    'cl}#go6g2M7@<Tmv&P_k9UjrO+PXqzuFEa6&-3%U5+h@gTh;T-P6HX2xwMi2s^OwFbZHzO+fR;XJBjSnwF1a^n0p(Sk{wD50GAk<'
    'B;!?B(s<-^8J0W;m#sWunln$B%~y;SW9lyl|H`*bpEyFBvJ~Ngr~QG8%q7S0C<C$y!UJK1_HAcs{WRnmU6DV1GJKLvHQmxlFUh7S'
    'q5vuI8a<Nzi745=DO>hPdivwaFcszo2`R1141z#33>%W6hY@glD^?IlW!Ni#7=l}!70-WZf(0U3ogPyBUiUGx?*C*yWWEpEuRqsP'
    'X*AQxCIKqsa}~%B7eWdA#G4w7B<eiRsx$%jNZ?!G&U?vd1ZkvPP4hWu;=wO};lJ9w*nY0!XGY5oenRNngs@!mUQ(9l59Gr^-pzAK'
    'A3WvdiNqan!K1$4SrIAXjY|GKFkq?yez0T!wxr44Rn(iEpt`TGVfS2*f!lb<ax%^OHd7gOWhAnhWW)%7lw{h?zM6IgD{=sE65KRe'
    'z;+u#2wZq9XTSn*7Zx@l7bt;zb!{QIAJSiagT3Mt9H0=^I(a@dV#BIINf>ga4_D-en|1~;G@*w>RglFggMLJ$76E11g|yZ^H!h#G'
    'A5Ki(<QtK;tlJv(kY(Ou&zEeIv@R1A#gd2U8Pkaw1z=(SME=r&U;S?Vpuem}FNWLXi>U2hbn*xGNc>om&zBYX)8YRI^6T)jKE6P1'
    'u@~`W`Xa8^FH`a-YA+MzMb%!^;mdlue$l2cLqUI8Yy1m%X_EWei?&(590l^@NdAa8zI>U<vzG(;m+%kpxF5fW<B8`l0y9Rb%lAcW'
    '<yxM+%-7P_$;)0Eu3sjzF+OB-;XqB>^KAIuurw=_l&4Ovnxcd5U?;v%1kluh+}e1(c}{1_jEtYsvp~vCO%nmQ2C_7<)|n<X80?9f'
    'XX7s?26d)Mo%oNit0s&d2*Gyuk!Qo~;B+COh6m#sS=>K5G5YlB7s-$EM@2f~4=@ox&ryHAkW~>^CC~vyUK27cVZla-2f!UbhDL*O'
    '1EeiLyE-n|qWLh^dTcroU8qhNjc(y_dNyOTys!Z<*w}b>?!5!`ko`sqnyr_NSW^cw`rSzOh+Qx%f<Bm|icKXX#W~EFsnO)1gc;}b'
    'L;5|vui<y1;=Qf#v6Vy06!pUyfp(UX{^j&ainhgRZ3OsT@W0?LHl$tyqs;9sQ4841=g0kMAvt{&dBM+?ZCRj|!zF=(T((Xxj4W2F'
    '1gO<JJX!+~ckruY2To_}1QhTSmmPS;g?j+LEhS+m;W#=UHFPHWG(JpZub-;L`D*H91;Mb;+)a{dtfSY<E+MFUTkZw;>lKcLFPb-1'
    '48!>LJDsVhILTpyoa<{mGaYe!uK(}<{x8UAjAuXZf5BQ$PZk&slc24Y^>$6F1>F-T*>-RU0k4vu;Ze77f6<e(hO+jc!Oc2D!1IIO'
    ';SKUeH3<G<R%3V@`RESto!K?CwP9=iO=AJaqOMbtgUy0FP&GX8POmQ6CXKQQ9lju<(hkXJA^}lIJkzbnEckw8p+vb&Sk5N$4M2oT'
    'D$`3qC*guzFlE<U$Tk2y1sMtljnF_SYXMWCDb6{vGe9~57iqBLL6kkSu8D#SxaE5Yd`i(X7?#jmkaY$^3x|+~dFp-B1(|3vXy7Sr'
    'xWg|;z_kHpXRWMlDzF0n!sNp`CuCZ%;nzI|D>x~P$y$bkuj$Esdah`mNuDQv!5MP-tfZg}Jm#0Rg&1VAY~YskE0G0B{hsHw)kd=t'
    'dgYCJAhW8^ahhptDz}wn=K@_}BZOK#+pVvry}&#OSpUe%O_qYg!s<AR^iz!XKmYaLTyRVL^I!iPoNE(l<>Vmrr|Pab&9`GnnB%Y%'
    'V-+8Mhb7%^09(If?VahTTb2$g#ep|yqk**Vy0IIDoebYL_5X=2xfH0+JbPo>DTWnN8-wq+*)kYS_z0?*F@UE1*NIU^jf1vi3~q<H'
    '`xINwI6=U&Xo~t1+c0zYv+LPEX{E+r-_f{ixY4a0rcuf?ez=V|bWv4TE=x$%jwdPt>ILCb&vJxT=BTcDq7u}NGy-rUp>9R$$$_pU'
    '(#Skf<5q?~;nWr=X!D7>079&GGzDt<Ov=8tX~SR?Pur#)zvDgvG&y5qj7(MFf;28;A`v2w6E-q}__LL8AYa1YeUSQ?e2aYdVN1Yz'
    'i`Z=60G{sqSF#G6BQc`#n6rx~5;_1Bf2DvjoU^=>;?pd_$*C_s*e@>*#ONFU-8W-?I_sZ4^Si(>(cfV_la?cdUqXukQl&rt^?y%c'
    '(^*e7Ki8B5O~F)4m_~!l!e}cR2-K2wVg}Tf`H{ns)#Zf@XMCWEf%D7Qg8G;CT!YN+Oq1MhW#N+*>kwQ;OE-wOO^ne5hUr((D+iH{'
    'm4#b{?0KZI^bQ*7@RqDNuw<3(a>Ow>*%6AN*hoM8%xG4tUe95!EL~9hS$`D-Mz)}m#vA}Um~W4R={J#HaM6wt0L{lRR$b6WAfIp~'
    'LJhHaoG=br@`-_JRlYCM_%UXqrAe)^=r4Tmk9;tah{j_Kf!8)ZRak_GxFvIZkh{+s0Gkxa(M+Fl`l1DKifCSz-wpYJ(j1)9f`p|g'
    ';4{O~;@G+&i+|$hiq(6-wC`Tu0;au(ES}UjNMUwdm^su1zd@}rKz1F=h~iRV(lushaty%BOW-e|A-@I!#&z@^a}10>`jaE$kJ6zr'
    '8;Ehy@Do8h7;3Wt0!&+WR$?6wuEC29y@}AOhaIKb5%rDRu0a|lJ8deFpKf~82-zEM1NnNcj|bndBQX%oLz_g`OB&b9(T0<5yG4!I'
    '@UR0s@a4sTt@6AYeB5yWg_oXByt$bEX!H9py*tjtf1;Z<oTmtv_#>1^IQ7_QuPrwiH$==Wuw3Bb^cZ@8_?f<MW9LCHoz?&!3`MN8'
    'QDAE0Dp~r7Q2{(liXo-Lkv3eX=?gr*-y0{<M9B$@!o7WBNx>0FH=KAfKs_M8izP!b|5)d7Gw3*+7gF;`!isZ)M4Kt2Sy0e16&1OU'
    'nYDr1m~!U@z%T}@>DCMsYb|AFtF{0W07>C<0350oUnn&Yzodg;H#UJ5J{xyG2R(Y)KvfXE2~P@snjW|8IRi!I^RKK}8Y68Uv0f?}'
    '4=?eDg)j-Zdr4C~&*pW+f3#W<^vz6&-^E#<XlE9zGwhsp@j3qKlUc1jJ&RH30utETs#q92?wP{(I3kc)$g$Bt`)0zpRKt<Qji^%3'
    'j^kSN?V&=E;gxP3Ayb*2-gTLd!6(nZS{M$R-q9pAjmN}>&H?5n6~h*gc>(g1^W4(#=yurEK7BGu`}E0~H_tRx>xYw!dPWg$<5lC7'
    '0i*PBP3eap_KrLQZ28O^02vg#@{8H<=hLz*{Hb#<YBPTlMc_pezOuKFjp7(|9@Bc98ZXUOjA<)QP~kp(qAY+WZ}PxbZ`$>%{Hy%U'
    'I8{Ybe`Asfuj~7-@?ZVcU;Qe>6@0;k7hI-RYSlrR;-^o)jFBrk%Eu(ypyyg86ZMu#XqaFR%pz~)T>frT9A>MDmWG~MkXL67VD+a?'
    '#~i1^9BwGdP@ldrq1=Xx$KdetEQOrYeHLr-yI##~Sy-5fuSE;PhyJuxA*Rasdh-k)w1GsX_IR+KS6j*~bYwu!2z{Bd&UJLuvv6T9'
    'J><_XK;i<2y+@L@t%|V^a8PH&K6vceNZ7)Wm3{gxOfr+?!l})6HgX$`&2rN<vEndDz;gK~#o8hd;1|oN^J)Zd*u6V0yAs(`W}OPW'
    '^aKzD6lJZGEw$Fu<j<Du<C1SGShv<d1dY>YT$d1uWvpO|Yi4eVv@U!#j#U`lx^bBq=cwag;~aR+CK^yVhl(ChBH0qoCXfquzd{>w'
    'EQOOcF=2nw3;o<ZmH7<(Q!G!WXMstKpq7;dGYpm&25<V+g<E@dy0s0@Jm#(lr^6Sj^MLoFDT*^+KJ2g`{rk=wARV5L;0<}XvBoSR'
    'kobi;Leq~qRy~xFNlU1-O9WXm*fVX)u}9CN_sz35ke!?}3~BRlijD0=H%X0bJjXUQ9gE~$8aD*W6+o!&wF%Da$>M!x_tJ(JnsY(G'
    ')24$IL*d2ejU{E-0KmC{-6ZdRXE?eD`OXS3_6|K(_n1fSj#^lf3un1!E^ie3+G74`<_twy|22<5(`Nbb#8>$61BIb}ULTB(TXg9X'
    'RY&r00crJ32u2F9X!lwA%2o}PN^FpZhUXvh6k}YCRUlky+XXHU)*Hih!5aRbX{jA75<`C+?ScAnIqeLmN@@_rD<)Nbo9usJ@pwBU'
    'KF#_L`^AdUuw8dkCh5ij!_)-EH$%y_y=Ma>(=f=51K=)aEMqKaGWvxit?i`vhN6f3a=IUYfD4Sm8Vl7t6({c)o&n^m8HQl!JCH`0'
    'X*M5z>}6{9+m0AwcPO=-1lb`Aa}2aRBZR^-4NiZswowJO0k#;CEqeNG+cMF=fJ_;|1vU%W-@%D%VR@$CYC2l?fvcqX6cHS71z^@A'
    '=ool?P)Hb~`}80Udrwd5(lj%=^#GpY*&m=L7z+F=h$0zk-xjn8ns`9Jg)Ul22=EJ;l627MvG_(X53?$RMW3d^qi<d6=4yl+;DTQt'
    'q&gEF{w>$$@3yjrA2hWXz4@6ZYta5c`sD3bdkO{gpmb(8GBMLFd~qw#(y3!n|5<~OczjfYrYEEH`=96`i3U*P7|8u699Zh%1c4FM'
    'bZd^4k)X>+s{lJM0Gc?N8j87c0ms}(u?12k{c7rI>L{(!u)>L?8>UX*ND^@sfj?tj0$Y*FBHRIZ3S=cPF{V<6{`EY9z!qv^H*94i'
    'v~bds9JuWnlHZFIDZra1<@-lit{YzhUpjMSEFF^2WDOw#?U;tp0=&cUqd!>I&ZP_n2)s!T9G9{q-6_cAH$)&XQ}G&D1MnOYsHj1('
    'kP;E@hHA&Re7#oq?y}y4k(gszEk{DFkuw9lh2~|X(K@xrG2~r#+YY_UF5R4`<f8Z{oZ%Fj!s2n!c<7#Fzl;?#T9PY7_9ETWK7BI3'
    'A~CoB0{kFdp#5H2U4`beW{#E@L71(}lvYz}z{G9(V=bw0JOrDCB08i96(P&OeACFFmo_X!<UV=Gw&Bw|q}7;Q8NadkF=6ZhqQMf>'
    'W#rikqatp}u94hGS*(LW@**>fc);1m?laV8H-OGshF$jv2oXDo_>-xh+phw`n!TOxmuyc2fOb$^9?%I924{KFez;*UmLXbY)4%*e'
    '-uv{4d|b+Khtq}AkD(Ssg|%n{%Xj<flcTwY^SmT#Y4_PYU9;(Yc{#h~@dWr_Fi0l}yiwC{ROod<R$Z6Z4Rw48`omvsaWR)(2*87u'
    '{S+K~p@e{jR#-zE!}!d!W9*H+3xj~SJ?7~g6Qm3?AC;vHa~`|N5aee*o)rND{R<oTGZoKcrn@;Q+aUM2GtY~kL-B@u;t)j5GZjPP'
    'F{B)i6@H207)Va9uS_SzvJK=vOAE08xi7#e0G0x|W~k^?{I=sNFnNOJZv&A6zPuwrFahBm5rWDXrdajiJS^jM#62wk1uk_-|4JlH'
    'nlBkrUJwNfE$2sNs~ShZ++Ltw$JD$8K>-IpJ2Qtu*ke{E45|=0B)qdm7#7CRC6O;gMm+RR@B=BzaE1_w6owE^Z}#UxQz1Q`@Au)j'
    'I!!6)olp3c%VWjpXrVU)X0(t;3)v;4kW)f>{a|4YTE_&0(ay$#s8gWW8%`7C5t#yML_=Ohb+*<u{4TSeJKeRrg(e8>jyN_a80|B8'
    'gc<zIi$1$T1?T%yWe;z`qh=_S0|SrVHxnT4(&SM<LB0fob{3buHU<qrkL;p9IDZo^h3Lh=A9oPb_xYERBEl@;?Ju7})Z*}nJblGn'
    '%z{oFG!%OgNk=n%(Pr{BO9n|u?rxfbw9J6yBad!Aj>qGxFD~!S4})=I)sKk5U)kleb^yT!wM_-M&8<GZPJH>ihT}ilv^^jUTx)C6'
    'lpAvSdanv=^nttK!6U9HDWvH_%Ea9u7p+Fv08c)B{!SD@NOu8E`a}lgldxK+$U^_L)KhR?`#C_$|6*F-L~WgR(bfT;`88qdvt9b?'
    'jYQK|oFN@tG0%Z(O%=IcT{00ke|4p3ci6S93<(IXDRL>?oUJB!3&p||M?Dsd-=sT+5gu`HXJZvHfS%c^1~uP63twNzM{C$rGv=nC'
    'xC@x<lgz~p>8Tgy;*|>42#3w`m{|bXe~~t@lArBfl{P$OI^^h?@e{xZ78ctHbQ#2587)QTOcxS8+1wFcZ3fs_`|5Xt>Ooh3fzQ-f'
    'HTVPm#4a0G@QGIpdKv*-MuQEY$7eNxMi~9}HW);Jbjv{}{$T4JsTr!|;K&Mt-%SXJ-(KJQ5o2r)ZSh_I6#ND!n#}tMHMC{}qviyi'
    '#=@a-8Km7$R)R%hObGI?07=ehkLNc6*1!zsSw+7Wr}2lNBIdESZ>%EM_zN4~TAdrLIXC)L!g{-Kj1A8<fXA7h30rk}?f^#5nhX~&'
    '0ERd@vOfb4Ad}<rLC_47iNT3-JSHS#EiISmEPUfa8eydYAcFCE%|?>@Q;#}CJQ~{}E3}1%h9-eS*_(44@{^evZ+Y~bxzsnx^zloL'
    'g_sp(VfxsyJn77uqRZ*u;`@y|0_Vhn^qDAWE6t~Y!$ij4ah`K2<vd87<eAwh3jldr>s+9tNyuz&0s$*6ccb2H!>I+kVJ2y(H$e1M'
    'h=_@<-jKJOdCv^Va|^>uZKe@PXd<C=o5mOyM|s7i^9;H~(%Tdpw6r;lDO(b(Y^GK4(MPGjHW40Za16R4z!iu3>4Z!=Pcr8yg7TlY'
    '%5a&7^Xw4HjA}I?C3MB^c5DlCrAKilX0rX5${LB+)CZWybBA&k(uE4eB^1Dkf|4JM*YAEAI{l_A`$Ty+$dbCgB3rfjk6zy0q=(d9'
    '*Y>2jpE$R|oL<SEBUditc(QmH@cjRMe8Su<>3rcf)2X&`RRJM}tzdYY{!UtK(+oiA7?a&G<&5mF7do^HUCW9tfeW$7(0tGp!vIA6'
    'eg+>z^MpSCAkDC<4~5Z0a#?QdGU>YfCMcPa3LdE#eoM)hkYKT05HOB`TK4T=XMC62gdKD?2&j^L38#p8<}B=uG+G2_MCr4U^SYJA'
    '%ZnYSh;)V{Pk|chNy%@*8Rgiw3-CqC;;VCiJ03ZKZ@Y*PXJNf5<M*-N{9Ff5u{0-y4fFFJ6QPArQAHkUe%B2JA%f#4J29caISnAl'
    '9BZ}Tg`TxmFv@JXq$ku67(@}1eg+QeC*Y1O>}hyVP^kwc*&BA4AUgz)&0X2F<~ZU%ezI1pbkY+=)lV^f{G1_RA)b)qa2=1Q91Zy='
    'Mv54Y%3u-vX3L}QGcu6V14*AVwY`s~N5@p@U){DJ0X`TH$0K~g?ox>+!D1HdB}RC;kxBilOVke-+~7>G?s9!M)@N2B6h@GZ7z|v*'
    'WXj)xwk2|;D1bP{oZFqi<>cd<sO#hk(V0bMxn0THO%(KGeyk#{IUt^=FuaT@_IN4*M4bEsaUTu{I(m&k&ly!xyeud+#Y_SCeMqD{'
    'NxfEu(QK<B{$+~hqrV={^cy6^gofT+!s->39~4g7XL(tFb-@X~4Sz0Z1LC*E%=|=90Dgy5+QQQH`kTX5$Rg;FSz<89Ubh1lfq^2B'
    'cD@lt^Y$(}dEUM@sOIN+GdR`g-Wit3&&RA9BA5kz1-UHGK%!2-l5H_fzKf7jRXe0q^*3r*W}7U3pbPc0{K>%WjkLt?=&zRoJbzTr'
    '`_W$vfArI*6D80LHDpOlJkM4}4C)BuNK?X+l)M^J&`f4t4d3xUClfhOzWpO<WW_Qro$`Js>$fo{*;%6n%!lZl6uF2=RqrEa{unar'
    'hlrd%2Kc;~bHOxZy#=Yna(VC;mWmZM6!J${*wCB#9NvkDWVsN~M@^E@Kdo)(V;qq-h}Jursid%Xko?G~<LQEt6+T6@WlmEdE=MyV'
    '0xg#{&;}(Rc))>iNdqK4<o^`Lk>T`#)msCA&<{2n!Z}@GlAS?85OB0b*z?+k+KNK}XA#d1>SIPMGute)cU~jMxd{bLy0n}z98+7*'
    'VZOOMk++uQn`+@7Vh3opa5gw@rX_G7Z*Y7l9Pu#RQ&w(kKhwo24C0^v`fsQsH<zn7Tj)7Rk7rm>M)C_XwwBTi11mrRMk;lJAV`MR'
    'Sp|9=8WRB;IiRr8xr95Eyx7qbVa?kVQ~-pg(*iUM02EK46YZ5*%V#A}vj|0dJ+mBKG8%AhLaR<~0MuBZF*^c0rokARX*Q;zv$+jL'
    '&ce}of7G#0To+YFMt(q>x`aN)!px~+l{%+xsW(zf85T6=XvF34yyAvylD#*h$oFi=YMfgGEPT3%tQBYX5k0fBsk9i)t$LoBd;g#Q'
    'r0Pvb@TFo1-TMY_kv0n$GNcY+<R*mkd7+8)aO{J6S>h&pa!SSpM%r9AWJxF|@UFONfaYknoGh>=;LL`U>gUSn{;8oTeoAzFbYlpP'
    'h5@~K(~Z|y)&`03bL=@gSt6T21k7p60iO{)+Kbf+(x>PWUGpE_l78)}m+a;Z*ExQKE=)L^4(@e3G;PkQMB}Nx?|ogISq^@)bm__?'
    'nKuFr?4ybjqp8e#d^U<~?7;B(4h+&A_|qHC_wzC%XbEo!jUYLZziT2rkr$5dT6f-%Ygob{XPP^@;{R!zf2t@8vI=1j90+3qI|A82'
    '=err6GY#flGhT<aryBxEu4_glrMpB8C0i%eC1M}*fOQ!Jfyfr@cG?Ze+)1}-+IaJUuQu9oqtJ&8&k@m<!)YQJP#4)_dE|zHzGh^D'
    'g$WI<=tFj{V!$4d%P7*a^nz4`#zPl2=%*P5&&S_5B|J+$IP}lRLRCxc`)b<tS=&wUEF!BM(pO~laiIwL{}mcD(pPZUc?HpV%0fzC'
    'G2E9NpwbyvDcW-SiucE^IQBghyy6&47=EV!HuUK23T(+&Up|8mH#bUO-AB0Sl#lIrzLZ>EN4dz;Rp86#0BIJSk`DbtiHNn5duR^v'
    'N`5;{)=D8tmUJx(J5Klp!<D}J$cEg=k+qUNE7>U3ewt;hX5Yz(S$IpTLS(hH0S5e5Dncu5qZuUfb4r9QA=qo`++GaTP>d}Qze!6#'
    'yx!`VvzY7`5T&%GqH8x~>Ly#2Z~>S?n&hvZt(LpxdhJgJ1bvDFwUbMKA^c>ktAuabPIG)5<9;ahkU9uS--=V%eHhzo<q}AL`{u$}'
    'O_|UQSB;)Tg2{!(&J)g{veY!L`Vtcvf(2=^HMk1MtT)UEM@DA0qH-<7S*xUegPjOOe%q>|<ad21+(95xlLI3kg=d6uplJ&-93ZYi'
    'VlPYv3Z2r3XeA$^0RT{-(L)x(B-vK>(c3IjJY?!xX|yu1yr2yp0EWPi)JQP{)8J}S*Feq3k$<;fU6e;AS_;U9;FY<ZOtCH^0Zz$`'
    'Lb4LVJjp;wd*MiHA+u#<M=T>E1*~q3qpOt20W+C8;JSK5MwA4I0io74Wa=`Zj(D<43!_fD<l&-37_$y1ZDUN)AYz<4^kfAx@0xUT'
    'OqxDYg}n^NN@Q`3d{hmf=S(XBW}OYYA!53ybbLJ|Ev8EXtx_=Vq=SmetZp1Y*n%Wtm&ak)WteV|(<wpVfDX|b$Z|2FBwckGSI2V1'
    'rbZ@%3Uw54t*Fuj_JvBC$z~9RdX7a3%a*9K64tcvk)e7(DOnXHCLIpe5YtAWb-B!h)THb&S%5G)jMmWnnXoK%V`-=gSi_*ak^o3e'
    'M!kz8$`x?NPoJRYciY(#aE`gPq^y^q&e6wV_p^nqlEr~gVy-Iqh{2&g^jybFJ(c<H)2y8!c*&3v0^VHChAQ%ISCgpc@RX)2h#i*U'
    '*gYH|nP&Ldp$%fCAo-$`E0ShFi)WGuvo?laz)FGZ_^PH!E3l-{`Z1Fq(Nl&neB|O9Ha02hd+I~WO8R{8*>XOU_46igJb?WVPf^KJ'
    '&Ql6dUee_1DXsV8=5~2rUdT<uOreTtgTj4-GQX$bb(_#lNuy0-8ltn6*FF0~hzO6uQm5hg=+6zeu7ReyZlEwCK9LF>_Ef`=%B*5H'
    'uBGq<0Lb8fj=%9Z`I41%J!O6|=&S~nK;SHngO9dT6d1;l4M6DdjVJdH-$LKN8`+IsKb%NAz(LZ_u&QnhR^&t0V$0@-hY&UdEMatP'
    'om%)j@4#^7>-Wq)Q$<yP$R<PrV+@Z9W3L`yOdkj*N9VjRA3md0$`N7eYP~#MPhcFbMNPZ<^5F(p<MZ|PaB}l87!AgPLhAZ@&EKe#'
    'q2T6YK0e_K#eDu~!UNYs^g6i`O8O!}pFf6|!}Kz_5Q+F=A#ync*OxMTJR0>Ge|{eB2;$AhxR?;fWBd`i`6wiZG5n<;Zazv0X*iCO'
    'AEVXH$HXuh7O+*@n~!2d2#v?DAHc;5gCL%5PIF)`7nau(_?L{2n-2v+u8-p<(TMoyAGqKjd>{E3FNDMJRR>^08rH?df`9P%PK!w5'
    'yD_tbVDJz4K?)K0P&jy6NHj_cF$NMfm$9&#Esr<AG*#bKOPVMW*C}85uDZh0jHolZeC2BkQ)MOiC<VUW&U_jv@tP3s8R_arqD1&G'
    '3#soT=!CwHKy-o3`92aEW{sQD_fZs9WHpip5xqw9`9Zn!F~~UIM<&g3ewK09K5i7`c+Go$F)`~>*L!KWm=WohJO)sb*YuR-X1Ls{'
    '?oeob@DL(TXa)FZ@-TF%-|!?o-LNApFJ*h>L*;O-O$D;GZi0|fmJ5?&I9y9XAN=Q!L_I#zc}XWyGmpC4`AQ4MJaqKzeT8uoRNER!'
    '1V_@ucj4{0=hD@X$JS6%JQW@stML4#sIzmYXFC@PyulPa&yInB|H8&N@S%v0CmRkc2t`Rx{opz9ak?E{i@K4p)@RRN`}|(bsrP#j'
    'GiL1uMq5*svk_;`Tncvp1v~ZgQH{3cW(wNnX^V`jwsz4=XG7@hVTkn*PAA`;&u|px^J8onACAYqkBM=N{Ci>i>FTrXT~a=H>Yt2K'
    'GMW5M!$f9~ZMF9((+OD#1sP$A^TTlBoGLMb;#ep44Gn2}?bX=|u)lM2W9({rmM|35XO>piIwB-rUoSj(txvbB;rr{HPk2sNHxveZ'
    '2-pv>A>>CUADROLavPQex91sRf<c{_fmae!bQ;yZVN`H_Mf?EvP$8|Qzp#*4jpfmBxo$L%!)f`;m5cc;yPsX3z*`x;mVK_zhUc=+'
    '^##68@aq+P-E0;3apk%qKR$+&Dc9>a@w=s%=31?^>jp%fXCm0&5N$yxGyVEUx^-tyAd0XtAy=5QHKAq!z<xSo3MNl5S%S$3Qgp#G'
    '-uUX@Kbru<V>mreJzdk}t32UP&Yb9&sEHnoz~fYFI9tg)*=~fdM|}Qx=q+j<b5ip-Q1kaW#icjSD9MGT6gpi>JUth;(ZdkkLnoXe'
    '_7jYOtWzL4peEi>Rp`|}eRhnQ{aBy*>$BAIDSKK<4(2jtPB0;7t9SbaRijw2r@M`i08%wKe5PsWU;T$?qUvd6qEVkBwc4f$EJDWM'
    'ISvcR(7d9nsE@*N`V4?Zw!JYu*Ka5AKQk>!+knK$oA6uN>Ohuhdzpn57*~)slJYjzRQAJYu*vsqG@8)xB%$G{pJj%GRha#^$5_C6'
    'NfGe~h77>Z;5_J+wt}M$dUo>mkq_|^UVQZrpUt%b2T2#EpU#~<o`X#4On*Kdm-CT3nQO-ioNqOKHa=b(00bDeK~#TzFG;eo7@;1<'
    'Qpq>J@B=RDf#*35Y!E*G>e(1yl(1j@i{0~2xWK?5m@Y6d1?Zk)Gk9aO7CR2k4sK+93Mg#Lky{yI*p;J3kWqgqJN?YU3?|R$Md)O!'
    '8Y?k@E77kDL(RG6p+6DZOEIHwziE5Zk`0lIEsZxf@fo|c*M71*Sjm3pI=wK<&<GS|jP9|+Vmz5ND~OzQ&o1!%fLO#mrz_VuM}et_'
    's((hN3&U7VelyvPu=$&CNKF`tgH`#uR;A~QF;3t$e~ppqH~4uC7mP+@ftbC}pcDyoxN_|J)1EMH6ZX6_h47s+e4a7<?d*D`$O^X3'
    'XMTHiIa0N1Ivi}E8zZyBSjHO~^TF&l)UM%4O#wrO?AIwv6GAlmHew~cCm|q{BrA~3;5DWQ&~SMgt|w}G>Zj0IEhM`XBjJV`%>nt!'
    'd76Pjp36%lB8dN@KR=Tea%gu+U+u4qIJA>Gae$3wfcwMcCEfSBuD*N@kOIEAE{2}q0kL~(B5<i^cB;LL9%!X)|KnQiLW2uK93z^s'
    'bqQ^bra{~BtZ8l^q@P{YOfBEaw7G=qCKTkuKJ!8nE`)fWt5vAA%e6xFn$O@f5&NYaK4rfYqEAKbm$G;%Zo3qwPsMz$T0N8Dc&sg$'
    'WIsbe;|2PY$67)@*L|T~Z(P&j%%9i>KH+l}>xI@eALHDGOsnlNDxg;roV!<GS6NAgI_c*%&l~NvE`^MzO6B`ZFVievCyml>3$@~)'
    'Q@f6s9q84Y)qJ;H=v`w;!MOcW$mo}KDQt{lqgp6u@`V=129~#9GW*zS)Z1K~zGJEe&Gff#fnSI2a;x?7m}w3&FOS{AV?N{gbr|ru'
    '{^Q^Nm;W^t!)1ZtQoB2?fBc7L=O6!}K>qF;|M(BN41~(mGOY|8E;kiTRJ4_X*#Qdl+FhoP|K?g5myb^-$pGh637lMTf8)V8*b~3|'
    'K70$1{qfQ+XKJOwOAqEaQ+v55BZXh!qgbyMv1R}Ae<pwbjw8!l7Dxkf_fR@rXm6DMEl}!Yv(>`OuftNS%{urm|2_Hpzqk(3Ovo!}'
    'Yt)SX1fU1lWbp05(#Tejs7V@I%hvc$l+<YzThxKa0H6g^CN#=e%CwOG1q$K{TcRpRf()hM!AJoM$-yy!JQLykpA=OPRDH@RLpZ~*'
    '4dGw53(aQcFMiZ0>{#-0DWs6hL+5A8Ad52eRvE2M{l5GYV*`5=N`i&kBNQB5g94E9bOmYEuut&F3v9r5i^Fn)W+B)J+}bb3mOLM1'
    '7~BrIO>UmOYwTM3*8fia{!i{sK&KDa-Tir8Y)`)oGW8-^udPyfz?N;PQ^tR*u#W#S_jvu1E0v-9?aPZ9XS;@@)2KQsf>l|E;ZasA'
    '4QtI7%K3WdC7W+uEUQ(k<KQOj=b&^{%cO?(OA$WG%^KNxwM@61d&y;*Z5XVVW*I*Vt$L@KE0~S_w^%`09?hVFa;sU#2IineM)PEQ'
    'Ro?<8)p~FK?uCP(nng*fI0GPjbE}XB8)WSTh#4*Fe<gqaz}*5y7R+U?Mu=X3%godv+a&<0FFFb$E3-0yp50dKxynnv-YvW|3e|Eh'
    'Q+uy@jin$H&ACd%OdQbg8|@_Hnkx(nR`dQXcS~eU0q`SSc*~fNR;KBAFP9<BsAk@4L{5OPNP$Cgbh#WdPQ?b!WviWOzE@bMMa$uC'
    '6%|V3lkwA4Ldwci%hf{tee%?4HB5R*H}YvI)jC=3t(RQAbzg72ROmmrEt@ZeYN66@)?e=H)f(9{FV#-2MC<zptgpG%G+b*IdkJv&'
    'N*?Fes)$@%fh#*4Dh9Z{xiQIrz(`cfwaR;=fkV;9_9x*aRuM)+B-Y3PB^~=wuN8WQEG_1LBY*#sQA~vl{z!on;=-122_ipnby@03'
    '!ygn_ZkF@q&i#80D-%s~wp}5?CPG0M(2Gb1F(sEp2FM6!Gu0nWd2y)>g(Wz+8oc;oab(Eq;p|I`Y&9YRH8U^eTDwp+DZu}M(^B0Y'
    'q}5Q_s*oMFh5HV@A2e|CF$e;-t<a%wzm)3jY`K}gxOI(jJ9#%#D_35~>jk7mnS7?{pqhWj<pfz6!RlxOb0*^+prVG2B#{k*WmW3;'
    '4Jf8kZx%90`wI1Ic99nO_t>VEvL*biqF@#eSB0<uQb?uE8BD@Kfyr1sJd$y$k_BBvx>?E$GTBaxj9RgEk#~SZL|Q2fXFyTv<M9ke'
    ';B+w;>Xa3elDJ<-FSTa9`qC>B;zx#%?41s&ubn5~@~y@Xc6naO1D|a|vnk&ub=_Ng1(L8G=_(=vlB?ev<3Z%VuAt78Ez%x~+JPVf'
    'UI3KD7A1v=Sx_7sm+v;U4PsQ>6rW7<|7pEE82G*PmjU3LHjLCp01jX&+9O|lt8|lsgR1E-Dgbz4mI2wschS=Za2M&ppW1^)p@neO'
    '2HK_T(<k%BHw}{$d<Rpx$1lIU(BG*Kv{C8R*JpHORgX6-NC#r{nfwZU_br7jWaS)ulSu)qZ{hD0GSs);s*qBWJQVr<dSjO0`t!f}'
    'S7c`3Kyo(5e7I(Du0Q|vzj7JnIm*yqQ;u=6#YRkpquZ7sgAFiyoDCo#>3HG0Ley^@P2&o@W?i8D_PSUE88(>xG8)N#vWBs@6m>{5'
    'yY7woal{;wS=#uB5a)T`7!$iO=G69%0bs=@aFO0H=sQHz^qdB;QT*YB6J!|DZqHU}^7lEN_!<h{kZ*>HqaePHiI;~yBrQSL{18!K'
    '84>7!A`I2SkB(n%J^f|sXAp&&TlaW8&kA+QBoDs6DvlsQ_YlYYq;Ga)`vv$=eC2O~o@=-8^AB4X+9seV4C*TaHeyF$sMF>_5gT&@'
    'AlsaVmzRX+)xzqtO%<FGl5LcuGw)ssx^Jn-o@bWj<d?Rjs)B!}f$C!3Wh3vZW7r5dC+!7@EvJZy6c2Nh=A~q+n#mI4Z-?UYFTkHe'
    'bUD(7Kbz2f?t`Dya!vj`f5dFAjdFlb1brhJZz=LMG{Am~ekY;<G|zs+<6ERh%Ri2m-jV#r5rR=KK94-lqx2#*Odnn?g!186*Ps9M'
    '{|vmN{W4kKZZ;?!I<oq}yH`~XsF8TUtrdEWBAqp&Y(QW)zZyQF+B%IUD;J#TA#Zanr7??R1aoi{46)Qm7miUotZ8W@Qmg1j@FVV;'
    'i<6s>dBg_lB<P*8n@$t0t(rC$wola3&#$SfIl`Jb!lFSfjJ=)`wQu70v>X3<c?o*Fyaly!#C)%Sp3;(ZcNO8_Nm&|8>_Vu#wsu&$'
    'Y&Naw)tAp;=l=2^|Mq|Q`_BRV`g!=JW!jeP&XS)4LvoYGudw$IS9ltFxcc%R{x!Lc_n6VkUd@nHgVs)bdUIuW8BJfc&}D$b{2)Zt'
    'BoYK<g29gaOg{GKzy7-`h>l8Mfw>KuO;0|cK#}~UCm<XJ5V*Sfl36ZUAu~zi+%7MJOI=7u%?&_)Mx?jrbAZ14<@^~WA08Z0G5y7L'
    'Qi;o3aEl%=^BLc$_dd=N*bt3!jhJ4FEJYjc=z#u42Ve#@Tl@4Qwnewvf>rCDAJ=A^jTN0V`N}?1aAkRRWn^AqhD^3={sIoH$+B`<'
    'ED6ztV7~)t0`vVxmuK=EHS97QY1&1tw1#i=R!-YsQ#KedxFKaQ=#&er=w1Hfqqx4JQG!p$-@5VJv<{nF(I|oR$^DB+gazmBBcxFD'
    'eELL~njwLZE07~{!`RS*upwkl7B7PAC^#50a8p}QqG~}51jt&k+F)Kb4ZE5-M2PJC5q$rbww<in@vCuRxHWW}bZqgNeubLD^$b?*'
    '46V|*&tc_IF@!D@-1~U8hPO@z!K{l9dFb=_BwH8Onj<YV=H5z4J+d<1p(i2G+i$c{%(woR6NCvZt$y>4Fkgj6-kN<!T-(fg?WYUc'
    '?Lt~jR$PW`*zpn;q1ynuJrL$OBD7E=>@@Y^n`=Xex=8+Xh_+|cmdqK9smr^7#fro!O;#eEG?A`gbeT67k9mPSmLh)uNLlUs|3qp^'
    'lRq2Xr*)r+eo)ZJ<+076_SG>}aGZDr^!H?HhK}vK*cmg(<N<T;j9E2hMEk_TXPpt#3vU>7_Vkr1O1&p9kmsp1Or%BNrl&78s1$mk'
    '8YZ8fzJOH!v=U1$zEnqD9nSQ#8mP=`roQq50IHa`Fd9PS-ar1mbyryGCpobeD@UO%3?DdenvwiPo2(<QudW<uwry2daP4XV6Ymxq'
    '5lAIDTWy!<wJ$5H8QA9)X!lufTHE0@9xI*o=tTC@K=Sfwew6U6LhMBP#^s`^TrlH-0g{TR1cU&(jVP2;vJ7e%5@w=-0aYR!&H6@e'
    'LTR37EYrA}f|ZWfUtb9k3fhpS-<COuFo3YY;I&+En>p98GuVD2o598ck(E?Lc>@!rQs=w`&Rt!vsmteNp&J@ZNXnP>H_pZ?X^{Q='
    '_=tbUyL|b=ZTfj8Yd5ZevPB1c@R>J5dy0xa6;_-;Ci6(>HkXk#!k@UUhG`+EG+7;H10^JxV|X8aqR|{p-}gO4UZ6Q=rg56FL?FH7'
    '8nDo)cR#?^Z6UOms6+4@<3-Tz-bYB~%`=2vG0=8Fr(cAbO23H0>IPx6e4<F<%Y8awkJ`;MiveMIuwgB-HweRFPoe`jzWqwU^)shf'
    '^RF;Q9!iog-t*b;$1%9JMMw+4Dian^)}@uZ0!bR4UtJ!LUEyK0e@EvWig&!M886e~Dc1LFd~|0V#h7PjDv_`^;AAiAh>Qu2Evb{t'
    'V>$icMi9J>l}`4XD^o1g+FZHTYBxK%cDY__xqKOb*8grw4;jA-L?2?b5cuHJCqzG6Q~i@7q0zf!dh9xYW^Et#u&b467pm2AyU@D1'
    'EEA{@4>dwLmcFctL~;e(L&8G17E5A$gGxU&Ech7kh>eBAMT5-S?phWEA4D;bJE)$avw)jYNF<98b|PLRsyq@^KgK^8ofbtCq!{%a'
    'o3M4JQ8In!@B@A4e6+aifUEavg(jD)cWUkC07ihVM~RC5mK@K_0K;$m_iF*7Ay8xj)Ci)<qrpVNt5lLn0m4ekSdtq6#Rfgy=8*aI'
    '|NUFP@4Jyv<dQ_XPk-4Pkf0$e+ep~N_;GoBQ51hRw&dEhllPf696%L0=i1oNbYG~WGYgWNP36Hh(H@sQm$PGY(CHzRg04xUzD&89'
    'Yi4fSP)TN{zP<k7rm_4k6ig_Ov*29jzR=8I<8#95jfH($6dm<8OaGVgBk}Sx+U04pq9@=@axKnOLRSGj5c6JeCI~*2ERC0u)|s#3'
    'FT#yi5(srOQR9HPt`O%70Ox1Q$j6NpMPI7`*6%C|Xr);a{2&B<Ml@KY=-_3u<`9H|#w9|GyN0n(w3PPgRA;Kydasb@z~Wu6kvWI4'
    'YTMSK*X8GG3Wmj5S;+tmf`*5g@$--?)&K-tv-cr8#j7oKh%!0JN$4Y5cv_hlz*H&gtIc9XGh+@R$p#cPOp}-V&;qwIA(YcLcgBvk'
    'h^x<GTJ)q;&3|HUgiDYtQG_pg8bGsILI&0u@%5Zb2zJ8_GH)W`tISo>u-(K=+YJ%E+!1hC_nAhUJ$KCkc7+F=pr~&gc@YxY7(&Jq'
    'X30#uAQHz#d7&<lQ4q%yyU&v_K{F4t$4t`hiErUsq9TUIDMRwnC#D?)wa6<Bm>enxrlCzhLz@r{js9G~&jtBOXl~})<omb9cS7u0'
    'kR?mH{)H@+B}h(Kk)@!6s~v{ej^XGBBj;JTsE+3ZIKlLaCSy3Nv1z`4PnmO#X*NiQ)3nPTa*=2!Wn1R+Q{`lJ^~I5)obZe}1;IlY'
    '6i0G&&W*q`oURb501nRa5x|tN<fcFW^}q4>nRIJ-#iC_`@M4EO2xLj*&?rY5kAgDQhCK`Ibb0lO+l5=0^q3J78th6`_L*ps5Hhg#'
    'C#l5lbD_pz(TS6%fDXXW0y#iJKm(6a(svF}TUsH@-2yTX#fd>U9!xVq(;Z8?6|4yYteJ`&!RjQ!T*x5GTVrH~UozT)11OE5vLz4y'
    'ojEONZ_{9SzPWlxq%5Ntlt)uJfmC8z9lk=us2NO+5x7*mu(_O(-T9TCH$j*NS8TL=Tv1rgmXd;f$x5@lvc-a+POEV29=IlQt0RI3'
    'd?h+L<7h5adQ4?_I$P6eJy?3qiE)eBq^wm6%bTrI$Sg3Eh{9tmr3*{72f6`f*hKw66d>871akOhJA*j*v&G0sH2bR|q$9WqYX~j}'
    'y1^)>x(nWguQ(=<3tlx=4SkH-n_JfCc-dehnw0H9QFJ~xJi_cDatLyK$HRoTL-;OXi;#hgs3R*x=WvuKtk6|qMb@G9fMX;HS+FPK'
    'b=ypIV)`9iF-K&Ns4TfJ+#k(61#((6Fz>`~qKR<+9Z%H^YA=6vfP&hrTtN>#i^B-fVfwQ11oG-~*e;xL1o9`V2-praCD6>#f=Pxj'
    '9G)|64DiCa3EM3GY+XTd`e{{!osr7iw#9?6JmWEd?#POckO=T1fP;E|s^Y3Zr-HB#M{VTN>FZ7-J?<o=1nT(e%b)-D-*F58*R<HX'
    'UOxywJ|p<^-~63*M39*nz5ZP%0>GbOcf-GyO`8>k+)oGYr=w_oWxPcgAzhwu9q@P<7sQf?@Q%hZ)}?bwabkpUd51O{VzX-tKWWz%'
    '-mq(*zK`32nmhIH&Lg#hqrhkA+`%+@>M1H%K&<vVWlk=YNiCIFXy%($BoQL4AB*p#GA2%>w4E(a_6&`lGXS5$bVQz+X(OdY0;5gO'
    'n1$ZhpG3S0dT2q0mORFS)G;kb9edQV*<<M38y)+&(Kz(OxAhFtbvQ@Ma42{a(}gDFrANj@DPic+qMf*;beug9E-_FYvk=g4CVKsF'
    'I|R%jmIls~0u@%=VqSU^T4p?a)5)E|A$d~cp%b2v>?aPlkqd79tnYg?m|{|Hgh{y=1>x{Nw@2>aV;5s2ej;8f;Ys}{R>KJF8$*cG'
    'r5HMBz*)cr#uX5PjuA+l899z4;h1E)1yW~w?d(FDnF7DkU3g;{2H$qQ9}mgKI<t%#J_&EHD$3vd42II2I-?=VR~JUAxNaCd!1SS>'
    'H>ky{FABTHw0Pozc)#m*lPAU@gQ?@lxfyhg<=6=*Y!E00Fm`_o*pxtc>ut0txa;!xequ!rEm}2Or(Ktija{jebq{CFaFO;3Rzhp`'
    'BoQqO;AvCV{M(GcDQJ^p@`et>Av}uM&hUZ9GGML&n-kh?QXeR$#G8;3>*yssiD1wUCK2?(|04!EgaIbOClF);u1D->65*gP9Hbx<'
    'u{Y5qAnuF8NhF4ep#>))M#RL=<3#W@96M^DJcRzhT}L4vJ3{^&|6Y^`EFlye@#3Y3?qJXn&i$Vp<l!t(KK9#y5BR8ui(u#BUcyIa'
    'jRJi*(F;heQ%M-nUSO8ek2=JU`%c8#m94o`Oi=n00qmD!Tz?opXa}0m4{za5kk*s^@#T-tf|0H9hOF$e%=zOQCvJx`@p>pd%_P<B'
    'Cml}^+U?^#+>nT(uQ+kmd)FgyHoWok+A9vj`JE8CV@&Y*-LUrh;a@DIBj%>kIBdl;sI$+?S|Doj@g_(i7XTfLjuo7L4BWuTJe(#9'
    'OUdm|CP>%qd;~(VUv<SSgtrxfT#r2r-(SgSKvw1v_i?FA6i(Yse2xpV)#RByj|__j=DHy)H(`e5#>jq;Gfo$cdSHkd#Lau#k>a&P'
    'jolO_n<;{ODauDf0&X1+;>dp%tt1Sil6vRXX)L(eO3uF|-8Ozq`DeS3;8^zt3egS44SP0%cCW5drXWHjb!EBLB^G*j9d!m}lUK+R'
    'Ge-f<7q~_3!~=Uyw;&%*`rwZW8Zi%-h&r%n2;;La<kp&K+)0h2bbxTSF<=!)_O=scmu$nIXnN4r?rU(%m(FP_NKO{IMHt{Mh=h}L'
    'w9xm?Tcn>rD)Ftv58m=e;XV8$ZxSlSCD@zspRSLL9<=l~wvs1x#iR7C*gK=&-g6O+lL)IPa_BYS`WX`dM@ATZMyA3KtaLfDkR8Bl'
    '8NgIc@ip|rtb!0O3#dD0X`CM{#n0z+$$au6K@0qY{%{JrxJ-W&GyvgcM(Dnf90oCTpO%Peyw8wVE-ciLKXOWRp$;E>COx**>*%Ck'
    '4Y6?G2yg3E#2)5sHO}4wM~Ju4crl8&12+1+rI?C0VShriUpKKeR4~wLwsrxXJfBXRNgYrLeDUCJZxZWMdW!JS=L9uE2&!}Bsz8`|'
    'f9wbB%10h80zzWgxgzmRV`NQ|x)QVn+v8^<L=fo{66A<MmW;q?A}&N>JHgGE9VY|}L=c9sfu@!EXRG8=;nqCCfuAu@#wftQt-U0z'
    'FU>Oyi7%}ALeBXn<3k^~M)Tnf?=yzY{E|B5>OswirNM`_JkSXY&W0cy8p1h&5c{LjDrF)iB*sF*4)zg*y=`%*^^h(3P|OMFWNc|C'
    'e34^ohkq35?|=k5VUwwMsFbsT+`EWP$)E$UiEcXMx91}C63ZoUKEp7%S;F0TB4M3!x>NiRP^&qnHrU$xak<ha?^58?*$P>+l@x@a'
    '7(A8UfTBGU!OIf2R0Tp;++mc#J+H6M=iB>do0vvc`RN0si|~YPK+N`D<ER8*Pul=X{%skOiHr#%McBnjG(0#=5s4qjkZ1M67JDXp'
    '^etgAV&eDkNgHvCgS2?kYuu%@4-Q&l_MJx@t<<H9(B{i8U0-~QU43OcRf8F1+bm=;mQd(DZW(%yTSnjEmgnq{ke_qG?O!0iyL*kv'
    'X|-!r8f`^sbWO2EZ|G0Y^B<ot&^4mYX*T)w9gMDZ^q&i(tDH+CwC4@d`M_G9q`=817V*ux*?MyytQ03ohWxMA>P!or3HjFAlaE^^'
    'ml=?M^SXXNXpk?FOkr7g=r$vvZD=%#P8W}l{XiqxT}#t>ZeF;T_KVqrTzI%!EK0}n@-~w#JQRYF&1@6fsWHvFk8L8u+hS*#Q!1HR'
    'rZRghAIhD(%>Cpz%`O(x;B=n7AMv9;FL@hcA};CPWbi4_ybt$x>TWo$N5k?a_PEN$gqSxO4h53Yrzd%tRrRhCnQ!ZzNi!D6mgDnn'
    'F%u=fBZK^^9*I<!b#iU8?Z7j+XnRIJhVy!v+}Pen$c<j)iF}k}PwU*ix~mm-6EAs0Y~K&H?0TPRWMnbBn~cR=Fc5ClZ<nnEzs@}#'
    'myd;~Nu{1`Mq>MR;E8W!nqu~Ge;Y_F=8J8w5O2maQX-q2<X07WH-E_RO2HeLPs+7HAs=W=$C2B9W-FHY@q;Gb9uuo}evp|@#CoPZ'
    '?j@I#b+;AiZHCc9pu3lZ{at&q8*a15NNJbR0<m?!D{6OpEtctrGNVW%o>8<CKW)!DxrMN9MEa9(a<tF3lhW>KUkG&j!>4>TK8A77'
    '@;xno*cVHg!%mfAwM}K*DP>lj>f=)-ciV~`*OT>NzF$k3_(ZB_0uim7^d9#8>gwSTFIS7}KxaDZ?D=F;Qq-1LS%|H`yxi<<6Op_e'
    'xEqjxoz{;<HKPso$(XQJo1=ciTPm&_*?CVr3{`1Tyb}Y#OzZJ>U&=~abv4*UG7pQI+HI9@AN0dI9=h%D)x+?vR2{CHk;bSz*TqIB'
    '7F)u6cJF47t$bCkM{f0ldb{;59~5C4_R4jkSX=gj-d#Ug7c;l}yquYZBk}$)CkkqLohX(jgJQNzhPSLfcCxohw5GSp57n`DpC9%U'
    'naq%n#T%JhG4r^u@?MD#?d9TnUnpgQiA=IQtjw0HxVOK~wMeZ?Sq@HuvEwqFXe)~+xpxSMBK>M*lo(bXw&6ozQF&PPBDc%=@OGW+'
    '4R05GHJ+)<`-g4jVVw!9on@pzhUz{%J=W!Mf7?8ij>WF9FIEDF_&hd^grq>EC}-AUe!brw6V=<}UM?*kyGw5(GRW4F!)R;KtqgnF'
    '(KvIvO1Asn!8Sj+4`)K+{3uLo{bPiz!>Am}&LfNJI$4Qzw0S>vYzH!0fqx8!JKNSnVDOO0hZfo5OsXCdr2XO`KY8$G>icrFA`Qi8'
    '>n<1Z#^vFr!XH|EZI`G73N2mT?Gg!fI;oFVPZe=_7d{HvBHvn;OR7}e)E@hTdbZYAcrhPsjq4$@7nk~dc@`Agi(V)jUDx-=Rz1>-'
    'k9)y8J~9;)evljGrPjQpOgoeK0`~AC)J#SS4~u>OJ~<YXb?@T17%b)+wR{)pHJ7bkRgYvxcaub8<ehcN;FRUZVoX*;huWarp9Z@3'
    '{X11yCR8D|A0!?gI;*E-Ny^G&WhrV|LUcm%GBJ-%rrvxq+gd+l!m+#DrZ*kTyP1VH3T4BUn3O5)H_OEAHg?!PW`m1aDHhx+xoNB3'
    'Z;FZaV|{nK$!5H@b(GBSZ9RJkJRP^iET0Kz6S-LpWn;s&lxS?`db3=Z#zs=1T`f)yf?U_S>%zF76{nfJDBf=PvNn%C1xpV}?Y4I;'
    '6q+4Hid6fFVm78$+d+8}Qa4YtNjynLuT&e&?;i5?R&=oLb=!}ne7-DZG%`ko&CJUeyT?UjDr(AMm3XSJW4ALoS%2_Gjz@1l#|w|7'
    'W07*Hx_La*R`JGMEIb|6yI!@oCM9@trAc?2A4>VkCdUs8RYJpx`_(Ld$d$X9S|d^47Y}oNw96*fVxTsP<a&W-E;_g$XL`CY3_UD_'
    '&@?G@<iI1ZdOLh^GVk9XAM%5E@M$yAdy(<Oq|~g`JArW{vMf|vbv4$nOhvt}W+f%Jxc9Et`)U{GGqDmvTRFTN^q#ie(k9l<?DM6&'
    'V<cSYs<GZto&_ZJ(C<v|YvOM4p!b&B<C51OvUiz&xvMG7nO<+T3)#?C+X=$DvS@1g+&Z$8x7D38(L43~Xg0L>CQIUGw3&4J%e!{1'
    'eyf$c`X(ghlgG(k?$jFcxS8#3Tf?#vJUnTI-fehX4BcsKwK3OoH6eTV7zr(dh1lQ_)74mFq!(@leqZlyO2We^<h?IWgzl~oZ!e>{'
    '<u)=%G~0LK`%Wp)tV9O|9`^EJP$%rA--tKv<#z1hVJ^ta8b3@l%13@%)hg}IP;Y7Z$82n;)U%^O{dUo*&4a;cqL&|)C-Yu(&?pzm'
    '{8Ow^6%M_~gIcIREX%EAOS)@DqTx`z6T9C}JFD_8(Tz194}^orx3Q<qeMXPmCd>L@Sj(&ngS?(d9*$c1;n>R6`kQw5X~387w`;z-'
    'oG%}HiA7EBWLgiUqjtM)RhM`5)x$#0lzU_z#N2Y931k~_BA#^u!DLUUD}}`<v95a)S=Ad^FS^x0EY@3l6}{UD_LSpjHeB{AtwW?L'
    'HFvv*ZSSslDEF(vh=`l5RVFq`j`@*Py&E33$~4kz#MWU=-Sq?UZa7)rlpE2IoE^tCsVFoLYcluI<f7@#PmYg0AxenmyclangxIDj'
    's$;plT}(Hzu~+6}fm)>Z5MPV}*{4b@o+~fn+g`5Q%;kl}Vl?eHEBDpWE|>E@#>Cc2$d^NRyGf?7s7JG<$)i+}VzH5S`>^T<)WvA5'
    'JoYD#jl?83s`2vV);pOtN6WCf9c+)eN3nLB4-$&Ao(~_N#`)XulefB<=*e-5kf%-Yuu#3XUO8UNMt6k8HY=^>xHC#ry%8b1jt&>C'
    '(R!q2>VZrrTGF=5YLt)PR+iIvxm#Q1XTv*L*u+Cgskx4K_;tIUmAb_-ztE0%{UyIH^c&kqL7(iTWPjcWWFygOb~Fo(1F?I(szl{x'
    'd8s4@i(V<58T8i8cyo{#wS&W5yI$Sht&Zbul&s6U#ACG`531$BLYu|!!quFR6o%V~e7ha!({|(bE|M>IRb@2NvcpDeF~55%%bD#i'
    'zKFNxy=E`7@6~gG=Cs^V6Z6PpEL2@r%HpiuyvyfDol-bn=_Ojp(yFS-_Xm})Z(@f@R~-x=v-MeDYey@+K~3o7n?rsb3VFNh_N}5l'
    '<uqZutpwCgqgf|QXWY0~=D~7atJfb&+jfNT<e2xiUmIl?$A{WscpQYHx7)&_*bGU_S#VI{+u3|IbhkR>#}zFf7vkC7V%J$|3qGja'
    '@sDI5jc1R0B8Ga4huuRb($DW3z1%#ud+PUtxse<tT2OE_)-<x>Tf6WyUfat(ua+w<TKQOLwh9lA*+@{SkBiez^Kh6fkB?=k*&A-;'
    'hh3tTO-OQYkf~>;ky1j=<PY9)clxvzc)s5X=<!ze@U$jm_fZ%nv-_4ev8fcuWXz)hv7ic)wt485?{>}bth((C!n?^saNeKyR@qp7'
    'xaaQ%GhX8rLdlc)`mz)V2V=n^A()BMrnwiY@@7_@i@8}&(L!>6-|x*rd@Q#QCClaQwwP?I)4?*fFUXr{&nxZndm+A2S9z`0@6@J^'
    'z`DO^Rwlt{K{)8;JAOhW{YE6aSk}h{aab2h^@<qS78l)GPm4{YhfXZ>wCN@Fa<e{2)<fZlCWh}ON<OA5+x~nRc*+IGy>Rgm<IB~+'
    'rrNqw>dl-!5cc=uhe2hj?aSlP?LJO~#<g72N{Niv-N^U3QGCCNS4ug(DYZ(gnyNna>!W_|I6h87#gSHvwhOiU=&`$u?*{W#URP?v'
    '&ZN~!u9HuC?69BT6+2Jr{<beX9;e0Fpr%F&3*`{a2Gz`Acwd_36Nf}`G$>8Q@UCCUtMQ$_2$z#y;i0Kky!r8@#CLj~5fQSa#v+oq'
    'ZT51}(4u^|J@yit@@{ckY{y#j(Q$pN5;ob+b;o1AC(dK}lFs*pC$%iKgWmqbqAlD#>_=-MFzRF*_3UG<SlV`rn%D^(5_h>qvN=q4'
    'CZ*Q6@lc2=57D@HINq;{L=GM-_TydfUc0Mrd9hsB?4?LPu~HLc2_!n+UGTAa+wIQwTB4~b(_w!wcpBe})u+I&x~z3WyV0>Us_)m~'
    'Tsx7IE1RuS6~|9&Z*y5*j`+YlBZ#wuHouQ{7yVhko><NLwdnmy_4bt#-`2I^wo+(M=AEw42_3T2yG1F`jxXk``TjvTt^-8yDduaz'
    'NG?uz8-I{W86v10$*g2{`D0?y3Rb(h<o0f`SnG>^qa(-49lkz1imQ5kAy=aZ<v8<3tNZ)M^8F@O?T&YeTuzRL9<=Cm<8AZRqQFbN'
    'U@0+Ff<ho5k2>N0XcL@HZWrrXelx!hZAQA%-VAf2C!H_HM~~r|Q1_~dwU+DeJ4c~1F6qbiQW29Oxm=PWx5Gs)B9@vRZBj_&1CfHL'
    '_ICkg(~B#;;c}|n1*&~Q4l3QTqTM|fymD<cIou7O2JytWoC!RZlaop?o+uZD<8~GqG&*xlIP%@$Lt;7ad3)_ADWi^O;npg<3I}V6'
    '0-r3;SEKbq;!$dpy?2datHoDZkx4*q3IYCho*B1V)g+N;A8Yf5P!)qwvcWo~;-fZFwZOC~cvsReG<{gz&-dki?5Udw<&y1X{a8L^'
    'B8{>rFG`bzmb(q8gXAdM;S-bTVe{DD%6H0oxPO#`m2FRp1T<dFb`s-4OdT$Yi>IYGAMJ$t(|KoFdGeOZxxTFMyRFcU#Y?$T`6v-J'
    'YFHZt%9&j@G-=#r<99-BmJGCNdv7d~lpgrIjJl}Dq;6bZ#-w1i?7gqbT3`_0wkEalLuewam0CGj+ciSX?uuUq7STjWNQxsq5loUQ'
    'kNNdH5UD-Zb4q6)EVjymyvr{m;iM8BdF%O5@-F{G$`^{wdRM6srLY`~Ys1AhoYA`Tc{tu)EE;lWGaNlO>Z9AIdaV+Dyc<p8-L1Ic'
    'ccDqFb9lNPtFcXSkbT%KMs-~u-Ht<2Qq?oD)nk1zN_uZc$!b{ahK|{TDvOy)xYZQP9eENb$`-$<@^U=G4@#}>a<v%dj=kGfp%Igk'
    '-b_;t2g0|NWAC^a?g~nz5L%0c+io*Cs}Y$a+KV>kv;Mf(7=>%c&E_c7I(enP7Q(~G)1vusd)UkCPG~pJ-ra?smR+q{oRht?%QU?G'
    '=p<h5spWb`e#(S`@lGYWjXVs3$xJEO7q;uC)o`77YK<SW>s>%AJw4qYld&luy<2Ca`B|V4zS}mF!_u-w?kJV&W8v7C7llY<zU{Zx'
    'ooKR}4fPK7&1liubhX5?(&D9Dec#d4#cDLqk8|q2DKyIsetaxco<@^yvbEb(mHWarOa!;b(UUkC#EaYHF1&iYZ^e$K{8Wh)yOVGx'
    'f7e$ZdWY@eE_yrYOOZxmxG!$Tk$a)Tt7JxJqdh;|i@lInjmwKcdoc8t_5R~iVwEX~Ya*T<;>E~*`uK3)Tx9r}9w;;>k^6->83oEM'
    'wH(Sw!C9rby6>vDrDTyXdm`a1xBJ{67TDcY9<$+1t;g3xwT4oxi+X6*t@dl>x;kIA7s+}!AT{>oUUpDhsh#AoEoF}Kp{|6Y*=ej5'
    '?g#pnqp0i_kA*c6*oKo_t9d`*^L-&!&qzgmJP3|Pf!pyqFUBkThmul#>J(eY&T##dzui{ivq+@ho&;vum6-4DvwCD49;_PG$6{x8'
    'U%Sg{ePI$7CX-`qRuU%3PNm5&hoecRe<-y_`{`Z&u@lX7xA$WqSbb`(<$Y({9F<#v?L59$R$}+DaPM6;x`k?<ANCrdnI7%)JHm7u'
    'y+vhK8*E~eNwwyk=0e-{SbWmAhv2$2o_IS8by6>OXAk7YB9f_Ph(>k19o8S0{Ia&3%<i<?+<0_oWLME?cy`y#ha%g`Vjt-CcDpX&'
    ')UCw+xX*4M`rC1P(XH!(q;A@TUMv^oP$PWXkrVAuPs!hJO4{wJBJH;0d1e~xFLRY<`;d)irSNKeT<cvvs22xueMWZ6<33j>(qL`V'
    'h&Jkp=6W}8?5f97t1~<n54GZGRtZmf!R<QM=y#%B^4jb{?&M}`vGY`oNUi%#e^=}7>w|1{-`cGsrBZU->5O-?L%sBvmE?MI5__0$'
    '=Aob#i41$8dR{&jlcC90&fOO(s<7AUPpe>OCLD&sKn5E4c&r>Mv(dB==JkB>n7zw+w?tMY?6k0bXlxex(=fa1&KJFjCe^B)Ni&~o'
    '7UTCBDYJMK+mTYMEk%pbMWUf4chOGuzPlVBig$!!KK43~QeiXSta-kh?Q6Mubk^zI@p6mT2<g#kxjxYfCnZ8ehr_$!q)~5{a_jJY'
    'D3g!gHP=L$Q}Ux$CAJLQ>pi~qAWvg=vOIn&cL&SL?3S0y%44>1D9`U^@mXQPdlTE+;X^-gH^{dJd2hDb>$H1B_^XBQ2CK;+f0upo'
    'MyG>pW;aPBa{Z)KeOx^CgR_>Xc2|X2Y_cmqmLpG-<~BaA6t^>}y^Cj>+9ntfqvGS?5G)_`Xro=MZAW^!B5&8>NOHkXa_!i>x_!`F'
    'jorE!2u%;2b@@rE9QL=Htk~$a<Xp6#+}zHk@Sxo4)grsBR>*~eo8czE3M{glNb;dq?%wf-MQkW_TKcA6&+Nke^<=%j8<xkxGSM(L'
    'QcqaPRYHLaS~)pr%@eCi_o+6h#ERv;Sjk3bQd1(DY_h0@dwjCJXwLhyrc%#j<a#g8Yw=@iyK8nLa!i?p^2N&SW<Q@~y)FGNF})?K'
    'T)xw;-2VTRytk6;(AKT@I0~RDco!&u_ueCew*=u0pI+#F{&TNXr9>gwSboki$Hykur~h92WAN-m8zqG2Q7X<X3JcYG{M_$!xBO?S'
    'qcGICsC{iHVo_PQ*FWh4;-7G?(egQfu7yRiwA-*;eECY!J~H3n-jm-q6CXU=1XfG*q|M5tzE^RnzT(n^jH&z(<lT4x!XiCq`S}|='
    '-(ci`+~(`{t0%5WVLT=tvrBC2kKdEAk5N2UIz5_>^R3oQN%3a0R%Xv$$KZ@z0yVtD0)jW$Xfv_a-e9s?+EOBZ<iPp$A?34mhy<Op'
    'muDjRt*2*edId@G!{$qzlDfJy-M}w1OLHOS{7>n>%NdpP_1Zj0T=s3U%w};EomutzNOHfP(d05)qaIF|fAvsfBxZ>~c^icj`yCv9'
    'AB=wcF}}&<Maf(GUFgQPJ+f_bd(;rIphf#f4q+bKz|U&|JGzXCNj!IU(UdXnaQ@k~DDn7rzWh~Sg8@SV7$RTW1ZEX7Tf<uPPZKmS'
    'RY_3gtl7pa>E!<`hx`sTv#Xz~LChutzM3Fg6pM!%vZj5Zi=SCtougpui+N)HFu#~=Hyst$KqYT}M&{D@yYkJ31+Qdu6fIq*hdR0R'
    '@GMYRtWQj`a7Cr4-Ptqwr}$YF$Uy9Yy?)U(bCO~Hy0v<1n|O#zhVjJ6gAulcL&o}?^{9>X*Y@}lNmshsRUbUk)`mG1gg%ZRq)e5B'
    'AG!zUrbX|+N2JD|2I}kVJ{GI+6IX1ee5!8AzXQDE;H|33IhNU_T~9Y5OcV9=rPYsQHU>wgNQ$2t9L4ci=e1uaGv}qA@Cw@D%XpNq'
    '`_+(o>!HBfcmYu{hzsg&tbCQ0o4wLzV#Ww5ldQJlUNPV~a&^$q7+y<kwiz`mslkKTx7KqYOH9W?bbWf%&FTSwqdXeL-dD1C491<x'
    '2STqVr~R{Rs_^$(%x?&FavS6nq>tTgFsJ(CDJs(agYKsYt(Z`i!F5A%HP#v8m%KLnk;>3S>4Mgh&#z->g(ulJKjS-zR{>AL7s6!M'
    '+qQ^zsXHsFvCSN)LoA_R$p-YM7%hy&mUT)REJvD&9f-HYIRE?rRkh)kYY4g({eY_|9h`kL2UCDaI;?A1Q~7PAW<-YvKdBNpE4gvu'
    'r}3D!15tU6KgHf(b~fl#uHwWvf>+~SkW%dCHF`U4(&+2foo!8im<sY=XF;*QVfhT%8JIRLPtGYO##7W#mllbf)rxq}TM;`0-%7gT'
    'DkI}HRr@mhT;o?W2b-)2WHOW&HJ?d(RPJ{kZZ<nE`aFPgV3D6l_o!_w-ZQ{q4R?X)s1jH)0tj#~>)58lhmJMk92rpeX{UbjiQ)@Y'
    'bNC>0pEAFcobdGB`w!Or8eW8;#77eB_QWt)gCUae6LK^nMWMD@JIPF*O90q+sm6&$>vIePJg@1!jx>vWRx<YRM1vHRVYk^ihMS7D'
    'F6l14Hp9xAUng}&NH<40q;Uj|iLf$-$miP_8Id<UdRd!y2*kAy7EeUqt9&YGs}7q%STUw&9Db!>o_BoRPUdR@Aai{DDD1$?Lby0@'
    't37YEEl#Bbu9YL4O=9Z{e(*ImD@&OF7C0hwd!XONZ6vX7djxpNN#H}gNL<?XfLHQ(zeB)LpMYmJQQHq9JOg^af%My8oaq5hr1PJT'
    '*~cWp8kOfRH&5^$$#=(h^ykHCW+TfEM6lRUN4uUE1tz{~=*Nk??x`6p1$jJgm-+g!%&MIu1rnc00iE-bYz{hS(g(rp0Vi6gX8(k$'
    '4V1$sjo3(4bIgsz8hn?24TM{$Ih-Ce#Bua?p%=M9%4?A0_~kks>mwq_o9Alj)JB>RVBJ9jhHBvKf}Q#Ev*B>oL0$ODE~9RpvMY#-'
    'o#uFxGV=M%cv%{1PB#H1CZX<DTX(V&CZr9YN82$-TeOM3383BS{3tI2)z?O)k7<m63P%i?^3e%zivzS{sCOUqt&evEoEJ2({bqVT'
    'OCQ%B0qJKqQKPIqHQapjTUo~Dh<KmdXpd2y3&^3e;13v9JUT6M^cDst@8(7$9Hf+6BFfIh&P&qHUbp8U*ZKBYg@Xxb2q8jdu>V4%'
    'GQZK-8gw`MKun|^ob{MAVxbi}xUe^fpwaE==d>6*X<k|Y`g!-zk6B_Y<CHYC2+lv$H<(h2YNb*D9S2K}If9$aa{QUd=NC^GOh3L2'
    '%t?+5u<WmG#^6|YW%@<iCTrc!oFVgJ<bx3~S#RnOmiXHn>IouR=SaoqGUuMqkf-gSn0r@SaWZ9`v7vW;%@28{=EY5zZXfDqd>*;m'
    '6I>_^p?#h6{0OY^89~f94nAhRy|bH`O0T$dge@|yb1@D!zbv|J@hmZ4SI|h7bBGlNCD4PTW9qyq@&J3eS^B_Aju7I=0BaW7Dw_#b'
    'H{wdvRCj12d>ja7tiwW}7r)<(-s=U}F~<w=_!GpsJTa%jRkIJ*J3fcy#^BCE*y6R6W9s{>3r$)oWDa7w@xZvYik|K3t*&jHi$3D{'
    '5gY@^)dup4D{qUmxp?JW-FWk|btRV8ts@{quchYQgV3(9_3$kT<81{&o*CAG^h@;GsJ=eY?rW51iT>iRS6v)AV$u0|gf{JMj2AEh'
    '|H<Cxt+1>=L~cNHV&Z-`dU8<k1XdvYY7aempvP8;TvgE!iDhKvK<%Qcj9NF*+`mE4asFb?C2Y)q#v{G43B;$lw)}1*EpuCIv#-50'
    '>784S_M?93-~4F>^Q|gy8S+g!ha)Z?M5^sFOz($hNDv2SEXnB9WI4f%+&>212HbV@hNBqpjojB@%ftz%kqbDfzq7k0L=4oHM3pnk'
    'gC}>+6vA3POL33hg_$CF@0a~%97#O}YrH<$jaDeep_VkhE9F%}mF7^ECSwyXaI<Ub_$H~9f6i4vH&R@Bk80Histci_X6FnuPQul1'
    '$;iJ<&wdo()=l<Ax|+6OS`C_i@iIfw5AQWQ@FLgqIUG^+(Gh8O<n>u{8EYjaYfXhX>mu-~2z?$>Wmdsv`hsmQ<p6N#w0X_>H4WOd'
    'wGK^u?N+UyG^~cm-NJillNFmo1)UPZZOX|gQyHr)-`O|&2?62AkFJU%-YS7y7``T$ud@KICq91(Tk-W^O-AaCi~prE5CxeEMP7fT'
    'y&P-`-j6BuuPj2#c94u(jzpAeEb{Zn#)SGQaP{C7CxvvfFRwn@<Us^nxu<8z;#lWABE(f;#?ROO1_t2uCaofgp54ADeEZ}roa6cx'
    'U*WTHhlv-0Y{QSs+=r>aMfl~)o99T<c3X8oy>J^I@T-iCb7XBcVvSUE{Ux)Sah4=ngfEMlN}42u1`qu}E)op6BZu_%PIhDqt;R_4'
    'hv&$rVTEO@p09fuQ;@dNd@pWcZq402@1J2n>xWUOE_jmeBm+apS3J0Bua8ulW{+`?{YUsT9UP+6t#}Z*<g?vi@Yy<kUB{ZvM1_)('
    't#Ddi&|Rl<&AgfmK<|2yy<8+*$Wp>R2CXtbRFM;+ti-*z)VaK*@`c6Q1ocPp7jj&p5}g3rRgJ*prF(NqER+<G3CJPMH1ZHl=L4*g'
    '9(Llhtvu)%HfxE`J~2naRTm3}xulss8AxPzMz@G>B%SEm4{m&_N$|GQS1MJ4L9?CTtO69)A*!$1VS5w}&4T;(BjylL<~(9wSfM(F'
    'O4~j}<PzZlJmNn-&d3cVvHOk8vmc0Elx<v$Dtd<K2%F(8$@7Y2!xTZTmrXHK?NWqCb?POK%j0tQ9EI=@ZX8d3#QlXd{&|u}gxTyd'
    'pCviM4fl#ZxCec(mS5|1Wa8(UbFSArm&!dj=`hu93RjS~F5``lrxJyix|T3(C{xRj=a)YD=!zLkbrQCEULj>%|0pnTi`K|>a(~17'
    'R!=Oy?hpa4nPmkTE3t(-HgGBrWce0}5*kGT_cnJ?L+#lpNC7E>I>LdFcuMSt(8A(bp%%9Be8X<_=5SPtL=PnxP2hXaoYTOISuIyY'
    '%6$LI;>S0Ng2##GqP6K3-U4Mo*9Y`158wGv+%q|R+3J?}%=q$95(75*Kod*hBD?Ib`5=qy$ECD@5HWdX*ZPe=sSqW=wb&Y3$YdYU'
    'c;*YV<$B)%?sAK4P~>A@LN30hB*j&uASe<3)Mjl)ofYb0_H8i#igxnYgEy3>6iC{HECIoqrVYna>Eh4eyIuY-Va`U|z7u$Im!p5p'
    'LFItWN~CQ7%vO&1VNOrkbb{|9YlWgWhNa{fdzG&|HQ-F)A!=gfJ}9HGT{;^LE!!auC}x{foZo1G`_K!%FI6fu&icxYF|lXQFX?HC'
    'L=HWrCfup+uBzoR#8c=s)^0O}l)?}<R5E#~CV=lglcwSl@fpY@aE<mHm&9^uMha)wh6evd*;APz?q#Je)9GblZr1HhF}@_rjZzXl'
    '6~bX6{X6cfijLk&Fuxb4?4XKYnfA=l(D|&{gAJ{H{FV<XMVRRq-o-jAD$Qd<c2DUKC2l+wtAQHaie5^ZRtn+pR+eZqi;sU8a=Bk7'
    'AEb}Z@77E<7FY1Hxo3y?>BS1Qqb?;y(4obGeZ1_a6i5PpU-=frNux-<EAjpBqj$@k%}{^Y1gX#%%$MVcV3I?a`31W|crbn6{CJRI'
    '`4ui_*Nu8M6-pde(ln7<Qp5{^;#<QwbW9>Sv_5c~XP@Pj?J;SFAsTX0uvrm(UL2M$)AB!s_-#W2Y=1M!Jjd5oahlyWCpCpcg?V8('
    'T<A&3H0_ICe5zx>wl}ZW?8#oU`HAC*DDhl`_k^JjQedB!+ZfDXIVB=KbE$j$Tv=btsKtG@`zmcu#9cL+6nuJ9AD|`<zgdITXjHQ0'
    '8?HrjR!>jNS-cBE#ctO%K)Tvcf6o=7IokFhc_cYlGm9&y1ft{IM8qx8OgKZVDHOd+>y|ISivm*+=r!*TI%dwq!0HnXrMOUmfV?+8'
    '9Z8UrdyU2%|42i)t8rXabQ^-^v_kg*w4wNe1L=&gdrx|LCcJnk=FQ1)vlM$Tc#aN?Z0D4L>{`7!Wg}E{k@bm~GoKWa{h<xgSBWMB'
    '8@pV}Vq)x}GZK&9Qh|UX=&ei*_JAc-2pLE-s-&~UP*JQ=%mSTYI*~yN|85z<D>A;siG-|AyZf7oaO3o*pqXXZ^GMU9l|si=^*AEK'
    'TH2!HuJ#=*5&!+Q+F;nA4wJZNj2O2v+x8I`V4Ra&?U`FFRJqhn#am72L*PaP@ZM$2KfSIYQmwqD$e!HawF&D#I;kwJUQ}zCxs4ud'
    'PvTh-L<!Yda3FJ&*Iog^z#XiMbJZIsO;Z=yCPtDtp6#c?PX<o3dj2Gb*~e#Sdc?+>LX1?=!4YG)T;(2}o97WoG)dIss+EHK?t&{v'
    'K;4lzd?GzE=wt8VEZPu%=_L9xTHA;(?)6eL<WZ<KgjyAE8A4mgIKrv$OmU<EikNbA_FUpi$5*|Vpc}ADz3B`O2zsXsq^cF4L?BWN'
    '_ERahyaRC*43jA5UYAZ}xlaudm5<?G8DDkO#{u%HIo2cb7`b5u>bE%aHLg@_8Uwq<*3C$<vkC{<#3$w}90v$-LV#Q;*mq(JbL7X*'
    'Noz{hOW_p|0#ef7zR%;zIgWrvAOM-Kvag2<o7`O~VMeSZ3D~FF>B-+hY|R3TPF4SvTDH%1gj%&=<vz+e##5M57nT~Q(oEfN4Y4C-'
    'HvUzrlIZVEd>+$>ptTb=j6q#l<)g=g8?a~!8Y|{!6=;UBoFBcWBzul9X^t}w4=iabxLA1hIp$yulc8q-(Dc06lF|7XvC|o0V?kHW'
    '5q%QN<mBI~Zo~YX2yo7bMtSo??XWGs56+$SGj48!7ZuWqLrQdm-;%y%_HUwNbZv$4@NOqC?{N;=b%bVt!y%_B>-cp1p5A|Sd2tup'
    ')&2VSLJphu)%;=2XZH1GoLHK8W4e)QMa8T>A$--%7fI=x4Ro40P<~<VXLNFDUbH89t}Ic;Hefl$duY0UUy<sM{?~Kb>}Ln8y$&oA'
    'yLDI`h!)%n^L}5D=+2C&I*@~$m2Ef@Oj7vs>nqUv@CsS5()QVeYY@jgc}u1E5W_-UHrsuMCv-EGrtk7<KTF?>P?mFfcoh|ezQd~>'
    'sJ~WCbD5v8WGLW6+9%kshVV-_t8QB%@k^v>|2=<v9+^$j?rqE!3g0I+Y}S6Upeb`>w%XvBHmx=u4nQ^xGYJ~s|K*0CXhbzs0WJN&'
    'LOB)0qGhdGPS$r*Qle1`4<;(_SiV`Wbg8KN1(KCUCvAObYRuFwa95otU5!Y|-RO<r^u;;vLv_TPuosNMYUM)ARv91u=Hp6j3nWf4'
    '0}B=PQoO18TMG6@ch9!1E#`ntIQ~wGntQcPpyrDMia-Gyt8L&lpZKxR(+p@-+jvWYGBW8KM%ua5;pAoYSVUJRI&gj30F9(hv#=A-'
    'y=KJ_8X=F_|J<y7a{;Z9Cjasp?qb%LjF?ScegIG6+??nFmU86%rJJ|l^AIU!r5baH=ZEH!*T0-T33+JRFq0(sUM1w+D~%R>>=VvA'
    'C#J8Sk+3Jc-Zj`re~#xq_Db_-Cl@(<`UbbdPS8aS24ae~?(id}QhV#NJg^5U_Scbmzb5#)8$wuTy7;}WJms^+FB4Szk~z_uqH+|y'
    '5K32HOdmf}RFLrooA=mR)jkldMfVmCeA<Rd0UZPTVTv*_hTg&AiFbvJJ0K(I$ZfRwQwTBa&HRa2p5lV>1Af9yMI^FB#UpXCDD0k1'
    'R6mS0kkQJnZu*niY$=9cgW1JYsPQ!d3G+-XhYStnJm->?TyOmLQtT5ElbSgqTR%93)eh=okc62n(6WM{CpZ%CS4tzPP*^#<M5BjB'
    '!Liw)(pH#0bOi;781Z&`s}HhmqW$d<bO}5OZe@DPZS^}}v0fh^xDMVkiUQ{oCSilrzAufe<~<wh3hH<W(Kwo6I{bZn>kJVCX-gMU'
    'L)=>2wDC~5{)v_!gy|nH+@%-d=K$+#5U?}mn8Sz7c@@gn7u%|pIHqKIj)nZGlT-+HBHY74{#&CHUnS=pNzp93N%zPkcBx^j$0&&0'
    'p1j!)Yr1ibtlTVub|<d1k2|Rq-KyT3F_3vA!-H_=6J1L*GVH%CHiMO^I^dD`&YF4m#F4+j)f0NzW|)Y=euskv)II0&$Hz>(Lhb{k'
    'zdh-&)2ySvJuzWiVCN6tWPtj?Y=QKCynzM}w#q~5NkrnfH}B+!ADt^vcB^1MHQz~$uj`sAQ+qb(Z@*ls`B&R(taYQvttI5=ES9uw'
    '9QT4-4Kmp1xKHSaUZ2JQ*3p3mWxd+idlp}=-ZOc}6I>v^!#5-Vq9HY7{QYQvtgO;S%GK{jO1~AACS|)A_|1Dcx;mz=aLMVTWI?v|'
    'okLUc_Eh{B-z{4b@K;nD6y%cDq4bZtV-wSJTiTS2*tkAc0GdWcl$YplqY}PKm<Mq`T1YvHY@`JiL!hMSUs$G~rJEOB=>&AE+Ax-g'
    '9(!0jxM$_FGIT59%_E^>C|!6X*uq8)J;<oLR-I*54=b~83!R2K^Xbn-dP5-u^uW6qi^xcZIy;?YMmvk1fJhPdR14%5Rk8J(vSMr`'
    '8R~B!p^gX)m5s*pS5Fk<17AEs`SCfbEw9jX&WdCJMy~%EtNt=v7en%)(=FTLRyBJ(_R389_bxLH?PjgM);;DxInWYH0N0T?t$yVI'
    'DK&#gr(L#gd=7ele$TmZPO1aTtyN6&yqxLXk#Lnaju}2?pS0)2>4cYkVk^Ep&#V+yt*%?B>CgUJnAPAY_B4LZ#=RQA#F!5X%000;'
    'GR*f!w$c@ShBUg&6Uxy*rsQd>SJv))koZt3H|DM0$&4KIQHIijNyAo{=S*-vMR5x6d1m^(`yox2;sMQg5$&2L>CDr9Eb50gqvDQ@'
    'VyaiS?N$%)hUr-Z@$Dk9l#hnZE}LX>lhXZWz_@Ni`Xx-|XDJwp`K79HNe5}BOCb<f=5g){dmITh>KbYnGXW!hc^h*Bd-!l4E1~!+'
    'I}}4V&L5Dtb3k^82a%Ts3M6Q=YwPr_#uoRTe8Q<NBUQQajq>gMN7qxLkMPe>I6xRRJF+m0hnIMxB>R~EzW0*&ugxzZWqpDEl5PGc'
    'Gv0ebVvT`f4;InKoqYBJJZJ!A!s$w@9Lj|SPN9t15TfXx2C^IEQ&dig1n*6+A?&QAd3!7_&OT`J!amNA_~wza8yok#K*}oCyp7bC'
    '<1zE6poR{SAl4=VTFVeF$c(-TnFxnr!Pbt3DN8{|&bA#1rod;coVo&F%>vL53rFuJ#h^lCgD;#wAAjsr?;g*lVr_sq#I~bP7Y3b<'
    '+v1lI>v_UA7fqP#DJDG#8u+wcsQ8%5Gcl5~Z)bzdBk1$fM4HL|wCB0hoay!{wz4n4S&R<ORpIFkMoh5eZ02im0iJ%UFJ1O37MY_Q'
    '#|%4*T$z@hfJc4acafaj#L)hB5vI>yQ{s}_XryZ1+r9L32Y@kY*~C6$vrCB4+%oY+0s;?r5+RkIW7>q>iw3M+TERcWH-e&SUEqY`'
    '!YA480R1kMc*!>nmOz~maP%z)iGGBB$MTR*&YANy?baQDL4PHU(Z0bJjU0=;)U#~`m~g_bS6Hz>t0uPkrRY-OZ~P&UuFbaok|tN4'
    '{nd`QL0v~4+^V8kyTD?--Ma~8|K^D=KLpg)>z6z_LJ_lzox`45gI!t(q@p;NKFQnXsjdB<;v@t=^9vAC3!sj3D3|gXsR%7@z!l({'
    '7Ia~>;Uja%-%!fP1X_Qe$1sRDM;z9zSQdoVzO#s5^?=BT5!`=&>A>sS4)zGbt>FlKsb;(2o%VkNUgQpNamZIL_ev7=Rcjafd)s|;'
    '657Q30(4MxpF$bk$#{YhK1*zE``gStQagdzBTD@MQgO({?ot~7e5<XD*4YG(^-?XvM#tIU(JPE#G>E=%o7xs^-D{>2!^#4kd8HM{'
    '-Dzq>gYD_<%CH#2*D-~^?mtbXC!Xs%P|lrtIh9^y#kX#mH~LhZj}vk~U+;tWh!Vr#KBPp%@0JBzBFMeR^=)Ca1Xy1^taf-Env5}B'
    '6sP?g5z`*6J|%{OGs8FXk&%4;%tRv!gqgItw62toVE#NOi6F>F!9bVw9($hta?|?`(%_wNc^*J9XN=uB<=!todh@fLFtVrAP3-a='
    'xDhpPgY@ZH8HvZ=ZC}bCl&ID)4HVB_DyY<_9ToE-_F~p|T%A{6mV7}Jy`H<Fk_(GTW8%(b`u5jnAM|J@X>0mr6*HhHXbC41s=`ir'
    'Cd!^e1Ew$pqG0*TOomGSxe4t`Dnup0Uk$ctCC|DcIfEugo}JQvi;g8WLlkn>kI~k?;8Z(g!m0fv?zs>vkgz+IvOMQp$%3+x-@^%T'
    'N|uTaZDJ}1*yVoXO<azh2>~U{?rvLI#vl2^ZS?DV%XMtJFzH3JMZP|q$b78h8<$+H<aayV7A~%cvhgGDai)y(!PnU1uw={*WpXD`'
    'DL|MwH}#vZ{>A~1GCnr+srRtEX=RQZ2bAlN*jogOS-Wag&U%l>Gk`T74$KGJ(5JRG_IMb+)uIKbwQ&rS6Qba?f@A6(Y^AX+AB1)x'
    '8Il@^Dxd^gGWqj$uZaw`GFZ^aFWx%C>tUoiWNU{OvT>lUvE#Y>F*Pp6+5)vFzUSuioyg&k=N;2)hF$UVz;(KLYoRhGLO4=7@G`DG'
    'X@)qb<&UXYKKNvv5gN_o<X{sGn;lpvWtP`lS%7@D5`2#hRzx;AKqwiDS36JTwRJ)I+8$54?t01eLs@H%j^A)%K*;u-yaHY8gc3i{'
    'KA#9jc*w2Eye0zutCBeKw8s6lNM;)v`<sAdy<kvG3vkrcK*;`hTTNZeZk{fTx0eZT7I7gO>MvSZOV_<6Y~1N%VL&22$YQ>1S=gTb'
    'voz{k@aKc*b7F=gZq*dA%Nf0zxp0dHdW%{de!#}TCRrQaIM>q_9^TSusV2--pc5Vln=;3~UvfI0c0;RmXB4!{5uT|kPs77=dvSb|'
    '5V=mIJNO1<`kjT?;MWxg-u4LLf2i_iJcOk=zw1`MYUanQsq5FomJ{UP_PKT2d4)i<L6h*rpM@6YQ}o{li!$Q)%Cstc+RZmL=(|!Z'
    '=T4jI1(z2Xhf^obsR))~OcMjoY~E;A5Ec0E>)7eBaAXty{eC#d-X)>K7~rfnY(M}+S>Wd!!pg+?k~$(Sh}s%k1e&Ho;L;kqR)<%n'
    'a+2v-=BQ{*dlQ6>N8A9DzqIY3vqn$T-*11AZ1y+HOe#TN8y90>`0Zj&y!>k|8%JME%@}i`SJ}nCn|{en>a8BK9#gA=xT!#6Bt74-'
    'RK--5#QqV*`Km~N@Yxw>mez;iI*r}oTMXuP521<l`q-5i+`xrXs?>+q+AVJIWAnjSZ<NLPK;Eaa!{`gPhPoR6{`I>_=<EKOk`ki<'
    'iJVCjH$(d*67-!vyZ;yd^SZ4SJ7*fw#&EJy+euWv*J;dz1{=~`(NbO<?*KC-`HgU}C7#ad9;TbXeFF7SNR~_V1@+eaC7v!jc5X9('
    '(0@$7%wgWDM0C@cn&M~;%D-_VpI%Vd$PgDIP^aw~=TRO`Im;Z=0f?4YwqqE{T>r36YufoWQEa;Qa{9v7FrQ|c2r&I4@)Q<U;K0Yk'
    '&M2D#%HrSm4K&wu+ldf3c$Qz!cs9UyL7S*ZaK6K#aESC8gGOTf#z#y~;`33X^-)cOJ5zLNmZpiX%JYv6V+M{KmTwzbE&2_#{Gu7)'
    'L*w3)<*5kx;MSAb&t>m7S?;#mK3kuM1Kco{>wfjnRH#)Io5n~1e_*XDb0acD!*Z5V_H5dMogdW)U=_lwLS+FNwviMu54GsP(Pxy>'
    'C;i3o`<JzSu9RaMNWQ8#v{S2Cjylc$65?LE&!Nny2aJV8l$Lp1ZJhe3e7+a<Iu<=%=jpe5vE|ooC$%*cPYmdqd!Z;@jD&M+qZmYi'
    'Y|7`OKg4rLI5Q(-wanoNhogcLEUMh<JO*?z;f?emOB^I9pOiA!+H5rlb4F^!!?`E$*F?cW@otG)>TdA4OL-so<Z$_(+3>0LOi(|>'
    '>CjK91JBu0StOdYn1i)CrZwx6vF@c%=mff$4SAUR8=`-;d}D=tQQ?7fi|@`qRTE($^cIND|IlHt#yWy7ObnZypBBh^p-`#13yQvK'
    'o%!5>5}7r`fmv=``q6s5FXVHeWsaeaa@K<d^0g;x68?>~j=8CmnJ}4b?1P7|!$oz&Z1RHp5QDgTACF*%M_5}543Q_MOje{R&R=qU'
    '(dS0;3(kV=N|>=x%m`;!y7ojtLfURV+A)gpFV$95Ba8<L&<_oX&VB8x;avqj>+Yh?>ay{qS52+CXKCbNqoaWR7ACOj7l~<F=dD3a'
    '=F_$N!mT*W$D^a#6YOcEgdd`R(xM{`#Krg+&S1(-;ysMfv-Dia5`G>`Khgtc>z=y?CC=;}Ez8-ZL?yoJ|N4KpoAYqaB*+g~`h&%~'
    '$}MzZ&Eb$z;@7`dIB6su!Vma_-*ELhkqj}I(<_315ri^4l&4u%Ly2)A{5OrgakpRr&4^J)zay&a<{hj-gw=plSC@{O7V>uWd-TcK'
    'KacOfi;DqtD(kOA1aJH9JAiH+c$|tZoSLRbW-Q@Cby9W5fECa2pYDX@FUI7Q^oUNt%r!p(B)}yCax6!PMQgma=n`ed^1RXm&%%ub'
    ';*pvr><bp4W#EaPk+7x*1u6OBNCtzt0~-2kl&wNpC2CtnC9Zl)ACn`p%-i~@KXR>zNc$OgENRKy53ZfpaIK<$-*Ze=Jc~ZnTlgdA'
    'C-?G`8q%;8Nb7kRIDSB#wcnJMHmYtE%A|&b@)n3+<IVxr`hM%gQg(FG)?!<2b0zH3>$G&V;i{F0hSwxSqIFyC-$(lk=8=7XGUCRH'
    'k5Y2vt{|V4_;vp5Migm*ylTW>8RhO`lQrn$fb8e<126^PgHl1J4f}n(>wB8*(Be_~sCzM8-q7q3{`!WK{b11$ts~+IM}58s;zgln'
    'IP05_p<`p;Z&Hw_ukY3yZPKY)jEqUU7Qs-K`k<_1!`*ztE$)cvt(BZiDMG7{jkx{N%i6U??IGuyM8~7P+6Yx_fb&^cl;yRlIMaPn'
    'fakB_yM`TyJ2xo|kRZYHnO<A0=-Qn}F8>8(cG$xHILdXl7ws-7^m#oRuGiyOY?3}Wl1n^ZzVP2?$>fR4;?m(Mg|n{$;QHS%Qek<G'
    'J+Ar67c1>W-4_+&*=mH_(4A#J8NH1h%7wB2J}*}E1$ro^Zev_<@5=K4IP;0?0Ty3h<(jjuuS#)XV_-iI@c-SN;PhBcG48SQ{Nk0?'
    'QTSTa5aK}ilTyS_3|Ug~cb|+JHsa%B$M*zKU#nP9NW%N`C4Nv2nPo96U<T6>QH;-}ZA0r>dV^p#>K=V%#m61NF%0WS%Ar^N3D;jM'
    '{^t&gB%lTzDdVBNjt@=t<VT;j(5x1O#l*9@hb3>sIncwsdgK?tNR}O>URRdV#J)gOf<mm#Up41<l=k$>Dsaw^sX}}%ISMR+;EoTN'
    'dW0&5HHv+Wdz*4J>l~97G<3xz=*Qzc`UV4A9BIRo4I1>*Q^HEW%RDI$@tOtklKZ*{FHeC<>tJBT3Hmyo=%db#xq>1X-PjRVVzt_R'
    '5OONm59ub6qn?DVhfRD2!}>J<b+5Iy*ybN3HF5pTAiBXT4vajL6<%<^xOFW%@x|Q-q<Fq}GMB=)n$dGoh;^>0<%Zu>OM`(IGgSYr'
    'L{bt@F#JI}a~at*Ok{Dc6288)Bh2fQCW+v$T{3?(-khleTVwTm(NXlcBjdxYMlG{|B$_xOmDgJL_hi<BJz;ewF10c^Jn{K^>+7_x'
    '+SRXP2TG?_(4tp!YNR*<;&-H0pS3B4>LGJ70kAqYoUK_u)#3+B_+dP>`pta)ElcXrF0TG#e{b~-)}P`uq6T!Rv0VN_g*8i(GGq6h'
    'b@>nTfL6hp9{0*A8WC?lVG@S0^ef{Gx#`)Af4sz}Z^~$6dq~|d|71a0``SFOlZx>E+WqF1hiFpt%d(le5Lc{n5Y_LSBZRobRG!UU'
    'JX>FYjm<7@Uiu6YR-F-=H5+u1WveEhYn%J~F%}OlPe*HR=I=OwOmCR9xoTSO0FBu1HE<oCN)1RVOVyZ*Sx3I9c+lAW;F0I(iPfeP'
    '*w=>x(0}(f3B*XTx%$8Eaw6NtO8(z>IsNB;r~l_&POVjeHwe&TxyQT>ddA<~R*V;fmaE}hqA35@|M7o{fv*4mz7=c#dntPVb1PPU'
    '1HH#E?C1D@-HO!>;oq%Ta2%q(%^S>XQ&nYb9>!CJO%hzsNdzZQu=$3=5X|TXCas0YC{2)9mQ|fM6N3+@2qV)pzM3UWnn>>$-ARFe'
    'zjmDta$XnmI2PcWEx-g+^ZdS3?Kpwn2T0TR@AnL_)F6T&D2kFe4jGD(;52Q^vK+?=tp2{|H1BK1gZ}%Bu>bu{dfTXq!)*Vb&vpaz'
    '@7edYn*DqBZR>eW>;9+hqi(I3h~EZ9nEkR=hAr6pvVWm>|NHy9c+ES4UHvdVrlAaiapvbF_pD+z%&3{4_g((=KeS8-iKFzAr}fT&'
    'P5aSaD6yuE2Fb^S882;OxPsZ;u>CiG&uQ3<zodgHFHL5SP54ejK;dtv!OEg=U1m??Kw!blmj*Hi9uCg;-x`^5g(T8q7)<IL3t^>-'
    '{M{8!OIm9b2_zX-F6?U=>6dS@DE4Y6-igD%Jrj1Th0R8;`1{o&3j!q6KAp#l@Fwrq0`s}3wWq=p6S|{g3@R=DVmBnw|JNFEvQ>-+'
    'tpd8)&tvlr-H(+Ovi)G1m5Tq}*h^%Z#Q=C5{?GX_<2M-VsK{jOw`miZn~sW_ENFQMRZ*ougPZ=5PnjxMd}*<NZ9IX~zY}v&{A(kR'
    'oBrTs6CQ~cfEzMX(icGS^OIxh2KAt@j_7~lK;fdpXQTmx&I?T}yP;?akSYz!AR=V3Ug5-j;4wiq&dP`%9p?YFV|7RQ+sH2|tp=$d'
    '1rS-9ocWz+u0jYsIZSq>6GI)v;D0y9WVpBg@3Rn6HowG!Q4+2;{K6)syEIL`@E`-)u1Ym|@&FI#btN^MV_X>S_rEwDzCtwR3V>(T'
    'Z3<uAI-n@vo~J<WI1cOTN8=_S@=b0r8RpT!`7gfT&4j|FWRilHQHDdlr*6Ci=uXz_E{O>rF>`1vN5Axm=_y$sHUEF|<+X6VsBN4)'
    '$$fRn5Q22h2H@hy#6ahCY~w6UnIyX9^S{n*#!L+2n=~#{IPwJ9<GZ%j?Rizew~83r2`R`I`Il=d$H?6sUA-d84Y_%;mgKA8{|Xx#'
    '@m-pKt`dtSRm?g5ch)^7u3_N*%dtV>j~q=zv_YsR8NY^Fhy)MT_}+5Ikqe~~45CSdAL*36qNAPbZ+>rb%P22%Rfb;SM*Ofm0Y*h?'
    'b(^dNTTarHZ$ZI1cv@Q9-1WSFxzAO7mGX82hCMg@BK}8J1;Fl}5JzGOP+t~_ab{uwN=BQkjokn0MTHr3<4`<{vx&zRH+qK5twoaS'
    'T`9l$&>XhUIGdsU-`wV~s=zojY4eFJ?+IOBl{F-5o&`8eRSa=>l*vJkZ&51*h5ykgg^0;S=o`mk!t^(x6NtAOJw3?vJ|pwPHW;~A'
    'GXjn#=PZe-@K5Jdjr-va-)ItNI~udAr?}ILhFif$c^I;Wv?Hmg;#oUfYP^GqA0Fkq|ItmY)?$m}Bf&F&fAieGl(LCM#)@Up)3H$<'
    'Q2&hdJKJoWe`DQ7@qhOOBRN%|2${(a@`pa3OIL&f0yJV>Nu;6zT^2c@t(nyOcK_86AE&hO_ziWz9+$3Kl>!lv|7^<f)!p_}<1XK<'
    '6lZU`-<IzG-hUM-L!I$U1Y=AzDu6L}9=6WFk3=|t?$<2-iX_Wop%L`|)eowA4B1%=8Eyc<z~CRd>>0c84MgSSVXF336-^cxC$x$R'
    '_MiFjKke5P*6m<&&Nk|6&UXA`xOI4_I3;)xiVjJ!P|~=gS7h<%hXttr&XL7b(}>RB2NPgs7YlbDxI1oKKFUn`TS{kq%CDTOk(Tps'
    'Ar1ahqg?1jm4@QvEwGqP#U84|lI<rck5D1A(c>EyUt6{n_Gb3pe{+qT#^~<U`D9_N^f*lvV7^o=Tm3;jU|o-HoNW#})PKj&NhQUX'
    '{1&^aQ;H#2q$X3k^o4faXeo{4v26nVvtiuG{<j`SEK3Gs&<5N(_!DPz%NpV*bITbUAO1v7fhu_NvMV+d|E{Tf$6-Qf2sgbj8Eo=$'
    'd3SJ;6~4I9anE<yUN=tZMA6;EO$>|N{YS5@fkqgG6!@kBP#KLT=H@&7{tkL$R&`}n7~>mmVXIN${wLO%U*h1O%*P7E6zOm?JGvqI'
    '_guS5?&H465D8XTvC${XmudF?pBQqak{vgOq(m>*z{PI&-*<B-uJqYUZlLB=N@&vtf_!5bIInz&c_%*TzxoJppUX3X@jr3JqR)LW'
    'JZ==+=BYg=LI%&6->TSWFO~p|Bwg;chdUDH&xBR6=vye}SSF?tUKzyyqs6rDA3|`PU??^jSf|4F^K8Z0e$muy0BUlK|APxgzeH@X'
    '*Qa-UM5(y@?r@_`81Yh1_J^_Guy_CCd2DxD6MW$KD~^ivtsIv+a?ov?N};AH#`#m-kzS4>PR<BvPyX!n*q}r=GDP&N5+hKG)=W!U'
    'Ftcw$fTY^=pEk3++mP*0v-WFg*3%vr)@Y(Z-Q(rbn29bF8okbG=4$dB-dVVpLJpWaLyt1)V;Ik!$yPolOqRaj2o?^1^W~+4Sr_5W'
    'O-j?b5P+VP*{u-?;GWl;#QRY+TK7VPC~9_LLO4}*pU(tDC{sQo=8*T!s|6M_VZuv>|H<9vks1*T0mi*JE6EssX~q{^>IX?aRIXkE'
    'z*yu#(e1A>j31ot$A_dH%Nd`A+|d|AVn%<hi^r+-KTn`(_PZPlF>_EU_=j9=ksQ(c0~r3@qDaM8W`fDM7XK!Kl=%tV_yV)-8*Yf@'
    'TYqE0k3VfP(TJu-3C2&O;BwyEuMX{Bso--;_Hv5~I&E}+Z|=4f*m0j!;TKEX(&J<&OaXbKui(kl)5N*}6$QX!J@W5y;PrCGHl@6%'
    '+P#`$TP&ALb^G6X1%(?2j8RepcdOdOod5*wvx*%)$}-JOR$MAPp8LkcjFrwG%GgR0xolmU24_=r@?}w@>X&Xg4g#G}P>SMrEOJE?'
    'eTFISr*(hchwBbTCE}+l=qFO=L)d%DG?R5`sq%tD@9EsJLwJOfnF%yrhXYX`2G%**5(+l+3$=#)v%?I#x$5p}wSqZOsf(I_wOtfU'
    '=4a$!OkdK;d+9?GNt>izRVlf^R|)bH(B8ZqQm)+%h7*95uGijAC%VXpu+TJMHDx`CFjwVO@lvGw=NXJvb~H+;8Ba&=M>0YyI!-4k'
    'DD@kjeA=cR3{+QDt0X<8eKk>DnULb@kg9eg5ZY&)K~jk|oS0UC!9P86jqhtIpp7@-yh#gL_<1bF$~UD;`31csaH$}p<91Cs9NIKw'
    'DK{4e8M!%BxuBvw8pRx25&q?<hLJ_$8+eMy_>jKw?njRu;8&dGqFPK>(92hDj<?zY@xcM)R4)vF-r~cRQv{lr@(cz|oqPsM=BX}v'
    'Cq8YQG==GFd7=-0-q93%W}0=3J(H_oJg;iD)Hw_XZc??b$zjRFr$8B_>>_~RE(K&}?1fMmvp*hdbrt%9#J^&3%Z(}BD0T^9|L0{*'
    'DQ$EtF6i?@NXpYe`5uCArb-_~qWBRpWX8BMEawxh-;@n{Hu<}NEHsOyE0-M78wSeY+xk)d?P+f-5D1cjW3sAk)S?S5-z3Z<sbD!>'
    'Jez)O4BR)QQ~4ct_j9Gos#ySQJ5S!fBpd|Zy5{YO=p@LOnx?tTd-g(?tW8X$#Ve7z_U=>>z9wptzLN+zlW~G0iSQZmQ9Cp-Uu@f$'
    '4bspqd5x9<<Qm0^jqJhNUk&IKe~uQeR%?ltL;Eg+z_iFmjIiFgECsDEKN0NCxMee+7=3HANVaiVXhx6&jcU~v&64E!v~dyp$7MzC'
    'd#-1N7mG5n8P=vPsn=&VOpK`d_)-8CecK#}<LGPLd^btEBIyHZa&c3Yb~Fcs<nFc6%AXGQEX|<~qtLxn{oT#e&s*m>MRJshiG_$b'
    'b(TA$e}Q3MHX!GHJ=Pybz;Xc6q@+^i=>dvK*j^drWC5C-j0L|TqDV)Sb|8^-S}|xDh8SQE4k-A5w3GvQ$3AT8PsJP!_m^@u@BilM'
    'JQgL@m2LY$H1Mv8_crl8yoXFYeEnn9KKHe26$mL}#vCD1kcPq`HtJD#@YCW}@c*7O@yLS*Z3m}V(*D5(JgxgY;2tZ*`<N5Hmqs}k'
    ')s=tQNU7q$i7}ZCkyy7)-7N#jY4_Jt%eI3MG_8||Zw~SL_ss4%;$B(p7^E39(aXI4$+*B=O^j1l4LnyftGJcVPUZ9HSh(y4<s%!4'
    'Q7@O<nO2O-{LbCa>1O5Chk4il3^P`{{?i70I1aij8GBSCK<&ck>@<#iWuq%0qh#eTh@g%*GY6AdEQ5&;%-_Oa9v6%Qo!UFqDU{Zi'
    'A0d5#yyXR#zZr%LMa(j`E8)(Sf}VSt8H;0<uWy%(E_G_r&hKBWv5rVHB{SjT3W70-4t^&ZAZh_3#p^8dq`%2>+UK*=BKCdF^lLfh'
    '4lD-ytbInYPC2pvaic1=HIwMS@}lRkg3@3J&~O_mbF7RC9DSN&e<<0RFILuy#p1~>6gr51T988(U_V{`^RF&)3eQwf^D1DEP(1Cd'
    'i25>$T2v5@3FoQ+R*?28{UE=WISO*s*}dw-pnx<&ehbC#M^;B8U>@x6f8$Cxt3FHpujTq_Qaz$lEUkL+)X}7-y4THlVNsW^qN^n2'
    '^+J{=L9%|UbmsvwXNmJ5zVW|4j+ijj<vmP57<(i`zaKs4*GIDG>j8^%<7Y3HtJ<fSc(NySC1Fg*y>1lefe)2uCEyVLr{{XiN$p8u'
    'aolt6Ks29dw=3@*^IL1=@gC<ft_|dG1MOhS7~0a%mG_zlcm5zT7X9(Re;QuB8jc0+xLwOA!{43>1f86WS>S2#GSxLAj!`MTy;nXA'
    '=Ism|+lU*>WbJ_b&Nw<6mFREy<3dkyA%+K;NRO9Pz=ov(IpHLU<dUx!B;g`<S)s8;A=$8wQiPr&DxQfGk@~vDYobDnjqwls!cD{S'
    'IJb9&QI)U$2GX*8$*~EjqP9<lx_)}^zL0AG{Bi=R3<9-;mJRaIST01hfUqj;7XRkR-hH3!##c+Lm3f(W7ZnAtr?mEtAklgi#;6Fp'
    '2Mr~*OE;CavY09si@Nv=$1zzNIIPh$ff4oQ%<bx<I{drtx9?MNY#B0>dY&hwd`L2wCT_Ro^CLMVj^e+erFgEpI$>r26f@OP&c5Ev'
    'po(#lCb=nV7R3U;k^XpdZkcy2pX3(AegrfUuU(GKET+B?3+Vjt1P3+9CS^>*GqB`?p_6+8C#MZY;S6@pO%9wrSTTt6S7YALU?iF?'
    'U-PWNOX~di)#sQ}5N~;U9XP19c9OsgJjOdEoFCUwQJDK>Kk2^I=#kV|D+kfx5%t$Bf-&_u7m|}*@y~bTl^pmv2Y(9L{><LLIaUP0'
    'G`R1n34QRR_f&TrY$N3|Z|I}0F$S#P^eY1LX|JvQoo18VSrnlFwd|E28B558KcZ;*)!ZLvulB}l!3`xTk`VU1r#iA1Z3d#cV~Xus'
    'pt$a7?Qx$!YjQC%^P*7h?K)1y<QFYv0l*e=x$ZCWZ(hGOSJp?pAmqLD&WC|91?GiCOPb}XC&t5Mk|i%II)|0jpY$kVDR^<N8^-8+'
    'e>0uFex9>O-{NPLIB4;!$*BZWu{*|Plb}z<?wGDyf9|`a#hpPu&i=^_7npJMo6Q9xUgEzVZ{tP|V^iW(lWpo_q7->~xyG5Rn~Ywx'
    '@6aqcVAySry(rk4uo94qc=Ywo=MV*zwUbzj!$cA{)NNWk)19|tEvhf%E*~<PUL_0xrVPykK28N?rlb+ei%od2j!1)VCXLG#S@g!0'
    ';9kQ53ZKgI=*UsAe`CuW4X{JEnb=lO!)M9X^ozglQlvqf!F>#xo}#8RUlW^T3-0H0R||tOeJCw>+dQ0}H^Pk_1F@VD8fqzAQXr2='
    'BsXF5Q>UxE$^al7HAL~5@#GoGLJjAuS*lx<tMj_$H4E~uhFFT8Dm<9`YAuvT$NT3<Ojpk|Ad5Z1njE$*u_xLUgQZ!NOez|ltgmt1'
    '5OV!~coBh=AEDPGR1O#q`K=|g`>~&Z2}O)rVomX>--RAG@B|(uFJL?$slhzNO#s-#&rnGf{?!g1s%N3h8FAsc(!3S5rS><H1+ke9'
    'A-dI_!F1Lu6utTC%&|7vNR!G3Pm~V_!K;6S%<fOi9P*#^lEddijb6w-$BMlsE4S2|Via+ix*G5FZlHyrK)|h7Tq;`u@ifVls{iFy'
    '*%u50o(sjHhSVhKw7|;mYsMpSFmBFVp_uVb$W$25*Im%`yaCJtZf_xbkWxTdYF07S9-e}1nigYYa%^^Egpm~2uj8Gu^KbFvRe(u0'
    '83v?N1nBiX(N}jEilq@XOeHG#kzW<P0HfS$bq=k|K|J~ycV>I*%C()(VYT0Q%LK)XT#zzQSpSkj_K<RX;HNq6V08_Su?$|)kg!JX'
    '^do(E_129dH^T(@SA*mxa$+`pNU~M!%xR<fWo(`(z^U>^W~Y#Inn*`;NhPosnFYZQ(VrJ&kY`?2Q@rKxnu6Wy;{qIE9zqB5jmK&{'
    'V5W>wzU#l9<y_}t!36ILnB0MJc<SCdkjaRJZ}sszj#E<Zl8~n;_)73A)z?_4yoRFuDa$c2<??ki#@2ay;Gt)fAXObw0rX#Ao)96H'
    'kC=1i(9=1y7cZ;uw90d-(pS^{PNR}Mtkz!T{`&Gd*b?DukV=HvFur1t_zT4KU;NX0%E*n2usmVQ&H`b@NX^{-EqSdGUP~$nBQ$^('
    'LlP=q`2W9uE4)k$viq~R>TV}D+Dsf+QVmsx2jo$bFP*ot{nwM9=5rAOij8W<u1HPFwn>v(&3(*I^tG<yTEXA=p9hW|p|HPyr;@3q'
    'R*{u6-5G!dpeFND&_M%Yu?wO%l;Zrax68axp;F9KYxhO|{gC9gw5KK9@zrq0mchCoR(_K1IsLyL>l;=M_SzGm#~_##6p2vLG~};4'
    'F0U7EK<4jqL*@S8p2<Gh;d$w7$%B)cck*6<XLG{zQDGW__;FDD*PmwAr*L#n4*q01YWA72IMAPmpP5TJ=bk*s0%8pP8@I#0LjA_}'
    '=dl1QN%Q$88(U<t4Z}3CtBBNMck!Qhudm&xIoq2m_J^O?)Vp}IE|ho059eJS{kkJo(92Kx&r>tL9};G=^3};9jQ+GKL{jPX{)=UH'
    'bj&6*4Dgucb_4d`m@}2pDR`>GJuexOhx(psvDt%CD>kbyf?3c{{Od)&Ow}_!5eHLUP)xR#b=vOvs<yUa$~{L(ubcbVyAtA?Q8$vw'
    'a(wlkc)bb-P!rFHmE<dyJo^W6-1<Y5|La%Ebx!f(DK8c;KsDvrLEOD7uy0q=Rp3j$@n;VI<<deW1zTDXVu#LK7fatYoyk+;ueuH*'
    'C}Q*f_Tg%c$naVPS%KvERO9PWv+P#UbDR0(e4{nWzy1t(HG+s?n<0afoymONglck0YP)aV=k==0M6tmjUH`WScI5A}n-K$iy8&@2'
    'LAbTCW${ayW>U9hZEOD<=imKBuorUnck*ibDNi?<dY>3{p8sh!L#$kIikq+huh&^{;FXjt+1Z6Fe$>q!?rc1zmozTL{b<5pQ_P;t'
    'v$bD9lL}?6XX{sdGic)U7U=iYT3GO=ngMUZhMO4slqpB>+yDBpOf(d9-Mg$b#hknIRzpxW0_5|-#=GuqaQf?U1IElHP}GGdf27B?'
    't&K%n%lvPjYxz18gXJBIj#4w%RB<ZoYte7tG_q&_g`ie+Lv5v&(p+9xvji%OADxUMh|3bctAd7ODIVn{WgAiL`uZIln6g6um+yvv'
    'iC*iUnL?GMkcSh^yR#sk{8KX}3()B7myC-^-|ld2uT7)tK%8kFGS11um03<NJYh9k01SvQVyJRDGcz0zX)lNwp%FgFe|tG>$xSCK'
    '_o+9KQ^A^Zl9*u*RUTID%!sjB&F+kav81sk6rzRN0(qI_!|=+EPv@ea=RQ7lC4CvfI%h2Ct^eOU7imhcw`#(c=@+e*u{{ddd_rY+'
    'H4J8^sc{0J`%VnKG6*@rdMuz)NQ^XOov4W4>5sA`4J%OQ^O`<Z{crzMw?~QM!I=cwENUynN!1d{u!y0UH(w?u_}lX>%EWCS-=cU@'
    '@dqUs_fO;@KH=CTVV1=TKCeKa(pUT6{$9HRoPL_+S);;3T=4SMldxf{1o*Q}B3GsW?gzE;asb8`Q3iAUM9}b6C{-t%#6*<!C&;WI'
    ';``>m-umQa2m5-@^Y^XRdLtr$ap~usQ?|p{Fu9hRjx89f0G<om3EpUYK$EhU-?I5Dv6xtOV2SVlzu(4XD_4EA`#F+V=}e(#8;b2}'
    '6JWc$!TUL}82zoMY)9z>+LX<pc<4{;UnJJ;;#bb$f4ahU>z$n<zyw~;!_+qgI<i{z9RKTI3Dx@4VRB@N1J)G9m*i1iF)IY>+<n#P'
    'zK3XM^t_(pdH$!@z~C~^8Sd<pwi^tg;G6wAejRLud6qbsD}o@*fr+KIWiB7)qn*kW`ZYfafV+QRt<s5K^nZIgO%^f5{%N#h5fize'
    'kp;WiZ)us70lvm7d?K~mdJf<&M3BJ06Qrn1!AooKe&We=r(6}-|K8gWHnzxJ@?^)0Eb*?)3-n|IXjo&iWRDYVYa#D%gk4UX+zVQc'
    'yyL5WcF4XNTzFk_4*b`r{o4a`!A8(N6t|-Lx)_Cmb)C(Um{tk2Y4B0W+UKz{a<^nZdfop1FBQB#T5i(s=Re(3iM=_w$;hx1(Oy)h'
    'FdP6;ojd!HP=8;6N>-2uTX?5*O+eRXMkI@>j+56BxdnfN^Pjhnh-k}XA2#-<&{|Y!ENxculK`g!F3&qTtGc0E_I$ajEDIXX*FG(_'
    'gME@H`1jrckNW`O0?%W%W#!6^Zrh_>a%wgw5u)PsjfsEb$M^64B)(qh9K3`@zwg}#<IP$%{o((#i9aaG+yQ#dr4}Qr>I<-Y_`+#('
    'sn|5X2HjXrIb%?0;Ly$2s+9%=FP4ti_qN*C{qG%`vfWXR;+~r2;36U%fhAqDVO~G_bqCO0k+o+IxyRm1q%At{TGxIa$?3Xs8E5~0'
    'd)Qg%0GJT87J9JctLW!%WvAK#meLK&zo0nN$2}6xxxkzUeB)m&v;wt%Yn(U9^}cWPqg=e*og(?^9+WqV8r~k#P|M7SmqU6G4e)I+'
    'GX3d)d&F|Zkg?%%qnjp@&<0Hiu$r0fB{s%u3rOO~ghVhgF6mIgQ3HDMPir-$<HnYw^6}Nsef)e>7yBxb3F6-UNl3^$s0OWlybVO`'
    'mz7fFbLAwjf^*HpO#F>o>2@tuWI*#6nR|*bu;o0rbEK1y;qyEw3sPKVC@PM~1~eRgHLN0BtH3<|*B@Yqjj2vOzML_V9Dg%#Dt`@J'
    'b~2UU**{H2csBx{zt6MrJREa%MVB!{2jgGAUKI*A(wmS49~XyJp)c`Nbk%;iD5h%1ap0@B7@m3i7D^!1(X$T6nr{8@`2D*0Z-1t('
    ';%{G97`|!`xyLQ=MTx<81VFFkoW`HV)m{4=K+p&ERNYILlV6xTo$tSAj~7Oum6C}PSdmf{i_49=mbrNZ5V4S%U?`!g8B^`QwGSmI'
    'e_c4JlbrqQ&o^dWWx6#iHy!~yxZUkUdb*DI-=~cD=hVG0t4ou?{?5_kzAfDARR)mUyw(5oMCn5<e&@YyY}>5@GTL7}dxXz(+By<+'
    'IiBimPqFLkO+xq+{;hTYp|Ow<b8f>qVfpNzBn8;4Ky60Gcv+K2<6tRnvMVZ*;`VY!C|f~2XItk1I->cjb@E3EDV^3!X8*V$+Um_l'
    '`Nt5|VYj~&N*UJf#v3+=wzw!S&A`Fn{#&QA41P6z#(Vyb!_x(eKYnMD<?I5<&6&HHSNj$lV8YN2HF87j3rOhi_Y+2WE_o}i?OQ-R'
    '>^8qENTJ{njmn#|FRv^w&LfK6%I>x9jC_4Q1t$;wI}-?YW}!W=p%Tq!@#tu*2bw4tX^04aec5^ON(~RahCHEu5X^7+5vv@$4hhv_'
    'pr(ROgcO65Cp?!)r!DiV-2++bv%J(RVZ~d4A!Wh7cdyY$9@J3R?(HVpvGReFfOEv%sm4&$aFX}Fk79U?pOatfp(4(%TfoD~2)K_J'
    'zy_y(gqh+q^rM|`l$A&D_fq8j`}L#pMp8B_VEEA<6-!s-$^f|ns={0`S^RymCgB+GyW0$~wZXEtKulUJhrQGL8I@wGg`L+`row)8'
    '^o6d-7)tx~w9-#)<@mOJxkIZem5E>kG6`y3(8R7}`q2*c>d2L&x^mB&?|C<+NB|3W)$2>zLU|Vk673z5k=%RDrGr|GNv^K78%%o|'
    'Cv_+EX)nL{D~!ac|D9sbBe(Ka(xA3V#(G$^Nq441kH24TGu7@933jd9Lp0D9F~?eSa$=jcS>iC3G5JWcROgN6RC+09qQ4h+r_tLg'
    '@GMmv%h+IZfl0@H#^)gv#%B1H`N7%?kNyA?X=Dj9^g@&TYvYUawi<s(gf-JNmY?#@BA6v*V|t-)T|0zXR_4BxBb;MU1I?%{i#fBv'
    '6b4D=hSxRUVsV>%&_3Io1y61lMNvhyB;_r{Ve>8TWxkEy(#H%t(@3pAW9%e+u6bRsD8b3Kbbe{3fUA}*K8lkFl%qf0ghHMD_zwsz'
    'k8Jb<{ZybiVTu4`o{=%+)>#N&>LI6mbCUp8+uTaN7%&=j!&<mzUSD-@Cj*8(cFvHHRi=aBx6k?ch=+<+cC{v5_q|eT5&>0C->g@I'
    'Y(qp3bZ}er>JOkJ(m{~8DrHQ#RzY{t2M6tyhKvr$>3K&*6G%v!FS+K>Wb=t%Sk$YRGJ^gjw*Zf}$2i+_y#a(d;ZE(QN)qJ<aheC~'
    ';}#L^VeZ;>@xyK2skpAm+S1d0wb$g#bh>~zR@--=YmE};ANdI+va!s7YB|W?0um}W`69enq}g+_H%xjMLijY@n57D#jgmXa7;`Wu'
    'wypedC}!q}uOP!%u=kY;Y&{L0ecpY7AVtXR@fHyzw}Sw7!Y$4pVcj1>GFY&Z8Eklc0K3B&j{)8ywJO$?xYQXLKo6`dyACA@6p8t)'
    '_le;MO8UbP=D4l+)#$}vB8nW%r~dQHYWYANiI8HDZ~T%}4slrq2>Nbf`GF+zH>&#wq}a!>EvEUnXaL~=%6U_~%<jNQu`+7pCY|u*'
    'S9yFKVdkRxZ}thM20Mxp?Kv8<FEfOrD+Pn_KDSNbRIHhtOmq?|$0Y8*%&o_8H}BS{jJkJ)g^n;H5kOOgWfkg_!*|5``pp90tD1OU'
    'jn&tv;Umo(2I9|amVZC=aI~8sUkW`(3_;`NyP@ng?X!pklhq__Wbk2%FiCc=BMPK!P^0aIohD%}X6eFLkg}ylx=1$8?YlCM69Y{H'
    'Goq#)tnJFE!3G-Eo|J}V-pN%yZ#Y8Lv&F)`MRwGcj{m9O1^qs))hI)c9R4+hZ6kzaK`#~~*Dr_?;XBkBI{dHc{8S^oN+;Qqx*?;n'
    '*Xynjlo?*ietem{Sc80&bfcjEKIMB-ta$&h6kE{#Xv57i;~WK1Fk}ki8@nE*5^Bz}j|0>CBd%oLR;-CdE6li7tgGfuyAfkjtqx(T'
    'M^w7Obb6qWTe{6<CwQC_sK=`YdqHIgE7PE<H2iXtXVHlp)vn$)VjuStf*PquIlCe4OyG^VD)nLLZ#DlKTgENSNb>wD=ui{$fTD9$'
    'i1;BEaxa?$AhXeta53MU>BBMPgi2LjHB^5w++gcc4!I3~oP>D9Gl0}H-$Gch8^iTsdS($!(zon2nBbt18jJaEZHe`K;nXdS4=ohu'
    'o^?S-yv1}X#j@X=BV=b^D8!PoXhjghy{50!dx(y3<1fVy4TH5+stI-V;q27oBGE{FfRUhKSZQj;V8pDib?jAgk%V0d*5D^zs3OZ%'
    'Yfd44%V-yp$zXT;#Jn(%IE$EqGkc0O$7V~x%i=0>=DtO{lykvvB3z{gJW}S2zImv--<09+Gyo$oqu%#x-r2U_M(aOT_i_cjh8hSw'
    'WNqgN`25Tl$JnC#X{QMd!X&mjt1#pm-^Sco(pv@iv~q?I4~~cXZ+o|^cTf!>mLx!9rr01j@|MY-xv{;~dB9iRwAc9YrJ+WE^6`)X'
    '{C=Y_^l^3df9J#eF2wD~OlR6g63fSWI9NmOlRH#`u=g^T_z*4($Hd(7trzgam~Gw9{5G2TW8c9#QZoTyK9EhPo-e;SdZjwHl(^5~'
    'wVSbE(V)3!-$?UHIbEFqx62j<{h6L;#zbiM91%ZT0g}q^^ZPM}{ex(#tbG08idM+(MQQsHS-XA7RWpBaBQEDL*N;@~oQ_p7fjg0-'
    '4o9H0+Jo5#R|^CMuwqiS&;Z`j>0N6j>BUb74Sb$kgsT;Ni(Md%hYMt)npmd}VXsDBD|UB7)+TM1SgZ;nD`v+yDutJ&RZGUDQA_;$'
    'Sb_^j!o20;#?VE8x$!PWXw~ZDaVJ7BpPYSX$!En$6^Mu824vSwIU^2st<r^XaDQLRYK?C%0(Czz>+TX4wdR1kv7af+l0yPVLL6hd'
    '&v7wpUXa;&=+q3)H=xZa1=+<;mEb=Y<-aBv8jXviHv%AkzsT|!Bk9B>b}2pmHlq5al>tNbOwLF`zT#ntN8I{(T!LhGpx!RJyta@5'
    'a^7S=U8Kj&YxN*kXZeu<il3z%T#*x)ARRfS;iX3iMxW|3Te<AWnP3f`o)XnMU``A}eDB_|^qRMe2iu<Gn>Qvstge1T8!{wqzlveZ'
    'O<Kx(+ES@I`x0G0V1;cM;A^*799tcI*c-~{yD?&@DuQTCSq1yYYM4l(Io%0)sUa{#bH!U`kDsaezzV@*0MzCyCoJ4v56)&O9scbW'
    'lOI$x<0}QbQi^|wx0X{iWnC(KfZ%7F1WbtgM`d1=@6Dnd<ud@HFMFdNKAWUWO;mZFn57Gz6tnm<-iz<g5%zlq_BxbrNbA}gI*=Zl'
    ')O=eG%8R$;)PP#qeO4Up%(3DZw5tQIEuD(6F*%-<2*_opTlN5iy^(M11e*o3W^S<hrG8mWx7G{l9sBj(+1)_SaM8`uTtGlPZtNaV'
    '5kaFk2Krn41IS+a92(awn%V;dr{DN>8T+ZxedvYEtYGuv3L;eM?lRW`u)k8sX0J=c(53#sjleIo9^mL`S0e#<P)L!dLNdtek~%3V'
    'M+R9EgcuM1v_35wPtZ9e@m%bv+WXxO9<<La;6uV_?{q|exUdX3<-OTlhQxjITS$cJ-=}ef^<3?64SL^Hv5Wj!2b_}qr?5^@w@|=-'
    '-Ms&a3w&0JPsHeyVE4(T4EFi~lo3uL-RHV-S=pQw++432fN0`bEvo5<8>`VAth0h3m`x0nv$WQe?)~NltLy+%4cUZ3ldb019Nz+='
    'rjt?8UfyI*oTUWn%<F8gG(UN(Xtf1wghyTF%onlTc75yS&t`x07kbc~iBO)y%kf>Oicl?iiTjU4mC<YL*ohB-FBO+HpW(_2J$??r'
    '`=cYjr6;7wgn%}WlIqGe@7``jPK8c_RcQ4_`Mqd!p5&+SS8nx=+RL9ZeM;SCbd-hKh}#g`G9^XgiLw&2&nm@`KitFk*J)<>7fYEX'
    '6aAaCQet#Uifxgo!WNyq%D$+RP(?4y{dSvSXSKV+g%)XE(5%3LFdM><F|jpw(Qx7@G|q<-s{KfphNYF1Mfp$W+Z^hE$9DL2?y;po'
    '>0<W1&$mRG#pV3Qj4XR-F&x11H`5EVv?xS%d<~>GrH2>uW}StMSe$M0#k_t3U+i|pM4>_sH{$ALje$RhADNKLwA0WMv0cmtXhwn9'
    '%Z5?TfI)D#(d!MSZQs%68|I0{3PR8-Wn!0ZqfX{bJ@tm!v>X`9(FFl)z4H19N%qaa(hOEQ7cHWv$xH|+kAuM;pIPne4dm;kcRjPm'
    '$<>wF>O^{0sv_;=!;@B+hTr0{TKxQNbG#rHT-q8snV4;UeEJ3Yd&2B4sU+jXxjhTo@+CHyC|X;mQ91kJHx&+orrK>dvQ>*9cvi+Q'
    'l#!p?1Kvq<5`O;7eUo>=h$LSP({{IcT}fNuE2o1DsU=lV^C1(&{II6?Y#%rx$7{Jd{DYH_UGk4irSqH=*&<sV0o`2@;vnyq$beX)'
    'ruZ&EQOqwiKl7e*_sN`Sb)($tLxE|{F?rY+02&*PO`V*Mc2^K_LD<)IF|*uE9-$)v;N=s{`wfFd98)It$>&b*x2mX060B7h{t!-n'
    'p~B3e^_-}Anp6&uvE8hgK^^zK)f;Zq7OP>(&Ca2=wJCr0ajM1#*+BiDLR8GXVQj@e#&4O0BAcLORj%wYt6Vv7mlXN_q!>OFp4EkA'
    '>87Cbq)2J0ujmzJ<e<;Q^==(?JK)FdBtWu0xs`71Y|f*I$d5==>xCEtM#ic=wMPvsN42|pv5Y3JQpPqK(vPw4CLbDX8Gf;H>}itw'
    'Sj5XdRaLH~Y0FDs^w&Q~5S;=&gpr2y?>+QyF&Sbe<`eui)hG*Cn^NM(cDgQ~=ZBL_2KcHSc(^z9`F1dkkoCkqDHV{+EBfR1rt2<`'
    'pO-#&6?>%mAhUNZydmZ3VfguJihfBHPP&nAkPPSPNp^}`!CP_I{R9KfeuV+O2b=_i7vf7Em!?mam|RCx?7oCI0CEK0F2HlqpP>9$'
    'pXcKzN#hKa#CO+DMxOH>$;;jjxFx1EF%bITBUm4cdUx#Xll{HIPrxsPAOS={TS!*{im!B8S!pk2REdDH{?WB2rSTWbuV45wK)sI7'
    ')Y#Il0r;)Tv0GhaP`yUEV@W>7hN8VTS1zG|!BKy{yGm$(dp#1K>naldtr`7U^u<7pOG6#>7k_mDYaNNxh%rT2`jp9C5gt(8el5Cv'
    'r!P+*beOSkyk~>-toTYT6X#JcR^?>eCBIMWZ}#J@nRW8jYoi<u={5Y9T$)o&{)o911y%+-5mArv<>kS;E|zmY9oAhfygSq%X`>OT'
    'eTSlJ_{#U$uL3{^Zw6}m-QI-)?3>W9=6X9KhM~8xuY%`sMP+A>buX;3D8pmio}zXWucrDtg!qf9V?%yRu9Q(m$8@hSk)m~6yTt6p'
    'YudBOe-v&YZRaM4oP|MRUg<$VUazd@U46{a&(NGJ*A-ziY<|buR^MPodKb=ajNi*x2?}{5V+S%;-aYvvH&ncsI6587WC(Vn00b<W'
    ')B%td)M`A8k+Yq!yV&V|VJ(ts5qohDX%lnI;lmbI%PBgcl{uZN(i<;39<nF;{A4a$i*p_*{+nXh16!x!gui@-F4Fl3NLBvcsC-kU'
    'rgK(2Wm(vu+7@z<{(7=$e9=MueN*Vxc@Jv0qK|$~^aqY@YKtwastG=nq=n)iZaW-jXoEwU$U{BQ01YmW-@g9gPmq^I^H&%dT><ez'
    'suGzjpcvwo=F@tu<*8TWAJq?&pYgi7WQx6p*~Dh|$b1Px@Gd&?gcZbp`TWep^9|A=va{wV-#yy$zXZ{U8P@%VlCJM{P8W|^@SaD^'
    'ci3d4uAj8wKpFb<VGV@i1gu+iWSw`|7${}6f?%%EnREH(jV%2-5Ozk%u<3eoGMauNkHg#=I)rg?qvC{?7w3DvE0hTvIpYE`7RbCI'
    'DH*<xJhk>W^`TtSxhVNC;c0`QFbF;xYk)ust~zItaVT8ibv*m$_yGJ?7%x(*?KegaH6KeI^ggc`jU8_f$*EhfJt22;^e*?&(3oF+'
    'GBlSovc_{-7giaWXnWdtf(4x15uwD;3*PzfAnpZ~^k?(%3x)LF`}Ccrf$D2>yLO5d!aeq6)JXp|AK(!`-=TFpqN21n^TQB?ZEI!z'
    'zRJXkx3T+XK3IA#m}KRPFC}nqK|_D~ntCp_gCXk?<{sWFd^o6c$@@|0Z8cRAHg5+5o{<o0<OOPUq=LeA`^VX$k}@oxM(RegiNnFW'
    '1XFFn&@0;+M$x()Z{=Xw%-*)@Dc!(-ouL+@6?2LY8K)FC)#jVk&1fd2q{g|mdLaL}G?oAxj)X}(LHw6P?wg27^e_;E4v_v}3NJxg'
    'ZOUKVdeOhZ2>_8)Chs65M(`SgXKWWgR)>-SoHm^dq6KXkQtFS}x7%O$+$ZU`H}L(oh`6Mci`;YfVUb3hCSy#O{76CQelZT1I%8g5'
    '<#;_!8Z5P8MD1*NLe?J*Nm}RhclrSX;CU9NRP)RQp1vu#0{n5t26%=}&mO4cxwo->Oh=*GSHA>JpG8gr7M9{)5jjf%;XzLX(JD;U'
    'bza4*9b)OpIItEeGgE>u5n}-B7oI5Kbb8-;Lx3FJRKNOaqEoc61}WVQ1nz2`McttHR=nXSq8Br5q%-(A7k|*$^~gbYI_~yOQjST5'
    'kcz%f%~7n1XdyK8eREmzUEsy$YEXyIUVTx#x9XqivT#|Ln(<iqx8hnq^w*{LTYK75cBY>cVodI!I%bJEdxW^~f#%nbm0Xj)_h)$#'
    'f6`CFB{<#ec@SD6QxEKOX0a4+qmyj#=s;pmabu`{1pe}b+7vZc042jR?R%|=<M+tm4P74uT}d!$)L+%IC1=-Jt7?gRwwMVUcPE=?'
    'LfcgGG)jegINd`5Vuo_nD47yxOqka!3`HD_eMkB39yg4aTP*o?Vi%gV#VR$8bZp0ML7ve35x#LF=d9^FZ-}KOR>uD2gU|H(D+8N!'
    'puLF3$uF4_604x)$4BZPTDkNY52as<m%Th@eojV_#X}M@a;p>-5Uy<H?4k6;MyV4vOq&2n%3nm1ck~3?E{x2KEr!$l=&J=s-XtwN'
    'b+qjp(PJGyfk3_DfLgf*^EGD`j<)ox!f9DHN|7P;23^B@6S-M~gv+ier~frUig-O(w$v)ICC*s)1m=)mgJv2#MkMXCf5;NH#jUNP'
    'USanT`q*(MmIt6nSayCr!q|Z}3TTRm-M8vb*3GN={qLBIr^_Q&Q#x@p_qc*bXhqlkDaI?Lg?;)v9s?19xSO=kNn#!v|DBy=eIU)c'
    'M!gwOQg%oIeDxaWjr5_h+1Dq0JCt&RJI(cZ`)n1}l$CsBH?}TrOVCjsbwZ4N=xf;~F&3S2m6s>?(dcX+cYhUY^xV&`7eE5rwdqRL'
    'cFBf}0wsP>G@F?*f7wxA&tVdNY|+>*n>v4zWVr9$qt{v+i*8^*Z^cuV$_g}DA>qOr|23Vm^~Um4Diz#|mgYqK_1Y5onU!AwK4bbV'
    'O)R;!I(SW51zLt`aT|N?R~89PIs5Y1yX#bIgnw?3JWk3xoqlVzW^L0wa1cNGU7I1&GL$~_p0I6uXiZb0aVYYGVf)h7aBJU~N0VY#'
    'N}gIEO@tQ)K~!TZ#h+muA9-;<cjGOHxiu<D6HAU|7R6Q#Doo%MHIEJIcC>z+7Q_(our@z5vu}l-G>NIhwO+ZSQ&cEV6I?cw>w(2t'
    'GLx%fRKzf>{2`?M3bxLXe%1}NKZtneBKn4v_!IJdML&)Y9>?dWm21%oztCO~fApGT?yMz^r+Ch_6L5t!stdfu{E<d;kVPI|*kWZd'
    'z-<%5X3*DxHX9i@Pb63b4lCmeuKnh#F1r%F$ub#JYAByXyQRMxFv{iax%4I(M#=5Su8tIIyWYqE*&8dIaF6=9j|M~Si`D&|gv^GE'
    'LK{BBk||uG^KZR)M{o_=iLCemEksUO#7wvY4(S58ST-zjh6tTy_V*8kPCB3Iu@8V)I^r1UipbZp4SK=A<7s=vTNgY7j4XdXwHD-0'
    'KxAN%qsgb6&GT5pi8razx-91xv*qkC%iyP;#7b>|w$SA(Cw~cwIBj8}#NhREQonQ<S>2V%CKm3cfQg|<PY1$&tzq$D!wQrK5Uvb9'
    '<GmEWjWCnsH)JxgvdxZ#ys|E84$#Ejwy)l$7;t;J>Ke39dRgCxGGmXl5n9FBHEng^T25(aL4+k5SjgnWopihiPB45PCW1aqZ%<$Q'
    '>a65~LW5%Nv+<60$m+;3Cb;#&)<N6p{$(T?__(m$driSL1P3;Ow$E5ge_zSPCBH!`qol=ttkWq{tXwQTMj3+d4;1}wlChTiz$Oyt'
    '>wd_`hio5Fue!qy{NFdrO46~<8gK3VAqn8<PU}2L&GYk&-!yz!xN7mPndug&cGGrv-N%Y9gPhNnF2G3dcuB!kH@;qDb!c-ka7gSd'
    'nFH0WYq{(a!ypMq?#jT(yFBf;#H0_!!bMU=W%I*&y>o-;Mz$%uRMxrPaC)$rhODTRAGnvM)oJ_vg9EmnQGs=_74y}VZwzmPxl(`U'
    'qF)FzEnXUSys-ul<~NIO7wS4?hTn7G!Z2d^O&PI6wYMzms#Z?a)f%4x(g=}*hE4-$csUP`@S&?g#8LObVs)qpeognwos`?Q$jjfR'
    'Xu>h6of(8ETOlL+ZSL+Og1<Lt@fieXrr=pZ3pE;6(d;$d?%%}YQV^1)1`OXXb)2{M@#HFR{gI4;#vMia92x<Y8jD(oufLo$wXZLa'
    'o^vQh(~6t^SZV>R(>Pe6laxTeeEo7n5{F8>T-o&XOW{GK4?qMsv{V&98GV0|(1qmG)$~W$0CKlO1y6+mx|aeiEb%ub>5Q4#mg>;d'
    '@v+c*)SZ((^;Y#9J(i_Na8g3k!Ymn%;DM5CFA+eCaw<e9zHU@7mMJ~9kMep+I*Wij6ikE||K=mt47XsIq9~<k<lD_eyf*JCgaI=('
    '|E97U-%)=<+D@T+9K`{%7rwww_6G>UxkJmATcN8Zo!Sn~5nrWz;~ax(D)eIQHmB9;XZ#&+JqoE+ImK$B7RH=X@pU4(#j(#e29z3c'
    'Qi;;5uuCu-ar5|`s5i+iHNF-L)j_oJhM-?qMwB;*ByKrlgNx6m9;<S;IAh8q!Nv&v$(1h8^Us1B=>75>3paW&?gIerm7PJbO8x1>'
    '<IXrfl^;N##vz`MFsrCeSdkomtr)doR|c<lhF7F~E<Lj_C4D#$WA_B^!U{lRZj%?zezEYCz`>IojG}K(y%;tpP!MnI86#zkx;pHZ'
    'ETI8S->L6zP!I`Eb{XLF#TW~qXoCjkQIy>D0eF$R*fIAo8DQmecrt*5wz$>Br7n$=#=fs%AnMe|tnB<)qwlP^J}d*3S}r|@gov=X'
    'qq2f#S*LlT@;qP@kP}WengT@fLUqjY(B2(HKC*i{t&zvh3NJ0Q$7m}98}~Th&qTlx$ug~Gve5@Ko>)Vbc|fv0`G5+7o|7nq@3afH'
    'L87rv!!y1ML;<K-s5J>+MPT#>jfYBo>aOZkUIfN>olPgJTr(kC+u5-3K<G#V40TgaFcGa`9K2q-qX4dM@%`2}v1jM4&Ss<Cf3Wb9'
    'My+~)Bv7vt;IR-P9gnOPfV|H$qSTh#O8(<j(rn!#xF?n?LTDTFmQ}lXxGQ)TC+fOqqR?SMf_`w_)@Xa)@kYA6vsJ&!{TdnIsX^k+'
    '|BUU1^eqXi1&QRmzgpY<YG-Sn-3?p6_#mLFC*M7n1L$d9OG+F$fGrF`ip9Di*Hl5!IUJ!89{Wz@4)hjfa@}`+#F%Q<Mg9v`*iMCv'
    'Lh&17kX=YI_FQdW(P?3Pv+Lp0Jh?04ep5}hFBqoOZ@!y)wo|*|h^pT28OEToJ^<O4tscEzvS)TyA-OXo1v|Hw4Qj&T3Z0vQ(p4{='
    '_L5*TrxkNXK;g8H9sT~e+KAPA&0Ft%9OL~XZ!;beOA-sQhO|m|=UbBb_u7FphnpVu@qPcuET<=-_zv>KczT1&x;kTesgS6a01gQ|'
    'Yg|S)Kr|(|C1**`6~nuoh7-!gY>>;i7bi845M0;7l{G>fJm#$CbCy0y#U6_)(N7I~d7o*onN?(T3oCjm`$cRGY^QFk$b|*0*k9NI'
    '=r?@p7g{GEwu`R?m28`Y8qX;aE?j9r!P?cg#q#s)@^j#vaK$_Pdo6t-AE`&jUOusB7ioggoZ27JD(%lS!n;lA)ebrH2F_PspHl&O'
    'YK2yxk3N@n)Egx#`!vOA<}~4RHWcL+NUtOhZKjlL_i>gr%Jv7k^oP_+O((ggsIqKAhmR3{Sb4@Ves+G&chc8F_}kqeFBo7zhKDr_'
    '>`-PSrR{9$@0J{TA)yAfh1%@CY^?)#O1bz=uKbhRluz5OXK6!vys;C@xMNZ1Qvsyr_d<Ww2@T#Y;Kzjb`ur`<VgWV178z!W(wDS+'
    'DO#oFeJAlzIT8hv&hCeJ^sD&_%YM}={>4Q$#`F^-_ZS%kzG-$!Z{NUB<CIyNMETf-Cr|5TSx#~3Zwd7o9~i7L_C#D#wy`hbm_oNT'
    'efZIO(P37@ixiV@2UoB<O5SxU>r#oR23-ANQOnow(2Ao+&fj$olR&q`B6OjF1sN^rEV_m;Thw_mY-N%tZb`TPcCUd`ry}hQVtX}y'
    'nMI3_MK-BXs<Mh9R3;j}vqYQC7tSp`VWABKx1dV_1j9MB{r!9x3GcMT_j>+0Xgxpu3!wb@Tr5Yk*uzcEF$LcV>N=BLOP|8(Ecu;*'
    'iU{&OYNitT==#CHJO303{R#4ZiM-gNR}DqopC^77P>P@$&EMQYIO!ght&gZAi<?X+4$#ipkE>+MHo$m{mS4d$#TkA_cij)V<;`{g'
    'P8b)oN(2K?>wR(sXAC^zZhaC<Y7}x?z^bhTcaSuN0(Sm&^6MJCStZ9IGkw+e><|84wuNm4jpOxidokbECej8)j-sK_6Tm27$}dzQ'
    'BH?>09T}b*5#8A=ifr=*5@0-YoE@>wT~?+=;X84HvGR6p3FE_Ge!sW_Vj!!CYVzw9FyZxyt1a0ab^hc!G$fjjT}_Cy{i<C8(VHcR'
    'UrHo{c`wR_3NB46K{Lvsd8KIJ&yPc>!ieoLaasYtE6<#Z;UJuGH(lKLxL@0S6*JZlbd>5p0sJ!i`&^>s0O!xyC;wSf|5mnB1)q{n'
    '#22+2=yRuv*FoLaYxOA}wBpL3VA2qNX>CgvF%IobTm`>;CY4kvO4foT70)l9=zgo{X#23cw+K6B812Y4%#m5jeu?;_yBjQ>hyt($'
    'yyJEFiIfktGaUX4TV61RcDMW<{DhXVD?4Ts6^NDTpW?D42!e)$uI`$~FM#)&N@Oy)4A7{x7hWfv)lz!F2G(}8UTFa*f+A3Smmrj_'
    'vDnX>q^!)4+{~D^`De9f$U0uLRfD4{bO&!&HM%tv`5U^w-<hUYF@7l&tzjSDn}G6K?yWaV;fgyb>9w-wlJH&nqA+EzdIMMZfB+rO'
    '<v|rWCd(^Q^9jV;f_V456Xr-=tUs8QSrB#ywhTVc?fYk`U}FnmbqxwzVgfqOy1MhbRUsn<>MoL2D=WZ&lF3LX{VV4VwZ+B_h&w5<'
    '$!n8nkokB4kF-5Upn}+Ku-vEQryk2Q7?2PJfBecCGq@{IVKmr&Cj9Sm&dQ3*?=0&p`&IxQl8Eita1ap3|3})Jv^lP22V(pB6``tD'
    'MMNPoFcV;8#VcbZK!N}`f?#IaA7+5WM9f4+F5I8g@<Ka%?{>Fswc7o)R8re*^+F5(ikJO%{Y!koh{(+Ms!CGZ`Cbsf9nL-X%;#Pb'
    'cT`a)W5szJGpgK@*xTKFe>`*849>f7LY;KluB5q>H%e~rl@TVo(a|JP;@F%Tg+Qak*wQs=9`Mvmm|e^S^OejhyOS!~49~$Ej?)gJ'
    'D_Qbfw?b8-;eNCY%6&A?d!bmL+is*)J+?RsE^nmJX_QW-{J=qnohkb<79*Q#Ub}`q(-l7D$JW@CJ(SkR$P$}yt7cs8w657iDl5So'
    'h1?efF46SaC|hgFrGbeGJe7J1i0p~Tq1F`w8#@vN_)dgj;$-VfvmE24-L5^1Hjv%#iEc{4M=sh=wt_Xo4TkC~x>z$H5^#l@5=Bu6'
    'w{;6_0euu_sm_YsT(@`0d?$znhm>g-D?58#YkO}xNp>cU;;Pe~v?&M>;L}=wMjg(Fw2)KiYTF`7mCUCSi52QW2l7$TwJh5!L#3_J'
    'b}qtu#gOfzdm`4bPmeK<KFhKcv96eF(#eUeswXHB7dNE}8*n1G*lw*F305dwf5te(_w*DiRwgu+YCR6T!*oWBND=LIpr`!Yw)YcS'
    '3Tlo&lzFgojJ9O4X_~CkSyP#ky^fQ;OoxQNSr%xiVogYD`?X4(R}yE;WdX!@Qldom)TJ~+aEZPeLoQ}--~?Tbc4B#^if}S3!+qeV'
    '5T!%v(Q8xFo8;2yRDvvJr*Z5yFDt4=$ii*+=Uoy+Z7&iO$$9}oZn*huR_{jK)>vZ_igT&%Rw;~x?9tekGqF?CnrgP)@SPem4x&Ey'
    '>}=rzttSuXO}a=Zb+k{luCPP1$8>w7+Q%XqdDDHzk-RzHl_Hr{_I93?(i#o-4ZH8PV5DGc+Md%B9L021ur}5nlQKab9rwG{nRORy'
    'Oz^DZIc0F0N9YMUI>gwd;LEvH$w%Vo5&0&M#w<pww!WvbMV$cS?oVZ4RwtThx#pD7DoVB|E(y<^EhfsUyV~|=vskb`fx&a0Laco6'
    '96BU9h+6~CP6U6fDaSj{p*@2~Q+EP$X*4~O)2zh|pr#5vmb22?Muj3b>oEt<qIA2)+9urPGk04xB%XEC8coY(bh4If&1D-tDwoRk'
    'oD1Tqb2F*QQATz(A^|$JpC6+|Z>)g`EQzl3m}r{r#g(I@wpA2kN3QWL2%zb3!>%X=vQuaw$xNx17@2FQe!kFz-rC{kLg;PaG0A;<'
    'l0$A5u1CFx#?Gej)m}eT2Tg(`YHF;A)9AFM9OdM=c0H%ft!^%yDGjgKB3SU$!d~rXGij#II2#=a=&qQLSU@m-bneUY5bdkhObhm~'
    'pReIvW3&gWI&sHNBn^9MwUUq1x@jI8x?a+XH028pJ>!^#IV-45-OvrFq{GH6y31DHYJJ|F!XlT9W#v~RaXLR@lTa{Vh4RXPv`VJv'
    '+<G|+j6F45XopA{C$=JbQPD1D0-i#KiV#zei)=^6ECh?AAwOH6CT5+UcfqJF8Iu^T;9bWwM_hz~{?LabR~DkBOykJOr@Lx~mF&*U'
    'h_vNsJ}AfA4BfCOA?yO6G}7Gnx>m84UeUufR0fveESb{v{fS@`2TJvD!F9*-2u0`<KB8<D<anMHidHIDlikQP_Z5kuLE>b~uBCQm'
    'p4qcgy4AdGtmcbpAX~>{OM8B{Q+Lx7Dol}cRJ$U`$w|0r8I()KI<!cIYNn%T-*Uu0F4bbSRiG|7$P#Vu{K8VBHK{OrWKy~XQ^bd?'
    '!B4{37K~WmY*{bG_oPOQ)zzpF9N#!m5maWf2pp1<<06o5RNB-nBJFxP-?K(A8^xQD3L0rY$_vG&asu}kr!s5kYTaQQWxW||rvz3I'
    '1(C}fMIfs?i7PH>2y5*Lc6!Xn_83Y^3vvqr@Iy|LX~i9Otu8D^<k`1!ZmNa_KMBado)k{1@pz^SL4!E+r3gFn^n9>Y+dJptvCE^W'
    'W7@k=+(JI2CwgfyT_`(VJ=;WpLaCy#Ucvjp84E&!r`YjQ6V9C!6&^6#Q;YHU>6s?e*^y31q=7Hf*0)V_I~-DPbwp?y>yby-6X<C1'
    'OIb#9nGBRs6LiL;MmL*kgO;HY_nU=Y3h3knFR^JElkG+(s)R2{z)o#4vDLCXJDb_e&W~_luvN}828n^-b-H&~ZmXL?AnryK@Uh1x'
    'Dix4sRQh4!BPbedA$~p8EVhOXV_Yk=RV$dpO6z`M8=@Tw3x_;|G^sp7n2+p$B`Q>|gWx@1&B->AP2FX4P933SIYN5h7QFM!>!taq'
    'BjBhiv<=S@=3;4Bl*o9-XwwQNYgv1$$UI7r%1FS2Il|(3&T4kMFVD7^@=Lk_-UZkpf7CbQY&za;a?`Xu7G38DL7(Bx(%_aLpzN1='
    ';|Ahk&#hg=U+pK!-e5o;x!zz|F?VaYL9H!%A_{)wwe_rJppik)oY~5CH-)v3G5NATAW$o4$(9sGaWf<A4Z`Wi1Um<E;^mta=I1Ks'
    '^2Od>X7f%;L&efvX-3W#2q!V)u+As7m<Ai?&?IV?XNW(wnsBx1e6&*A*-j>1Ut8?4C@e(#XzloNx8>0_UijMs5}iTt&j(BTJl14-'
    '+Z_~g$9P2Gto@u_?N2b}k@F1NRt~kpyn@*n#C&Bo_;K1-QD}%+H`$z#)g)d9%N3r-)Z~b&xo=yGMF(+SmHO-6n;hgm8c!pE+H>g~'
    'Kjl-s%=sknS9Or@*ZjK9=uSu-RR{6Y;TRki#+(NDoIqYAd0fLfY3X5XZyep|bhbMWcrtc8&bn>NG<1M>T)Ux+gM$Pqy*XPf8r!kA'
    'QIpvQjl&Ion5=pQ=An2>rZ(0}O0p**e;(6kbDwktQbm<HEf*_9u6brv=&`+Q_A`(l@(IYz3R}c@cCsXcQE5x_jV(l{baK)$1|~sP'
    '>^qX41@UGUi(W=84xSROmS);i-R$Vp1v*p5W(3cVu@j}qxE1Y)$mTFLl^8Fw40<Nd;z_Y~%YNom*u0v=^_CzpvqqHp-1d)96FXHK'
    'fWT))+6+reae$X6>Wos^ww7kI&hSgzo|H$#MnjpIU{E&YdP1kYew>MpSmoP^&~6j-EYF#_B;XFhp77#$w)t(q(@F_XX{DZ`d^>}}'
    '<IX#=l0J!BooedQ$|vjDY=a>J;pUo%<22eAf=HuOIU_3<Hcd$ic3MlfE-!MhI-YKhB-xCDZR0>Ve^hH*q(YBD5pP5#Hsex4&#WcN'
    '>LQ2&LV(5nJlq}1vKxsR2$2Z7Uynsv+m=wXB*JJ8Vk>u!Q2rFz9n5iP(6QKw<-sB&otk;>NW&+oq3);j3J&S5aaba=^M-~vGIhXY'
    '3TSigg9)B`jj_REEd|3n!fXX8I%yG#sfr<f#4>rxv(T0#7v3ZW5$Ym>X(Z;V({_o*B@ed=eWIH}V))?~C8p_3tzd`GX~yd+eY!r_'
    '^;nj=zNR4aNZZ@l0@e_0+YDb<+ekJCONDgS9maIjF+7IaqnL|b)?~3c(U~4f=R^}vhF9c>bQt+ZCoc@uvuRyp1U&KhIYF}8%-LZm'
    'mr$k|_hz()Iaa5DKt#sQvbANbjDfE%mvXJEGVM*1<U9tML%lx}b5o8ee2Ou}@Cq9Kn644ZmPMMyg9-0pytUm_=S_KXIaS*44@uBa'
    'S;ZMOlFqp%qvBj_x4sOo!~+Nm@`i9$tRU>7gGDu+KO?FAzUDhNA%O>8Q<Tmu$ets`VlFhZ?LLV8-9(A}(-zYv2ud}(I*RpCLyY1v'
    'OM1;xW1AL%52k`f3$kP5q75m|mm+|K)DgniRON;1P=wx`HH_s097*J4hUC?_*47{@Ax&>KvQ498)7Ff-4moXW8D_A4l+hx!(==#Y'
    's=*R><OX;(*3mH4Z~U2!*(S8?W)Z1}r{f%fj@jC`lS+-a`XFKgFkm~q_9h#AVRk|5IB_QImYAxI573g9V2Ub;vRzE};c79~n}hF='
    '(mZp69AZEaHEJbX&n(ij`m#H%(P%mM-O-6{G<$;jv3ah|vZL@^VHOq$l=Ugr={V22@L^PE2WJ&1XTflaUaVM;&|6*`1D2z!WFl8u'
    '>yRr-h(=*Sgo?Vum&vGu`#u@LBYASxjCL*Wi+bnn`^^;J<TKdTIAagPi8%FB5OZ%p;4r0g)WqoFz$>UJeN})HJFvz|L4crei6<`E'
    '7&3o!Eo33C$YtxAOK3}<+C%T?eKGGE$V3w!qynLbTiZsN&>~2%c9Q^yz2mYS`FmoF8*;tP;TEN$B&02|q(q`k>g5g#6_`YJHL=Y$'
    'Zl%;jQ*Mh^PURH{@lefhJ5r>EcVRaC${%6LN$#>xLL%UZamYm0&B}_VBLiK@z(g7A?UVu%b23>YD~N<pxk{*(RDmP=zG-1!2T{Q8'
    'gi+GbZYQOa3U%kJc;sLaTsmDO!|=>jBMbM`d5mgAJfE)km6Uqv`CORe!%pCKdW^xFLpvQ)mUt!@YCc~ah+56C0H0Gb#MiwT>k^A0'
    'hxHy=?T?P*?oUUx6nmbEcSgQXVX{w;2$`IB#IZycr?jryLZG*F36-SiA{6RS0<$|Er8-4*FVS$3R7aH}w@E68#DaD$$2r<jy&P>u'
    '`?x}nbFxgrQzahjr6Eea;EfmiGcdrArjA95O6$}_n{jORQV?hD4jr+zO(F9$&Fb`8o5F|1@Ee=GP-zneTJLDNq);2<&n>bmaMceN'
    ')GB5y6KBZKrxxRbmd?%CPrUg_D;E?|k9DXR>5F2`Pbh}B#oc+lqcsS!<KxPj$~n~bwF1GCT?sVP$XVf5oVCruKEd2t?R&{lsa7t='
    'qKziL-nn7e9@_b4vYV$~sq1TMqE^L5N*pdH6?fs0t8&IP`)%v(SN-twu%o=x?PR5nWP|K=XI#YS++yWC0PeVG_8|B~YARYxTT4}i'
    'bnFO7%O;EfFX4sA&37YO>pVhc99G)q+AP5xtIH2CzDP^RVC|LMIGNQhMvL9pU~Dg!x{xZZiEZ0ly`Ru0XU>8oCiEOrrY6an-oosn'
    'HnawtQmD5xw>I9$+nnM-+-n`($~KtQWWH#Yy&dNHGML+kEi6iwMC>$wepXl%trnbern2=Ug+YS06<s)(LexHA$I4dEYa)lsvTkQK'
    '%YvL?o;2bZ!F351+Jk81kpSd+gX{v=A!@r;<gGg?;kA9J=!qU-2F`8g=c3W)R;-P?$n*(B?87`#M^TJRwGwtZo2k2E!HILTATa}L'
    'ye)M+>vii0+k*(q7vY{{*lN2>-<?b<gM#yx0m%nLZtYpNXh(v}QKl=dPq}0h!e)$5$+{bz#iNYth2(~we9jkSgDwuWOVyNj-X4sG'
    '*w%<EHw1aWJ)ANl&nvW3WN(53N4atmP?o2UFn%qKWz*ZOxQ)u1yUv*$0dAU9`}+gkR-Tx--9$!4CgCu|N>Hrzc)un11D*sF%Fpdc'
    ';cRJL=g<_y?t)v-MMA*^$7^(C3`J<dm2IeuW@DK5@k4*uxmAOx%H*Wkh=xk(7y>C1CFOeyo-b-~w2C856?A8VNlK~imm{%-b%~fs'
    'XSGVH;e`QFH!qf|=`c!fMXnV}8gvlFAfY1LQyUkljySbmpZU<oN5J&S*v^*5_EKw)a9S5tWVmkBBl?a}e9TkpQNpcNr^=^i(>y36'
    'lQMQ|DOVMCB9;;yVEr;}I?Spk3_Iq1Sy=ZyT^-efN<*D~s^znqIvh%B#~D3ZbGc=?d>ZUVyLicvbbjP<BJf4}JoO!v5!@M?ua$BR'
    'aWfY(sfi?wm9_7gxyjV7&(I#Jm)(4Q_ED0f(AsxQ1+%A$Je?#{Z3nx+)Do?j=nE{FPxkm^6BCTj7KH9;huUAP%=2=;QRpd%nmO#u'
    '#igZW93?u6%LcQxzMd(p#*JjQVLe4#<-#^R3-;E~kJ-}bS<R<CtdzoI5FvYFq~#nj(;0n>ZMG{t@^|SOYqmuNk-KR^SynjaXikbC'
    'P|>fGdS`96@=9^kHON;fkksnt88<4-tB`a!O9rP!4vKf#!PG?kM8R{-=EjpWFwmoXW{5dk8=Le%?}mNMJ*I}<#+LoQI%0A%!S)e+'
    '?ASeRz;&}YOqWF`jxZaz@_4+2`YBu-In*-rjGs-qy)d2}nh=j-{=h)CIMba8hR&fRB?-m1o5GRQEJGALg8c&nq_Uy*YEMj&Bhm5M'
    'dQb6%8+Ak=b&=kVMKpxeg{mS5MeNK&J&{_!b{c126_bebT&tW!1SbVJJu78&1fr^?R^WSMO3|_z=8fXB4zgZ|V+m)`KD0oV1JaC^'
    ';HzA#g)VNVtev_+N=nP~F|?VHYHqunpQ?hp(M(|916Ms)2b*B}EpLEqNy4Vftv6CP6DsC(XKN=KR*ts&RWWg}M9_PMIg2L&Y9S9Q'
    '=J4b|fhh0PZ=-$Vw1vl>$7fDU%G1&Dg=M_}6I}<XL3V`WH(3*kXsd*~IpFJ#R?fZJy3TquG4qXr9cS2>T}iR7$0vQfS$d8bF9~6J'
    '^2ePts*9C-mU*3A9Y#igjrLB@If-(#2zM$NGo|c@J^OZNM{==WpFK!Cs8gr2#_hI@@Flx&b8|YH0slQ4ujkv+oH_<&?QMcS@MCej'
    '%I0-vXxR3w?c&{*I`@2MMpnn?>3oujXx-+s)?cc`RFAY~)-NlAq3Oh<ih$FyM(rn49X+{$LZ#VkzjUeTSuIm49WCTJN%D|7-EQ(W'
    'nj8|394ioyBB>KC*W?T&e&h1Y<Eq@cVw#o9h2&bixL>1wpqlbDBW&_O(LOY5*X4d2EVi9u?xkpY&VW1gx*20ga|#t^9;(4poS0D7'
    'nc~-$A~*Sd0wM>!;yEgUsd!m3R_`y4OB8`^MowV5S-{e9QBCEj5ro4GqLML=(&K{IdU`$MdmBhM&f<+oNHC+0#K~f@V>Jvz4~t1|'
    '?({t*;_WimaEYFR;Jn`lg+Fmhsjk+Dq)5uF*!%7d8TI5CTg{N&T!gbRI&r84+}Qf?y?Th8(Mx2)2$12j6oeTw*va)>s7*(nt*^+r'
    '+;$>f?080BSPIps`>GASLo=yodu((xmyxP=)-IdwL43dv<)U6EVl<wrZ3#gMPVJkuIMoi8#Wv$2(Zo_epW0=lhX&s7mV0PIRYZht'
    'dWvEI6^ofaoz_tSrHis&EGS7yY5|qhZ5_4gdX1M`d#u<C4la+=jz4F0L&ZGJZztZkH^@^&ZIELx?57>JL!8F9Bs@?`&TG9`^X*L='
    'NPM{$$!v#ldW{(rv(s6S2nh?MIye6Ou%50~2A-a5kon74UN_izlPhb}YM1@78;i!=H`54peXh!5tP`U$3#SmO2f8W5`|}}XoOnkn'
    'HWL!;A@^NjuM@7pz<qqihO_E7yu;$PaO@9j0$n6>43yB;)Slx~#&t6)?A-%4ibyjoU1O03C+mpujZecprb&tbi{_z)6LdEA6ahlq'
    'J)N6+Q7tvG)l0k!M@k4p2ahqXtRXD*!$KDd7+Q}hs^qYd>!PqF*={`TQ0lnTcs$+1dIgdiq1&!Rn^p8wtGv2Z8%Iz^TSw?sSr*sU'
    'R$aJgCVLdOfP7ukL|RPtRUb{G)ggcm%o<0^#6-22Km(%3b!6EHFtXckb9^$k^?JOI)T14MD65{15A2d(5MFT{p$8-Hyd$((fOvnZ'
    'IlRXh3xkj_IGh;LDDjoSI;`gm%_-Do;rLs|;(e+RP(+&)=FY1_ZcpXB?pyda5#3ac0mGDL1YybKz_+%N6nqS~)P7RntEQT&Caz6|'
    'HMdzTNAsgzk#QH-iG_%JbzjUhdrhp_twD8Uso{mtI7+bvnS!$&H<@L$qI`gm`4oYdYai<J06~&+F&)0A**LnYHInS^sa2)=mPM{f'
    'gWJLZURirMg_?v^sx!!&rMc~8Teltei%y8f@bq+WDm(KmEIktrq)?EAo0)w=YUeygOO6wgP7-1?fh<N#B76hjrL$lILp{|AwRLhc'
    'w?I)h<jmQb<jB-!j|sL#oV}4MHh*lHY+Z}eh(0m91A5SfiY)ZDZ>MM~#cF92xE)*N6nL@H9U*9Fb4@YZ4A#zCZ6+By*SQ9B_qz~Z'
    '`R6Y7Pn=?+9<fAH;vh`7(I#*wiMX41wvDmIR={PAWRK@rcPQq9z1WwBI4yVCg!FdNa>VSS2%`dc<rw3-(^NDaAKZ})jZcNoru~#a'
    'Lw`Z+mNCrl^qFv;&bO(>deZnH95!NM9;&0#>Io~U9PT9{Nus7lM^hNC9od_Dbq1ehR8D5?L^Y7OTCXKX6Q)IfU|X5Bh+P)e5YxA|'
    '(}^>+$IgKUD<C|tfLZD`WWl#t!EjY5*2n!+v^SkYu4t=WBP-dS#USaeuxT<@@cF8nouSRij726qOcWSbYI22zcoyLR0kQ8H0^7E6'
    '#y3H;T7@TFHbjzKq9ew4&do#|Z;ngZEu$t)`-rb2KdxDQVV-S!gQlz9SkPp<3idQ4I&*)D7Bou(Uz|tsW?^g<jaDisGElXjF@&*0'
    '>A6m$feYoD8Ppi;ou`acJ1FfOp>w<A)}10vljYg-OafRn6F#h$ioVD~NE|Z@o!FoFi8WgIsM-qtW-2TspFL7bemZds847!mhf#Ms'
    'm6XYH49VpNuf$QJl>A&;3}2z%CL>2?<IK)<4UcV69A_)V8j09E?Y!|C>Da0aG3?-VIuzRBanhQeH$PJ%cMznco9(UE><!~^>=&Fr'
    'VyF{pj;A|vmdN2!-5+gJgoI5sV}vqYIl)@NPex}A=PU>s2syhcFESA&2Rx9}v!9i8V(%9Gc{f^*gme$#MSeMxW*%kC1Oi@TtXFO8'
    '<PoQ+B_*@sCS;>oO6a!MTWhmBGK!ehdQFN<Gg6SH7b{$Ow2Y+h3vrLQcErgkw-P36f!A4z)P+MtZ!G?N;)8C?rh#o_o*B*{K0I@j'
    'wcK#&(l^cCEk=>GoR4VsP%#r>PKRA;Q>Q(Q;Er-R4-i_|#*}SS%o}fP0B<r~iuQgdbV8-EJ)x3v8wr~gGE=pD+9ttD0Afxtr-TGv'
    'Yv&&(lWDzQvfCi&97eVXp<#PuGnGY(+X>CdV2h-rr1|1FC8~ghgs2~_0%N3hW0L68U^B{28<QtVf6HR$POR%ar$`tGO5}Mi^H5{Y'
    'qkgtDM>|!)n6z1LgIRwpv*j^Qj%&JLCT<WSSiu_QPH&XSoHc7Y6t^)Q?R%4{a0lx6Dl|%UT~wox2$vi`JMpY9BfHwKGx5}w`$No@'
    'k%&!%IxEmtC}f~k%XI~2y6a(w*`Z4`TFlxxW(fg*F!ng4o_nUKSQY>~gFssA;{aV3b4^GSA&pa;Bl2k0dfS!4qL|=p`-8DkU|u`T'
    'VqxK?>&gkmM4rUZ!A>DjArk0N!H1>Co=^i>WD$K{pFq^Uc9>D83lRrf`axz3TEb6cGRIkm(K_BqqIRu_bV|B`=~Wuzj!vUc7EJ-4'
    '!v@A@5;h50UEfMrPFO@IPyxGY&qsz>a*^2Pt9mB&?Iabc$T=Sg5EG&%BX#C*RE#$FrsUbELFS*K2{~=g$S7@B+9oxoK{1?HiT6w{'
    'mF<`%&-hH;>pt+jNIsglP`Svbu;%vD{YVr9Bbc%KOhMP)QkqnVL@{YA(GxzjddqLL<%Wpo%PK?Hj2g!{>}@mjJQ8P2-ltyR^1%v`'
    '5MRQ%dfsYl3MH9!UvGn>7pM~lDhyzogbFZasS(mXRE2C*tmG9BBYlw5!Af5oBF$dVVvE7*j@Z(CzD=Ir38|6`#XZxy$ynixaW?&w'
    'pF|<Si<o4Sk&$yS@R=RRAEmlDd7C}kt@RoYO<qE0=;aJLAfiCMwH8v!Ajd{ZGCdw5A>B<)hHBSZhKDvZl7VcvH7nT?&hHaZUqBOt'
    'AQ-rn#1fr6zcV~uPFYXe%-0TQb+U8hPLaB3V}jVXGt}%(NQ%yuqd0aWWNl)tFpYa_MZ}2<uWNQ?3gd11Jf{lG$wOKt5YDU4ZIImd'
    '=@S=j(lm5{_?TxC!@_B0tSM&cko3CGvYA5m!cfmiD8IeTi&YkBtTDU(6wWmhqR$g8D$TOzW&{`7!49899#QE`?(j2At%cQGq(VpV'
    'J$Bvd*hwGWU(C&<vmG%?*oIX*vyWY$%!*k<FXgm37R;FJ8K4*O#AEOlP<T9=O-{`mS<QOAX?d?WzrN3wwadlC@Qf^3Emw2-piYRw'
    '9W$7vHnFc3Ah2fj)-vYwl<XDpptq~CI-mhmvlNIeFK56=qYa0X@VI6CDJ7L^kV8#RdNdcc{Eo3{kw8mC>6WXmrqjZdU2Z9byuRIe'
    'dOs33`0G1<*@m7})k&fiXDa9O^CHcJ{Y;oqG~?GUBsNK>q|B67Hp#{XBCld&Kim@wagz`4$tAg-;A)B!JY}5iswpI|LMo&fc&6x^'
    'LRV6m=69{1Y_xtJobZ<N5rI&#)9U4Y(B2_0nFb`a&`LwLrLkK=xCk-G6big8tSYI8F*c^=#i^-DAJ05QWIPH^n|9J{cAMGo-qz0I'
    'odxWUrZA(qG`;PW!k!Ub5SMgp$VJw)5`3zy-6R@*f4k$jg3=U&KVbsN)EnPww)9aC(y~}(+n4w9Q{=J_cEBDIVVG>pbtIiBAzJ%Q'
    'M<FYk!+>?*FkfsT&TUm+J{%XC)1EidCM(S~KT1~8G#j(iD7C`v%lpim(4$#=u2oL4@r9ChQ)Sd0FnDe=w0jWigh!WWia78AHEf72'
    'x3bW1^RdhZJa9}<hj4i2?h$iyId4doiYW`6-jSH#CTqKsH9q1e^P>_SnJqRmM!vpL)h03L=hPQ{96Cp1VXe{P0$J%0+A#5WF}}Pn'
    'npq*rgcKUJqm0dx+HCwO<EU_(IRUY21f=fgwLPLEDnK1E%Gt@rv}k#Mq}{R~>5MYwXh#!Y-mktnF$}IPrS0e}TfLr}JhBe-4LOIG'
    'GPUOIjAB@t;RD9tMbqb(jsde>E!ETT)btyJF~rj@o{I+h`fmB@sfsLH-A&t+LY)#I-v!Mwq$h{K*XGHX?-ah(CT6ue;zBx3{4rCH'
    'wRto4_#WM!sdRxk9MvsbQhq*%c8`cgJJ~Vmd@n&Yj$&yXrws0JdyuJdJ3SfM^>Bh}KyYY43J!sLt88&bjcGnN_GA;-=4zv@zTmem'
    'fpHaUNocZSyxt!+?7VLe0;$4oTZ@~X$zZh9bxj4nr$O2V-tW{kN);V3PvuTrA9|Q~4_;&(U(PmX({oLkY7>-G>NFY6(F!(W!IhDt'
    'tI`Vs)hxZ8Iw5*I+wH7oQQ}1F`n;3QR@M3#1M+1)@FqRf9DLbZu9{P<9DUcU!`fu4AT!Ow>v_@&ZcgAJC_^-fyfXrF#wLmocJ2YM'
    'V^7hsC^Q=<uPA&W)6BdF;Vn_L(_EWQXvLPTIFCog$b)Iw$yezag_1^)b~Vko!DM({%JF$VeA=%;4!;e#!wxu(!(<svs7VB6tHRO9'
    'elho)5lqdsCOtwFDk==)F~I5>kz{&(i}ka*81|*kw6qN*gLO@ITh29aMcHG0JZ5F|oVHCONbq93%gYX0#Qa8mKA%=vg6L!021~Wp'
    'bF{Zi{)A?(G;96l*yFHVv*HvAJtr}+Glw#(Op=Rr*y;65AecikKWO&Zn71M9@ep-9FZ5j~_RgUd4YR>rcR@0*XB#7EDQMzpq=Woh'
    '=doby!J_5%G|t3QNt_*Aj@q`Zp<KmLy@8Kih0cw9!_Zr5;ts#bL9r&goB;#k*NE<wQV6yNNCVNOxP?aRNQKX?SU{3oH88H#U82s*'
    '6*&$Exz$oGi;m9o`{Ol2Tpn1UmBf)-2dCkEj%CKx$FOf<77ognvtY8u$$2{L4~Y!rBRBMm&cpfjh7}ewNL@Q{!XMeQ;f2fRGi-MC'
    'rX|$cT)MnOB&fWS8+oft_}HO&sMV#@Cc3=)98Sc=j*l#F>9=#bZN{5T$xkcVMGPEOnAWv57NRC)lzJe}xtwD&9Z6(3fw~2X=Gs!G'
    'f!YY8rS6onFXBxY5W;->d={pETG0UmLoLpbaU>k7WWMf@s*~2OWhYXg)66*EKeq*RgvebQfUK#(0v}IC%Ou-o$JU-w<%TvzIKa_O'
    '`Rq&S{>%|hZ?~)lol&hYU5e6c&XYvCfzb)6xKShp)^PY9XN)eo@1LA9D*_k})^XCu%A}>5tgHG(6VjV_2{W@IaJD!er;)LEK9^gH'
    'S00FG=beWF6~R>n-*ffJjwYMHTDa&Acj!Kt)-1kd>HTmf#6$^(cjI?T%RyY+2CS-?XjtxgkvL35gTxFs)5(U==g;TV0Do!}>tv=e'
    'aIiE$$dw&%C}i7>n^*=%3I6c=u}-u@@mW8Vl^ODz)`Hg%)ws*!DR8qC7C`{4qhLrLZ!MabU(S^180H{B2W&WtL<WAA5I}r&s?0NA'
    'R}1~5i<Br&dW{(oK>au4sm_#xZ{hZ`REJ{9pwy&-#pBU{JAMX?mI8q!GcE9R=CL*=F4gSonMNfeB@-OWpdOu*t8Nta60Qer$x4Li'
    'GpKTip3n1;LHLqvF{Wr|R9(?KV3o0aCg;=1gdby4zAp-W-FgtCo(uExuJyqttVa!lgAj!2$5f@aCxr(T<-+p{z~A<QXBp1Ocs>(&'
    '@QrHPa~`*D`4ek$b%;nVxuLbPXV5YnG3-w6Nlk<@;+3Y-S|iOop2O|2R3ysgr9?hsimRJt7k8&dY*f|_*w(2ws_^AJDbH>lh^hNy'
    'C>d%eZyC0wKnlI;=jFI<&chK;TZk3U#W&-0*kYsjzB^I44U$Nuw2q_QW*O1zBoN50srZdk&k>rPwhYX$q~R=%FK5~mxWTwR)dzD!'
    '9go#4i${xt%g@)xtcuqzJtJ%XTmv#mz&$Gm?v>t>OSCP|w)$`m8ASs6S_rv_NyJ1oiO+p8CY8D91q~vA@G<Z-ko#@tU(ThEVFOHQ'
    'Ww$HLq`JoCcSP+ef>}q{oC%P064b1>3%tdMXoEC85>krp&#$~58<SR`n7PAFT2;|NqC`%Fj%$|wDCLbaGCSqr@P=c3*T@TpM_V?u'
    'X6x|ChcD-#D+?B+6#-!VxTn$RurgNK@wi52N`vpxHF;u;MyoAD7?$Q}>&&18vy-R$R2;A9;cSE#ojI^Vn#FL6ABGp^`e^3p3n!?i'
    'F*81kYM{CZ4B^{mH9L2ew<OV^iEBk@0@C4JD|nW}qs$n%&CE+CY3CHPExBz{Zbwk(!UofbGg&<F&IF35C(*W>Q>n^FkOA#rpb|QK'
    'KsNM#W0=5WIw0v%A;#!={IHFU?m{bI`<Cvh939udT5tufmqjo&7;%%VqT_j@Q~b_i6=p?k+%B${7$od_2_`ol%TCF#=}x`E9iGp@'
    ';FvhuEDwp<P-_bljZy3{r*=|kk}wv@K<uSO<c*^-EJ&gg)XSaY(*?-g_41^oix3ji!1C1DI8FKH(5FjSS)CTIx;2yi3A0bMPO3V8'
    '(XO1Lb0W?=K~%i-HKi5g^dxUy>;iX*F$dqZjAK!LIRh;OU|!3G>X}EEvve-@=Y{X)?`zAPm}i?Q%Wjdv?R<F<h!bIeNS7J@vD4*-'
    '6pG_C2!hAQ>$g91vb3zOgvavnyH!<0X>e0MKBjdX|K|Gop}f5>ygarX?*@MN%U^%@^Xm_AaOXUJck}W3m)8&1zqFG4?e*RDuZR1%'
    '8g9QEZiCD1&xhMnoed8^zy3LR_ys<Gd;RI1^WpaP?a$y}UA+PSt}4$;uHr1n9<E*nyDHC#oyAvm>A6?-`6~1**DJ0d(8_WFig#C*'
    '>t0!DlvovLF_ePp3$S0oKdXxK$LCoAFpqBL)QOi?_kmXlu{YeZXW6~E&Vo0?px3u=BmV}py#3gQQS1%3_kL8A6$c*O+u^bBlC1GA'
    '&p)kx`#e(g%|K4!0kmGmQdc+EVO8Z1FbqPa`xd_++$)A42wXM+AQG5E;0;J5_oY`c72ttgS03n9c>eXB%>ACKHgc;F^c@kux1$#Y'
    'Vf6>A^TI2=qVbqA_nc~JRZ#}ocJs(J!QWNlc@^k3Ow-D9FLj@%9VNG)USuV9|1eQs81zh3K%N&yw10p)H`i{|fX3~;6I*4eT8Z~~'
    'oyXmq*u4gYQ3~QIX+2jSuYV01UR@eJ{(O+qpMUpj7!-Z?)AFkV`%)Dp!Ic$Pk3ZM!IBKFS{rOc{IFCQShQy7cK-ZvQnOJfB-9*q<'
    'I<uA;<w{o9f}+S1LFI&B!_U>%Z(|qW0;pE8o}U%oO?wAQzLA1YKZ`v;n6I-u)n0L4c`=}HRsga@>G56R#g7r7$A@R?{84=SG5&*e'
    '8G3+r@%_;2dgylj_DkDAAAZE0`1VtLKM2gD%zbjK$_a10+mD~Vs2B&3W{b!TysI0#j^gSnOXD;6xQf!sD}11H<<&(nQXtFeRTW0%'
    'l@GMx0X)62i>w8cznZSD8~~`i{i15m+~wFuUD@4#9popEPfs5&{T@Dkx+}ckCcX1-KMq6OUy9$QA09RP07!KY*cb)r&5!Cp?@you'
    '=vt>Y&Ygdk-+nB-sxH#2)N8NwB1@vuySd4ZcWHL}_}#~^`tPTY-@<Y(ux{V^A1?Iw)7vTpQ@el>ieg~Yfb^ALrw-5x06zmTvO0Ai'
    'uC5^my1u`L{M)xLBLdEpS=@LxetMJN-riTCm%bqJl?7=AK0kc||G!$=w12F=nA+-F`})IQzxm<s2K(whes}%DU;psiAO7Ztzy0Aq'
    '{P2JN@PGaAAAk72fB3s=AcU^hY5t9S`)$Y1|MJb}zkKcZ`CoqiUq1h<&;R=K|N8lV`~1Iu{)^B5=JQ|vfsUX556}lp>f54!Hx%6g'
    '$$RB3vtB)Z6tm2IfWd?-t1hgxdU7n^dvY@0_q?Y(>U-<Su8Y7co`NECz{Lk0o)XWBpT7T3-~aXZfARGFZ@>TB@Bi)R{{dY8;`6_F'
    '`p<s}F8}@KKYRN8FNSA0x?2}k<HZkfm{nf<<i~>zd$OVeD1!G?SzYv0+W>G?SW)`q*Pu;cl~1`<904JpKK~g2{wGhL|Ni^mf-(N$'
    '`@ebm{@;H87hsgX{o&7_zW+C1l)w4m&%wCh_D_EJ^Y8y77*O;5$nhTF>~aN=asWOrE(-AkCYs0Ia2W&v=<-uFT%KI7JU#*Ve+B-2'
    '3qTL^7-snN{l5p}{?+C2x5I2aCwzd*%&%Ij@Sb8Y0<a%XPMp>5)5ZK2PqCF(Sq`X}<n=ISXcg|Iby?e`Q$+bN^gy8Be*V+@-wgEn'
    '{%;2GPoMwf^WTF4Fu~7%{{+Z7OnDe|Q$=x9ML^Nui{&XI=c%;@(3eT2UiFlRU>Z;LrQsP+1N8mpPv8Hm@Ba;$)IcBr^tZ$3(?CwZ'
    'pn)?hfG)rvKpjM)j;qTA2ATn}0UUZttO0&%rJyMGf`RG({`<fB{HFlf0nqn<_xVo&%>mwj`u%?ZI0Ixq{}~(sjo{e(!5&;!UI+Zu'
    '$Ddi{Id!gb*9S(*fAt;p<Dj1#Fa!-keCvFvdpp?M^6~omEwINo!$b6lyp4Wc-^X4WRN>nQdc-kmMBkRs<Fm5e`#^6wKx8g+y}^3M'
    '=bItUxvTF1!L1AE=q`euyS+O0tgas4eRz2&yhpgKfT2#_7r%L*!odZN<n7O%BZr&hvGDG_&U0?c+uK+C%jz+C);}nDhkSTJ@Xkvg'
    '%P(qq4J`RH;Oo1xy0`}~{WWrHgQDZh;DgZzUCKe0Zst}M-X~UfgWSCUe}f~)?d!uceO#-u9>1AgS%Fc3W&`N37z4rJJqOSNzOR5{'
    '-wf~p(qFBoTV5zXG)e~FPy%sWU62HB+w%ti*RNy(4!*o^i>R{f*c+k(1KfMX&EVRHV((@^=GoC_z*^tFy&(4!&RVS%RTp!-^vWCn'
    '2Hi>^B9=RVy}iFogROzp0g%73vH*uFN^9@avmbVTS1yLpen&K%e^fLs-F~lh3=RZl*DthlZf{?4cr~1L`q({w*L^ju@893NON+|('
    'Z*Jee|M2t<c|(2ph~D9!Zh^_YvF_~KA*@axuHUEEcLlf<*LM}T0L`!;uCMR>;p6%i#MHOodIPRE;QIbOxB(xZ-q|1i=<yNwD$fTN'
    ')BVl=FGvr+hb}k3)|Q?Of)o1=P~i59i>Qu|@cVZ+H@|s!_usz%FwE`!`}^Bp-Gck_SL^B1`<tN-ls$p^_qQL0s#{P63fG6H>!+XJ'
    'KK=RzkYmie5v@1=`|<;H``ys>@N~0&|Es69`?Thtg!S!<zEzjc!7mJae$~C|u{u8Mo-^nk;7|1q1tb~x_^OIv237g^?*9IMr~~=~'
    '<cEo4z?<KP;?vEW-@JFB_xIrQS77kl4{t93?ty3t7LdFg1RG$S{OdRaQV?LmrR?^t7nj}@XaVK#un)g}1ET(y7S~tTASQUNu0ZWi'
    '0Sskd0aWkspG+lu9Lm0tu5xhPKp%fB_u)4}kG=LyAHT3N9Hbjq9w6J;?HxM02zL4%j{fqO>90|YdO_&-i9-s4ngPF$z(n5Xbs63a'
    'ZGq)^W(?59Aq5zUe%#>G&t9Upp*XSfn~R!&0TQ6oAgGQ9yTN8z>{;pU{UM9en?aC40Qj@AP7<q#dLWChbEzKF{wBX4Jjm12^%r}z'
    'daUlt95}ff_~tji1}y)h-+cc+|L{M30CERCy-y+d_74tyDSM{ccNp@l>8qE5+ZWWU7c-0ik|D2S`i~z!y}haKt4zsSui&h~&OHkm'
    '2-4o?AC*rZJ`#7I;Gn*JdV2Ta_KP63kKg(4+7FL6!{^fzatonfw5xO;R~KAwy1VFNBEa>od;rh?6(bd%TLXN7nP~wG3;HtB9ddgM'
    'U%W|qDyo~;ncsc_`u#H5(z!1)Q1@b^?ECT!Fp9TdNRZ#BPfytGj~ZF`(Hr|ddZu#r_+572z4G$v`fFDLXawM^lK~t0kFhkZlVOqK'
    'WBFKq6Z^g||Ji@}=l|~i`PUy_#DDN@ckkVg*r$K?Vw=m`U;grs;P?0M-7f{VKZ5c8{<-g$lItM?24V5D`u(Ww-ODg9q`Byk2$J3b'
    'DhOyU-lr}=*73@Xn|Ckx-NMhT0EXe|=?08y-)vUEtZkN06IOqcmrL-szI|`Q(X$z=zO)B7H}DWV4<XeM#Dd5Z-2BPQe5%{uT!Zew'
    'dJkdy#X@G46<^H73+<}p+3I~`@_@YyKq&75Lwjldbom5NZtXo;3CMb?mxt$S+lns%9>4*_(BJ>3tN;9$AmIM~-+|}9`}Y18SWx$U'
    '`r#vThmoJYO#e6UOJGLdy?5{LJ`Bb*y1gV}Rq`ruuQ(^5?A@2*H|U3pB^_+ZbBoKgo}QvowbbXLFOe3=)qiK2uj79^{1cFm!SN0r'
    '>+b#ocmhuNSMNa8MQ{KMfUUnsZu0oufYA`Q{m4N4(ev;fP?Be?z|b!k|K>F``!<dM)wd7B-AjOCRgc#iNEnOfIOQ4r<B)j|`PMC%'
    '>~MW|{P4<QFh$Vk`1TSIzAnVL-^dvdCxATh>D`<6@Q2I%upiw&{hqSdd+d(*Gzi`|0ty`KvxtAZ%<m2eb>XGX`2pPA0aUyoE5L(Q'
    '4Iz^E;C=!*?$;H)jr`LUg4OEr`d1(Atb0>NJ#Zxtc2>Av@dlIt3Z&Hoisc=Q-ji4IkgDAMd<91E0HB}WZLK~kz%0|dwH0QGbyr$x'
    '`39sQkq@Lh&WeX$cw^7@sZaOW$2=>eA#Hl_qt0{R4vRL`1M;?ia|w$dP!J@)btB*ztn)((QlYng3_@o&D!fa^{{R5iN&42doFm9&'
    'hs?jQ+{lXG1jBV$nHeKU-d&NGPpi5@kw3md?tX!iD2Z8jAUjP<U=)UBlo9gBw|7NgTQ~R}emA<iAKzZ!x<!`1c^0JyJFbfx9DusL'
    'DlI^6K+7AH1RdYLX+8TGRd4?3J)W0Che<?N_c&Qz*;y5S`frZj*)OcbE3cxDga7`R<(31IKR}fWwm|-phtjb?40S)IN#NA)LAd+z'
    'l}H19-Ue3wK<C|C3uNW#8xYMW<pW4)0X`ria)$-K2XvqZN`OXRI9pX&@_>TkGK(Yk>Ou;PB=27T?h!zd3;o*y3^06L#=f#Y4k9r~'
    'iU&9bKn{%_&`)*^K&E&1c9nhvatQp*L!Mny+aEFPcgLY_U$FWI(Lu4-W^V>&*X3nWUuHNOCJ3bTnQYHec8`+f3tA6h29o-ZKScz^'
    '$9KcuWdsb6_qp|b{%y-4F0zWRGKS)$>jihe7}=EV`**(>TO)A&g59&!e<N$JDEOIEmv5S=j6k|{cMl-{sAP!LhM^v?FI4!2HMSAo'
    '|8(y(AD^lGHi^<V&r8TaDK7+g)v3Y*IbYOxZ-<%san?SBk?VTjs>_?pa`x{i&F|p}eR~C%@gt1^&$r*gx(EO^AUk}#ePKBOY7h8c'
    'l}+&RvJwvXg#7W_SDeB9r~5egY6>hH%(bq(x5dk(1|DYlGk1T7Um&C#qPn~Lf1=R*j?7@+$P7Km%<C|}qsD`}+zz+`)qK^rC>=QT'
    '#*Q=R`1W~rW6=L)a^tW1^)lR`9v~(T0MnkQ2gLN#eee9k(|=XY;r?~xporXyre7fB>BpBb2|(L#Wr9S$>2xs<f53)5<9VU<KSIEt'
    '@PNLf?@(;uz^D7l{#{c<{8THE|2nfnU*KNdXX!tzt~h9CyRUljMd+=%%6?+^03APFmOegyRngeWOYh<J=IvKW{Zxf_mHY7(0to=n'
    '|8)}pqB%szZ!Y%uA@=+V$N(^-mmx5EAjeNt^wR!Ip%=$dUPk3xkUUr38=!!W2mIm11Xtn57q>dLEW|;+>VH{9&hdQF9pqc4{Q|KO'
    '8^r)o!;e3fCh+kFc#C{kD|+)R7bP$wxd#H~fsBJX#CJfthNUcYpyeIv7a*z{*gQM}m>>UP+fM$I)O2t)|FCU;`;E`}eFSVl?>Cq5'
    '>*4YVh#v#&uA=1kS)uU-#AQ<h%&`Ju&<tMcM;Ki6th&0-gO5Mz^^<{r%#5#C(m%Fdzwmt@{oN71OpzEyYhPLG+qRDppYDOj`cgun'
    'H2LX1c`cyrF>YC(fEW3Rv;71z>wm~zU98F%5Ar(}3j`~#9Q(!(0qpT_Ova0kdvQ<S#5U#CJyl*kJ4_HS`%wx6_$?qAkWJumo;Bjl'
    'ppV}~J|&1^KYopN3J}tQun8X_z{`Swr@X9|e=BFdKnd`l^ZzYs7=J@`pxmFnY_iW}m4EygrFmUFyt|f%D@ZhdL0hyxcCJ6%0TnGQ'
    'XQ*3)+pCwyp$Sg7_;?JOSP`gY<SY2<%UZ}#Z&PE!AA$PHA9}yebf|jfG^olhqiS{aGVBNg<NDVhzU)keAPfIT_GyPE_mTU&N1I2v'
    '_syoHow?^9ZAuP}Uz7Lc<E5)rRhAR3Ld(tCn~zE6dJoqb=yCn&C37A29LvXdAMVuQqrB{Wrq_4Cwmx2ir|Y}cD$=29`}nZ~uIcXl'
    'FhcH*AUM3U>+<~QTOeh>yKHej-@i^SIjWC0!|ose{4sJLE@0z_XD&Psdkx@RN6%dGU++HMU0PS&rS*j`!ZTlhG+ugqVUz#${-sx0'
    'UwW;+vI?}fqD#|(f3NMF?9%Q9@D-O0$!zLgaW9G1xBZ5-k}p^l&scrsH)vP+mv$F%e{GmOBl61p<52R9@o@e0ob0BL-~D(SHof~;'
    'R)7$03@{(|fG;WR9Z=2k;oXN%x3{0(0<zwGS*p_X)#JyP0O#Gcc)59Ai@5sk3IQ@VpjJG7SNv$H?b6^o<QA|yD+Uo=fy?l%kLRBM'
    '<zM`d-}Zc7Ir{Np(~bQMWLVF7b7Osd05Dz8t#c1R<%b*48IW`UK5+ai+}Ev|%Z9|tt8Tum@O+EwAC>o^Ro-+%k$3ycUzYbk%U>UF'
    'KYi7t0%Yd?T>?=1{X5hztuCVhGI`6(_gjWRK}<4yh2kQr+3}_rHks?Vdam(?J?cwUn%#W6X>Fy$PW7-)a&-;)_bD)X!}8s`<im}B'
    'JE+$4#@d&C?aTU7dIu!@>lZYV$L|K+dS0mgm_DTUz%hS%UU^CH{l~}07mavb1HI_XMR5FKRr2y}f#<RBs&hWvA3@T6H~6am?r1+i'
    'H~#%_52FZ1+yWknLxz5XURD~v8RS)kUNOst?YFOsB>q+AKM#HT@v_u4>;VjWRsh2Dhy#$^^{;QM$LIZ|VVAK^Uw0WVb$8D-g$w!&'
    '!0xUG;xQ%jb%W{p_UrQdSHKq-Um*WZ|MjK%xnFzpObzJz;p&nVT>;_we|!7Z-Zru<vG4vBWp+o!5{t!$-lU3JSysE1*ped2?eS_A'
    'yGWL(vM3h2ij+u81dJe=36Rd0%w`uzHbAfl_5lPtm|bip0T%f%`4inc-~0#mFXTM#y>+WdN_NjoFw+*R?(5up&pq#Z%IJlLf7SGX'
    'v$qZG%*Y??98sWwckKmTlp$e;=VU22H5ZrOn_2K3U~4h-X_1xv@nB(rVSJ3+#1Tb$3mlc#l?LE}LFw=H0E{p)cJ`hYQL-=&pMGVb'
    '6M?L+?w}qDe3-YptqU)TYXj-j#8$Pz#F|JG|3uqaqIh$*HNtHrd=w+5DG>&a05KvuI<7?o-PX+A)!5=KLBo~pUadN@YNm<Umbe+^'
    '(F76@`-79<$_ILw2LW{E1c>xLG=cf>&xDuyOo58Vw~3XQ-%}tkRhLH)#-jrmsRI}>I+9T?a`2B$)DZhl8}cGY{!Hw7@J{@+leHGV'
    '<S_*ze+s~yNf_kwY4t3R^RFkcNjqgf@~_>%ZS0>0#md>j0{?Z8qfC(|Set$HE(HJ;AZXi9oL126tlo1#NHL)nNFI@Q12i*nSi_KR'
    'u!W=L12(s!i8)wUc#MEe#rhl#d&aQOZg)5#Z68CPBHUtX2FqQBrcCCfkviMQcDro^i3p)Oc+{im2|A(CTbKayPnXN3%~)UyNUU+5'
    'OVHvhS<j{0xO}XL53pXb3gM-xMH<m7U=e0rj7<wLP19?NcmQ?h3HcLV%gK!0Kr1@AQ&GMWn_eebYY+|nx{$}}`^uRGVuS#O1P2`&'
    '7*N}^w5M`E@l+NpL0%;;XmpSyK^)YaBm!Sug3ox+0`=Ctb{o6->m-y_L|k1X8msvYnqAnJZg532e9WMVNv1*$uX2t3kRUR~{=ne?'
    'LsJO1Etfa7KD(h=NNsk(H1Nsz^{+6fEO{x^V|*XCF8nKxg3joC?@Hg9ZJ1WU6yc3T%i&Mdko7=DF*gSn@VuKJQAK=^jkzgR7XV2&'
    '94>$)B<6I7ZG46`%}1xBGw!54tJ};Q0?(WztBo2$UOUf#-@P^qfdO(?5b&+LyL~`?_V>V6yDaw8_N1kdTe;Xxnl7L=joNG&n{nUk'
    'rPg0R!?4oyxLLw#srb>sMN(PFHL1NEU@>sjVFVbJM3<_lQYyi)QnQw7*YD&A#&ZX0)7>5OP9VrHL0b~uTeYpUc=Ur>kSwRRT+~Rd'
    'GuO@Qb3}a4V&O{=Nj`q~GbC74_2Y;CYUF|4+awLx#?J9KC<&185L*(%B_o`%%rGV$bC(DaEJ$YAWACcp1@U5q&|NGyIVlT#>{eKK'
    '5!(z)qxc$^SIT88g$Tor;=ZUOauBCZo@1tT=F2_`(I61F{GdOGX<ohS5QErg&Ly0(1qy}{54>pLC?9hxOkt(Q^>MIPxUkR)nMMdW'
    'u3Yg#(rQvtG*6|a$l7`SN&<K#kT4%xAQWEvD4(_c0k8m+3R&&>@W%#Ff!3ulxbTfQ97Zjc+Y(^InPW>1j-a!PQ3oNEAcPtSUgR61'
    'S%4AufF{%uQ3T<DQ9-FEK!8J`Aq)s1E<2zH?!i82V^=;d843d<6b{r@AijCn;|%=^`$xWO+ysLQtW&@@uqz(yRohVYaUk04sg2%;'
    '9UOK5VUfO2H5s#zkT1mJk01WrNQh$Q5UGF^;+5hA(QoYICPM^na*dDw`M(+BJlr@vaUN<0KVQunqBhM;Xf)tR0JUnM(aJWQ01~$0'
    'Y+iv}s(jpYEi@j?-s2$fmq*V<DGL_xO!^`wVacCDmuDbxq7;uklSJ&a!yDE-aa4G2!O~v>qt?V?R6Ma~pkd*q)-w-k+3Oh0@kmoL'
    '`+1~uiNL&nx}Ui9X+uMu;o=*qXT6KVo+1aZ7A6{-P$_b##Qx{U2Y_|N(u4DHUYrBL!fqv7o)*GE0P#WQ0DLD|TcS&AV%cQds9Ls('
    'etX0_m_&);5C`sC6e>(0^iq~cq>F1UhB}8aBDtI%R{gK?r*7eoihposmF%4PWhDnlk^>1=pI9rt#wfhuxqp6c7DAFJB-=+y|3^K1'
    'tIt!^!Kaqn_!ihRUaU#l=+RR)NslEQMBgM9oFq{V-J|Ty1t*keFO=IPf)9e&MG0)n#GlCP+eq9+=_|LoQnsJDYh@M3blm~kN`Xv0'
    '3S<(4j@)1||EloJvRf`1NI{vn#F!7UHTeKI3$BkbsvwWekBZN5@r*G%E|+u0sEV&g^s36Q051SR-5eT~SL7pmN8DUBR}x&v-0a8`'
    '*=y$v;4%~>;O3wU4E!tx*mHnAE88&$0r(UB8F?DjE?YTZa9tRVov=9|r-4@lP2TTfd&x6%jZJir83GKm@CrL-Gr5~vhcP1<x>C&{'
    'X@r*Sj#{?i|JADPtgl$f#9$fFGz#bkg432MtmH7O8RqGA%cS*6uR^+qYOR8GO80_TUC)9@cOq1)F%&K5<}}8VOd~Qvi2ktchOF^L'
    'xeTj8j*c7Ad`-PU6B4yai6hw8RF5mGsz-L7%;-XiFsM;(;lD_eKYsWNv&J&=)_mEWh5ji49$RvssEloyWVM66>9PJ`CIC-KP^}<p'
    'b%8dGXoFrAE3341Ett$IA_)9ZQ(~6@A#-}X&+3J}KB-=KB|fVc#y`MtaV5|2<aIN;(UlV+CpqKV>kfT5Z<V@Jtykcf4WS=rJ<b{I'
    '6x_kEGdCA-6mu}}5m8DEiaNEW4sgnZx2k|^5M3zzOWJVvrBxd!ie-UL5r^|`lr_Bwpl>!l{+FK{hk_s*PliFa?MKMmH|aR5+Jj!M'
    '@lXHo?+qnPZ?X*lw3ysEPzzwK@B<2R#?`Pp2tW=tyjIKa!`z&H``mVrts}*^ovXG@Jk2J_yR-;rhWvgoZyL0*$?hrYJnW~*3j%-='
    '6aXL6brD`+&`A`0SiD){QouOf(g4yLt9_R!<D@$<3zwwH6i}oCf?Phsm6zS5H4p|6){h7v0UGt72jB|@v+?my{-=Sa7Ov&DVLhpy'
    'sxP&q9JlnQT1pl<)e`IbEfC0l_SdMt%r1Y&<tQ=CtT0M1=?>mcfF^(TpOV^BHw|0Y3@rSG{kiTmfR*5LXD+Mw#zAI*f5!#WGC1H0'
    'A7Pm-TxaNoaeK2w9crU>Nq<EAPIikgI09846YEJ_mu7*uDDhC@I;EhIyu)oYVBCGFGw|_%bAM?mN@mT~Gj*umw{od<d>^D2@(;uC'
    '3e+yb#F-2KKAh121Wj1{fA=3}w>VF?_$t84|NYOiJ2eGsAHYay@=aXP(^K{-nk?=h_M?Ix_&4U6eM%asZ60cGPy>b9iN-;1$r=R}'
    'CEbvMJ&;XZqo8%yUKHpChH0I#_icc?D&|Vk#{duEfOae=;f5|*8OHZpCdj5t6LB^J+HkcL`tIe0pq5h6<31vXrj^gw<7OLsX1h(s'
    '2qDStml%`{lr=3k##a5yy!pilpa^@UOOW3R>Ji2|B7DF#F$mM7x{;?<X2T=D?`1l<l{QCdA7qt%4}~|zXJt*Y95x(MGtG1;Zfm0S'
    'YfWerzm*vU)fbb*WiEd=t6ZoDkFxVeqp5ky+jwRsf&NVlpHIyNfoh_m-UCg`8AwYeC|<L=bb4*Aw+^)Lq`O0*ZvV8<Q9TA{uo|-0'
    'I@Si#kIJ6w^X(NMc>(hMU5xE8@9xwK!?bRFGFgFs`P4u6fR%wps78biDe4!O=bTsP!s~T>myO8Sf5va;I|DE3093+(C*q#n67a+?'
    'O92Nv3!4|3$%v5xB)Ue1?z=5=;?=l<LpGfFRWP{7v+t{9T3f;kR%4^NvY6ar-_nsqVKnTOv{CV_UE1vDnn;i0rJMNELbUE_jz8)1'
    'dkQNJYOtBO3ojE-VMy!e<~4tzG`iA#y_DZjnz={TZOUvfLq)D?qr`MSVapdAbF9hd+21F;YhhpCHecyvm#*3=5(h{Dyp;OiKHaQo'
    ';klFAyj|uv15i<6Iee!V!XS3Hri2IkQvR--+2^p(_XZYZya{akeXQAj=gm)_AW!AJ+lC&1&AJ?y4-~QLtk~-Qq*Gn7p>(lrB~5W@'
    '-UpfU{ytxEs!R*shtp-Hr1U&XucW&lOItut@P6bIWY)kXcDfiKdjv-u7VO5AOS-sJEf+y~P5}->*!jpI4Xe0bwn{e^R2aF-Sa0k`'
    '4r^PbYH_)|2raW~(YjV3)LYj8<IRN+^aA&N#yNivq@nG12j1(=@>a#E)SM0Iitd$0;%*7{A%eovBt;+(-SvbcjdaVF(c9e)V7fph'
    '=;?M;^U>M_WB;TGv$4nO`87O`CpZjHvO^wc$Lm8&AI1;^@3pN-3KC4!At8C(j^t3dP{}~;$QjY1C1b&>F>PQ6FDRu_W(>4|s!tZ`'
    '%nV$^K4F7cJk17!0Z@64W_ZW~b9<E1V2GCjgWfqlCOMoQb^aaZ6uX|+^<<hSW5BC&uj0rQPi5V5SQWYbGG;-6;?3zH=s47y3kywY'
    'Qk>YUW#Al-Fh>MVUCK=^KGe1BEs+;==VuzhQq!`VbM2vwZ#a0uUW2}CX7xK0Dj>1m3Gos;kQGn@@f|M;S`3cSU|?2O`y+fWk2Zme'
    'P^5z1nwFk_V`5=+6zmLL=WjfEM4Q8EPJA&adIQ)eA=9$jhg!oB^p8h|kxFgi72^xP+ob|15*cxlQhXr_xn(2M{1RaHLCZaO@_g@`'
    'y@P$@*}=)z+b@igakTpkp0}SHbJL(ucNdk$(f0AzCoDxawojgKA4?}%2@12|4nfA|2EYE5@oew;_CEgDJA%LHRCs={1LM5dJ~S4L'
    'oxPLS#?$SSZC%3D=8~Cbk)!Wo)V)xk<@GF*xP=)T{G1L4y=Z*1yK{1IM1vUn2PZK6_S4;`5`JBC^@>Ec^gc-8-+6v;yled5Kg}o`'
    'ydNdr5b=}-c@TzOGBC&)rS)F!-@rLt`@-^w?*L=r0LNFk#_`F~?(PY$l^XlLuCjf^9%xC&+q9u4yT;y&?Pt43uYXimgRl=I<>cV-'
    ';Mvjk;n#aRQ@!XK2ClxJXc_kpB-WlTtbkJY-JckQJf8@rX#E~k$l^Sm^PVQ8b^g;o{D;pQP5Mj#+@Jp3czW<^AF;|fIDR3JIn!Cn'
    'h$OZhr;LW8#@>s=gQF8XgJh{l3`$TVxax<|AZ=Ju_N0y<lKqISNV=#DC55S%_+rY&^hwhNjR&D<?EWMLX=;}GnMj`kOcIhDfmrC<'
    'dU>DjfdRU-yxz4J%VD7)t@YClK|U@96ry5rgwzxfjhi;6#_n@tNs*3EUOs(oY#;4zBTd2$D;c}TM|;MT?c-fKXEP`$8#UE(h{wjS'
    '|JpbJ`j440{J{%=2QxvC<Pb*j%#H{gzXLo&P%yOQB*k1*j0m&Pd~*c9RJ_96`jqK~8@$4wH{ST+M&zI3Mu+(G;T9fnS#IzgLzIWH'
    'ub6<EYO-_1UYI7w>RsarP!!s~0Yy$l{<p&*@(oYqr0U^4*${*sLKMe%Dh`|9Hm*swFwT9v00~Xee;s?*lnD+*u<qEAd_<s`LOU-G'
    '+P+Sng0`=aa+>3E>*637;0e``hL@*YNlkrjH^704cojw)X=Wv~rzswUmhhsSB2btQe@upG&PXP>*;l*UCohk7k7c5=3>=?02qN0l'
    '2uDcCj(4BE*xf(*E&E4ZyPfTSfBVJmQv*l&Eqf;no&x{y`S#B4F`Vje_MSfnem8HB2X-!v03<v--+sM&bSyETItK%?q@F@K0C*<r'
    'OvmY6GaM<30>U@mBBAZz;19puF!1yna2jsH=+Y3=y8t~8&bPamOe;mme>(`6l4uYBrHx{c({3bPk#NWtzb8P%-X@SRjRHtOnjf&B'
    'uVA6dzb8Pt9(srs7?Sb<ARVCkJ)}UM0t72V;qM6)RKn1304UEI3?@B155obaE>l3rYWG2LFR~+3+}r;Kj{m{YYl-elbI?5{t;D_;'
    'wJuUJxOl@8lTWl^7a{6kZtj>~qL&)DsEw%{{IP9Z2i>mM@ofw-z;tGVk01U5gaKf!n3D<vIY2}v&!fh6xc?&GoQS94P$e^1R?tHu'
    'NEnUvX35JbPCgtUX_LH(`47nxC^us$6Fj$uXfBZK${?~8J2O<BhqmPFy<^ynJ=B|C9z6j)>e<o3tCO$g<}7~_H^PYhL9yjU?Wx&t'
    '5o?m0&Bl?B@*Z&2Vbt^($2AK3HLxJyg~upBRW?>uKYsXmwOpyB>1;-n;{iy5NFoE4s`CXmZou-wF~z{uj2B_oyAI&!9fk1)z?Fw#'
    '*Dc3595%ZFD9LR=qG5Y1e9d*fTVZgpJEq=fdw@!?OHH)EdC~ZjcH&2@T0iXL#>4*Ud};UK@cHiNuUQ{Gzn{HiU&E;hBfJ<X)&#R='
    '__1T`_`P@-8^X(ux-{K4Lnpml7pMnI7>zMlZw%+=#~|##*aw|R;ObLAUclWG#X46$30>vEm&$(Q`@j4CufG4=AAa`n!*`Tc@E4d8'
    'CndFh|M$Q7?uUQ<!@rp>_&ZA0_{-mX2aW0BZ>Q?~@P9B>AtqJ){x8#w{}K~eQtHPUg@5&%?>N6@c1RrIXET8O$6o+|2*NMZ!~feK'
    'e)|3YLJ)uWS*GCoUqMGuke$;1{{9!)mkjFPWcnuPdF3$UBTgk<{y!*X<1eSz?Qa0A540{&WXzh==U~P0!ONqaT{1fzpX?q<d|3Uo'
    'zK9ASHh2cbI_5CDa$GBwq&AKU@wwNGf=j3Emq6n8N<rlHoQuI#7o)t;GVSKxG=WWDV%!O6l)Vs*d8j=-lWoaX1<i<<i@Q_C$DjV`'
    'X33i#8vBpifzxZXoKAS{1X1b1k*M?Ir+YZiK9LDLrG5AXe~Ej{8%?C+WveFM+;>{gY19i^!`ShM4-dVgsvA#4YF_~2*vABhAeNB7'
    '3l9Fg@qri&F8ooy8%6-dFz&=S>4%4XdHn3y*u}=XqA?DOvQ+HNUt3`GR~XxS6I=$MM+6=v(8i|{UY)Fg#{DKde?u04H_h>zKMcF)'
    'UI&Qan-?Llhc=MAcm2+Tz-gqCx+2XK$@KbKS;6)YrGf{5kyaQaX1wx;bhwtW4+OD+lNti$9g|sP;9<r_$9NIMF-mhR1jV*7?2+!o'
    '(hxicJt_7`$w;TxNWo>U2ABrLoy9PZG2k!E&M{6ft26xHGceOL$y;QAwwXuv3`&KI_?K`=(6f8MZaajbD0yALDh<YtaSSp|w;KQ`'
    '5?`Qa%4|z1+bL>YMEn^2D7*$uJE|LA3$%O&5s_R#O_`L3BK$~kWT~{5NNb<AFQL$zvVr4^j7^xyMe)iXctU?;>Qf^l@ax?ZWwuL<'
    '!SwH|XUFTyhyc5X$IoiZOVw3;(5**Lo*ewdSXy(cWnkm*cWKqw2ZeKa!&zR3H}H3D#n@FujiDvGzMO+Dcw&S`%H&MX(oC13fqilU'
    'DfzXjcOt3mbI!z0qy(hqL<UJ!Zo|R^-CX0a>!Udaz0?^^S^RnQXp@~7S?@*B?{xrubB#yr2{KVHVxFzVh(M#pJXcQ8wrnGU<w5VH'
    '*0Tw(S;pZ4v>lmN9X;%ivHIQJV=k61KI!Hhj9f0jk;ttx8syDtTgz$<YR&GEdkgYe4YzQ0W8LnCy&7!V%KFC2#HQVKZvlM<7gVEc'
    '-}v#MM!ReGK*FQfORF}l8@*mzQGQl(Ik>k-T52L80W5CK4C5=)#vyrl2Y%A1@-gh$XpOE_mh3iA4|a-66Hx8+%tkckw`4P`VWcBa'
    'l)PnwY}-a(Xsw*2bAU7Np5BgYC~4YWZFQw=V^Wok<&Db3ruVD(euLjHFRiSsiT7*xzEatsf^}FBS+I@;)s2m1D5!3f%d1PGV1s(9'
    'Qdi5BwYBASDyTvg?5bQ{#u6A|X?0bUR4P=myjp>h)uoM%mCEEy0)KuraC>fJe|XizAT_+qPuVWf!z!ZhO}|%sd2H&}`C@<Y1h6^}'
    '3rVNIH8ZEcv>D-DQ$u*ux@G*r6Jc78aKt?hd-dc!A1f%;U4`^cuf)A)YVk|W;ftI1lh=8%{r3ChN?dhu@x5(~+&sK5RM5r0v|3*5'
    '!SQgR_98_B9PX8%#5TrmzEY$&Kp%S-oDzEA_3-*~Nz}AT)y1C7<TtX%lMECuqi+7a4Fz<;j_}qYPY+(V@{+s$ZzVV8)a4HFj!qDV'
    'J-)aQUX`|^7D#iHA-*KCgU6*;VbpEE*<<zqAoY)_bqPl<eR=zS0{@KhpV8!PeQJF4HT_NiIDwAdz~~P_kR1vuk%yZ3F;E{8Jw&q+'
    'w{`lx&RcC&Q35@|dsSjtML>-|cHe$^n@n($=|-DB9c@Z90j*@DgrS!KRim=x+apK_Xr1%?!H=lrrngrHKsDdFx4~7X7F^jFc{CRE'
    '=^PN$Z}Y<hd(hHQ+(IMD!7Xn5%AgXem87JgYTQq{o(_4;klRq#%FY<Wuo^&9EG=s6^wPdQLkEvmk+14rGe~!LQ(de<7y3)S@RPrs'
    'IpC&?)j6xCy7S+Br)?-;6eb+DR1{CbT4u)Zw3B$9wvT9d7>xWbeP-qEu3}eVE4Tx`D4_z8DjbtULA)}^hoX{1b)o#vtIx&UU@*dk'
    'R#{>4ZMzKrqkmP9lSVXKXu_oM8YDZ&pyXuVyS!e=m25^Spj-S7sh9XgG|cY1Q*_OKXtfk+s)-qws)c;t85LX3$Xcud-@*(8GOP)U'
    '#!xh-qRI3%CPWOFefpx(gD{Xh!NY?{A&1M{c6xYM?_G5)Z2`-PXiO{+Bid>_s)H9Qjwz<w{Gw8+w5pz|-rv*ok?|uo3?}mvp4NFc'
    '#3KjmF1KN&QniW|8xSp9rJz?SRIr!V=_=!*+OnjZY@I@?PN4!*kof>cE<#oxZMryoeN-q|vS^G&uj^wfg1=BCuaN=M%#Z$A9yzFG'
    '6~tfhj9Wb3EZ^OY8^mIhWc@PZv`)5>UfS`<)lgDH$XE}wE94V=q;$qil`Pyc#7U;f0|!Vh^ayQj>;nEvf<+$>1l5F@WD#Jky0WyM'
    'L4Zs*gm!ebOSY;mEv+uMOs!-_J2*T7W#WtQ#=S+SQ;h`~%?kyBjPQBb<mpM(pf_3#GUumiu=_@<f}W974Sb=MOQ%Juj&gV;6(<5)'
    'w9sP4Y$+_Og#RwyxkqyceintkB!qdC`wl4>Z{%HR%6E(xygj}F1#>qS79Qi$IQVdPCrYHhOO^8HRqpbqCQTO83*p~4Xye9*Ffh*?'
    'P}{r1wjX2vmTXD&EY-7c8mW%)Sry79P^I!k7LhwJ-;N)Go)C?Ru4y$u;e<CG6;w?WUtOsG*46ny2V|-+f)P+f$MD_s3(Uw3eSPbU'
    '@S_HIci%c=`D4@&$EF|(8uGNj3k_UA&ZZBF;~`LmJfktlbl9a0jchS-UevAS8piCFZ6VbzR<p!1UETcRyu9Ap!276Q_-n1THI0bo'
    'XB`=!v|Izl$ydaeD_S+?5veg27V`a5lY_}U^X%@f&r$0O3kd;kxRt6n)FH+dQmRmy*V>#S_vh#5;?Pohyd6w{2(QcKvi|x>cNn=#'
    'sxbzR&x8b4aa35vwJfe!+4kj$`eF)Tg<z9-#9SRcy5mmRGq+M(Upq}b>KTwIrV>sfb;P`wzTI?3GCGGfZ&v4{0L8yzC_f00oYf`i'
    'yA@*3loV?wzP3U{QutS3=3~(jFF!^EpM(;(thyWp#Z>+XhunLu)+BRScr~~~3J}yVcM1{Jf!*ROxs~-58`N;SS}EI3wQ8BQEI|<!'
    'SE1hO64%44yW&dk%9;%dx?L$R!Ru8^N9RcvopmC%h5r&Jf#@WH2CNxlf3fT}*Zp+`Ru+DQr&@*omM|@DRl&7U0dP0$N)=wOtXSDY'
    'GzAL1z892=vs!c3Q-=?ERjDM*vgo2JV(#(CCvPhT0_D9v5cv^bJr!jXbZtxL-;~qOlI*Y5AEYozv&AG<8fz}Sg64oP`0v<WyN^Pd'
    'Uu;yo4SB@pQX)kJG)m;Gq-jw?QJP`5ZB#11E3&ejCMzacJ58G1r~nv1(=2XGlau-*U13rvHy|o-YF>q~OSrojJwNPSB4dmKOe&@`'
    '$AQ#!5$4wUTANrhUeSY{!ac+0$jI+$x71u-ZOTs<2-ID!+ST&9U0JEv&Klt8Bn2sB<UpnqngMKTsI98AUOQFb+ZuG4dbNtSCKS~Q'
    '3W}1%-2}PnN+@>|<f|ua#H}n%D{aF*TF>`nV1iOl&)u{jWOKBE5b(-2`4f)#w>)(4lV!JZB7l``A&_8U7}UxWTb$V#zjBjM<`Ly%'
    'OysT6l)N=1Z4ooYZ(T5K7XLYIofQgHq(}y#53@61YZ{XiO&m2FXemF7q=*X$b+CQC@TO<hCG4jcXKr45;BW0rCM<8JW9~9myz?u('
    'nkMqk)b$2ZRL<5GKw@#a0f9Zgftppim6E3CG^6r@d<X;CT1Brw)8z7qxCf5J5_T$o>o^WKRr_31-x8asOmz9v%QH)4qf=m-e2F|y'
    '#u_Mnn{ihF0I)_k(t-cwZJx2wq{z0|?@$<*nc$--<5yLPrztShqyR8Z)@LTzYR(9RG8G1!=wd9QTcXcg9J>RY=JZI$;lW;PPGDkp'
    'cbC>g-3S0UadEHlRZ}=a-fDMhADHDnIqo8ThS{#Cwp$;mkl7%)E9uO)O%QmB9!fpxTH*TV?S_mb{POnlljmNa$`gp{Ga2Xe`UeCf'
    'aa;1-#|trL$?FHDPB^&mu1e(QDWO%~v~Pj^w$b?vLSM~{VL6In6acTqtk7(n2`@$JMUi&#>ywj1!z@I2_j53erFrw6yq-z1@Oi7A'
    'CWh`i87#l0-r*;2L^brTKo$IhfZg5ECATR`TbG%?l2%CQ#A!<|p=3_#m7@~8ZoTF8y^>J8Aylv?DxlZEK(F1Wd`af{>$f#?_Wc!e'
    ')~I}Oi4v%%Mm4`!KX0#kKB-03=EiDEHrKqQ_dzXPr(fP)Iot$j?8|+M@-ZjqAANZU00P`tqpbqA-*|(&J7@yyCmxbkFtrEVvLps*'
    'a9GM2NKsB1fX#0>I9y!$GDOHYe)&d3=OGwg$9IfO0D266x+)A^#h?#+P>4QrZViZwPG^yjja>P?^PmHp*mmTdxzvX#;}A9juk(UD'
    'MH1{bGDFcDLRm9y{6ui}NXg|xsX@54P+zf48ElB;j(faLrVJ9vzr+i8SeU()AVLl}xCA&j`RKU^iVmZ|JeH8Lc{3bgLNz_TDv395'
    'ltIRQz)VyBR5BoD1f&2^@FE1(aCmTxlIJ|aVDojWxOQubjW3>nrUsZjmAq?WWBP(xCSlm^)MO@j>3$9wkwob3?(w@UEqdpW4+L;p'
    'MS-$C&y<OVHR4#mA9vF`rtUW+CyAmZ_#COb4#o+FT2Oc&ZJ-G7XbrqxXV~?kB-n%U_z9&5_g;m2AY!zFz8(~5)(4@7S9hmSEG9i&'
    '2LX^SywsCbr<%6Y%aTf8ZJSM$A0Aki%)&ax4kboZM-;C@#c`d(To84W!(|)6IV{@PhE>2&n;2Vpz*j*H2zm&-I$dOQm~jyK@)gD!'
    'QI1WvY|yVHZ5=+c_i3rRh~94cM=iuNKScb4b;e7wzOhs_UOd6j8j7^=BU7#e_c%!(_&ovu=Oy}q>fd<X0Op4;2_?L1{E3^&b5HMA'
    '`Wyofbm=(I*9%2z0-6B@N~ljCKX`6=W&VGjTEV_+@b|Yrue`4Joz~3u@qA~V!g)s^HO4H|pM!={cIOqgI1K}TRW(s6nLg~$huHE;'
    '2b*C77LHAlXVA>nAISWvQ|4gdki#gItj(8VRkD`hNxGNkpf7NIhH2p_sp`t-F~hEgm8Z<k^gTjurB4AT1@$xEWL2{pxn+9{|MlFm'
    'rl`_AL1;zim*YyDApVN7jOF{7ZhK*2`ZY+_*6pa^Vukt`|5ncGy+T1bi+fwNR^w8SmS<GzO=_9@{Y-to64X5Zt=uSJu!4i8?<I)q'
    '{!kBDuy)^H8a5`vYvo5*vHPuxi_yLXD^D;c#z@P+Qj<GZm-eT9Bx0CTVM*3CZ}s5!@WF}vb6aWL@Qc*6vpHY!#V^0k09Lb`;Edp0'
    'Cpl8+>rVP2sQj1tb3KdX+({U3Q%RLzv3Zr<+?Th(B+*IzxHZ?7o){l+*7z2tjY6yl&lGEGCfXxM&}qFUMhUS-_+!cmb(L^^?o0&Y'
    'i5s?WwXAngd-h$F{m`IKf|52YuABtDgf(=>QYMznL1u`++<Caz(`kofDupwZmL=b$)o<b#P<Bx@dJe1?BWd#{Wk)b=EiFXLO_M6h'
    'Zy&IwzNH(*S{Zv-D{Bf%q90c5<h2TFNTbTz*$Z?mqEb<hk^3V-%HWWdLWX&j1ddGY9%;?^l^iW6t{5+t_C`Ylv&HnKW9_@f3!9Cc'
    'i61p?;kO;k1z?g3-c`R2jAj#mcL(?rGj}a?=w}Xpeme~DA!p{`;ftk>x;deou$fQ^{D$`+AGB?ZA`+YAcYzpTC}zv`yHkOa_6@$}'
    'R4K1GQlh$Ewl9*mUz3yX?ygc<|AZJAXvXm`H;Zk25Ya6c@YK35j3N_6absUdS_d35b}{Brec1aHW_M;`@Iit%fZ|xuTC6ygD#k7V'
    'pXhsS_qJPGTDGIwx{co~vzxVQb%KzjJ?kq=tIKT@-s^tC^k)o~>H7t@9IOC6JA*?0qDVjJ-=?(~l$M~2ls7@TsIW$t!nLG3>V{fH'
    '{7!j9TEYQ<-<KQ)#jCIv(oFz_O*j6poo_5PtN0eTavML6=9=^!NOL~i*BD%}n6DH8P)l@3SS#{^dFGZDdUQP%m}%AY;!>qtE?Wf?'
    'NCM5SxMI&;mco)HcpHiXxKT{%ujQA|Yt%&{SQP8h<<+rDd8#baQCar5CI+b#uS+l;YcVq%X1z{t0!kE$y!C0sU`y>o-x&dWLywi('
    'EAhsf!V~4`(eR|IZC|pxFy?6@$>2v(M)rk(FkP#hDN4B@^*tAPgICBgC%;f9@q#LAsK6ib&0@{^(#BeI1+C_An$(i;=jSza5ZgV1'
    'HLwxHfI(cf&_I~YZiE5b4$)%d6!hUN{_-0rJy?`ZxTGb-0n$byu_>*2*lKnXA{nYzPiUN(x^)PBVV3k+#r?34ZYeZw+RH#`G&Mk*'
    '46XX~Y(TdJocQz!A@u3_aOCBqbO3yj`<u^Wv0OO`5VZR$Qw3R@98&kyrV6sQNUL&Rea=3Z<<yw8Y+d8jg^HDAIMn*auh4yV=RnSv'
    'wZ4nfeJjJ#J$=hMQ!3Yt7L+H?w0)oqiBTY()R4XuFS_D{DGyGJ+}N1of-XMI(6dE9m}^npp_rF$Ql#pcN;>%|YfF*WNw%!WLknpt'
    'ewVl}9<Uz)27OT@IWvQ>)4^<MoXEwrN5EQ|YUwz+O2!bBjt|G%6kF!K*;mZkbV&P_DFV_BXu2Cm0crEWAZEL$ys89kP3(?dikiy4'
    '3t*m_?Dn%cc0mSy;R_0Cv(3aHnuyJpZbP@3nuW{z@Ql)v$`xT9aV9c}Z&v#F5wn!4na<+qz`9)J@ylZLsm&;?KN69#(_Ly={ix$x'
    'QS<&pd;(YS@=7YNpPti?F2E!asa^W6un_nsGT1r8D6qp0*%T%!9(pd!NQxO|5eOt8`n;%Mo09pt)s@x7>f)jnRom9n2qwJ)>uc-T'
    '1htZJHWHWKCgHgJ81_;cjkpmqaxp5mJt|?~W^e3bbZvW#Pnw$48<p}YAg#rv)pD`2UY5QpKWe!$GzCPW>SAx4Z6Y@h^)S9wf_F*i'
    '7hNyGJ}i)%*UR#9NkVPqwWqM}YUG5_fD=V#cU3Y>ZDSwY*C8-y9O7XNfbtgRb$*~WWxr%hnUVf-HoKX_)>5f5Yru(;Y@+sUAHP3x'
    '?TgzL_W;yxb_G%PKbx7}1U)#cGdg9VNYHt81A-)n-;KaTNmnI5m>yrG8&)SW$u|rqtdEhD8bm_ALQW?pL_P#^nel}>7GrGSlmPri'
    'O^InNu-GiniW_xyvl)(Rc$05ZpOK2OgeGRZ;D|TF8;|}Uk)0%y'
)


WEB_HTML = zlib.decompress(base64.b85decode(WEB_HTML_B85.encode("ascii"))).decode("utf-8")

UI_SHELL_HTML = r"""<!doctype html>
<html lang="en" dir="rtl">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="theme-color" content="#000000"><title>OBLIVION ORBITAL 5.3</title>
<style>
:root{color-scheme:dark;--bg:#000;--surface:#070707;--accent:#91a9ff;--text:#e8eaf0;--muted:#9297a5;--line:rgba(255,255,255,.12);--glass:rgba(255,255,255,.045)}
*{box-sizing:border-box}html,body{margin:0;width:100%;height:100%;background:#000;color:var(--text);font:13px/1.45 Inter,"Segoe UI",system-ui,sans-serif;overflow:hidden}
body{display:flex;flex-direction:column}.shell{height:100%;display:flex;flex-direction:column;min-height:0;background:#000}
.shell-head{height:58px;min-height:58px;display:flex;align-items:center;gap:18px;padding:0 18px;background:rgba(8,8,8,.86);border-bottom:1px solid var(--line);backdrop-filter:blur(20px);z-index:5}
.brand{display:flex;align-items:center;gap:10px;white-space:nowrap}.brand-mark{width:27px;height:27px;border:1px solid rgba(145,169,255,.55);border-radius:50%;display:grid;place-items:center;color:var(--accent);font-size:15px}.brand-name{font-weight:700;letter-spacing:.16em;color:#fff;font-size:12px}.brand-sub{display:block;color:var(--muted);font:9px/1.4 ui-monospace,monospace;letter-spacing:.14em}
.tabs{display:flex;align-items:center;gap:6px;overflow-x:auto;flex:1;scrollbar-width:none}.tabs::-webkit-scrollbar{display:none}
.tab{border:1px solid transparent;background:transparent;color:var(--muted);padding:8px 15px;border-radius:10px;cursor:pointer;white-space:nowrap;font:inherit;transition:all .2s}
.tab:hover{color:#fff;background:rgba(255,255,255,.05);border-color:var(--line)}.tab[aria-selected="true"]{color:#fff;background:rgba(145,169,255,.13);border-color:rgba(145,169,255,.42);box-shadow:inset 0 0 18px rgba(145,169,255,.06)}
.head-actions{display:flex;align-items:center;gap:9px}.version{color:var(--muted);font:10px ui-monospace,monospace;border:1px solid var(--line);border-radius:999px;padding:5px 9px;white-space:nowrap}
.head-btn{border:1px solid var(--line);background:var(--glass);color:var(--text);border-radius:10px;padding:7px 10px;cursor:pointer;transition:all .2s}.head-btn:hover{border-color:var(--accent);color:#fff}
.workspace{position:relative;flex:1;min-height:0;background:#000}.module-frame{position:absolute;inset:0;width:100%;height:100%;border:0;background:#000;display:none}.module-frame.active{display:block}
.shell-foot{height:25px;min-height:25px;display:flex;align-items:center;justify-content:space-between;padding:0 12px;color:#777d89;background:#050505;border-top:1px solid rgba(255,255,255,.07);font:9px ui-monospace,monospace;letter-spacing:.06em}
.about-backdrop{position:fixed;inset:0;background:rgba(0,0,0,.72);display:none;align-items:center;justify-content:center;padding:18px;z-index:30;backdrop-filter:blur(8px)}.about-backdrop.open{display:flex}.about-card{width:min(480px,100%);padding:24px;background:rgba(12,12,12,.94);border:1px solid var(--line);border-radius:18px;box-shadow:0 20px 70px #000}.about-card h2{margin:0 0 7px;font-size:18px}.about-card p{color:var(--muted);line-height:1.7}.about-meta{display:grid;grid-template-columns:110px 1fr;gap:8px;margin:20px 0;font:11px ui-monospace,monospace}.about-meta span:nth-child(odd){color:var(--muted)}.about-meta span:nth-child(even){color:#fff}.about-close{border:1px solid var(--line);background:var(--glass);color:#fff;padding:8px 14px;border-radius:9px;cursor:pointer}
@media(max-width:700px){.shell-head{height:auto;min-height:56px;flex-wrap:wrap;gap:8px;padding:8px 10px}.brand{min-width:0}.brand-sub{display:none}.tabs{order:3;flex-basis:100%;width:100%}.tab{padding:7px 12px}.head-actions{margin-inline-start:auto}.version{display:none}.shell-foot{font-size:8px}}
</style>
</head>
<body>
<div class="shell">
<header class="shell-head">
  <div class="brand"><div class="brand-mark">◈</div><div><div class="brand-name">OBLIVION</div><small class="brand-sub">ORBITAL INTELLIGENCE SYSTEMS</small></div></div>
  <nav class="tabs" role="tablist" aria-label="Application modules">
    <button class="tab" role="tab" id="tab-orbital" aria-selected="true" data-module="orbital">Orbital</button>
    <button class="tab" role="tab" id="tab-umbra" aria-selected="false" data-module="umbra">Umbra</button>
    <button class="tab" role="tab" id="tab-web" aria-selected="false" data-module="web">Web / GOTHAM</button>
  </nav>
  <div class="head-actions"><span class="version">BUILD 5.3</span><button class="head-btn" id="aboutBtn" type="button">About</button><button class="head-btn" id="logoutBtn" type="button" title="Sign out">↗</button></div>
</header>
<main class="workspace">
  <iframe class="module-frame active" id="frame-orbital" title="Orbital Core" src="/orbital-app" referrerpolicy="same-origin"></iframe>
  <iframe class="module-frame" id="frame-umbra" title="Umbra Intelligence" data-src="/umbra/" referrerpolicy="same-origin"></iframe>
  <iframe class="module-frame" id="frame-web" title="Web and GOTHAM" data-src="/web/" referrerpolicy="same-origin"></iframe>
</main>
<footer class="shell-foot"><span>OBLIVION ORBITAL · LOCAL-FIRST MODULAR RUNTIME</span><span id="shellStatus">CORE ONLINE · BUILD 5.3</span></footer>
</div>
<div class="about-backdrop" id="aboutBackdrop" role="dialog" aria-modal="true" aria-labelledby="aboutTitle"><section class="about-card"><h2 id="aboutTitle">OBLIVION ORBITAL 5.3</h2><p>Unified local-first application shell. Orbital manages the process lifecycle; Umbra provides data intelligence; Web hosts the embedded geospatial workspace.</p><div class="about-meta"><span>Version</span><span>5.3</span><span>Architecture</span><span>Single process · Plugin registry</span><span>Modules</span><span>Orbital · Umbra · Web/GOTHAM</span><span>Runtime</span><span>Python 3.10+</span></div><button class="about-close" id="aboutClose" type="button">Close</button></section></div>
<script>
(()=>{'use strict';
const tabs=[...document.querySelectorAll('[data-module]')];
const frames={orbital:document.getElementById('frame-orbital'),umbra:document.getElementById('frame-umbra'),web:document.getElementById('frame-web')};
function select(name){for(const t of tabs)t.setAttribute('aria-selected',String(t.dataset.module===name));for(const [key,frame] of Object.entries(frames)){const active=key===name;frame.classList.toggle('active',active);if(active&&!frame.src&&frame.dataset.src)frame.src=frame.dataset.src;else if(active&&frame.dataset.src&&!frame.hasAttribute('data-loaded')){frame.src=frame.dataset.src;frame.dataset.loaded='1'}}document.getElementById('shellStatus').textContent=name.toUpperCase()+' MODULE · BUILD 5.3';}
tabs.forEach(t=>t.addEventListener('click',()=>select(t.dataset.module)));
const backdrop=document.getElementById('aboutBackdrop');document.getElementById('aboutBtn').addEventListener('click',()=>backdrop.classList.add('open'));document.getElementById('aboutClose').addEventListener('click',()=>backdrop.classList.remove('open'));backdrop.addEventListener('click',e=>{if(e.target===backdrop)backdrop.classList.remove('open')});document.addEventListener('keydown',e=>{if(e.key==='Escape')backdrop.classList.remove('open')});
document.getElementById('logoutBtn').addEventListener('click',async()=>{try{await fetch('/api/logout',{method:'POST',credentials:'same-origin'})}finally{location.href='/login'}});
})();
</script>
</body></html>"""


def _umbra_frontend_html() -> str:
    """Return Umbra's full SPA with API requests mounted under /umbra."""
    if not UMBRA_AVAILABLE:
        return _module_unavailable_html("Umbra", UMBRA_IMPORT_ERROR)
    page = _umbra_FRONTEND_HTML.replace('data-theme="light"', 'data-theme="dark"', 1)
    patch = ("<script id=\"orbital53-api-mount\">\n"
             "(()=>{const nativeFetch=window.fetch.bind(window);window.fetch=(input,init)=>{\n"
             "if(typeof input==='string' && input.startsWith('/api/')) input='/umbra'+input;\n"
             "else if(input instanceof URL && input.origin===location.origin && input.pathname.startsWith('/api/')){const u=new URL(input);u.pathname='/umbra'+u.pathname;input=u;}\n"
             "return nativeFetch(input,init);};})();\n</script>")
    page = page.replace('</head>', patch + '\n</head>', 1)
    return _apply_shared_theme(page, "umbra")


def _decode_web_html() -> str:
    """Decode the embedded, self-contained GOTHAM UI source."""
    return zlib.decompress(base64.b85decode(WEB_HTML_B85.encode("ascii"))).decode("utf-8")





def _start_orbital_module() -> None:
    """Orbital data stores and engines are initialized by the core at import."""
    return None


def _start_umbra_module() -> None:
    global UMBRA_APP, UMBRA_ROUTE_HANDLER, UMBRA_AVAILABLE, UMBRA_IMPORT_ERROR
    if not _umbra_UMBRA_NUMPY_AVAILABLE:
        UMBRA_AVAILABLE = False
        UMBRA_IMPORT_ERROR = "NumPy is required by the supplied Umbra engine. Install it with: pip install numpy"
        return
    cfg = _umbra_AppConfig.load()
    UMBRA_APP = _umbra_UmbraApp(cfg)
    UMBRA_ROUTE_HANDLER = _umbra_make_handler(UMBRA_APP)
    UMBRA_AVAILABLE = True
    UMBRA_IMPORT_ERROR = ""


def _stop_umbra_module() -> None:
    global UMBRA_APP, UMBRA_ROUTE_HANDLER
    try:
        if UMBRA_APP is not None:
            UMBRA_APP.storage.close()
    finally:
        UMBRA_APP = None
        UMBRA_ROUTE_HANDLER = None


MODULES.register("orbital", _start_orbital_module)
MODULES.register("umbra", _start_umbra_module, _stop_umbra_module)
MODULES.register("web", lambda: None)


def _dispatch_umbra(self, method: str) -> None:
    """Dispatch a /umbra/api request through Umbra's original route table."""
    if not UMBRA_AVAILABLE or UMBRA_ROUTE_HANDLER is None:
        self._json({"error": "Umbra is not initialized"}, 503)
        return
    original_path = self.path
    try:
        parsed = urllib.parse.urlsplit(original_path)
        stripped = parsed.path[len("/umbra"):] or "/"
        self.path = stripped + (("?" + parsed.query) if parsed.query else "")
        if method == "GET":
            UMBRA_ROUTE_HANDLER._route_get(self)
        elif method == "POST":
            UMBRA_ROUTE_HANDLER._route_post(self)
        else:
            self._json({"error": "method not allowed"}, 405)
    except Exception as exc:
        try:
            if UMBRA_APP is not None:
                UMBRA_APP.logger.exception("Umbra route failure")
            self._json({"error": str(exc)}, 500)
        except Exception:
            pass
    finally:
        self.path = original_path


def _is_loopback_request(self) -> bool:
    try:
        return ipaddress.ip_address(self.client_address[0]).is_loopback
    except Exception:
        return False


def _validate_external_target(url: str) -> tuple[bool, str]:
    """Reject malformed targets and private addresses before proxying."""
    try:
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            return False, "Only absolute HTTP(S) URLs are accepted."
        if parsed.username or parsed.password:
            return False, "Credentials in proxy URLs are not accepted."
        if len(url) > 4096:
            return False, "URL is too long."
        if _WEB_ALLOW_PRIVATE:
            return True, ""
        addresses = socket.getaddrinfo(parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80), type=socket.SOCK_STREAM)
        if not addresses:
            return False, "Host did not resolve."
        for entry in addresses:
            ip = ipaddress.ip_address(entry[4][0])
            if (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
                    or ip.is_multicast or ip.is_unspecified):
                return False, "Private, loopback, reserved and link-local destinations are blocked."
        return True, ""
    except Exception as exc:
        return False, f"Invalid proxy target: {exc}"


class _SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Prevent an external proxy redirect from reaching a private address."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        ok, reason = _validate_external_target(newurl)
        if not ok:
            raise urllib.error.HTTPError(newurl, code, reason, headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_WEB_OPENER = urllib.request.build_opener(_SafeRedirectHandler())


def _bridge_health(self) -> None:
    self._json({"ok": True, "name": "OrbitalIntegratedBridge", "version": APP_VERSION,
                "lmstudio": _WEB_LM_BASE, "proxy": True})


def _bridge_proxy(self) -> None:
    """CORS-free, cached external feed proxy with private-network blocking."""
    parsed = urllib.parse.urlsplit(self.path)
    target = urllib.parse.parse_qs(parsed.query).get("url", [""])[0]
    ok, reason = _validate_external_target(target)
    if not ok:
        self._json({"error": reason or "Bad URL"}, 400 if "Invalid" in reason or "absolute" in reason else 403)
        return
    now = time.time()
    with _WEB_CACHE_LOCK:
        hit = _WEB_CACHE.get(target)
        if hit and _WEB_CACHE_TTL and now - hit[0] <= _WEB_CACHE_TTL:
            status, content_type, data = 200, hit[1], hit[2]
        else:
            status = 0
            content_type = "application/octet-stream"
            data = b""
    if not status:
        headers = {"User-Agent": "OblivionOrbital/5.3"}
        for name in ("Authorization", "x-windy-api-key"):
            value = self.headers.get(name)
            if value:
                headers[name] = value
        try:
            request = urllib.request.Request(target, headers=headers, method="GET")
            with _WEB_OPENER.open(request, timeout=60) as response:
                data = response.read(_WEB_PROXY_MAX_BYTES + 1)
                content_type = response.headers.get("Content-Type", "application/octet-stream")
                status = response.status
            if len(data) > _WEB_PROXY_MAX_BYTES:
                self._json({"error": "Upstream response exceeds proxy size limit."}, 413)
                return
            with _WEB_CACHE_LOCK:
                _WEB_CACHE[target] = (time.time(), content_type, data)
        except urllib.error.HTTPError as exc:
            body = exc.read(1024 * 1024)
            self.send_response(exc.code)
            self.send_header("Content-Type", exc.headers.get("Content-Type", "text/plain; charset=utf-8"))
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        except Exception as exc:
            self._json({"error": str(exc)}, 502)
            return
    self.send_response(status)
    self.send_header("Content-Type", content_type)
    self.send_header("Content-Length", str(len(data)))
    self.send_header("Cache-Control", f"private, max-age={_WEB_CACHE_TTL}")
    self.end_headers()
    self.wfile.write(data)


def _bridge_lm_proxy(self) -> None:
    """Forward LM Studio API traffic; restricted to local clients."""
    if not _is_loopback_request(self):
        self._json({"error": "LM Studio passthrough is available only to loopback clients."}, 403)
        return
    parsed = urllib.parse.urlsplit(self.path)
    suffix = parsed.path[3:]  # remove /lm
    if not suffix.startswith("/"):
        suffix = "/" + suffix
    target = _WEB_LM_BASE + suffix + (("?" + parsed.query) if parsed.query else "")
    length = int(self.headers.get("Content-Length", "0") or 0)
    if length < 0 or length > 32 * 1024 * 1024:
        self._json({"error": "Request body exceeds LM Studio proxy limit."}, 413)
        return
    body = self.rfile.read(length) if length else None
    headers = {"User-Agent": "OblivionOrbital/5.3"}
    for name in ("Content-Type", "Accept", "Authorization"):
        value = self.headers.get(name)
        if value:
            headers[name] = value
    request = urllib.request.Request(target, data=body,
                                     method=self.command if self.command in ("GET", "POST", "PUT", "DELETE", "OPTIONS") else "GET",
                                     headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=180) as response:
            self.send_response(response.status)
            self.send_header("Content-Type", response.headers.get("Content-Type", "application/octet-stream"))
            for name in ("Cache-Control", "Retry-After"):
                value = response.headers.get(name)
                if value:
                    self.send_header(name, value)
            self.end_headers()
            while True:
                chunk = response.read(65536)
                if not chunk:
                    break
                self.wfile.write(chunk)
                self.wfile.flush()
    except urllib.error.HTTPError as exc:
        payload = exc.read(2 * 1024 * 1024)
        self.send_response(exc.code)
        self.send_header("Content-Type", exc.headers.get("Content-Type", "application/json"))
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)
    except (BrokenPipeError, ConnectionResetError):
        return
    except Exception as exc:
        try:
            self._json({"error": f"LM Studio unavailable: {exc}"}, 502)
        except Exception:
            pass


# Attach shared protocol helpers to Orbital's HTTP handler. Umbra's original
# route closures call these same helper names, so no second HTTP server exists.
def _umbra_send_json(self, payload, status=200):
    try:
        encoded = json.dumps(payload, ensure_ascii=False, cls=_umbra_JSONEncoder, default=str).encode("utf-8")
    except Exception:
        encoded = json.dumps({"error": "Response serialization failed"}).encode("utf-8")
        status = 500
    self.send_response(status)
    self.send_header("Content-Type", "application/json; charset=utf-8")
    self.send_header("Content-Length", str(len(encoded)))
    self.end_headers()
    self.wfile.write(encoded)


def _umbra_send_html(self, page):
    encoded = str(page).encode("utf-8")
    self.send_response(200)
    self.send_header("Content-Type", "text/html; charset=utf-8")
    self.send_header("Content-Length", str(len(encoded)))
    self.end_headers()
    self.wfile.write(encoded)


def _umbra_error(self, message, status=400):
    try:
        if UMBRA_APP is not None:
            UMBRA_APP.logger.warning("API error [%s]: %s", status, message)
    except Exception:
        pass
    _umbra_send_json(self, {"error": str(message)}, status)


Handler._send_json = _umbra_send_json
Handler._send_html = _umbra_send_html
Handler._error = _umbra_error
Handler._dispatch_umbra = _dispatch_umbra
Handler._bridge_health = _bridge_health
Handler._bridge_proxy = _bridge_proxy
Handler._bridge_lm_proxy = _bridge_lm_proxy


def main() -> None:
    """Start Orbital 5.3 and all registered modules in one HTTP process."""
    parser = argparse.ArgumentParser(prog="orbital5.3", description=f"{APP_NAME} v{APP_VERSION}")
    add_arguments(parser)
    parser.add_argument("--version", action="version", version=f"{APP_NAME} {APP_VERSION}")
    args = parser.parse_args()
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    print_banner(args.host, args.port)
    MODULES.start_all(logging.getLogger("orbital53"))
    class OrbitalHTTPServer(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True
        block_on_close = False
    server = OrbitalHTTPServer((args.host, args.port), Handler)
    server.daemon_threads = True
    print(f"  Modules:          {', '.join(MODULES.status())}")
    print(f"  Umbra:            {'enabled' if UMBRA_AVAILABLE else 'unavailable — ' + UMBRA_IMPORT_ERROR}")
    print(f"  Bridge:           integrated (/proxy, /lm/, /health)")
    print(f"  About:            OBLIVION ORBITAL v5.3")
    print("-" * 72)
    print(f"  Open:             http://{args.host}:{args.port}/")
    try:
        server.serve_forever(poll_interval=0.35)
    except KeyboardInterrupt:
        print("\\n[Oblivion Orbital 5.3] Shutting down...")
    finally:
        server.shutdown()
        server.server_close()
        MODULES.stop_all(logging.getLogger("orbital53"))


if __name__ == "__main__":
    main()
