"""
NGDSA CTF - dashboard ingest service (scoreboard backend).
Containers report captures with a PER-TEAM HMAC token issued by the spawner.
"""
import hashlib
import hmac
import os
import re
import sqlite3
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

DB_PATH = os.environ.get("DASHBOARD_DB_PATH", str(Path(__file__).parent / "ctf_dashboard.db"))
ADMIN_KEY = os.environ.get("DASHBOARD_ADMIN_KEY", "")
INGEST_SECRET = os.environ.get("INGEST_SECRET", "")
EVENT_PASSWORD = os.environ.get("EVENT_PASSWORD", "")
SHOW_PASSWORD = os.environ.get("SHOW_EVENT_PASSWORD", "0") == "1"   # 1 = show the gate password on the public board
JOIN_URL = os.environ.get("JOIN_URL", "")                            # e.g. ctf.uni.gr, shown next to the password
for _n, _v in (("DASHBOARD_ADMIN_KEY", ADMIN_KEY), ("INGEST_SECRET", INGEST_SECRET)):
    if len(_v) < 8 or _v in ("changeme", "super_secret_ingest_key"):
        raise RuntimeError(f"{_n} is missing, too short, or a known default - refusing to start")

FLAGS = [{"name": n, "phase": 1, "points": 100} for n in ("A1", "A2", "A3", "A4", "A5")] + \
        [{"name": n, "phase": 2, "points": 150} for n in ("B1", "B2", "B3", "B4", "B5")]
FLAG_INDEX = {f["name"]: i for i, f in enumerate(FLAGS)}
FLAG_META = {f["name"]: f for f in FLAGS}
TEAM_RE = re.compile(r"[a-z0-9_-]{1,32}")

_rate_buckets: dict = {}
_rate_lock = threading.Lock()

def check_rate_limit(key: str, max_calls: int, window_seconds: int) -> bool:
    now = time.monotonic()
    with _rate_lock:
        bucket = _rate_buckets.setdefault(key, [])
        while bucket and bucket[0] < now - window_seconds:
            bucket.pop(0)
        if len(bucket) >= max_calls:
            return False
        bucket.append(now)
        return True

def enforce_rate_limit(request: Request, name: str, max_calls: int, window_seconds: int):
    ip = request.client.host if request.client else "unknown"
    if not check_rate_limit(f"{name}:{ip}", max_calls, window_seconds):
        raise HTTPException(429, "too many requests")

def token_ok(team_id: str, token: str) -> bool:
    return bool(TEAM_RE.fullmatch(team_id)) and hmac.compare_digest(token.encode(), ingest_token(team_id).encode())

def ingest_token(team_id: str) -> str:
    # must match spawner._ingest_token
    return hmac.new(INGEST_SECRET.encode(), f"ingest:{team_id}".encode(), hashlib.sha256).hexdigest()[:40]

@contextmanager
def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()

def init_db():
    with db() as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS captures (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            team_id TEXT NOT NULL, flag_name TEXT NOT NULL, ts TEXT NOT NULL,
            UNIQUE(team_id, flag_name))""")
        conn.execute("CREATE TABLE IF NOT EXISTS teams (team_id TEXT PRIMARY KEY, ts TEXT NOT NULL)")

app = FastAPI(title="NGDSA CTF Dashboard", docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["GET"], allow_headers=[])

class Capture(BaseModel):
    team_id: str = Field(..., min_length=1, max_length=32)
    flag_name: str
    timestamp: Optional[str] = None  # accepted for compatibility, IGNORED (server clock is authoritative)

@app.on_event("startup")
def _startup():
    init_db()

@app.post("/api/ingest")
def ingest(request: Request, capture: Capture, token: str = ""):
    enforce_rate_limit(request, "ingest", max_calls=600, window_seconds=60)
    if not token_ok(capture.team_id, token):
        raise HTTPException(403, "invalid token")
    if capture.flag_name not in FLAG_INDEX:
        raise HTTPException(400, "unknown flag_name")
    ts = datetime.now(timezone.utc).isoformat()
    with db() as conn:
        try:
            conn.execute("INSERT INTO captures (team_id, flag_name, ts) VALUES (?, ?, ?)",
                         (capture.team_id, capture.flag_name, ts))
        except sqlite3.IntegrityError:
            return {"status": "duplicate"}
    return {"status": "recorded"}

class Reg(BaseModel):
    team_id: str = Field(..., min_length=1, max_length=32)

@app.post("/api/register")
def register(request: Request, reg: Reg, token: str = ""):
    # called by the spawner so teams show up on the board before their first capture
    enforce_rate_limit(request, "register", max_calls=120, window_seconds=60)
    if not token_ok(reg.team_id, token):
        raise HTTPException(403, "invalid token")
    with db() as conn:
        conn.execute("INSERT OR IGNORE INTO teams (team_id, ts) VALUES (?, ?)", (reg.team_id, datetime.now(timezone.utc).isoformat()))
    return {"status": "ok"}

@app.get("/api/standings")
def standings():
    with db() as conn:
        rows = conn.execute("SELECT team_id, flag_name, ts FROM captures").fetchall()
        regs = conn.execute("SELECT team_id, ts FROM teams").fetchall()
    teams: dict = {}
    blank = lambda tid, reg=None: {"team_id": tid, "flags": [0] * len(FLAGS), "last_capture": None, "registered": reg}
    for r in regs:
        teams[r["team_id"]] = blank(r["team_id"], r["ts"])
    for r in rows:
        if r["flag_name"] not in FLAG_INDEX:
            continue
        t = teams.setdefault(r["team_id"], blank(r["team_id"]))
        t["flags"][FLAG_INDEX[r["flag_name"]]] = 1
        if t["last_capture"] is None or r["ts"] > t["last_capture"]:
            t["last_capture"] = r["ts"]
    out = [{**t, "score": sum(FLAGS[i]["points"] for i, h in enumerate(t["flags"]) if h)} for t in teams.values()]
    # more points first; same points -> whoever reached them EARLIER first; then registration order
    out.sort(key=lambda t: (-t["score"], t["last_capture"] or "9", t["registered"] or "9", t["team_id"]))
    return out

@app.get("/api/feed")
def feed(limit: int = 20):
    limit = max(1, min(limit, 100))
    with db() as conn:
        rows = conn.execute("SELECT team_id, flag_name, ts FROM captures ORDER BY ts DESC LIMIT ?", (limit,)).fetchall()
    return [{"team": r["team_id"], "flag": r["flag_name"], "phase": FLAG_META[r["flag_name"]]["phase"],
             "points": FLAG_META[r["flag_name"]]["points"], "time": r["ts"]}
            for r in rows if r["flag_name"] in FLAG_META]

@app.get("/api/firstblood")
def firstblood():
    with db() as conn:
        rows = conn.execute("SELECT flag_name, team_id, MIN(ts) AS ts FROM captures GROUP BY flag_name").fetchall()
    return {r["flag_name"]: {"team": r["team_id"], "time": r["ts"]} for r in rows if r["flag_name"] in FLAG_META}

@app.get("/api/banner")
def banner(request: Request, x_admin_key: Optional[str] = Header(None)):
    # Public view shows the password only when SHOW_EVENT_PASSWORD=1 (turn it on at event start, off afterwards).
    # An organizer can always see it with the admin key in a header, but only via localhost/SSH tunnel.
    enforce_rate_limit(request, "banner", max_calls=300, window_seconds=60)
    proxied = any(h in request.headers for h in ("x-forwarded-for", "forwarded", "x-real-ip"))
    keyed = bool(x_admin_key) and not proxied and hmac.compare_digest(x_admin_key.encode(), ADMIN_KEY.encode())
    show = bool(EVENT_PASSWORD) and (SHOW_PASSWORD or keyed)
    return JSONResponse({"event_password": EVENT_PASSWORD if show else None, "join_url": JOIN_URL},
                        headers={"Cache-Control": "no-store"})

@app.post("/api/reset")
def reset(request: Request, x_admin_key: Optional[str] = Header(None)):
    enforce_rate_limit(request, "reset", max_calls=10, window_seconds=60)
    if not (x_admin_key and hmac.compare_digest(x_admin_key.encode(), ADMIN_KEY.encode())):
        raise HTTPException(403, "bad admin key")
    with db() as conn:
        conn.execute("DELETE FROM captures")
    return {"status": "cleared"}

# --- admin backup / wipe (only reachable from the host, never routed by nginx) -------------------
BACKUP_DIR = Path(os.environ.get("DASHBOARD_BACKUP_DIR", str(Path(DB_PATH).resolve().parent / "backups")))
BACKUP_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")

def _admin_only(request: Request, x_admin_key: Optional[str]):
    if any(h in request.headers for h in ("x-forwarded-for", "forwarded", "x-real-ip")):
        raise HTTPException(404, "Not Found")
    enforce_rate_limit(request, "adminops", max_calls=30, window_seconds=60)
    if not (x_admin_key and hmac.compare_digest(x_admin_key.encode(), ADMIN_KEY.encode())):
        raise HTTPException(403, "bad admin key")

class BackupReq(BaseModel):
    name: str = Field(..., min_length=1, max_length=64)

@app.post("/api/admin/backup")
def admin_backup(request: Request, req: BackupReq, x_admin_key: Optional[str] = Header(None)):
    _admin_only(request, x_admin_key)
    name = req.name.strip()
    if not BACKUP_NAME_RE.fullmatch(name):
        raise HTTPException(400, "Invalid backup name (letters, numbers, . _ - only; max 64; must start with a letter or number).")
    BACKUP_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = BACKUP_DIR / f"{name}.db"
    try:
        fd = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)   # claims the name atomically
    except FileExistsError:
        raise HTTPException(409, f"A backup named '{name}' already exists - choose a different name.")
    os.close(fd)
    try:
        src = sqlite3.connect(DB_PATH)
        dst = sqlite3.connect(str(path))
        try:
            src.backup(dst)
        finally:
            dst.close()
            src.close()
    except Exception as e:
        try:
            path.unlink()
        except OSError:
            pass
        raise HTTPException(500, f"backup failed: {e.__class__.__name__}")
    return {"status": "ok", "name": name, "bytes": path.stat().st_size}

@app.get("/api/admin/backups")
def admin_backups(request: Request, x_admin_key: Optional[str] = Header(None)):
    _admin_only(request, x_admin_key)
    out = []
    if BACKUP_DIR.is_dir():
        for p in BACKUP_DIR.glob("*.db"):
            st = p.stat()
            out.append({"name": p.stem, "bytes": st.st_size,
                        "created": datetime.fromtimestamp(st.st_mtime, timezone.utc).isoformat()})
    out.sort(key=lambda x: x["created"], reverse=True)
    return out

@app.post("/api/admin/wipe")
def admin_wipe(request: Request, x_admin_key: Optional[str] = Header(None)):
    _admin_only(request, x_admin_key)
    with db() as conn:
        n_caps = conn.execute("SELECT COUNT(*) FROM captures").fetchone()[0]
        n_teams = conn.execute("SELECT COUNT(*) FROM teams").fetchone()[0]
        conn.execute("DELETE FROM captures")
        conn.execute("DELETE FROM teams")
        try:
            conn.execute("DELETE FROM sqlite_sequence WHERE name='captures'")
        except sqlite3.Error:
            pass
    return {"status": "wiped", "captures": n_caps, "teams": n_teams}

# --- restore a backup ------------------------------------------------------------------------------
class RestoreReq(BaseModel):
    name: str = Field(..., min_length=1, max_length=64)

def _claim_backup_path(base: str) -> Path:
    """Atomically reserve <base>.db (or <base>-2.db, ...) so a safety copy never overwrites anything."""
    BACKUP_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    for i in range(1, 50):
        p = BACKUP_DIR / (f"{base}.db" if i == 1 else f"{base}-{i}.db")
        try:
            os.close(os.open(str(p), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600))
            return p
        except FileExistsError:
            continue
    raise HTTPException(500, "could not reserve a name for the safety backup")

@app.post("/api/admin/restore")
def admin_restore(request: Request, req: RestoreReq, x_admin_key: Optional[str] = Header(None)):
    _admin_only(request, x_admin_key)
    name = req.name.strip()
    if not BACKUP_NAME_RE.fullmatch(name):
        raise HTTPException(400, "Invalid backup name.")
    path = BACKUP_DIR / f"{name}.db"
    if not path.is_file():
        raise HTTPException(404, f"No backup named '{name}'.")
    try:  # make sure it really is a scoreboard backup before live data is touched
        chk = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)
        try:
            tables = {r[0] for r in chk.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            n_caps = chk.execute("SELECT COUNT(*) FROM captures").fetchone()[0] if "captures" in tables else 0
            n_teams = chk.execute("SELECT COUNT(*) FROM teams").fetchone()[0] if "teams" in tables else 0
        finally:
            chk.close()
    except sqlite3.Error:
        raise HTTPException(400, f"'{name}' is not a readable database file.")
    if not {"captures", "teams"} <= tables:
        raise HTTPException(400, f"'{name}' does not look like a scoreboard backup.")
    # 1) save the current data first - if this fails nothing is replaced
    safety = _claim_backup_path("pre-restore-" + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S"))
    try:
        cur = sqlite3.connect(DB_PATH)
        dst = sqlite3.connect(str(safety))
        try:
            cur.backup(dst)
        finally:
            dst.close()
            cur.close()
    except Exception as e:
        try:
            safety.unlink()
        except OSError:
            pass
        raise HTTPException(500, f"could not save the current data first ({e.__class__.__name__}) - nothing was restored")
    # 2) replace the live database content with the backup
    try:
        src = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)
        live = sqlite3.connect(DB_PATH, timeout=15)
        try:
            src.backup(live)
        finally:
            live.close()
            src.close()
    except Exception as e:
        raise HTTPException(500, f"restore failed ({e.__class__.__name__}); the current data is saved as '{safety.stem}'")
    init_db()
    return {"status": "restored", "name": name, "safety_backup": safety.stem, "captures": n_caps, "teams": n_teams}

static_dir = Path(__file__).parent / "static"
if static_dir.exists():
    app.mount("/", StaticFiles(directory=str(static_dir), html=True), name="static")
