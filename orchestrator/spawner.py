"""
NGDSA CTF — challenge orchestrator / spawner.

Serves the team gate (gate.html), starts one hardened Docker container per team
(own network, port from PORT_MIN..PORT_MAX, per-team ingest token), hands out API keys
from a pool file, and exposes an admin API (only reachable from localhost / an SSH tunnel).
Required env: PUBLIC_HOST, SPAWNER_ADMIN_KEY, INGEST_SECRET, EVENT_PASSWORD
(each >= 8 chars). See local.env.example for the full list.
"""
import os
import re
import secrets
import socket
import threading
import time
from datetime import datetime, timezone
from typing import Optional
import docker
from docker.errors import NotFound, APIError
from fastapi import FastAPI, Form, HTTPException, Header, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
import hashlib, hmac
from collections import Counter

CTF_IMAGE = os.environ.get("CTF_IMAGE", "ngdsa-llm-ctf:latest")
PUBLIC_HOST = os.environ.get("PUBLIC_HOST") 
DASHBOARD_INGEST_URL = os.environ.get("DASHBOARD_INGEST_URL", "http://localhost:8000/api/ingest")
ADMIN_KEY = os.environ.get("SPAWNER_ADMIN_KEY", "")
CONTAINER_PORT = int(os.environ.get("CONTAINER_PORT", 8001))
MAX_AGE_MINUTES = int(os.environ.get("MAX_AGE_MINUTES", 240))

# NGDSA Additions
EVENT_PASSWORD = os.environ.get("EVENT_PASSWORD", "")
INGEST_SECRET = os.environ.get("INGEST_SECRET", "")
def _ingest_token(team_name: str) -> str:
    # per-team token: a container can only ever report for ITS OWN team,
    # and the master INGEST_SECRET never leaves this process
    return hmac.new(INGEST_SECRET.encode(), f"ingest:{team_name}".encode(), hashlib.sha256).hexdigest()[:40]

def _team_ingest_url(team_name: str) -> str:
    return f"{DASHBOARD_INGEST_URL}?token={_ingest_token(team_name)}"

# the spawner runs on the host, so it reaches the dashboard via localhost (not host.docker.internal)
REGISTER_URL = os.environ.get("DASHBOARD_REGISTER_URL") or \
    DASHBOARD_INGEST_URL.replace("host.docker.internal", "127.0.0.1").replace("/api/ingest", "/api/register")

def _register_team(team_name: str):
    def _go():
        try:
            import requests
            requests.post(f"{REGISTER_URL}?token={_ingest_token(team_name)}", json={"team_id": team_name}, timeout=3)
        except Exception as e:
            print(f"[spawner] leaderboard register failed for {team_name}: {e}", flush=True)
    threading.Thread(target=_go, daemon=True).start()

FLAG_SECRET_SALT = os.environ.get("SPAWNER_FLAG_SECRET_SALT")
if not FLAG_SECRET_SALT:
    FLAG_SECRET_SALT = secrets.token_hex(32)
    print("[spawner] WARNING: SPAWNER_FLAG_SECRET_SALT not set", flush=True)

PROVIDERS = {
    "groq": "Groq",
    "cerebras": "Cerebras",   # was missing: "cerebras:" / csk- keys were dropped from the pool and the gate dropdown
    "gemini": "Google Gemini",
}

# names accepted in the key file besides the PROVIDERS keys
PROVIDER_ALIASES = {"google": "gemini"}

LABEL_MANAGED = "ctf.managed"
LABEL_TEAM = "ctf.team_id"
LABEL_PROVIDER = "ctf.provider"
LABEL_TOKEN = "ctf.token"
LABEL_PW = "ctf.pw"
LABEL_KEYSRC = "ctf.key_src"
LABEL_KEYFP = "ctf.key_fp"
PORT_MIN = int(os.environ.get("PORT_MIN", 20000))
PORT_MAX = int(os.environ.get("PORT_MAX", 20099))
BIND_HOST = os.environ.get("BIND_HOST", "0.0.0.0")

# --- API key pool --------------------------------------------------------------------------
# KEYS_FILE: one API key per line (root-owned, chmod 600). Optional "groq:" / "cerebras:" / "gemini:" prefix, "#" comments.
# A bare key is matched by prefix: gsk_ = groq, csk- = cerebras, AIza = gemini.
# List a key twice to let two teams share it. A new team gets the first unused key; "add your own key" at the gate
# bypasses the pool. A key is free again as soon as its team is deleted, reset or expired.
KEYS_FILE = os.environ.get("KEYS_FILE", os.path.join(os.path.dirname(os.path.abspath(__file__)), "api_keys.txt"))
POOL_DEFAULT_PROVIDER = os.environ.get("POOL_DEFAULT_PROVIDER", "groq")
# where the admin console's "open" link goes (the admin page itself is only reachable through the SSH tunnel).
# Set this to the public base URL of your deployment, e.g. https://ctf.example.org (no default on purpose).
ADMIN_OPEN_BASE = os.environ.get("ADMIN_OPEN_BASE", "").rstrip("/")
# the spawner talks to the scoreboard for backup / wipe
DASHBOARD_ADMIN_KEY = os.environ.get("DASHBOARD_ADMIN_KEY", "")
DASHBOARD_BASE = (os.environ.get("DASHBOARD_BASE") or REGISTER_URL.rsplit("/api/register", 1)[0]).rstrip("/")

def _key_fp(key: str) -> str:
    # fingerprint stored on the container label instead of the key itself
    return hmac.new(INGEST_SECRET.encode(), b"keyfp:" + key.encode(), hashlib.sha256).hexdigest()[:16]

def _load_pool() -> list:
    """[(provider, key, fingerprint)] read fresh from KEYS_FILE, so edits need no restart."""
    try:
        with open(KEYS_FILE, encoding="utf-8-sig") as f:
            lines = f.read().splitlines()
    except FileNotFoundError:
        return []
    except Exception as e:
        print(f"[spawner] cannot read key file: {e.__class__.__name__}", flush=True)
        return []
    out = []
    for n, line in enumerate(lines, 1):
        line = re.sub(r"(^|\s)#.*$", "", line).strip()
        if not line:
            continue
        # "KEY"  or  "provider<sep>KEY"  with <sep> = ":" "," ";" tab or space; quotes ignored
        parts = [p for p in re.split(r"[\s,;:]+", line.replace('"', "").replace("'", "")) if p]
        provider, key = POOL_DEFAULT_PROVIDER, ""
        if len(parts) == 1:
            key = parts[0]
            # bare key -> guess the provider from its prefix
            if key.startswith("AIza"):
                provider = "gemini"
            elif key.startswith("csk-"):
                provider = "cerebras"
            elif key.startswith("gsk_"):
                provider = "groq"
        elif len(parts) == 2:
            provider, key = parts[0].lower(), parts[1]
            provider = PROVIDER_ALIASES.get(provider, provider)
        if provider not in PROVIDERS or not key:
            print(f"[spawner] key file line {n} ignored (unknown provider prefix or bad format)", flush=True)
            continue
        out.append((provider, key, _key_fp(key)))
    return out

def _pick_pool_key():
    """First unused slot as (provider, key, fp), or None. Caller must hold REGISTRY_LOCK."""
    used = Counter(e.get("key_fp") for e in active_teams.values() if e.get("key_src") == "pool")
    seen = Counter()
    for provider, key, fp in _load_pool():
        seen[fp] += 1
        if used[fp] < seen[fp]:
            return provider, key, fp
    return None

def _pool_stats() -> dict:
    entries = _load_pool()
    cap = Counter(fp for _, _, fp in entries)
    # read-only snapshot WITHOUT the registry lock: a spawn holds that lock while Docker starts a container, and the
    # gate's access-code check must not queue behind it. (The real assignment in _pick_pool_key still runs under the lock.)
    used = Counter(e.get("key_fp") for e in list(active_teams.values()) if e.get("key_src") == "pool")
    in_use = sum(min(used[fp], c) for fp, c in cap.items())
    return {"total": len(entries), "in_use": in_use, "free": len(entries) - in_use,
            "file": KEYS_FILE, "file_found": os.path.exists(KEYS_FILE)}
docker_client = docker.from_env()
app = FastAPI(title="NGDSA CTF Orchestrator", docs_url=None, redoc_url=None, openapi_url=None)

active_teams: dict = {}
REGISTRY_LOCK = threading.Lock()

_rate_buckets: dict = {}
_rate_lock = threading.Lock()

def _client_ip(request: Request) -> str:
    # Behind nginx every request arrives from 127.0.0.1. Only then trust X-Forwarded-For, and take the LAST
    # entry: that is the one our own proxy appended. The first entries are client-supplied and can be spoofed.
    if request.client and request.client.host == "127.0.0.1":
        xff = request.headers.get("x-forwarded-for")
        if xff:
            return xff.split(",")[-1].strip()
    return request.client.host if request.client else "unknown"

def check_rate_limit(key: str, max_calls: int, window_seconds: int) -> bool:
    now = time.monotonic()
    cutoff = now - window_seconds
    with _rate_lock:
        bucket = _rate_buckets.setdefault(key, [])
        while bucket and bucket[0] < cutoff:
            bucket.pop(0)
        if len(bucket) >= max_calls:
            return False
        bucket.append(now)
        return True

def enforce_rate_limit(request: Request, bucket_name: str, max_calls: int, window_seconds: int):
    key = f"{bucket_name}:{_client_ip(request)}"
    if not check_rate_limit(key, max_calls, window_seconds):
        raise HTTPException(429, "too many requests — slow down and try again shortly")

def get_free_port() -> int:
    used = {e["port"] for e in active_teams.values() if e.get("port")}
    for port in range(PORT_MIN, PORT_MAX + 1):
        if port in used:
            continue
        s = socket.socket()
        try:
            s.bind(("", port))
        except OSError:
            continue
        finally:
            s.close()
        return port
    raise HTTPException(503, "no free ports - contact an organizer")

def _parse_iso(ts: str) -> Optional[datetime]:
    ts = ts.replace("Z", "+00:00")
    ts = re.sub(r"\.(\d{1,6})\d*", lambda m: "." + m.group(1), ts)
    try:
        return datetime.fromisoformat(ts)
    except ValueError:
        return None

def _network_name(team_name: str) -> str:
    return f"ctf-net-{team_name.lower()}"

def _container_name(team_name: str) -> str:
    return f"ctf-{team_name.lower()}"

def _team_url(port: int, token: str) -> str:
    return f"/_team/{port}?token={token}"

def _admin_open_url(e: dict) -> str:
    u = _team_url(e["port"], e["token"])
    return u if u.startswith("http") else ADMIN_OPEN_BASE + u

def _rebuild_registry_from_docker():
    containers = docker_client.containers.list(all=True, filters={"label": f"{LABEL_MANAGED}=true"})
    with REGISTRY_LOCK:
        for c in containers:
            if c.status != "running":
                continue
            labels = c.labels or {}
            team_name = labels.get(LABEL_TEAM)
            token = labels.get(LABEL_TOKEN)
            if not team_name or not token:
                continue
            port = None
            try:
                ports = c.attrs["NetworkSettings"]["Ports"].get(f"{CONTAINER_PORT}/tcp")
                if ports:
                    port = int(ports[0]["HostPort"])
            except (KeyError, IndexError, TypeError):
                pass
            active_teams[team_name] = {
                "container_id": c.id,
                "name": c.name,
                "network": _network_name(team_name),
                "port": port,
                "token": token,
                "pw": labels.get(LABEL_PW, ""),
                "key_src": labels.get(LABEL_KEYSRC, "legacy"),
                "key_fp": labels.get(LABEL_KEYFP, ""),
                "provider": labels.get(LABEL_PROVIDER, "unknown"),
                "spawned_at": c.attrs["Created"],
            }

def _ensure_team_network(team_name: str) -> str:
    network_name = _network_name(team_name)
    try:
        docker_client.networks.get(network_name)
    except NotFound:
        docker_client.networks.create(network_name, driver="bridge")
    return network_name

def _pbkdf2(pw: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 100_000).hex()

def _make_pw_record(pw: str) -> str:
    salt = secrets.token_hex(8)
    return f"{salt}${_pbkdf2(pw, salt)}"

def _check_pw(pw: str, record: str) -> bool:
    try:
        salt, h = record.split("$", 1)
    except ValueError:
        return False
    return hmac.compare_digest(_pbkdf2(pw, salt), h)

def _spawn_container(team_name: str, provider: str, api_key: Optional[str], pw_record: str) -> dict:
    # api_key=None means: take one from the pool (done under the lock so two new teams never get the same slot)
    name = _container_name(team_name)

    with REGISTRY_LOCK:
        if team_name in active_teams:
            raise HTTPException(409, "team already exists")

        try:
            existing = docker_client.containers.get(name)
            if existing.status == "running":
                raise HTTPException(409, f"team {team_name} already has a running container")
            existing.remove(force=True)
        except NotFound:
            pass

        key_src, key_fp = "own", (_key_fp(api_key) if api_key else "")
        if api_key is None:
            picked = _pick_pool_key()
            if not picked:
                raise HTTPException(409, "No API keys available right now - add your own API key.")
            provider, api_key, key_fp = picked
            key_src = "pool"

        network_name = _ensure_team_network(team_name)
        token = secrets.token_hex(16)
        port = get_free_port()
        try:
            container = docker_client.containers.run(
                CTF_IMAGE,
                name=name,
                detach=True,
                ports={f"{CONTAINER_PORT}/tcp": (BIND_HOST, port)},
                mem_limit="512m",
                memswap_limit="512m",
                pids_limit=256,
                cap_drop=["ALL"],
                security_opt=["no-new-privileges"],
                nano_cpus=500_000_000,
                network=network_name,
                restart_policy={"Name": "unless-stopped"},
                extra_hosts={"host.docker.internal": "host-gateway"},
                dns=["8.8.8.8", "1.1.1.1"],
                environment={
                    "TEAM_ID": team_name,
                    "LLM_PROVIDER": provider,
                    "LLM_API_KEY": api_key,
                    "ACCESS_TOKEN": token,
                    "FLAG_SECRET_SALT": FLAG_SECRET_SALT,
                    "DASHBOARD_INGEST_URL": _team_ingest_url(team_name),
                },
                labels={
                    LABEL_MANAGED: "true",
                    LABEL_TEAM: team_name,
                    LABEL_PROVIDER: provider,
                    LABEL_TOKEN: token,
                    LABEL_PW: pw_record,
                    LABEL_KEYSRC: key_src,
                    LABEL_KEYFP: key_fp,
                },
            )
        except APIError as e:
            raise HTTPException(500, f"docker error: {e}")

        entry = {
            "container_id": container.id,
            "name": name,
            "network": network_name,
            "port": port,
            "token": token,
            "provider": provider,
            "spawned_at": datetime.now(timezone.utc).isoformat(),
            "pw": pw_record,
            "key_src": key_src,
            "key_fp": key_fp,
        }
        active_teams[team_name] = entry
        return entry

def _teardown_container(team_name: str) -> bool:
    with REGISTRY_LOCK:
        entry = active_teams.pop(team_name, None)
    name = entry["name"] if entry else _container_name(team_name)
    removed = False
    try:
        c = docker_client.containers.get(name)
        c.remove(force=True)
        removed = True
    except NotFound:
        removed = entry is not None
    try:
        docker_client.networks.get(_network_name(team_name)).remove()
    except (NotFound, APIError):
        pass
    return removed

def _reaper_loop():
    while True:
        time.sleep(60)
        now = datetime.now(timezone.utc)
        with REGISTRY_LOCK:
            stale = []
            for team_name, entry in active_teams.items():
                spawned = _parse_iso(entry["spawned_at"])
                if spawned is None:
                    continue
                if (now - spawned).total_seconds() / 60 > MAX_AGE_MINUTES:
                    stale.append(team_name)
        for team_name in stale:
            _teardown_container(team_name)

@app.on_event("startup")
def _startup():
    if not PUBLIC_HOST:
        raise RuntimeError("PUBLIC_HOST env var is required")
    for n, v in (("SPAWNER_ADMIN_KEY", ADMIN_KEY), ("INGEST_SECRET", INGEST_SECRET), ("EVENT_PASSWORD", EVENT_PASSWORD)):
        if len(v) < 8 or v in ("changeme", "super_secret_ingest_key", "LLMCTF_2026"):
            raise RuntimeError(f"{n} is missing, too short, or a known default - refusing to start")
    _rebuild_registry_from_docker()
    print(f"[spawner] key pool: {len(_load_pool())} keys in {KEYS_FILE}", flush=True)
    threading.Thread(target=_reaper_loop, daemon=True).start()

def _provider_options() -> str:
    return "\n".join(f'<option value="{val}">{label}</option>' for val, label in PROVIDERS.items())

@app.get("/", response_class=HTMLResponse)
def registration_form():
    return open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "gate.html")).read().replace("%%PROVIDERS%%", _provider_options())

def _wait_ready(port: int, timeout: int = 30) -> None:
    import urllib.request, urllib.error
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=2)
            return
        except urllib.error.HTTPError:
            return  # any HTTP reply (e.g. 403 without token) means it is up
        except Exception:
            time.sleep(1)

def _spawn_reply(request: Request, url: str):
    # the gate page asks for JSON so it can show errors in place; a plain form post still gets the 303
    if "application/json" in request.headers.get("accept", ""):
        return JSONResponse({"redirect": url})
    return RedirectResponse(url=url, status_code=303)

@app.post("/spawn")
def spawn_container(
    request: Request,
    team_name: str = Form(...),
    team_password: str = Form(...),
    event_password: str = Form(...),
    provider: str = Form(""),
    api_key: str = Form(""),
):
    enforce_rate_limit(request, "spawn", max_calls=300, window_seconds=60)

    if not hmac.compare_digest(event_password.encode(), EVENT_PASSWORD.encode()):
        raise HTTPException(403, "Invalid event password")

    team_name = team_name.strip().lower()
    if not re.fullmatch(r"[a-z0-9_-]{1,32}", team_name):
        raise HTTPException(400, "Invalid team name (letters, numbers, _ and - only, max 32).")
    if len(team_password) < 6:
        raise HTTPException(400, "Team password must be at least 6 characters.")
    api_key = api_key.strip()

    with REGISTRY_LOCK:
        existing = active_teams.get(team_name)
    if existing:
        if not _check_pw(team_password, existing.get("pw", "")):
            raise HTTPException(403, "Team already exists - wrong team password")
        # pool teams rejoin with name + password only; teams that typed their own key must type it again
        if existing.get("key_src") == "own" and existing.get("key_fp"):
            if not api_key:
                raise HTTPException(403, "This team uses its own API key - enter it again to rejoin.")
            if not hmac.compare_digest(_key_fp(api_key), existing["key_fp"]):
                raise HTTPException(403, "Wrong API key for this team.")
        _register_team(team_name)
        return _spawn_reply(request, _team_url(existing["port"], existing["token"]))

    pw_record = _make_pw_record(team_password)
    if api_key:                                   # participant chose their own key
        if provider not in PROVIDERS:
            raise HTTPException(400, f"unknown provider: {provider!r}")
        entry = _spawn_container(team_name, provider, api_key, pw_record)
    else:                                         # take an unused key from the pool
        entry = _spawn_container(team_name, "", None, pw_record)
    _wait_ready(entry["port"])
    _register_team(team_name)
    return _spawn_reply(request, _team_url(entry["port"], entry["token"]))


@app.post("/api/check-pass")
def check_pass(request: Request, event_password: str = Form(...)):
    enforce_rate_limit(request, "checkpass", max_calls=300, window_seconds=60)
    if not hmac.compare_digest(event_password.encode(), EVENT_PASSWORD.encode()):
        raise HTTPException(403, "denied")
    return {"ok": True, "pool_available": _pool_stats()["free"] > 0}

_ADMIN_RL = dict(max_calls=60, window_seconds=60)
_TEAM_RE = re.compile(r"[a-z0-9_-]{1,32}")
ADMIN_CSP = ("default-src 'none'; style-src 'unsafe-inline' https://fonts.googleapis.com; "
             "font-src https://fonts.gstatic.com; script-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'")

def _admin_guard(request: Request, key: Optional[str] = None, need_key: bool = True):
    # Anything that came through the reverse proxy carries forwarding headers -> admin is tunnel-only.
    if any(h in request.headers for h in ("x-forwarded-for", "forwarded", "x-real-ip")):
        raise HTTPException(404, "Not Found")
    enforce_rate_limit(request, "admin", **_ADMIN_RL)
    if need_key and not (key and hmac.compare_digest(key.encode(), ADMIN_KEY.encode())):
        print(f"[admin] DENIED {request.method} {request.url.path}", flush=True)
        raise HTTPException(403, "bad admin key")

@app.get("/admin", response_class=HTMLResponse)
def admin_page(request: Request):
    _admin_guard(request, need_key=False)
    html = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "admin.html")).read()
    return HTMLResponse(html, headers={"Content-Security-Policy": ADMIN_CSP, "X-Frame-Options": "DENY",
                                       "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})

@app.get("/api/status")
def status(request: Request, x_admin_key: Optional[str] = Header(None)):
    _admin_guard(request, x_admin_key)
    with REGISTRY_LOCK:
        return [
            {
                "team_name": t,
                "url": _admin_open_url(e),
                "key": "pool" if e.get("key_src") == "pool" else "own",
                "provider": e["provider"],
                "network": e["network"],
                "spawned_at": e["spawned_at"],
            }
            for t, e in active_teams.items()
        ]

@app.post("/api/teardown/{team_name}")
def teardown(request: Request, team_name: str, x_admin_key: Optional[str] = Header(None)):
    _admin_guard(request, x_admin_key)
    if not _TEAM_RE.fullmatch(team_name):
        raise HTTPException(400, "invalid team name")
    print(f"[admin] teardown {team_name}", flush=True)
    if not _teardown_container(team_name):
        raise HTTPException(404, f"no active container for {team_name!r}")
    return {"status": "torn_down", "team_name": team_name}

@app.post("/api/reset-all")
def reset_all(request: Request, x_admin_key: Optional[str] = Header(None)):
    _admin_guard(request, x_admin_key)
    with REGISTRY_LOCK:
        team_names = list(active_teams.keys())
    print(f"[admin] reset-all ({len(team_names)} teams)", flush=True)
    for team_name in team_names:
        _teardown_container(team_name)
    return {"status": "cleared", "count": len(team_names)}


# --- admin pool status, backups, wipe ---------------------------------------------------------
def _dash_call(method: str, path: str, **kw):
    import requests
    if not DASHBOARD_ADMIN_KEY:
        raise HTTPException(503, "DASHBOARD_ADMIN_KEY is not set in the spawner's environment (local.env)")
    try:
        r = requests.request(method, DASHBOARD_BASE + path, headers={"X-Admin-Key": DASHBOARD_ADMIN_KEY}, timeout=20, **kw)
    except Exception as e:
        raise HTTPException(502, f"cannot reach the scoreboard at {DASHBOARD_BASE} ({e.__class__.__name__})")
    if r.status_code >= 400:
        try:
            detail = r.json().get("detail", "")
        except Exception:
            detail = ""
        if r.status_code in (400, 404, 409) and detail and str(detail) != "Not Found":
            raise HTTPException(r.status_code, str(detail))
        raise HTTPException(502, f"scoreboard answered {r.status_code}: {str(detail or r.text)[:150]}")
    return r.json()

@app.get("/api/pool")
def pool_status(request: Request, x_admin_key: Optional[str] = Header(None)):
    _admin_guard(request, x_admin_key)
    return _pool_stats()

@app.get("/api/backups")
def list_backups(request: Request, x_admin_key: Optional[str] = Header(None)):
    _admin_guard(request, x_admin_key)
    return _dash_call("GET", "/api/admin/backups")

@app.post("/api/backup")
def create_backup(request: Request, name: str = Form(...), x_admin_key: Optional[str] = Header(None)):
    _admin_guard(request, x_admin_key)
    name = name.strip()
    print(f"[admin] backup {name!r}", flush=True)
    return _dash_call("POST", "/api/admin/backup", json={"name": name})

@app.post("/api/wipe-db")
def wipe_db(request: Request, x_admin_key: Optional[str] = Header(None)):
    _admin_guard(request, x_admin_key)
    backup_name = "pre-wipe-" + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    # 1) safety backup first - if it fails nothing has been destroyed yet
    _dash_call("POST", "/api/admin/backup", json={"name": backup_name})
    # 2) remove every team instance (this also frees every pool key)
    with REGISTRY_LOCK:
        team_names = list(active_teams.keys())
    print(f"[admin] WIPE database: backup={backup_name}, removing {len(team_names)} team instances", flush=True)
    for team_name in team_names:
        _teardown_container(team_name)
    # 3) clear teams + captures on the scoreboard
    wiped = _dash_call("POST", "/api/admin/wipe")
    return {**wiped, "status": "wiped", "backup": backup_name, "teams_removed": len(team_names)}


# --- restore a backup ---------------------------------------------------------------------------------
@app.post("/api/restore")
def restore_backup(request: Request, name: str = Form(...), x_admin_key: Optional[str] = Header(None)):
    _admin_guard(request, x_admin_key)
    name = name.strip()
    print(f"[admin] RESTORE backup {name!r}", flush=True)
    return _dash_call("POST", "/api/admin/restore", json={"name": name})
