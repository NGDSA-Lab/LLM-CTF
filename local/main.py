from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import uvicorn
import json
import os
import sqlite3
import base64
import asyncio
import httpx
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
import logging
import socket
import re

from flag_crypto import unshroud
from flag_config import (
    _PARAM_A1, _PARAM_A2, _PARAM_A3, _PARAM_A4, _PARAM_A5,
    _PARAM_B1, _PARAM_B2, _PARAM_B3, _PARAM_B4, _PARAM_B5,
)
from chains import AutoPartsChain, EMPLOYEE_DB
from parts_db import search_parts, get_part_details, PARTS_DB

app = FastAPI(docs_url=None, redoc_url=None)

# per-team access token set by the spawner; the app checks it before serving a team's instance
EXPECTED_TOKEN = os.environ.get("ACCESS_TOKEN")

@app.middleware("http")
async def verify_token_middleware(request: Request, call_next):
    # If no token is set in the container, allow access freely (for testing)
    if not EXPECTED_TOKEN:
        return await call_next(request)
        
    token = request.query_params.get("token") or request.cookies.get("access_token")
    
    if token != EXPECTED_TOKEN:
        return HTMLResponse("<h1>403 Forbidden</h1><p>Invalid or missing access token.</p>", status_code=403)
        
    response = await call_next(request)
    
    # Set cookie so ?token=... is not required on every click
    if request.query_params.get("token") == EXPECTED_TOKEN:
        response.set_cookie(key="access_token", value=token)
        
    return response

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory="static"), name="static")

auto_parts_chain = AutoPartsChain()

TEAM_ID = os.environ.get("TEAM_ID", "solo")
DASHBOARD_INGEST_URL = os.environ.get("DASHBOARD_INGEST_URL", "")


class Message(BaseModel):
    content: str = Field(...)
    phase: int = 1

class PartQuery(BaseModel):
    query: str
    include_sensitive: bool = False
    phase: int = 1

class FlagSubmissionRequest(BaseModel):
    flag: str

LEGACY_JIRA_CONFIG = unshroud(*_PARAM_B2)

# B2: writes the "forgotten" backup file whose TODO line is the Brainfuck-encoded flag.
# It is only served after Phase 2 is unlocked (see download_legacy_archive below).
def seed_legacy_config_file(path="legacy/config.txt.bak"):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    encoded = _to_brainfuck(LEGACY_JIRA_CONFIG)
    with open(path, "w") as f:
        f.write(
            "# legacy deployment notes — do not commit\n"
            "OLD_JIRA_PROJECT=ENGPARTS-LEGACY\n"
            f"# TODO remove before deploy — {encoded}\n"
        )

@app.get("/legacy/config.txt.bak")
async def download_legacy_archive():
    if not team_has_phase2_access(TEAM_ID):
        raise HTTPException(status_code=404, detail="Not Found")
    return FileResponse("legacy/config.txt.bak", filename="config.txt.bak")

def _to_brainfuck(text: str) -> str:
    code = []
    current = 0
    for char in text:
        target = ord(char)
        diff = target - current
        code.append(("+" if diff >= 0 else "-") * abs(diff))
        code.append(".")
        current = target
    return "".join(code)

seed_legacy_config_file()

PHASE2_FLAGS = [
    unshroud(*_PARAM_B1),
    LEGACY_JIRA_CONFIG,
    unshroud(*_PARAM_B3),
    unshroud(*_PARAM_B4),
    unshroud(*_PARAM_B5),
]

VALID_FLAGS = [
    unshroud(*_PARAM_A1),
    unshroud(*_PARAM_A2),
    unshroud(*_PARAM_A3),
    unshroud(*_PARAM_A4),
    unshroud(*_PARAM_A5),
] + PHASE2_FLAGS

FLAG_NAMES = {
    unshroud(*_PARAM_A1): "A1", unshroud(*_PARAM_A2): "A2", unshroud(*_PARAM_A3): "A3",
    unshroud(*_PARAM_A4): "A4", unshroud(*_PARAM_A5): "A5",
    PHASE2_FLAGS[0]: "B1", PHASE2_FLAGS[1]: "B2", PHASE2_FLAGS[2]: "B3",
    PHASE2_FLAGS[3]: "B4", PHASE2_FLAGS[4]: "B5",
}

ENG_PARTS_DB_PATH = os.environ.get("ENG_PARTS_DB_PATH", "eng_parts.db")

def seed_eng_parts_db(db_path: str = ENG_PARTS_DB_PATH) -> None:
    conn = sqlite3.connect(db_path)
    try:
        cur = conn.cursor()

        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS parts_cache (
                part_number TEXT PRIMARY KEY,
                part_name   TEXT NOT NULL,
                category    TEXT
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS _legacy_debug_cache (
                id   INTEGER PRIMARY KEY AUTOINCREMENT,
                note TEXT
            )
            """
        )

        cur.execute("SELECT COUNT(*) FROM parts_cache")
        if cur.fetchone()[0] == 0:
            rows = [
                (details["basic_specs"].get("part_number"), part_name, details["basic_specs"].get("type"))
                for part_name, details in PARTS_DB.items()
            ]
            cur.executemany(
                "INSERT INTO parts_cache (part_number, part_name, category) VALUES (?, ?, ?)",
                rows,
            )

        cur.execute("SELECT COUNT(*) FROM _legacy_debug_cache")
        if cur.fetchone()[0] == 0:
            flag5 = unshroud(*_PARAM_A5)
            encoded_flag5 = base64.b64encode(flag5.encode()).decode()
            cur.execute(
                "INSERT INTO _legacy_debug_cache (note) VALUES (?)",
                (f"stale export from old parts-sync job, safe to ignore - {encoded_flag5}",),
            )

        conn.commit()
    finally:
        conn.close()

seed_eng_parts_db()


@app.get("/", response_class=HTMLResponse)
async def root():
    with open("static/index.html") as f:
        content = f.read()
    return HTMLResponse(content=content)


@app.get("/downloads/backup.db")
async def download_backup():
    return FileResponse(ENG_PARTS_DB_PATH, filename="backup.db")

@app.get("/api/phase2/clearance-token")
async def phase2_clearance_token():
    if not team_has_phase2_access(TEAM_ID):
        raise HTTPException(status_code=403, detail="Phase 2 locked — 5 valid Phase 1 flags required")
    return {"token": unshroud(*_PARAM_B5)}

STATE_FILE = "state.json"
try:
    team_flag_counts: Dict[str, set] = {k: set(v) for k, v in json.load(open(STATE_FILE)).items()}
except Exception:
    team_flag_counts = {}

def register_valid_flag(team_id: str, flag: str):
    team_flag_counts.setdefault(team_id, set()).add(flag)
    try:
        json.dump({k: list(v) for k, v in team_flag_counts.items()}, open(STATE_FILE, "w"))
    except Exception as e:
        print(f"state save failed: {e}")

def team_has_phase2_access(team_id: str) -> bool:
    return len(team_flag_counts.get(team_id, set())) >= 5

async def report_score_event(team_id: str, flag_name: str):
    if not DASHBOARD_INGEST_URL:
        return
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            await client.post(DASHBOARD_INGEST_URL, json={
                "team_id": team_id,
                "flag_name": flag_name,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
    except Exception as e:
        print(f"Dashboard ingest failed: {e}")


@app.post("/api/validate_flag")
async def validate_flag(request: FlagSubmissionRequest):
    """Validate a submitted flag."""
    if request.flag in VALID_FLAGS:
        register_valid_flag(TEAM_ID, request.flag)
        asyncio.create_task(report_score_event(TEAM_ID, FLAG_NAMES.get(request.flag, "unknown")))
        return {
            "status": "success",
            "valid": True,
            "message": "Congratulations! You found a valid flag!"
        }
    else:
        return {
            "status": "error",
            "valid": False,
            "message": "Invalid flag. Keep searching!"
        }


@app.post("/api/chat")
async def chat(message: Message, request: Request) -> Dict[str, Any]:
    try:
        if not message.content.strip():
            raise HTTPException(status_code=400, detail="Search query cannot be empty")

        if message.phase == 2 and not team_has_phase2_access(TEAM_ID):
            raise HTTPException(status_code=403, detail="Phase 2 locked — 5 valid Phase 1 flags required")

        if message.phase == 2 and len(message.content) > 1000:
            flag3 = PHASE2_FLAGS[2]
            raise HTTPException(status_code=500, detail=f"Buffer Overflow Exception inside NGDSA subsystem. Memory dump: {flag3}")

        client_ip = request.client.host
        response = auto_parts_chain.process_message(message.content, client_ip, phase=message.phase)
        if not response:
            raise HTTPException(status_code=404, detail="No results found")

        return response
    except HTTPException:
        raise
    except Exception as e:
        print(f"--- REAL ERROR: {e} ---")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/parts/search")
async def search_parts_api(query: PartQuery, request: Request) -> Dict[str, Any]:
    try:
        parts = search_parts(query.query)
        parts_list = []
        if parts:
            for part_name, specs in parts.items():
                parts_list.append({
                    "name": part_name.capitalize(),
                    "category": specs.get("type", "Unknown"),
                    "part_number": specs.get("part_number", "Unknown"),
                    "specs": specs
                })

        return {
            "parts": parts_list
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/parts/{part_name}")
async def get_part_api(part_name: str) -> Dict[str, Any]:
    """Get detailed specifications for a part."""
    try:
        details = get_part_details(part_name)
        if not details:
            raise HTTPException(status_code=404, detail="Part not found")

        engineering_response = None
        try:
            chain_response = auto_parts_chain.process_message(f"Tell me about {part_name}")
            engineering_response = chain_response.get("engineering_notes")
        except Exception:
            pass

        return {
            "name": part_name.capitalize(),
            "basic_specs": details,
            "engineering_notes": engineering_response
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/internal/employee/{employee_id}")
async def get_employee_details(employee_id: str) -> Dict[str, Any]:
    if employee_id in EMPLOYEE_DB:
        return EMPLOYEE_DB[employee_id]
    raise HTTPException(status_code=404, detail="Employee not found")


connected_websockets = []
clients_received_flag = set()

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    if EXPECTED_TOKEN:
        token = websocket.query_params.get("token") or websocket.cookies.get("access_token")
        if token != EXPECTED_TOKEN:
            await websocket.close(code=1008) # 1008 = Policy Violation
            return
    client_id = id(websocket)
    connected_websockets.append(websocket)

    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        if websocket in connected_websockets:
            connected_websockets.remove(websocket)

async def send_flag_to_client(client_ip: str, websocket: WebSocket):
    try:
        flag4 = unshroud(*_PARAM_A4)
        await websocket.send_text(f"CTF-FLAG-4: {flag4}")
    except Exception as e:
        print(f"Error sending flag to client: {e}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8001, reload=True)
