# NGDSA LLM Security CTF

A self-hosted capture-the-flag about attacking LLM applications. Teams get their own sandboxed container running a deliberately vulnerable "auto parts" chatbot, and a live scoreboard tracks captures. Ten flags in two phases (prompt leaking, data exfiltration, IDOR, WebSocket sniffing, backup files, system-prompt override, forced browsing, input handling, RAG impersonation, client-side secrets).

local/            Standalone single-player challenge (no spawner or scoreboard needed)
  chains.py, main.py, Dockerfile, docker-compose.yml, README.md
It is a fork of arcanumsec's *AutoPartsCTF*, extended with a per-team orchestrator, a scoreboard, a second phase and multi-provider LLM support. The full solutions are in [WRITEUP.md](WRITEUP.md), so **it is all spoilers**.

> **Security warning.** The challenge app is intentionally insecure. Run it only on a host you are prepared to lose, never reuse real credentials in it, and read the "Deploying" section before exposing anything to the internet.

## What is in here

```
challenge/        The vulnerable app (FastAPI + LangChain). One container per team.
  chains.py         LLM prompts and chains; PROVIDER_CONFIG = Groq / Cerebras / Gemini
  main.py           HTTP API, WebSocket, flag submission, Phase 2 gating
  flag_config.py    Obfuscated base flags; rewrite_flags.py makes them unique per team at boot
  Dockerfile, docker-compose.yml, entrypoint.sh
orchestrator/     Runs on the host
  spawner.py        Team gate (port 9000, localhost) + Docker container manager + admin API
  ingest_main.py    Scoreboard / leaderboard backend (SQLite) on port 8000
  gate.html, admin.html, static/index.html   Web UIs
  quicktest.sh      End-to-end smoke test (spawn, capture, scoreboard, hardening checks)
local/            Standalone single-player challenge (no spawner or scoreboard needed)
  chains.py, main.py, Dockerfile, docker-compose.yml, README.md
WRITEUP.md        Solutions and organizer notes
```

## How it fits together

1. A team opens the gate, enters the event password, a team name/password and either picks a key from the pool or brings their own provider key.
2. `spawner.py` starts a container for that team: own Docker network, memory/CPU/pid limits, all capabilities dropped, `no-new-privileges`, a random port and a per-team access token. The team is redirected to `/_team/<port>?token=...`, so a reverse proxy has to forward that path to the host port.
3. Inside the container `rewrite_flags.py` appends a per-team hash to each flag, and the app reports captures to `ingest_main.py` using a per-team HMAC token (a container can only report for its own team).
4. The scoreboard (`/api/standings`, `/api/feed`, `/api/firstblood`, `/api/banner`) is public. The admin APIs need a key and are only served to localhost (reach them over an SSH tunnel).

## LLM providers

One codebase supports **Groq**, **Cerebras** and **Google Gemini**. All three use an OpenAI-compatible API, so nothing needs editing to switch:

| Provider | `LLM_PROVIDER` | Key prefix | Phase 1 model | Phase 2 model |
|----------|----------------|------------|---------------|---------------|
| Groq | `groq` (default) | `gsk_` | see `challenge/chains.py` | see `challenge/chains.py` |
| Cerebras | `cerebras` | `csk-` | see `challenge/chains.py` | same as Phase 1 |
| Gemini | `gemini` | `AIza` | see `challenge/chains.py` | see `challenge/chains.py` |

Model names change quickly, so check `PROVIDER_CONFIG` in `challenge/chains.py` against the provider's current model list before an event. To add a provider, add an entry to `PROVIDER_CONFIG` there and to `PROVIDERS` in `orchestrator/spawner.py`. The two flags that rely on the model's behaviour (B1, B4) behave differently per model, so rehearse with the one you plan to use.

## Quick start (one team, no orchestrator)

```bash
cd challenge
cp .env.example .env            # put your key in LLM_API_KEY
# set LLM_PROVIDER in docker-compose.yml if you do not use Groq
docker compose up --build       # http://localhost:8001
```

## Running the full event stack

```bash
cd orchestrator
python3 -m venv venv && ./venv/bin/pip install -r requirements.txt
cp local.env.example local.env          # fill in the required secrets
cp api_keys.example.txt api_keys.txt    # lines like:  groq gsk_...   or   google AIza...  (chmod 600)
docker build -t ngdsa-llm-ctf:latest ../challenge
bash quicktest.sh                       # end-to-end smoke test, cleans up after itself
```

`quicktest.sh` shows how the two services are started. The scoreboard listens on the `docker0` address so containers can reach it, and the spawner on `127.0.0.1:9000`:

```bash
set -a; source local.env; set +a
IP=$(ip -4 addr show docker0 | awk '/inet /{print $2}' | cut -d/ -f1)
./venv/bin/uvicorn ingest_main:app --host "$IP" --port 8000 &
DASHBOARD_REGISTER_URL="http://$IP:8000/api/register" ./venv/bin/uvicorn spawner:app --host 127.0.0.1 --port 9000 &
```

Environment variables are listed in `orchestrator/local.env.example`. The services refuse to start with missing, short or well-known default secrets.

## Hosting it locally (one machine, as a mini event)

Needs Docker, Python 3.10+ and your user in the `docker` group.

1. Build the challenge image and set up the orchestrator:
   ```bash
   docker build -t ngdsa-llm-ctf:latest challenge
   cd orchestrator
   python3 -m venv venv && ./venv/bin/pip install -r requirements.txt
   cp local.env.example local.env       # set PUBLIC_HOST=localhost and the four secrets (8+ chars each)
   cp api_keys.example.txt api_keys.txt # add lines like:  groq gsk_...   or   google AIza...
   chmod 600 local.env api_keys.txt
   ```
2. Start the two services (this is what `quicktest.sh` does):
   ```bash
   set -a; source local.env; set +a
   IP=$(ip -4 addr show docker0 | awk '/inet /{print $2}' | cut -d/ -f1)
   export DASHBOARD_REGISTER_URL="http://$IP:8000/api/register"
   export DASHBOARD_INGEST_URL="http://host.docker.internal:8000/api/ingest"
   ./venv/bin/uvicorn ingest_main:app --host "$IP" --port 8000 &
   ./venv/bin/uvicorn spawner:app --host 127.0.0.1 --port 9000 &
   ```
3. Open the gate at <http://127.0.0.1:9000>, enter the event password and a team name/password. The scoreboard is at `http://<docker0 IP>:8000`.
4. After joining, the gate sends you to `/_team/<port>?token=<token>`. That path is normally served by a reverse proxy; without one, take the port and token from the address bar and open `http://127.0.0.1:<port>/?token=<token>` instead.
5. Optional: run `bash quicktest.sh` to check the whole stack end to end. It cleans up after itself.

The admin console is at <http://127.0.0.1:9000/admin> (needs `SPAWNER_ADMIN_KEY`).

## Deploying for a real event

The repo does not ship unit files or a proxy config. What the code expects:

- A reverse proxy (nginx, Caddy) with TLS in front. It forwards `/` to the spawner gate, `/_team/<port>` to the team's container port, and the public scoreboard routes to port 8000. It must append the real client address to `X-Forwarded-For`; the spawner trusts only the **last** entry.
- Do not publish the admin routes. Keep the spawner on `127.0.0.1` and use `ssh -L 9000:127.0.0.1:9000`.
- An egress firewall for the team containers is strongly recommended (allow only the LLM provider hosts, block the metadata service, the Docker host and your LAN). The spawner does not set one up.
- Keep `api_keys.txt` and `local.env` readable only by the service user. The spawner stores only a fingerprint of each key in container labels, but the key itself is in the container's environment while it runs.
- Back up `ctf_dashboard.db` before and after the event (`/api/admin/backup` on the scoreboard, or the admin console).

## Credits

Based on arcanumsec's AutoPartsCTF. No license file is included yet; check the upstream project's terms before reusing the challenge content.
