#!/bin/bash
# NGDSA LLM-CTF quick local test. Run from anywhere:  bash quicktest.sh
cd "$(dirname "$0")" || exit 1

docker ps >/dev/null 2>&1 || { echo "Docker not usable. Run:  newgrp docker   (or log out/in), then retry."; exit 1; }
[ -f local.env ] || { echo "local.env missing in $(pwd)"; exit 1; }
set -a; source local.env; set +a
IP=$(ip -4 addr show docker0 | awk '/inet /{print $2}' | cut -d/ -f1)
export DASHBOARD_REGISTER_URL="http://$IP:8000/api/register"
export SHOW_EVENT_PASSWORD="${SHOW:-0}"   # run "SHOW=1 bash quicktest.sh" to see the password on the board
[ -n "$IP" ] || { echo "no docker0 address, is the docker service running?"; exit 1; }

ok=0; bad=0
chk(){ if [ "$2" = "$3" ]; then echo "  PASS  $1"; ok=$((ok+1)); else echo "  FAIL  $1 (expected '$2', got '$3')"; bad=$((bad+1)); fi; }
code(){ curl -s -o /dev/null -w '%{http_code}' "$@"; }
spawn(){ code -XPOST localhost:9000/spawn -d "team_name=$1&team_password=$2&provider=groq&api_key=fake&event_password=$3"; }

cleanup(){
  echo; echo "cleaning up..."
  curl -s -XPOST -H "X-Admin-Key: $SPAWNER_ADMIN_KEY" localhost:9000/api/reset-all >/dev/null 2>&1
  curl -s -XPOST -H "X-Admin-Key: $DASHBOARD_ADMIN_KEY" "$IP:8000/api/reset" >/dev/null 2>&1
  kill $ING_PID $SPW_PID 2>/dev/null
  docker rm -f ctf-alpha ctf-bravo >/dev/null 2>&1
  docker network rm ctf-net-alpha ctf-net-bravo >/dev/null 2>&1
  rm -f ctf_dashboard.db
}
trap cleanup EXIT

if ! docker image inspect ngdsa-llm-ctf:latest >/dev/null 2>&1; then
  echo "building challenge image (first time only)..."
  docker build -q -t ngdsa-llm-ctf:latest ../challenge || exit 1
fi

rm -f ctf_dashboard.db
./venv/bin/uvicorn ingest_main:app --host "$IP" --port 8000 >/tmp/ingest.log 2>&1 & ING_PID=$!
./venv/bin/uvicorn spawner:app --host 127.0.0.1 --port 9000 >/tmp/spawner.log 2>&1 & SPW_PID=$!
for i in $(seq 1 30); do
  [ "$(code "$IP:8000/api/standings")" = 200 ] && [ "$(code localhost:9000/)" = 200 ] && break; sleep 1
done
echo "services up (ingest $IP:8000, spawner 127.0.0.1:9000)"
[ "$(code localhost:9000/)" = 200 ] || { echo "spawner did not start:"; tail -5 /tmp/spawner.log; exit 1; }
[ "$(code "$IP:8000/api/standings")" = 200 ] || { echo "ingest did not start:"; tail -5 /tmp/ingest.log; exit 1; }

echo; echo "== spawner =="
AK="X-Admin-Key: $SPAWNER_ADMIN_KEY"
chk "/docs hidden"                   404 "$(code localhost:9000/docs)"
chk "admin via proxy headers denied" 404 "$(code -H "$AK" -H 'X-Forwarded-For: 1.2.3.4' localhost:9000/api/status)"
chk "admin wrong key denied"         403 "$(code -H 'X-Admin-Key: wrong' localhost:9000/api/status)"
chk "admin right key works"          200 "$(code -H "$AK" localhost:9000/api/status)"
chk "wrong event password"           403 "$(spawn alpha secret1 nope)"
chk "spawn alpha"                    303 "$(spawn alpha secret1 "$EVENT_PASSWORD")"
chk "rejoin wrong team password"     403 "$(spawn alpha badpass1 "$EVENT_PASSWORD")"
chk "rejoin correct"                 303 "$(spawn alpha secret1 "$EVENT_PASSWORD")"
chk "spawn bravo"                    303 "$(spawn bravo secret2 "$EVENT_PASSWORD")"
sleep 2
chk "teams listed before 1st capture" 2 "$(curl -s "$IP:8000/api/standings" | grep -o '"team_id"' | wc -l)"

echo; echo "== container hardening =="
HI=$(docker inspect ctf-alpha --format '{{.HostConfig.CapDrop}} {{.HostConfig.SecurityOpt}} {{.HostConfig.PidsLimit}}' 2>&1)
echo "  info: $HI"
case "$HI" in *ALL*no-new-privileges*) chk "cap_drop ALL + no-new-privileges" y y;; *) chk "cap_drop ALL + no-new-privileges" y n;; esac
chk "master INGEST_SECRET not in container" 0 "$(docker exec ctf-alpha env | grep -c '^INGEST_SECRET=')"
for i in $(seq 1 20); do docker exec ctf-alpha python -c 'import httpx' >/dev/null 2>&1 && break; sleep 1; done

echo; echo "== scoring (sent from INSIDE the container) =="
post(){ docker exec -i -e T="$1" -e F="$2" ctf-alpha python - <<'PY' 2>&1
import os, httpx
try:
    r = httpx.post(os.environ["DASHBOARD_INGEST_URL"], json={"team_id": os.environ["T"], "flag_name": os.environ["F"]}, timeout=5)
    print(r.status_code, r.json().get("status", ""))
except Exception as e:
    print("ERR", e)
PY
}
chk "own capture recorded"        "200 recorded"  "$(post alpha A1)"
chk "duplicate ignored"           "200 duplicate" "$(post alpha A1)"
chk "forging another team blocked" "403 "         "$(post bravo A1)"
chk "alpha on leaderboard API"    1 "$(curl -s "$IP:8000/api/standings" | grep -c '"alpha"')"
chk "first blood recorded"        alpha "$(curl -s "$IP:8000/api/firstblood" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("A1",{}).get("team",""))')"

echo; echo "== ingest / leaderboard =="
BK="X-Admin-Key: $DASHBOARD_ADMIN_KEY"
chk "/docs hidden"                  404 "$(code "$IP:8000/docs")"
chk "no-token ingest refused"       403 "$(code -XPOST "$IP:8000/api/ingest" -H 'Content-Type: application/json' -d '{"team_id":"alpha","flag_name":"A2"}')"
pwof(){ curl -s "$@" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("event_password"))'; }
if [ "$SHOW_EVENT_PASSWORD" = 1 ]; then
  chk "banner: public view shows password (SHOW=1)" "$EVENT_PASSWORD" "$(pwof "$IP:8000/api/banner")"
else
  chk "banner: hidden from the public"   None "$(pwof "$IP:8000/api/banner")"
  chk "banner: key in URL ignored"       None "$(pwof "$IP:8000/api/banner?key=$DASHBOARD_ADMIN_KEY")"
  chk "banner: proxied + key ignored"    None "$(pwof -H "$BK" -H 'X-Forwarded-For: 1.2.3.4' "$IP:8000/api/banner")"
  chk "banner: organizer key shows it"   "$EVENT_PASSWORD" "$(pwof -H "$BK" "$IP:8000/api/banner")"
fi

echo; echo "RESULT: $ok passed, $bad failed"
echo
echo "Look at it in the browser now:"
echo "  leaderboard  http://$IP:8000     (password shows only with: SHOW=1 bash quicktest.sh)"
echo "  gate         http://127.0.0.1:9000"
echo "  admin        http://127.0.0.1:9000/admin"
read -r -p "Press Enter to stop everything and clean up... " _
