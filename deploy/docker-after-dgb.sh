#!/usr/bin/env bash
# Boot-order orchestrator: DigiByte node needs the whole Mac's RAM during its
# ~45min index load. Docker (2GB VM) must NOT start until digibyted's RPC is
# live. This waits for the node, then brings up the docker stack + DGB pool.
#
# Installed as a LaunchAgent (RunAtLoad) replacing Docker's own autostart.

export PATH="$HOME/.docker/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"

LOG="$HOME/Library/Logs/docker-after-dgb.log"
echo "=== $(date) waiting for digibyted RPC ===" >> "$LOG"

# Wait up to 90 min for the native DGB node to finish loading
for i in $(seq 1 360); do
  R=$(curl -s --max-time 4 -u mujina:c94ef41d7af488216bc7cef8a2710c56 \
      -H 'content-type: text/plain' \
      -d '{"jsonrpc":"1.0","id":"x","method":"getblockchaininfo","params":[]}' \
      http://127.0.0.1:14022/ 2>/dev/null)
  if echo "$R" | grep -q '"result":{'; then
    echo "$(date) node live after $((i*15))s" >> "$LOG"
    break
  fi
  sleep 15
done

# Start Docker Desktop (its LoginItem may already have started it; that's fine)
open -a "Docker"
for i in $(seq 1 40); do
  sleep 10
  docker info >/dev/null 2>&1 && break
done

# Bring up the BCH stack
cd /Volumes/ssd/bchn && docker compose up -d >> "$LOG" 2>&1

# Bring up the DGB pool twin (only if the node is actually live)
if echo "$R" | grep -q '"result":{'; then
  /Volumes/ssd/digibyte-node/start-dgb-pool.sh >> "$LOG" 2>&1
else
  echo "$(date) WARNING: node never went live; DGB pool not started" >> "$LOG"
fi
echo "=== $(date) done ===" >> "$LOG"
