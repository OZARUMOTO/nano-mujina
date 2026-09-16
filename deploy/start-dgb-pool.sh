#!/usr/bin/env bash
# DGB pool twin — mirrors nano-pool exactly but talks to the native digibyted
# on the Mac host (host.docker.internal:14022) and mines to the DGB payout.
# SV2 listen :3336, stats panel :3337 (host side).
export PATH="$HOME/.docker/bin:$PATH"

docker rm -f nano-pool-dgb 2>/dev/null

docker run -d \
  --name nano-pool-dgb \
  --restart unless-stopped \
  --network nano-solo_default \
  -p 3336:3334 \
  -p 3337:3335 \
  -v /Users/satsman/nano-mujina:/work \
  -w /work \
  -e NP_NODE=digibyte \
  -e NP_LISTEN=0.0.0.0:3334 \
  -e NP_RPC=http://host.docker.internal:14022 \
  -e NP_USER=mujina \
  -e NP_PASS=c94ef41d7af488216bc7cef8a2710c56 \
  -e NP_PAYOUT=D76edx2imfErFaHrh5fFwWNVKgWfojh2sa \
  -e NP_STATS_PORT=3335 \
  -e RUST_LOG=info \
  nano3s-build \
  bash -lc "cargo run --release -p nano-pool --bin nano-pool"

echo ""
echo "DGB pool:  stratum+2://192.168.0.24:3336   (stats http://192.168.0.24:3337)"
echo "BCH pool:  stratum+2://192.168.0.24:3334   (stats http://192.168.0.24:3335)"
