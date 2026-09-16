#!/usr/bin/env bash
# Start the Fractal Bitcoin SV2 pool twin (single-pool mode: 3334/3335).
# Requires: fractal-mainnet node running + RPC live (warmup done).
# Stop the BCH pool first: docker stop nano-pool
set -euo pipefail

export PATH="$HOME/.docker/bin:$PATH"

: "${FB_PAYOUT:?set FB_PAYOUT to your Fractal (1...) address}"
: "${FB_RPC_PASS:?set FB_RPC_PASS to the node rpc password (see /Volumes/ssd/FB/mainnet/bitcoin.conf)}"

docker rm -f nano-pool-fb 2>/dev/null || true

docker run -d --name nano-pool-fb \
  --network nano-solo_default \
  -p 3334:3334 -p 3335:3335 \
  -v /Users/satsman/nano-mujina:/work -w /work \
  -e NP_NODE=fractalbitcoin \
  -e NP_LISTEN=0.0.0.0:3334 \
  -e NP_STATS_PORT=3335 \
  -e NP_PAYOUT="$FB_PAYOUT" \
  -e NP_USER=mujina \
  -e NP_PASS="$FB_RPC_PASS" \
  -e NP_RPC=http://fractal-mainnet:8332 \
  nano3s-build \
  bash -lc "cargo run --release -p nano-pool --bin nano-pool"

# give it the node network too (DNS name fractal-mainnet)
docker network connect fractal-node_default nano-pool-fb 2>/dev/null || true

echo "FB pool starting on 3334 — panel http://192.168.0.24:3335"
