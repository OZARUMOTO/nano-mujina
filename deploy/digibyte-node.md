# DigiByte SV2 Node + Pool (solo mining, second chain)

Second chain for the Avalon Nano 3s: a **pruned DigiByte mainnet node** running
natively on the Mac (Docker can't fit its RAM profile — see "Why native" below),
with a **second SV2 pool instance** so the device switches coins by just
changing its pool URL.

- DGB pool: `stratum+2://192.168.0.24:3336` — stats `http://192.168.0.24:3337`
- BCH pool (existing): `stratum+2://192.168.0.24:3334` — stats `http://192.168.0.24:3335`
- Payout (DGB P2PKH): `D76edx2imfErFaHrh5fFwWNVKgWfojh2sa`
- Node RPC: `127.0.0.1:14022` (user `mujina`), algorithm: `sha256d`

## Layout on the SSD (`/Volumes/ssd/digibyte-node/`)

| Path | What |
|---|---|
| `mainnet/` | datadir: restored `blocks/` + `chainstate/` from the 5.4GB backup + `digibyte.conf` |
| `bin/` | digibyted/digibyte-cli source-built binaries (mirrored to `/usr/local/bin`) |
| `start-dgb-pool.sh` | one-shot launcher for the DGB pool container twin |
| `docker-compose.yml`, `Dockerfile` | legacy docker attempt, kept for reference only |

## Node (native, LaunchAgent)

- Binary: DigiByte Core **v9.26.5** built from source (`/tmp/dgb-src`), headless
  (`--disable-wallet --disable-tests`), installed to `/usr/local/bin/digibyted`.
- Autostart: `~/Library/LaunchAgents/org.digibyte.digibyted.plist`
  (`-daemonwait`, `-datadir=/Volumes/ssd/digibyte-node/mainnet`).
- Critical conf values (must be present **before** first start with a pruned
  chainstate): `prune=40000` (MiB), `algo=sha256d` (GBT builds SHA-256d
  templates — DGB's default mining algo is scrypt!), standard Bitcoin-Core
  options otherwise (`dbcache=150`, `par=1`, `maxmempool=10`).

DGB specifics that differ from BCHN:
- Standard `getblocktemplate` (no BCHN "light" extension, no `job_id`, **no
  `merkle` branch field** — the pool computes the coinbase branch itself from
  the full tx list).
- The block version carries the algo ID in bits 8–11: SHA-256d = `0x0200`.
  The pool forwards the template's own version (never hardcode it).
- ~24.2M block index entries (multi-algo = ~5x more headers than BTC).

## Pool (second container instance)

`start-dgb-pool.sh` runs the same `nano3s-build` image and the same pool
binary as the BCH pool, configured with:

```
NP_NODE=digibyte                          # standard-GBT path
NP_RPC=http://host.docker.internal:14022  # native node, not a container
NP_PAYOUT=D76edx2imfErFaHrh5fFwWNVKgWfojh2sa   # base58 P2PKH (DGB version 0x1e)
NP_LISTEN=0.0.0.0:3334                    # mapped to host :3336
NP_STATS_PORT=3335                        # mapped to host :3337
```

All pool-side coin support was verified with unit tests before deploy:
base58 P2PKH decode (golden vector vs `validateaddress`), merkle-branch
computation from the tx list (golden vectors), and algo-version forwarding.

## Switching the nano between coins

Device UI → settings → pool:
- BCH: `stratum+2://192.168.0.24:3334`, user `D76edx2imfErFaHrh5fFwWNVKgWfojh2sa.OPNANO`
- DGB: `stratum+2://192.168.0.24:3336`, user `D76edx2imfErFaHrh5fFwWNVKgWfojh2sa.OPNANO`

Restart the miner after the change (or use the dashboard's restart button).

## Why native and not Docker

DigiByte's block-index load needs **~4.5–5.5GB resident** (24.2M
`CBlockIndex` entries ≈ ~220B each, plus load-time overhead) and does two
24M-entry sorts at boot. Inside a Docker VM the cgroup limit turns that into
a guaranteed OOM kill (`exit=137, oom=true` — measured at 5.5GB), and on an
8GB Mac no VM sizing fits both macOS and the node. Natively, macOS swap
absorbs the transient peak (~4.4GB measured, steady state ~3GB) and the boot
completes in ~30 minutes (block-file load → sort → sort → "Processing
blocks" → chainstate → verify → live).

Related host tuning: Docker Desktop VM was right-sized to **2048MiB**
(`settings-store.json` → `MemoryMiB`) so it never competes for RAM again;
BCH node + both pools run inside it comfortably.

## Boot timeline reference (fresh, unthrashed)

| Phase | Log marker | Typical |
|---|---|---|
| block-file scan | `Loading blocks... 0→100%` | ~9 min |
| index sort #1 | `Sorting 24217870 block indices by height` | ~5 min |
| index sort #2 | `LoadBlockIndex()` second pass (silent) | ~14 min |
| process entries | `Processing blocks... 0→100%` | ~8 min |
| chainstate + verify | silent, then `UpdateTip` | ~5 min |

If a boot ever looks stuck for hours in a sort with RSS collapsing to
<1GB while swap grows — that's the thrash signature; kill and reboot fresh
with Docker stopped, then relaunch Docker after the node is live.
