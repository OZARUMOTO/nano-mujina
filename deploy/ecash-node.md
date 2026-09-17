# eCash (XEC) SV2 Node + Solo Pool

Third chain on the Avalon Nano 3s. Warm-started from the user's pruned
blocks+chainstate backup — full IBD took ~5 minutes (vs Fractal's 280h).
Mining works with **zero pool code changes**.

## Running pieces

| Piece | What/where |
|---|---|
| Node | docker `bitcoinabc/bitcoin-abc:latest` (v0.33.12, matches backup), container `xec-mainnet`, datadir `/Volumes/ssd/xec-node/mainnet` (mounted `/data`) |
| Conf | `prune=550`, `rpcport=8432`, `rpcauth=mujina:...` (HMAC-SHA256), no `port=` (mainnet P2P is **8333** — do not set 8433) |
| Pool | container `nano-pool-xec` = same `nano3s-build` image + repo mount as `nano-pool`, ports 3334/3335 |
| Stats | http://192.168.0.24:3335 |
| Payout | `ecash:qq68vhpreem7tl8p9m3y9vzpgxphesvd0sg5wrz639` |

Device pool URL is unchanged: `stratum+2://192.168.0.24:3334` — coin
switching happens host-side only.

## Pool env differences vs BCH

- `NP_NODE=standard` → standard `getblocktemplate` (ABC nodes have no
  `getblocktemplatelight`; same path DigiByte uses)
- `NP_RPC=http://xec-mainnet:8432` + XEC rpcauth password
- `NP_PAYOUT=ecash:...` (cashaddr payload is prefix-agnostic — same
  20-byte pkh as BCH, but XEC wallet expects ecash-prefixed addr)

## Coin switch (single pool at a time)

```bash
# to XEC (current)
docker stop nano-pool 2>/dev/null; docker start nano-pool-xec

# back to BCH
docker stop nano-pool-xec; docker start nano-pool
```

Device auto-reconnects via backoff (~1–2 min). No reflash, no device
config change.

## Gotchas hit during setup (do not repeat)

1. `rpcauth` hash must be **HMAC-SHA256(salt, password)**, not plain
   SHA-256 — generate via python, never shell interpolation (a shell
   heredoc ate the `$` and produced `Invalid -rpcauth argument`).
2. Do not set `port=` in the conf. ABC mainnet P2P is 8333 (host side
   owned by BCHN container — XEC P2P stays container-internal; only
   RPC 8432 is published).
3. If peers sit at 0 after start: `addnode <ip>:8333 add` from
   `seed.bitcoinabc.org` DNS — kicks the addr manager, then it fills
   to 30–50 peers on its own.
4. BitcoinABC-Qt.app (macOS build) is GUI-only — headless goes through
   the docker image.
