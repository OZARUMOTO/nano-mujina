# Fractal Bitcoin node + SV2 pool (solo mining, third chain)

Third chain for the Avalon Nano 3s: a **pruned Fractal Bitcoin mainnet node**
(official `fractalbitcoin/fractal:v0.4.0` image) with our same nano-pool
running as an FB SV2 pool. Same playbook as BCH/DGB: the device switches
coins by changing its pool URL.

- FB pool (single-pool mode): `stratum+2://192.168.0.24:3334` — stats `http://192.168.0.24:3335`
- Payout: FB uses **Bitcoin address format** (prefix 0x00, `1...` addresses)
- PoW: plain double-SHA256 over the 80-byte header (verified: genesis hash
  matches dsha256 exactly; `CheckProofOfWork` checks the block hash). The
  nano and the pool need **no PoW changes** vs BTC mining.
- Mining template: standard `getblocktemplate` (like DGB path) — pool env
  `NP_NODE=fractalbitcoin` selects it. The template `version` is forwarded
  verbatim (FB auxpow/asert bits included).
- Fractal mainnet p2p port: **8333**, RPC **8332** (same as BTC; RPC stays
  unpublished to the host, reachable on the docker network only).

## Node layout (SSD)

```
/Volumes/ssd/FB/
├── docker-compose.yml     # fractal-mainnet service
└── mainnet/
    └── bitcoin.conf       # prune=30000, rpc bind 0.0.0.0, par=2
```

Start node: `cd /Volumes/ssd/FB && docker compose up -d`
Check sync: `docker exec fractal-mainnet bitcoin-cli -datadir=/data/ -conf=/data/bitcoin.conf getblockchaininfo`

## Snapshot note

`utxo-935000.dat` from bitcoin-snapshots.jaonoctus.dev is **Bitcoin mainnet**
(file magic `f9beb4d9` = BTC; Fractal mainnet magic is `d99eb4b9`) and FB
v0.4.0 only accepts snapshots at heights 840k/880k (hash-hardcoded in
chainparams). No public FB snapshots exist; the chain is young so fresh IBD
with `prune=30000` is the path. Deleted the BTC snapshot.

## Pool (single-pool mode)

`deploy/start-fb-pool.sh` runs the same `nano3s-build` image as the BCH
pool with `NP_NODE=fractalbitcoin`, listening on **3334/3335** (the device's
existing ports) — when switching coins, stop the BCH pool first
(`docker stop nano-pool`) so ports stay free.

## Machine notes (8GB Mac)

- Docker VM set to 3.5GB (settings-store.json MemoryMiB=3584) — enough for
  FB IBD + BCH node + one pool. Don't run BCH pool + FB pool simultaneously.
- FB IBD: ~600k headers-first then block download; prune caps blocks at
  ~30GB (chainstate ~191GB due to inscriptions — needs the SSD).
