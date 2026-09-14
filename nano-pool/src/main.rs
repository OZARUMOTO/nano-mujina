//! nano-pool: a single-downstream Stratum V2 pool for solo mining a local
//! BCHN node with the Avalon Nano 3s.
//!
//! Role: SV2 **pool** (server) on the LAN side, GBT-Light **client** toward
//! the node. The device does its own coinbase hashing with per-chip nonce2
//! rolling (extended channel), so the pool assembles the full coinbase
//! (`prefix + extranonce_prefix + extranonce + suffix`) at share time and
//! checks the header hash against the *block* target. A share that beats
//! the block target IS a valid BCH block: `header + 01 + coinbase` goes to
//! `submitblocklight`. Solo mining in one file.
//!
//! Env config:
//!   NP_LISTEN   SV2 listen addr        (default 0.0.0.0:3334)
//!   NP_RPC      node RPC url           (default http://127.0.0.1:18443)
//!   NP_USER     node RPC user          (default mujina)
//!   NP_PASS     node RPC password      (required)
//!   NP_PAYOUT   BCH address for block rewards (required)
//!   NP_WORKER_TAG  coinbase tag        (default OPNANO)

use anyhow::{anyhow, Context, Result};
use bitcoin::hashes::sha256d::Hash as Sha256d;
use bitcoin::hashes::Hash;
use bitcoin::BlockHash;
use serde_json::json;
use std::str::FromStr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use stratum_apps::key_utils::{Secp256k1PublicKey, Secp256k1SecretKey};
use stratum_apps::network_helpers::accept_noise_connection;
use stratum_apps::stratum_core::{
    binary_sv2::{B032, B064K, Seq0255, Str0255, Sv2Option, U256},
    codec_sv2::StandardSv2Frame,
    common_messages_sv2::{Protocol, SetupConnectionSuccess},
    mining_sv2::{
        NewExtendedMiningJob, OpenExtendedMiningChannelSuccess, SetNewPrevHash,
        SubmitSharesError, SubmitSharesExtended, SubmitSharesSuccess,
    },
    parsers_sv2::{CommonMessages, Mining, MiningDeviceMessages},
};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc, Mutex as AMutex};
use tracing::{debug, error, info, warn};

type StdFrame = StandardSv2Frame<MiningDeviceMessages<'static>>;

/// Pool -> device pushes, fanned out via broadcast.
#[derive(Clone)]
enum Outgoing {
    Job(NewExtendedMiningJob<'static>),
    PrevHash(SetNewPrevHash<'static>),
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct Config {
    listen: String,
    rpc_url: String,
    rpc_user: String,
    rpc_pass: String,
    payout_pkh: [u8; 20],
    /// Original payout address (display in the status panel)
    payout: String,
    worker_tag: Vec<u8>,
    extranonce_base: Vec<u8>,
}

impl Config {
    fn from_env() -> Result<Self> {
        let payout = std::env::var("NP_PAYOUT")
            .context("NP_PAYOUT (BCH address receiving solo block rewards) required")?;
        Ok(Self {
            listen: std::env::var("NP_LISTEN").unwrap_or_else(|_| "0.0.0.0:3334".into()),
            rpc_url: std::env::var("NP_RPC").unwrap_or_else(|_| "http://127.0.0.1:18443".into()),
            rpc_user: std::env::var("NP_USER").unwrap_or_else(|_| "mujina".into()),
            rpc_pass: std::env::var("NP_PASS").context("NP_PASS required")?,
            payout_pkh: decode_payout(&payout)?,
            payout,
            worker_tag: std::env::var("NP_WORKER_TAG")
                .unwrap_or_else(|_| "OPNANO".into())
                .into_bytes(),
            extranonce_base: hex::decode(
                std::env::var("NP_EXTRANONCE_PREFIX").unwrap_or_else(|_| "6d756a696e61".into()),
            )?, // "mujina"
        })
    }
}

/// Decode a BCH cashaddr (with or without `prefix:`) into its 20-byte
/// payload hash. Legacy base58 addresses are not supported (use cashaddr).
fn decode_payout(addr: &str) -> Result<[u8; 20]> {
    let a = addr.trim();
    if let Some(colon) = a.find(':') {
        let (hrp, rest) = a.split_at(colon);
        return cashaddr_decode(hrp, &rest[1..]);
    }
    cashaddr_decode("bitcoincash", a).or_else(|_| cashaddr_decode("bchreg", a))
}

/// Minimal cashaddr decoder (BCH checksum, 5-bit groups; payload is
/// 21 chars for P2PKH: version byte + 160-bit hash).
fn cashaddr_decode(hrp: &str, data: &str) -> Result<[u8; 20]> {
    const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    let lower = data.to_lowercase();
    let mut values = Vec::with_capacity(lower.len());
    for c in lower.bytes() {
        let v = CHARSET
            .iter()
            .position(|&x| x == c)
            .ok_or_else(|| anyhow!("bad cashaddr char '{c}'"))?;
        values.push(v as u8);
    }
    // P2PKH/P2SH cashaddr: 8 checksum chars + 34 payload chars
    // (version byte + 160-bit hash, 5-bit groups)
    if values.len() != 42 {
        return Err(anyhow!(
            "cashaddr payload must be 42 chars, got {}",
            values.len()
        ));
    }
    // checksum: polymod(prefix_expand(hrp) ++ values) == 0, where
    // cashaddr prefix_expand = low 5 bits of each char + single 0
    // (DIFFERENT from bech32's high/zero/low expansion)
    let mut poly_input: Vec<u8> = Vec::with_capacity(hrp.len() + 1 + values.len());
    for b in hrp.bytes() {
        poly_input.push(b & 31);
    }
    poly_input.push(0);
    poly_input.extend_from_slice(&values);
    if cashaddr_polymod(&poly_input) != 0 {
        return Err(anyhow!("cashaddr checksum mismatch"));
    }
    // 34 x 5-bit payload chars -> 21 bytes (version + 160-bit hash);
    // drop the 2 leftover bits. The 8-char checksum is the LAST 8.
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    let mut bytes = Vec::with_capacity(21);
    for &v in &values[..34] {
        acc = (acc << 5) | v as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            bytes.push(((acc >> bits) & 0xff) as u8);
        }
    }
    if bytes.len() != 21 || bytes[0] != 0x00 {
        return Err(anyhow!(
            "unsupported cashaddr (len {}, version {:#04x}) — need P2PKH",
            bytes.len(),
            bytes.first().copied().unwrap_or(0xff)
        ));
    }
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes[1..21]);
    Ok(out)
}

fn cashaddr_polymod(v: &[u8]) -> u64 {
    // BCH generator constants from the cashaddr spec (40-bit, GF(2^5))
    const G: [u64; 5] = [
        0x98f2_bc8e_61,
        0x79b7_6d99_e2,
        0xf33e_5fb3_c4,
        0xae2e_abe2_a8,
        0x1e4f_43e4_70,
    ];
    let mut c: u64 = 1;
    for &d in v {
        let c0 = c >> 35;
        c = ((c & 0x07_ffff_ffff) << 5) ^ d as u64; // 40-bit state, 35-bit mask
        for (i, g) in G.iter().enumerate() {
            if (c0 >> i) & 1 == 1 {
                c ^= g;
            }
        }
    }
    c ^ 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cashaddr_decode_p2pkh() {
        // from the node's validateaddress (scriptPubKey hash160 confirmed)
        let pkh = decode_payout("bchreg:qrcek9wqa9qwudcsnaffx3x9zcypsq07tgr6nylczg")
            .expect("regtest address decodes");
        assert_eq!(pkh, hex::decode("f19b15c0e940ee37109f529344c516081801fe5a").unwrap()[..20]);
    }
}

// ---------------------------------------------------------------------------
// Node RPC (GBT-Light)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct NodeTemplate {
    job_id: String,
    height: u64,
    prev_hash: BlockHash,
    /// merkle path, internal byte order
    merkle_branch: Vec<[u8; 32]>,
    coinbase_value: u64,
    bits: u32,
    min_ntime: u32,
}

async fn rpc(cfg: &Config, method: &str, params: serde_json::Value) -> Result<serde_json::Value> {
    let client = reqwest::Client::new();
    let resp = client
        .post(&cfg.rpc_url)
        .basic_auth(&cfg.rpc_user, Some(&cfg.rpc_pass))
        .json(&json!({"jsonrpc":"1.0","id":"np","method":method,"params":params}))
        .timeout(Duration::from_secs(30))
        .send()
        .await
        .context("node RPC unreachable")?;
    let v: serde_json::Value = resp.json().await?;
    if let Some(e) = v.get("error") {
        if !e.is_null() {
            return Err(anyhow!("node RPC {method}: {e}"));
        }
    }
    Ok(v["result"].clone())
}

async fn fetch_template(cfg: &Config) -> Result<NodeTemplate> {
    let t = rpc(cfg, "getblocktemplatelight", json!([])).await?;
    let branch = t["merkle"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|h| {
                    let mut b = [0u8; 32];
                    hex::decode_to_slice(h.as_str()?, &mut b).ok()?;
                    Some(b)
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    Ok(NodeTemplate {
        job_id: t["job_id"].as_str().context("no job_id")?.to_string(),
        height: t["height"].as_u64().context("no height")?,
        prev_hash: t["previousblockhash"].as_str().context("no prev")?.parse()?,
        merkle_branch: branch,
        coinbase_value: t["coinbasevalue"].as_u64().context("no value")?,
        bits: u32::from_str_radix(t["bits"].as_str().context("no bits")?, 16)?,
        min_ntime: t["mintime"].as_u64().unwrap_or(0) as u32,
    })
}

// ---------------------------------------------------------------------------
// Coinbase construction
// ---------------------------------------------------------------------------

/// BIP34: coinbase scriptSig begins with a push of the block height.
fn bip34_push(height: u64) -> Vec<u8> {
    if height <= 16 {
        vec![0x50 + height as u8] // OP_1..OP_16
    } else {
        let bytes = height.to_le_bytes();
        let len = bytes.iter().rposition(|&b| b != 0).map_or(1, |p| p + 1);
        let mut out = vec![len as u8];
        out.extend_from_slice(&bytes[..len]);
        out
    }
}

/// Fixed scriptSig size so prefix/suffix stay stable per job. The device
/// rolls its 8-byte extranonce inside the scriptSig, and we prepend a
/// 10-byte channel tag to the shared extranonce_prefix, so the declared
/// length must cover: bip34 push + tag push + tag + en_prefix(10) + en2(8)
/// + zero padding = 96 bytes total.
const SCRIPT_SIG_LEN: usize = 96;

#[derive(Clone)]
struct Coinbase {
    prefix: Vec<u8>,
    suffix: Vec<u8>,
}

fn build_coinbase(tpl: &NodeTemplate, cfg: &Config) -> Coinbase {
    let height_push = bip34_push(tpl.height);
    let tag = &cfg.worker_tag;

    let mut prefix = Vec::with_capacity(64);
    prefix.extend_from_slice(&2u32.to_le_bytes()); // tx version
    prefix.push(1); // input count
    prefix.extend_from_slice(&[0u8; 32]); // prevout hash: null
    prefix.extend_from_slice(&0xffffffffu32.to_le_bytes()); // prevout index
    prefix.push(SCRIPT_SIG_LEN as u8); // scriptSig varint length
    prefix.extend_from_slice(&height_push);
    prefix.push(tag.len() as u8);
    prefix.extend_from_slice(tag);
    // The channel's extranonce_prefix (6-byte base + 4-byte channel tag)
    // goes HERE, and the device appends its 8-byte extranonce right after
    // it — all INSIDE the declared scriptSig. The padding must leave room
    // for those 18 bytes so the assembled tx's scriptSig is exactly
    // SCRIPT_SIG_LEN, matching the varint above.
    const ENSPACE: usize = 10 + 8;
    let used = height_push.len() + 1 + tag.len() + ENSPACE;
    prefix.extend(std::iter::repeat(0u8).take(SCRIPT_SIG_LEN - used));

    let mut suffix = Vec::with_capacity(46);
    suffix.extend_from_slice(&0xffffffffu32.to_le_bytes()); // sequence
    suffix.push(1); // output count
    suffix.extend_from_slice(&tpl.coinbase_value.to_le_bytes());
    suffix.push(25); // P2PKH script length
    suffix.extend_from_slice(&[0x76, 0xa9, 0x14]);
    suffix.extend_from_slice(&cfg.payout_pkh);
    suffix.extend_from_slice(&[0x88, 0xac]);
    suffix.extend_from_slice(&0u32.to_le_bytes()); // nLockTime (tx terminator)
    Coinbase { prefix, suffix }
}

// ---------------------------------------------------------------------------
// Job state
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct ActiveJob {
    sv2_job_id: u32,
    node_job_id: String,
    version: u32,
    /// internal byte order
    merkle_branch: Vec<[u8; 32]>,
    coinbase: Coinbase,
    extranonce_prefix: Vec<u8>,
    extranonce_size: u16,
    min_ntime: u32,
    bits: u32,
    height: u64,
    /// LE bytes
    prev_hash_internal: [u8; 32],
}

struct PoolState {
    cfg: Config,
    next_job_id: u32,
    active: Option<ActiveJob>,
    shares_ok: u64,
    last_prev: String,
    // ---- solo-stats panel (served on NP_STATS_PORT) ----
    started: std::time::Instant,
    /// best share seen, as difficulty units (hash_target / hash)
    best_diff: f64,
    /// true when a block hash beat the network target this session
    block_found: bool,
    /// node's verdict on the last submitted block (null = accepted)
    last_block_result: String,
    /// last accepted-block height fed to the device
    node_height: u64,
    /// device's self-reported hashrate (SV2 nominal_hash_rate, hashes/s)
    device_hashrate: f64,
    /// SV2 connections since start (device auto-reconnects; count them)
    connections: u64,
    /// currently connected (set in setup handler)
    device_connected: bool,
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();
    let cfg = Config::from_env()?;
    let state = Arc::new(AMutex::new(PoolState {
        cfg: cfg.clone(),
        next_job_id: 1,
        active: None,
        shares_ok: 0,
        last_prev: String::new(),
        started: std::time::Instant::now(),
        best_diff: 0.0,
        block_found: false,
        last_block_result: "none yet".into(),
        node_height: 0,
        device_hashrate: 0.0,
        connections: 0,
        device_connected: false,
    }));
    let (job_tx, _) = broadcast::channel::<Outgoing>(16);

    // Solo-stats panel: tiny HTTP server (JSON at /stats, HTML at /).
    let stats_state = state.clone();
    let stats_port: u16 = std::env::var("NP_STATS_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(3335);
    tokio::spawn(async move {
        if let Err(e) = stats_server(stats_port, stats_state).await {
            error!("stats server: {e:#}");
        }
    });

    // Template refresher: poll GBT-Light. Only rotate the downstream job
    // when the node's template actually CHANGED (its job_id is
    // content-derived): churning the SV2 job id on every poll orphans the
    // work the device is hashing and every share bounces job-not-found.
    // New tip -> future job + SetNewPrevHash; same tip but refreshed
    // template (mempool moved) -> immediate job (min_ntime=Some uses the
    // last SetNewPrevHash prev-hash, per the SV2 mining protocol).
    {
        let state = state.clone();
        let job_tx = job_tx.clone();
        tokio::spawn(async move {
            loop {
                let cfg = state.lock().await.cfg.clone();
                match fetch_template(&cfg).await {
                    Ok(tpl) => {
                        let mut st = state.lock().await;
                        if st
                            .active
                            .as_ref()
                            .map(|a| a.node_job_id == tpl.job_id)
                            .unwrap_or(false)
                        {
                            continue; // unchanged template, keep current job
                        }
                        let new_tip = st.last_prev != tpl.prev_hash.to_string();
                        st.last_prev = tpl.prev_hash.to_string();
                        let sv2_id = st.next_job_id;
                        st.next_job_id += 1;
                        // carry the channel prefix across jobs if one is open
                        let prefix = st
                            .active
                            .as_ref()
                            .map(|a| a.extranonce_prefix.clone())
                            .unwrap_or_else(|| st.cfg.extranonce_base.clone());
                        let mut job = make_job(&tpl, &st.cfg, sv2_id);
                        job.extranonce_prefix = prefix;
                        let (mut j, ph) = to_sv2_messages(&job);
                        if new_tip {
                            st.node_height = tpl.height;
                            info!(height = tpl.height, prev = %tpl.prev_hash, "new template (new tip)");
                            let _ = job_tx.send(Outgoing::Job(j));
                            let _ = job_tx.send(Outgoing::PrevHash(ph));
                        } else {
                            info!(height = tpl.height, "template refreshed (same tip)");
                            j.min_ntime = Sv2Option::new(Some(job.min_ntime));
                            let _ = job_tx.send(Outgoing::Job(j));
                        }
                        st.active = Some(job);
                    }
                    Err(e) => warn!("template fetch: {e:#}"),
                }
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        });
    }

    let listener = TcpListener::bind(&cfg.listen).await?;
    info!(listen = %cfg.listen, "nano-pool: SV2 solo pool ready");

    loop {
        let (stream, addr) = listener.accept().await?;
        let state = state.clone();
        let job_rx = job_tx.subscribe();
        tokio::spawn(async move {
            if let Err(e) = handle_downstream(stream, state, job_rx).await {
                error!(%addr, "downstream: {e:#}");
            }
        });
    }
}

fn make_job(tpl: &NodeTemplate, cfg: &Config, sv2_id: u32) -> ActiveJob {
    ActiveJob {
        sv2_job_id: sv2_id,
        node_job_id: tpl.job_id.clone(),
        version: 0x2000_0000,
        merkle_branch: tpl.merkle_branch.clone(),
        coinbase: build_coinbase(tpl, cfg),
        extranonce_prefix: Vec::new(),
        extranonce_size: 8,
        min_ntime: tpl.min_ntime,
        bits: tpl.bits,
        height: tpl.height,
        prev_hash_internal: *tpl.prev_hash.as_raw_hash().as_byte_array(),
    }
}

/// Build the SV2 job + prevhash pair. Merkle path on the wire is
/// little-endian (internal) order per the SV2 spec.
fn to_sv2_messages(job: &ActiveJob) -> (NewExtendedMiningJob<'static>, SetNewPrevHash<'static>) {
    let path: Vec<U256<'static>> = job.merkle_branch.iter().map(|n| U256::from(*n)).collect();
    let job_msg = NewExtendedMiningJob {
        channel_id: 1,
        job_id: job.sv2_job_id,
        min_ntime: Sv2Option::new(None), // future job until SetNewPrevHash
        version: job.version,
        version_rolling_allowed: false,
        merkle_path: Seq0255::new(path).expect("path fits"),
        coinbase_tx_prefix: B064K::try_from(job.coinbase.prefix.clone()).expect("fits"),
        coinbase_tx_suffix: B064K::try_from(job.coinbase.suffix.clone()).expect("fits"),
    };
    let prev = SetNewPrevHash {
        channel_id: 1,
        job_id: job.sv2_job_id,
        prev_hash: U256::from(job.prev_hash_internal),
        min_ntime: job.min_ntime,
        nbits: job.bits,
    };
    (job_msg, prev)
}

async fn handle_downstream(
    stream: TcpStream,
    state: Arc<AMutex<PoolState>>,
    mut job_rx: broadcast::Receiver<Outgoing>,
) -> Result<()> {
    // Local pool static Noise keys (no authority pinning — solo rig only).
    // hex priv: 242d334c034463ac4dee875ac09220f6183f60c505ebcecb2c5ae22c2c3057c1
    // key_utils parses base58check; pub = b58check(0x01,0x00 ++ x-only key)
    let prv = Secp256k1SecretKey::from_str(
        "Gw5k5r6LcSWS1ywqNExwYdNeSH8RPLbxGdqC4azKLyirTu1Jr",
    )
    .map_err(|_| anyhow!("bad static key"))?;
    let pub_ = Secp256k1PublicKey::from_str(
        "9bThaKaaFTfTYCZhDx1p9RmSmLZeRjoGXvye5QLk9G9EjuXqWUa",
    )
    .map_err(|_| anyhow!("bad static key"))?;
    let noise = accept_noise_connection::<MiningDeviceMessages<'static>>(
        stream, pub_, prv, 86400,
    )
    .await
    .map_err(|e| anyhow!("noise handshake: {e:?}"))?;
    state.lock().await.connections += 1;
    info!("device connected (Noise OK)");
    let (mut reader, mut writer) = noise.into_split();

    let (out_tx, mut out_rx) = mpsc::channel::<MiningDeviceMessages<'static>>(32);

    // writer task: serialize everything the connection sends
    let _writer_task = tokio::spawn(async move {
        while let Some(msg) = out_rx.recv().await {
            let frame: StdFrame = match msg.try_into() {
                Ok(f) => f,
                Err(e) => {
                    error!("encode: {e:?}");
                    continue;
                }
            };
            if let Err(e) = writer.write_frame(frame.into()).await {
                error!("write: {e}");
                break;
            }
        }
    });

    let mut setup_done = false;
    let mut channel_open = false;

    loop {
        tokio::select! {
            // pool -> device job pushes (only after the channel is open)
            out = job_rx.recv() => {
                if channel_open {
                    if let Ok(out) = out {
                        let msg = match out {
                            Outgoing::Job(j) =>
                                MiningDeviceMessages::Mining(Mining::NewExtendedMiningJob(j)),
                            Outgoing::PrevHash(p) =>
                                MiningDeviceMessages::Mining(Mining::SetNewPrevHash(p)),
                        };
                        let _ = out_tx.send(msg).await;
                    }
                }
            }
            // device -> pool
            frame = reader.read_frame() => {
                let mut frame: StdFrame = frame
                    .map_err(|e| anyhow!("read: {e:?}"))?
                    .try_into()
                    .map_err(|_| anyhow!("unexpected frame kind"))?;
                let msg_type = frame.get_header().ok_or_else(|| anyhow!("no header"))?.msg_type();
                let payload = frame.payload();

                // Parse borrowed from the frame buffer, then lift to
                // 'static immediately: handlers retain messages (job
                // state) beyond this iteration; into_static() deep-copies.
                let msg: MiningDeviceMessages<'static> =
                    match MiningDeviceMessages::try_from((msg_type, payload))
                        .map_err(|e| anyhow!("parse: {e:?}"))?
                    {
                        MiningDeviceMessages::Mining(m) => MiningDeviceMessages::Mining(m.into_static()),
                        MiningDeviceMessages::Common(m) => MiningDeviceMessages::Common(m.into_static()),
                        MiningDeviceMessages::Extensions(m) => {
                            MiningDeviceMessages::Extensions(m.into_static())
                        }
                    };

                match msg {
                    MiningDeviceMessages::Common(CommonMessages::SetupConnection(m)) => {
                        if m.protocol != Protocol::MiningProtocol {
                            return Err(anyhow!("not mining protocol"));
                        }
                        if m.flags & 0x1 == 0 {
                            warn!("device did not declare extended-channel support; continuing");
                        }
                        setup_done = true;
                        state.lock().await.device_connected = true;
                        let _ = out_tx
                            .send(MiningDeviceMessages::Common(CommonMessages::SetupConnectionSuccess(
                                SetupConnectionSuccess { used_version: 2, flags: 0 },
                            )))
                            .await;
                        info!("setup complete (proto v2)");
                    }
                    MiningDeviceMessages::Common(CommonMessages::SetupConnectionError(e)) => {
                        return Err(anyhow!(
                            "device rejected setup: {}",
                            e.error_code.as_utf8_or_hex()
                        ));
                    }
                    MiningDeviceMessages::Mining(Mining::OpenExtendedMiningChannel(m)) => {
                        if !setup_done {
                            return Err(anyhow!("open before setup"));
                        }
                        let target: [u8; 32] = {
                            // ~difficulty 256: shares are only a stats
                            // feed here (solo pool banks nothing), and at
                            // 6 TH/s difficulty-1 flooded the device's
                            // little core with hundreds of SV2 messages
                            // per second -- it starved the dashboard API
                            // and LCD (found live 2026-09-14). ~0.7
                            // shares/s at 6 TH/s is plenty.
                            //
                            // Byte order: the device reads this U256 as
                            // LITTLE-endian, so byte i weighs 2^(8i).
                            // Diff-1 target ≈ 2^224 (bytes 26..28 set);
                            // diff-256 = diff1/2^8 ≈ 2^216 → byte 26
                            // only. (Setting MORE bytes makes the target
                            // EASIER -- that mistake briefly took us to
                            // diff ~0.75 and a 180/s flood.)
                            let mut t = [0u8; 32];
                            t[26] = 0xff;
                            t
                        };
                        let extranonce_size = 8u16;
                        let (prefix, success) = {
                            let st = state.lock().await;
                            let _ = st.active.as_ref().ok_or_else(|| anyhow!("no template yet"))?;
                            let mut prefix = st.cfg.extranonce_base.clone();
                            prefix.extend_from_slice(&1u32.to_be_bytes()); // channel tag
                            let success = OpenExtendedMiningChannelSuccess {
                                request_id: m.request_id,
                                channel_id: 1,
                                target: U256::from(target),
                                extranonce_size,
                                extranonce_prefix: B032::try_from(prefix.clone())
                                    .map_err(|_| anyhow!("prefix too long"))?,
                                group_channel_id: 0,
                            };
                            (prefix, success)
                        };
                        // latch prefix onto the active job for share checks
                        {
                            let mut st = state.lock().await;
                            st.device_hashrate = m.nominal_hash_rate as f64;
                            if let Some(job) = st.active.as_mut() {
                                job.extranonce_prefix = prefix;
                                job.extranonce_size = extranonce_size;
                            }
                        }
                        channel_open = true;
                        let _ = out_tx
                            .send(MiningDeviceMessages::Mining(
                                Mining::OpenExtendedMiningChannelSuccess(success),
                            ))
                            .await;
                        info!("channel opened (en2={extranonce_size}B)");

                        // Send the CURRENT job immediately so the device
                        // starts hashing without waiting for the next block.
                        let (j, ph) = {
                            let st = state.lock().await;
                            let job = st.active.as_ref().expect("template exists");
                            to_sv2_messages(job)
                        };
                        let _ = out_tx
                            .send(MiningDeviceMessages::Mining(Mining::NewExtendedMiningJob(j)))
                            .await;
                        let _ = out_tx
                            .send(MiningDeviceMessages::Mining(Mining::SetNewPrevHash(ph)))
                            .await;
                        info!("initial job + prevhash pushed");
                    }
                    MiningDeviceMessages::Mining(Mining::SubmitSharesExtended(m)) => {
                        if let Err(e) = handle_share(&out_tx, &state, m).await {
                            error!("share: {e:#}");
                        }
                    }
                    MiningDeviceMessages::Mining(Mining::UpdateChannel(m)) => {
                        state.lock().await.device_hashrate = m.nominal_hash_rate as f64;
                        debug!(nominal = m.nominal_hash_rate, "update_channel (solo: target fixed)");
                    }
                    other => {
                        debug!(?other, "ignored");
                    }
                }
            }
        }
    }
}

async fn handle_share(
    out_tx: &mpsc::Sender<MiningDeviceMessages<'static>>,
    state: &Arc<AMutex<PoolState>>,
    m: SubmitSharesExtended<'static>,
) -> Result<()> {
    static ACCEPTED: AtomicU32 = AtomicU32::new(0);

    let job = {
        let st = state.lock().await;
        st.active
            .as_ref()
            .and_then(|a| (a.sv2_job_id == m.job_id).then(|| a.clone()))
    };
    let Some(job) = job else {
        let err = SubmitSharesError {
            channel_id: m.channel_id,
            sequence_number: m.sequence_number,
            error_code: Str0255::try_from("job-not-found".to_string())
                .map_err(|_| anyhow!("ec"))?,
        };
        let _ = out_tx
            .send(MiningDeviceMessages::Mining(Mining::SubmitSharesError(err)))
            .await;
        return Ok(());
    };

    // full coinbase = prefix + extranonce_prefix + extranonce + suffix
    let mut coinbase = job.coinbase.prefix.clone();
    coinbase.extend_from_slice(&job.extranonce_prefix);
    coinbase.extend_from_slice(&m.extranonce.to_owned_bytes());
    coinbase.extend_from_slice(&job.coinbase.suffix);

    // coinbase txid (LE)
    let cb_txid = Sha256d::hash(&coinbase).to_byte_array();

    // merkle root (internal order): climb the branch
    let mut root = cb_txid;
    for node in &job.merkle_branch {
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(&root);
        buf[32..].copy_from_slice(node);
        root = Sha256d::hash(&buf).to_byte_array();
    }

    // 80-byte header (prev_hash + merkle root in internal/LE order)
    let mut header = Vec::with_capacity(80);
    header.extend_from_slice(&m.version.to_le_bytes());
    header.extend_from_slice(&job.prev_hash_internal);
    header.extend_from_slice(&root);
    header.extend_from_slice(&m.ntime.to_le_bytes());
    header.extend_from_slice(&job.bits.to_le_bytes());
    header.extend_from_slice(&m.nonce.to_le_bytes());

    let hash_le = Sha256d::hash(&header).to_byte_array();
    let hash_be: Vec<u8> = hash_le.iter().rev().cloned().collect();
    let target_be = bits_to_target_be(job.bits);

    // Best-share tracking: share difficulty = network_target / hash, both
    // big-endian, compared by their leading 64 bits (enough resolution;
    // avoids bignum math).
    {
        // Best-share tracking in standard difficulty units: d =
        // diff1_target / hash over full 256-bit values. diff1 ≈ 2^224 has
        // 32 leading zero bits; a hash worth 2^(256-z) therefore has
        // d ≈ 2^(z-32). Power-of-two granularity is fine for display.
        let z = leading_zero_bits(hash_be[..32].try_into().unwrap());
        let d = 2f64.powi(z as i32 - 32);
        let mut st = state.lock().await;
        st.best_diff = st.best_diff.max(d);
    }

    if hash_be.as_slice() <= target_be.as_slice() {
        // *** SOLO BLOCK CANDIDATE ***
        let mut block = header.clone();
        block.push(1); // txn count
        block.extend_from_slice(&coinbase);
        let block_hex = hex::encode(block);
        info!(height = job.height, "*** BLOCK CANDIDATE *** submitting to node");
        {
            let mut st = state.lock().await;
            st.block_found = true;
        }
        let cfg = state.lock().await.cfg.clone();
        match rpc(&cfg, "submitblocklight", json!([block_hex, job.node_job_id])).await {
            Ok(v) => {
                if v.is_null() {
                    error!(height = job.height, "*** BLOCK ACCEPTED — SOLO BLOCK! ***");
                    state.lock().await.last_block_result = "ACCEPTED 🎉".into();
                } else {
                    warn!(height = job.height, resp = %v, "block rejected by node");
                    state.lock().await.last_block_result = format!("rejected: {v}");
                }
            }
            Err(e) => {
                error!("block submit failed: {e:#}");
                state.lock().await.last_block_result = format!("submit failed: {e:#}");
            }
        }
    }

    // bookkeeping + protocol response
    {
        let mut st = state.lock().await;
        st.shares_ok += 1;
        let n = st.shares_ok;
        if n % 1000 == 0 {
            info!(shares = n, "progress");
        }
    }
    let cnt = ACCEPTED.fetch_add(1, Ordering::Relaxed) + 1;
    let resp = SubmitSharesSuccess {
        channel_id: m.channel_id,
        last_sequence_number: m.sequence_number,
        new_submits_accepted_count: cnt,
        new_shares_sum: 0,
    };
    let _ = out_tx
        .send(MiningDeviceMessages::Mining(Mining::SubmitSharesSuccess(resp)))
        .await;
    Ok(())
}

// ---------------------------------------------------------------------------
// Solo-stats panel (http://<mac>:3335/)
// ---------------------------------------------------------------------------

async fn stats_server(port: u16, state: Arc<AMutex<PoolState>>) -> Result<()> {
    use std::sync::atomic::{AtomicU64, Ordering as AOrd};
    static CONN: AtomicU64 = AtomicU64::new(0);
    let listener = TcpListener::bind(("0.0.0.0", port)).await?;
    info!(port, "solo-stats panel listening (open http://<mac>:{port}/)");
    loop {
        let (stream, _) = listener.accept().await?;
        let state = state.clone();
        CONN.fetch_add(1, AOrd::Relaxed);
        let n = CONN.load(AOrd::Relaxed);
        tokio::spawn(async move {
            let _ = serve_stats_http(stream, state, n).await;
        });
    }
}

async fn serve_stats_http(
    stream: TcpStream,
    state: Arc<AMutex<PoolState>>,
    n: u64,
) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (mut rd, mut wr) = stream.into_split();
    let mut buf = [0u8; 2048];
    let _ = rd.read(&mut buf).await;
    let req = String::from_utf8_lossy(&buf);
    let path = req.split_whitespace().nth(1).unwrap_or("/");

    let st = state.lock().await;
    let secs = st.started.elapsed().as_secs();
    let (days, hrs, mins) = (secs / 86400, (secs % 86400) / 3600, (secs % 3600) / 60);
    let shares = st.shares_ok;
    let shps = if secs > 0 { shares as f64 / secs as f64 } else { 0.0 };
    let best = st.best_diff;
    let height = st.node_height;
    let payout = st.cfg.payout.clone();
    let (block_found, block_result) = (st.block_found, st.last_block_result.clone());
    let connected = st.device_connected;
    let conns = st.connections + n;
    let bits = st.active.as_ref().map(|j| j.bits);
    let device_th = st.device_hashrate / 1e12;
    drop(st);

    // Device hashrate comes from its own SV2 UpdateChannel reports
    // (nominal_hash_rate, hashes/s) -- authoritative, not share-derived.

    if path.starts_with("/stats") {
        let body = json!({
            "mode": "solo BCH via local BCHN (GBT-Light) over Stratum V2",
            "payout": payout,
            "device_connected": connected,
            "connections_total": conns,
            "uptime_secs": secs,
            "shares": shares,
            "shares_per_sec": (shps * 100.0).round() / 100.0,
            "device_hashrate_th": (device_th * 100.0).round() / 100.0,
            "best_share_diff": if best.is_infinite() { json!("inf") } else { json!((best * 100.0).round() / 100.0) },
            "node_height": height,
            "network_nbits": bits.map(|b| format!("{b:08x}")),
            "block_found": block_found,
            "last_block_result": block_result,
        });
        let body = body.to_string();
        wr.write_all(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .as_bytes(),
        ).await?;
        return Ok(());
    }

    let banner = if block_found {
        format!("BLOCK CANDIDATE THIS SESSION — {}", block_result)
    } else {
        "no block yet — every share is checked against the network target".into()
    };
    let connected_html = if connected {
        "<span class=ok>connected</span>"
    } else {
        "<span class=bad>NOT connected — check miner settings</span>"
    };
    let html = format!(
        r#"<!doctype html><html><head><meta charset=utf-8><title>nano-pool solo status</title>
<style>
body{{font-family:-apple-system,system-ui,sans-serif;background:#0d1117;color:#e6edf3;margin:0;padding:2rem;max-width:760px;margin-inline:auto}}
h1{{font-size:1.3rem;margin:0 0 .2em}}
.sub{{color:#8b949e;font-size:.85rem;margin-bottom:1.5rem}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:.8rem}}
.card{{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:.9rem 1.1rem}}
.k{{color:#8b949e;font-size:.72rem;text-transform:uppercase;letter-spacing:.06em}}
.v{{font-size:1.45rem;font-weight:600;margin-top:.25rem;font-variant-numeric:tabular-nums}}
.big .v{{font-size:2rem;color:#58a6ff}}
.ok{{color:#3fb950}}.bad{{color:#f85149}}
.banner{{margin-top:1.2rem;padding:.8rem 1rem;border-radius:10px;background:#161b22;border:1px solid #30363d;color:#d29922;font-size:.9rem}}
.note{{color:#8b949e;font-size:.78rem;margin-top:1.4rem;line-height:1.5}}
code{{background:#161b22;padding:.1em .35em;border-radius:4px}}
</style></head><body>
<h1>nano-pool — solo BCH</h1>
<div class=sub>Stratum V2 pool → local BCHN (GBT-Light) → solo block submit</div>
<div class=grid>
<div class="card big"><div class=k>Shares</div><div class=v id=shares>{}</div></div>
<div class="card big"><div class=k>Best share (difficulty)</div><div class=v id=best>{:.2}</div></div>
<div class=card><div class=k>Device hashrate (self-reported)</div><div class=v id=hr>{:.2} TH/s</div></div>
<div class=card><div class=k>Device</div><div class=v>{}</div></div>
<div class=card><div class=k>Uptime</div><div class=v>{}d {:02}h {:02}m</div></div>
<div class=card><div class=k>Node height</div><div class=v id=height>{}</div></div>
<div class=card><div class=k>Network nbits</div><div class=v>{}</div></div>
<div class=card><div class=k>Connections (total)</div><div class=v>{}</div></div>
</div>
<div class=banner id=banner>{}</div>
<div class=note>
Share difficulty is ~256 (stats feed only — one share per ~2^40 hashes).
The <b>block</b> check runs on every share against the real BCH network target
(nbits above): {} ≈ 1 in {:.0} per hash. Expected solo block interval at this
hashrate: months. Payout: <code>{}</code><br>
JSON: <code>/stats</code> — refreshes every 5s.
</div>
<script>
const fmt=n=>n.toLocaleString();
setInterval(async()=>{{
 try{{
  const s=await(await fetch('/stats')).json();
  shares.textContent=fmt(s.shares); hr.textContent=s.device_hashrate_th+' TH/s';
  best.textContent=(s.best_share_diff==="inf"?'∞':s.best_share_diff);
  height.textContent=fmt(s.node_height);
 }}catch(e){{}}
}},5000);
</script>
</body></html>"#,
        shares,
        if best.is_infinite() { f64::INFINITY } else { best },
        device_th,
        connected_html,
        days, hrs, mins,
        height,
        bits.map(|b| format!("{b:08x}")).unwrap_or_else(|| "—".into()),
        conns,
        banner,
        bits.map(|b| format!("0x{b:08x}")).unwrap_or_else(|| "—".into()),
        {
            // difficulty from nbits for the note line
            match bits {
                Some(b) => {
                    let t = bits_to_target_be(b);
                    let t_top = u64::from_be_bytes(t[..8].try_into().unwrap());
                    // diff1_target / network_target, top-64-bit approximation
                    let d1: u64 = 0x0000_0000_ffff_0000;
                    if t_top == 0 { f64::INFINITY } else { (d1 as f64) / (t_top as f64) * 65536.0 }
                }
                None => 0.0,
            }
        },
        payout,
    );
    wr.write_all(
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            html.len(),
            html
        )
        .as_bytes(),
    )
    .await?;
    Ok(())
}

/// Count leading zero bits of a big-endian 32-byte hash.
fn leading_zero_bits(be: &[u8; 32]) -> u32 {
    let mut z: u32 = 0;
    for &b in be {
        if b == 0 {
            z += 8;
        } else {
            z += b.leading_zeros();
            break;
        }
    }
    z
}

/// bitcoin compact `bits` -> 32-byte big-endian target.
/// target = mantissa(3 bytes) * 256^(exponent-3); the mantissa's top byte
/// lands at BE index 32-exponent.
fn bits_to_target_be(bits: u32) -> [u8; 32] {
    let exp = (bits >> 24) as usize;
    let mut t = [0u8; 32];
    let m = [((bits >> 16) & 0xff) as u8, ((bits >> 8) & 0xff) as u8, (bits & 0xff) as u8];
    for (i, &b) in m.iter().enumerate() {
        let pos = 32usize.checked_sub(exp).map(|p| p + i);
        if let Some(p @ 0..32) = pos {
            t[p] = b;
        }
    }
    t
}
