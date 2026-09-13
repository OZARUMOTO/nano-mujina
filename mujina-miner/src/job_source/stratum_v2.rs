//! Stratum v2 job source implementation (extended mining channels).
//!
//! # Why extended channels
//!
//! The A3221 chain rolls `extranonce2` in software to explore nonce space
//! (see the fork's own scheduler notes: header-only jobs can't work on this
//! ASIC because per-chip nonce2 rolling needs the raw coinbase + merkle
//! branches). SV2 *standard* channels only carry a fixed merkle root, but SV2
//! **extended** channels carry `coinbase_tx_prefix`/`coinbase_tx_suffix` +
//! `merkle_path` -- exactly the material `MerkleRootTemplate` models for SV1.
//! So this source opens one extended channel per pool connection and maps
//! SV2 jobs onto the same `JobTemplate` flow SV1 uses.
//!
//! # Protocol flow (device role, extended channel)
//!
//! ```text
//! us -> pool: SetupConnection        (MiningProtocol, flags: require-standard-jobs bit CLEAR)
//! pool -> us: SetupConnectionSuccess
//! us -> pool: OpenExtendedMiningChannel {request_id, user_identity, nominal_hash_rate,
//!                                        max_target, min_extranonce_size}
//! pool -> us: OpenExtendedMiningChannelSuccess {channel_id, target, extranonce_size,
//!                                               extranonce_prefix, ...}
//! pool -> us: NewExtendedMiningJob {job_id, min_ntime(None=future), version,
//!                                   version_rolling_allowed, merkle_path,
//!                                   coinbase_tx_prefix, coinbase_tx_suffix}
//! pool -> us: SetNewPrevHash {job_id, prev_hash, min_ntime, nbits}
//!             (activates the future job with matching job_id)
//! us -> pool: SubmitSharesExtended {channel_id, sequence_number, job_id, nonce,
//!                                   ntime, version, extranonce}
//! ```
//!
//! # Byte-order rules (verified against SRI sources)
//!
//! - `prev_hash` (U256): SRI's `u256_to_block_hash` does
//!   `BlockHash::from_raw_hash(Hash::from_slice(v.into_array()))`, so the raw
//!   byte array IS the sha256d hash bytes of our `BlockHash`.
//! - `merkle_path` nodes: raw byte arrays, concatenated as-is when climbing
//!   (identical to our SV1 climb in `MerkleRootTemplate`).
//! - `target`: little-endian U256 (SRI's device reads it with
//!   `U256::from_little_endian`; our `crate::u256::U256::from_le_bytes` is
//!   the same layout, and `Target::from(U256)` converts losslessly).
//! - extranonce in a submission: the *rollable* part only; the pool
//!   reconstructs `extranonce_prefix + extranonce` between
//!   `coinbase_tx_prefix` and `coinbase_tx_suffix` (verified against
//!   `ExtendedChannel::validate_share` in channels_sv2).
//!
//! # Share target
//!
//! The pool assigns the share target (`OpenExtendedMiningChannelSuccess.target`,
//! later `SetTarget`); we pass it straight through as `JobTemplate::share_target`.
//! The scheduler handles submission rate limiting itself. We request a
//! difficulty-1 `max_target` on open (the easiest allowed); pools clamp to
//! their own vardiff anyway.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use bitcoin::hash_types::BlockHash;
use bitcoin::hashes::Hash;
use bitcoin::pow::CompactTarget;
use async_channel::{Receiver as AsyncReceiver, Sender as AsyncSender};
use stratum_apps::network_helpers::noise_connection::Connection;
use stratum_apps::stratum_core::{
    binary_sv2::U256 as Sv2U256,
    codec_sv2::{HandshakeRole, StandardEitherFrame, StandardSv2Frame},
    common_messages_sv2::{Protocol, SetupConnection},
    mining_sv2::{
        NewExtendedMiningJob, OpenExtendedMiningChannel,
        SetNewPrevHash as MiningSetNewPrevHash, SubmitSharesExtended,
    },
    noise_sv2::Initiator,
    parsers_sv2::{CommonMessages, Mining, MiningDeviceMessages, ParserError},
};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::tracing::prelude::*;
use crate::types::HashRate;

use super::{
    Extranonce2Range, GeneralPurposeBits, JobTemplate, MerkleRootKind, MerkleRootTemplate, Share,
    SourceCommand, SourceEvent, VersionTemplate,
};

/// Process-wide SV2 pool accept/reject counters, for the dashboard's Info
/// page (mirrors the SV1 counters; the board reporter sums both).
static SV2_SHARES_ACCEPTED: AtomicU64 = AtomicU64::new(0);
static SV2_SHARES_REJECTED: AtomicU64 = AtomicU64::new(0);

/// Monotonic sequence counter for SubmitSharesExtended (per process; the
/// protocol requires it to increase within the channel).
static SUBMIT_SEQUENCE: AtomicU32 = AtomicU32::new(0);

/// SV2 pool accept/reject totals since this process started.
pub fn sv2_share_accept_reject_counts() -> (u64, u64) {
    (
        SV2_SHARES_ACCEPTED.load(Ordering::Relaxed),
        SV2_SHARES_REJECTED.load(Ordering::Relaxed),
    )
}

/// SV2 pool connection configuration (parallel to SV1's `PoolConfig`).
#[derive(Debug, Clone)]
pub struct Sv2PoolConfig {
    /// `stratum+2://host:port` (scheme stripped before connecting).
    pub url: String,
    /// Wallet address / account, sent as the channel's `user_identity`.
    pub username: String,
    /// Core SV2 mining has no auth layer; kept for config parity.
    #[allow(dead_code)]
    pub password: String,
    /// Sent in SetupConnection's `firmware` field.
    pub user_agent: String,
}

/// A job received from the pool, flattened to owned data so it can outlive
/// the frame it arrived in (future jobs are stored until their
/// `SetNewPrevHash` arrives, arbitrarily later).
#[derive(Debug, Clone)]
struct OwnedJob {
    #[allow(dead_code)]
    channel_id: u32,
    job_id: u32,
    /// `None` => future job, waiting on `SetNewPrevHash`.
    min_ntime: Option<u32>,
    version: u32,
    version_rolling_allowed: bool,
    /// Merkle path, deepest first, as raw 32-byte arrays.
    merkle_path: Vec<[u8; 32]>,
    coinbase_tx_prefix: Vec<u8>,
    coinbase_tx_suffix: Vec<u8>,
    /// Pool-assigned extranonce prefix (constant for the channel).
    extranonce_prefix: Vec<u8>,
    /// Rollable extranonce width in bytes (our extranonce2 size).
    extranonce_size: u16,
}

impl OwnedJob {
    /// Map onto the scheduler's `JobTemplate` (prev-hash/nbits supplied by
    /// the activating `SetNewPrevHash`).
    ///
    /// Extranonce layout mirrors SV1 exactly: `coinbase1 = prefix`,
    /// `extranonce1 = pool extranonce_prefix`, `extranonce2 = rollable space`
    /// (`extranonce_size` bytes), `coinbase2 = suffix`.
    fn merkle_template(
        &self,
        prev_blockhash: BlockHash,
        nbits: CompactTarget,
    ) -> Result<JobTemplate> {
        if self.extranonce_size == 0 || self.extranonce_size > 8 {
            return Err(anyhow!(
                "pool assigned unusable extranonce_size {} (need 1-8 for software rolling)",
                self.extranonce_size
            ));
        }
        let merkle_branches = self
            .merkle_path
            .iter()
            .map(|node| bitcoin::hash_types::TxMerkleNode::from_byte_array(*node))
            .collect();

        // VersionTemplate requires the base version's BIP320 region (bits
        // 13-28) clear. SV2 pools send the consensus version with the GP
        // bits reserved for rolling; mask defensively rather than reject.
        // BIP320 GP region = bits 13..=28 => mask 0x1fff_e000.
        let base_version =
            bitcoin::block::Version::from_consensus((self.version & !0x1fff_e000) as i32);
        let gp_bits_mask = if self.version_rolling_allowed {
            GeneralPurposeBits::full()
        } else {
            GeneralPurposeBits::none()
        };
        let version =
            VersionTemplate::new(base_version, gp_bits_mask).map_err(|e| anyhow!("version template: {e}"))?;

        Ok(JobTemplate {
            id: self.job_id.to_string(),
            prev_blockhash,
            version,
            bits: nbits,
            // Overwritten by `build_template` with the pool's target.
            share_target: crate::types::Difficulty::from(1).to_target(),
            time: self.min_ntime.unwrap_or(0),
            merkle_root: MerkleRootKind::Computed(MerkleRootTemplate {
                coinbase1: self.coinbase_tx_prefix.clone(),
                extranonce1: self.extranonce_prefix.clone(),
                extranonce2_range: Extranonce2Range::new(self.extranonce_size as u8)?,
                coinbase2: self.coinbase_tx_suffix.clone(),
                merkle_branches,
            }),
        })
    }
}

/// Per-connection protocol state.
#[derive(Default)]
struct SessionState {
    channel_id: Option<u32>,
    extranonce_prefix: Vec<u8>,
    extranonce_size: u16,
    /// Pool-assigned share target (wire byte order, little-endian U256).
    share_target_le: Option<[u8; 32]>,
    /// Future jobs parked awaiting `SetNewPrevHash`.
    future_jobs: HashMap<u32, OwnedJob>,
    /// Current tip fields (from the last SetNewPrevHash).
    prev_hash: Option<BlockHash>,
    nbits: Option<CompactTarget>,
}

/// Stratum v2 extended-channel job source.
pub struct StratumV2Source {
    config: Sv2PoolConfig,
    event_tx: mpsc::Sender<SourceEvent>,
    command_rx: mpsc::Receiver<SourceCommand>,
    shutdown: CancellationToken,
    expected_hashrate: HashRate,
    first_share_logged: bool,
}

impl StratumV2Source {
    /// Create a new Stratum v2 source (same shape as SV1's constructor).
    pub fn new(
        config: Sv2PoolConfig,
        command_rx: mpsc::Receiver<SourceCommand>,
        event_tx: mpsc::Sender<SourceEvent>,
        shutdown: CancellationToken,
    ) -> Self {
        Self {
            config,
            event_tx,
            command_rx,
            shutdown,
            expected_hashrate: HashRate::default(),
            first_share_logged: false,
        }
    }

    /// Strip the SV2 scheme, returning `host:port`.
    fn host_port(&self) -> &str {
        self.config
            .url
            .strip_prefix("stratum+2://")
            .or_else(|| self.config.url.strip_prefix("sv2://"))
            .unwrap_or(&self.config.url)
    }

    /// Human-readable source name (parallel to SV1's).
    pub fn name(&self) -> String {
        format!("sv2:{}", self.host_port())
    }

    /// Main loop: wait for hashrate, then connect/run with reconnect backoff.
    pub async fn run(mut self) -> Result<()> {
        info!(
            pool = %self.config.url,
            "SV2: waiting for hash threads before connecting"
        );

        // Phase 1: wait until hash threads report hashrate (mirrors SV1), so
        // OpenExtendedMiningChannel carries a meaningful nominal_hash_rate.
        loop {
            tokio::select! {
                Some(cmd) = self.command_rx.recv() => {
                    match cmd {
                        SourceCommand::UpdateHashRate(rate) => {
                            self.expected_hashrate = rate;
                            if !rate.is_zero() {
                                break;
                            }
                        }
                        SourceCommand::SubmitShare(_) => {}
                    }
                }
                _ = self.shutdown.cancelled() => return Ok(()),
            }
        }

        // Phase 2: connect with exponential backoff (mirrors SV1's 1s->60s).
        let mut backoff = Duration::from_secs(1);
        loop {
            self.first_share_logged = false;

            info!(pool = %self.host_port(), "SV2: connecting");
            match self.connect_and_run().await {
                Ok(()) => return Ok(()), // shutdown
                Err(e) => {
                    warn!(error = %e, "SV2: session ended");
                    let _ = self.event_tx.send(SourceEvent::ClearJobs).await;
                    tokio::select! {
                        _ = tokio::time::sleep(backoff) => {}
                        _ = self.shutdown.cancelled() => return Ok(()),
                    }
                    backoff = (backoff * 2).min(Duration::from_secs(60));
                }
            }
        }
    }

    /// One connection session: TCP + noise handshake, SetupConnection, open
    /// extended channel, then run the message loop until shutdown, protocol
    /// error, or disconnection.
    async fn connect_and_run(&mut self) -> Result<()> {
        let addr = self.host_port().to_string();
        let socket = TcpStream::connect(&addr)
            .await
            .with_context(|| format!("SV2: tcp connect to {addr}"))?;
        info!(pool = %addr, "SV2: tcp connected, starting noise handshake");

        let initiator = Initiator::new(None);
        let (receiver, sender): (
            AsyncReceiver<StandardEitherFrame<MiningDeviceMessages<'static>>>,
            AsyncSender<StandardEitherFrame<MiningDeviceMessages<'static>>>,
        ) = Connection::new::<MiningDeviceMessages<'static>>(
            socket,
            HandshakeRole::Initiator(initiator),
        )
        .await
        .map_err(|e| anyhow!("SV2: noise handshake failed: {e:?}"))?;
        info!(pool = %addr, "SV2: noise channel established");

        // --- SetupConnection (mining protocol, extended channels wanted) ---
        let setup = SetupConnection {
            protocol: Protocol::MiningProtocol,
            min_version: 2,
            max_version: 2,
            // Flag bit 0 = REQUIRE_STANDARD_JOBS. We need extended jobs,
            // so the bit stays CLEAR.
            flags: 0,
            endpoint_host: addr
                .split(':')
                .next()
                .unwrap_or("unknown")
                .to_string()
                .try_into()
                .map_err(|e| anyhow!("SV2: endpoint_host: {e:?}"))?,
            endpoint_port: addr
                .rsplit(':')
                .next()
                .and_then(|p| p.parse::<u16>().ok())
                .unwrap_or(3333),
            vendor: "mujina"
                .to_string()
                .try_into()
                .map_err(|e| anyhow!("{e:?}"))?,
            hardware_version: "nano3s"
                .to_string()
                .try_into()
                .map_err(|e| anyhow!("{e:?}"))?,
            firmware: self
                .config
                .user_agent
                .clone()
                .try_into()
                .map_err(|e| anyhow!("{e:?}"))?,
            device_id: "nano3s"
                .to_string()
                .try_into()
                .map_err(|e| anyhow!("{e:?}"))?,
        };
        send(&sender, MiningDeviceMessages::Common(setup.into())).await?;

        let mut session = SessionState::default();
        let mut channel_opened = false;

        loop {
            tokio::select! {
                cmd = self.command_rx.recv() => {
                    match cmd {
                        Some(SourceCommand::SubmitShare(share)) => {
                            if let Err(e) = submit_share(&sender, &session, share).await {
                                // A failed submit is logged; the connection
                                // stays up unless the transport is dead.
                                error!(error = %e, "SV2: share submit failed");
                            }
                        }
                        Some(SourceCommand::UpdateHashRate(rate)) => {
                            self.expected_hashrate = rate;
                            if channel_opened {
                                let msg = Mining::UpdateChannel(update_channel_msg(
                                    session.channel_id.unwrap_or(0),
                                    rate,
                                    session.share_target_le,
                                ));
                                if let Err(e) =
                                    send(&sender, MiningDeviceMessages::Mining(msg)).await
                                {
                                    warn!(error = %e, "SV2: UpdateChannel failed");
                                }
                            }
                        }
                        None => return Ok(()), // command channel closed => shutdown
                    }
                }
                frame = receiver.recv() => {
                    // async_channel recv() returns Result<_, RecvError>;
                    // a closed channel means the pool hung up.
                    let either = frame
                        .map_err(|_| anyhow!("SV2: pool closed the connection"))?;
                    let mut std_frame: StandardSv2Frame<MiningDeviceMessages<'static>> =
                        either
                            .try_into()
                            .map_err(|e| anyhow!("SV2: frame: {e:?}"))?;
                    let msg_type = std_frame
                        .get_header()
                        .map(|h| h.msg_type())
                        .ok_or_else(|| anyhow!("SV2: frame without header"))?;
                    let payload = std_frame.payload();

                    // Parse borrowed from the frame buffer, then lift to
                    // 'static immediately: handlers may retain messages
                    // (future jobs) beyond this loop iteration, and the
                    // sub-enum into_static() calls deep-copy the payload.
                    let message = match MiningDeviceMessages::try_from((msg_type, payload))
                        .map_err(|e: ParserError| anyhow!("SV2: parse: {e}"))?
                    {
                        MiningDeviceMessages::Mining(m) => {
                            MiningDeviceMessages::Mining(m.into_static())
                        }
                        MiningDeviceMessages::Common(m) => {
                            MiningDeviceMessages::Common(m.into_static())
                        }
                        MiningDeviceMessages::Extensions(m) => {
                            MiningDeviceMessages::Extensions(m.into_static())
                        }
                    };

                    match message {
                        MiningDeviceMessages::Common(
                            CommonMessages::SetupConnectionSuccess(_),
                        ) => {
                            debug!("SV2: SetupConnectionSuccess");
                            let open = OpenExtendedMiningChannel {
                                request_id: 1,
                                user_identity: self
                                    .config
                                    .username
                                    .clone()
                                    .try_into()
                                    .map_err(|e| anyhow!("user_identity: {e:?}"))?,
                                nominal_hash_rate: self.expected_hashrate.0 as f32,
                                // Ask for the easiest allowed ceiling; the
                                // pool clamps to its own vardiff target.
                                max_target: Sv2U256::from([0xffu8; 32]),
                                // Want a full u64 extranonce2 space for
                                // software rolling; pools typically grant
                                // 4-8 bytes (their choice, we adapt).
                                min_extranonce_size: 8,
                            };
                            send(
                                &sender,
                                MiningDeviceMessages::Mining(
                                    Mining::OpenExtendedMiningChannel(open),
                                ),
                            )
                            .await?;
                        }
                        MiningDeviceMessages::Common(
                            CommonMessages::SetupConnectionError(m),
                        ) => {
                            return Err(anyhow!(
                                "SV2: setup rejected: {}",
                                m.error_code.as_utf8_or_hex()
                            ));
                        }
                        MiningDeviceMessages::Common(
                            CommonMessages::ChannelEndpointChanged(_),
                        ) => {
                            // Channel reallocated upstream; reconnect cleanly.
                            return Err(anyhow!("SV2: ChannelEndpointChanged"));
                        }
                        MiningDeviceMessages::Common(CommonMessages::Reconnect(_)) => {
                            return Err(anyhow!("SV2: Reconnect requested"));
                        }
                        MiningDeviceMessages::Common(CommonMessages::SetupConnection(_)) => {}

                        MiningDeviceMessages::Mining(
                            Mining::OpenExtendedMiningChannelSuccess(m),
                        ) => {
                            session.channel_id = Some(m.channel_id);
                            session.extranonce_prefix = m.extranonce_prefix.to_owned_bytes();
                            session.extranonce_size = m.extranonce_size;
                            session.share_target_le = Some(m.target.to_array());
                            channel_opened = true;
                            info!(
                                channel = m.channel_id,
                                extranonce_size = m.extranonce_size,
                                prefix_len = session.extranonce_prefix.len(),
                                "SV2: extended channel opened -- subscribed"
                            );
                        }
                        MiningDeviceMessages::Mining(Mining::OpenMiningChannelError(m)) => {
                            return Err(anyhow!(
                                "SV2: open channel rejected: {}",
                                m.error_code.as_utf8_or_hex()
                            ));
                        }
                        MiningDeviceMessages::Mining(Mining::NewExtendedMiningJob(m)) => {
                            handle_new_job(self, &mut session, m).await?;
                        }
                        MiningDeviceMessages::Mining(Mining::SetNewPrevHash(m)) => {
                            handle_prev_hash(self, &mut session, m).await?;
                        }
                        MiningDeviceMessages::Mining(Mining::SetTarget(m)) => {
                            session.share_target_le = Some(m.maximum_target.to_array());
                            debug!(channel = m.channel_id, "SV2: SetTarget");
                        }
                        MiningDeviceMessages::Mining(Mining::SubmitSharesSuccess(m)) => {
                            SV2_SHARES_ACCEPTED.fetch_add(
                                m.new_submits_accepted_count as u64,
                                Ordering::Relaxed,
                            );
                            if !self.first_share_logged {
                                info!("SV2: first share accepted");
                                self.first_share_logged = true;
                            }
                        }
                        MiningDeviceMessages::Mining(Mining::SubmitSharesError(m)) => {
                            SV2_SHARES_REJECTED.fetch_add(1, Ordering::Relaxed);
                            warn!(
                                error = %m.error_code.as_utf8_or_hex(),
                                "SV2: share rejected"
                            );
                        }
                        MiningDeviceMessages::Mining(Mining::CloseChannel(m)) => {
                            return Err(anyhow!(
                                "SV2: pool closed channel {}: {}",
                                m.channel_id,
                                m.reason_code.as_utf8_or_hex()
                            ));
                        }
                        MiningDeviceMessages::Mining(Mining::UpdateChannelError(m)) => {
                            warn!(
                                error = %m.error_code.as_utf8_or_hex(),
                                "SV2: UpdateChannel rejected"
                            );
                        }
                        // Standard-channel / job-declaration messages must
                        // not appear on an extended mining channel; ignore.
                        MiningDeviceMessages::Mining(other) => {
                            debug!(?other, "SV2: unhandled mining message");
                        }
                        // Extension messages (e.g. WorkSetup extensions)
                        // are optional in the mining protocol; ignore.
                        MiningDeviceMessages::Extensions(_) => {
                            debug!("SV2: extension message (ignored)");
                        }
                    }
                }
                _ = self.shutdown.cancelled() => return Ok(()),
            }
        }
    }
}

/// Encode and send a message frame.
async fn send(
    sender: &AsyncSender<StandardEitherFrame<MiningDeviceMessages<'static>>>,
    msg: MiningDeviceMessages<'static>,
) -> Result<()> {
    let frame: StandardSv2Frame<MiningDeviceMessages<'static>> =
        msg.try_into().map_err(|e| anyhow!("SV2: encode: {e:?}"))?;
    sender
        .send(frame.into())
        .await
        .map_err(|_| anyhow!("SV2: sender closed"))
}

/// Handle NewExtendedMiningJob: activate immediately or park as future.
async fn handle_new_job(
    source: &mut StratumV2Source,
    session: &mut SessionState,
    m: NewExtendedMiningJob<'static>,
) -> Result<()> {
    let min_ntime = m.min_ntime.clone().into_inner();
    let mut job = OwnedJob {
        channel_id: m.channel_id,
        job_id: m.job_id,
        min_ntime,
        version: m.version,
        version_rolling_allowed: m.version_rolling_allowed,
        merkle_path: m
            .merkle_path
            .into_inner()
            .iter()
            .map(|u| u.to_array())
            .collect(),
        coinbase_tx_prefix: m.coinbase_tx_prefix.to_owned_bytes(),
        coinbase_tx_suffix: m.coinbase_tx_suffix.to_owned_bytes(),
        extranonce_prefix: session.extranonce_prefix.clone(),
        extranonce_size: session.extranonce_size,
    };

    match (job.min_ntime, session.prev_hash, session.nbits) {
        // Immediate job with a live tip: activate now.
        (Some(ntime), Some(ph), Some(nb)) => {
            job.min_ntime = Some(ntime);
            let tpl = build_template(&job, ph, nb, session.share_target_le)?;
            debug!(job_id = tpl.id, "SV2: immediate job activated");
            source
                .event_tx
                .send(SourceEvent::UpdateJob(tpl))
                .await
                .map_err(|_| anyhow!("event channel closed"))?;
        }
        // Future job: park until SetNewPrevHash with the same job_id.
        (None, _, _) => {
            debug!(job_id = job.job_id, "SV2: future job stored");
            session.future_jobs.insert(job.job_id, job);
        }
        // Immediate job but no tip yet: park; if the tip's job_id matches
        // it will activate there, otherwise it gets dropped on next tip.
        (Some(_), _, _) => {
            debug!(job_id = job.job_id, "SV2: job before tip; parked");
            session.future_jobs.insert(job.job_id, job);
        }
    }
    Ok(())
}

/// Handle SetNewPrevHash: activate the matching future job (ReplaceJob --
/// a new tip invalidates all previous work).
async fn handle_prev_hash(
    source: &mut StratumV2Source,
    session: &mut SessionState,
    m: MiningSetNewPrevHash<'static>,
) -> Result<()> {
    let prev_hash = block_hash_from_u256_bytes(m.prev_hash.to_array());
    let nbits = CompactTarget::from_consensus(m.nbits);
    session.prev_hash = Some(prev_hash);
    session.nbits = Some(nbits);

    if let Some(mut job) = session.future_jobs.remove(&m.job_id) {
        job.min_ntime = Some(m.min_ntime);
        // Older future jobs can never activate (superseded tip); drop them.
        session.future_jobs.clear();
        let tpl = build_template(&job, prev_hash, nbits, session.share_target_le)?;
        info!(job_id = tpl.id, "SV2: job activated from future queue");
        source
            .event_tx
            .send(SourceEvent::ReplaceJob(tpl))
            .await
            .map_err(|_| anyhow!("event channel closed"))?;
    } else {
        debug!(
            job_id = m.job_id,
            "SV2: prev-hash for unknown job (no future job matched)"
        );
    }
    Ok(())
}

/// Build a scheduler template from an activated job.
fn build_template(
    job: &OwnedJob,
    prev_hash: BlockHash,
    nbits: CompactTarget,
    share_target_le: Option<[u8; 32]>,
) -> Result<JobTemplate> {
    let mut tpl = job.merkle_template(prev_hash, nbits)?;
    if let Some(t) = share_target_le {
        // SV2 targets are U256 integers in little-endian byte order on the
        // wire (SRI reads them with U256::from_little_endian; our Target
        // conversion is from_le_bytes -- same layout).
        let u = crate::u256::U256::from_le_bytes(t);
        tpl.share_target = bitcoin::pow::Target::from(u);
    }
    Ok(tpl)
}

/// Submit a share upstream as SubmitSharesExtended.
///
/// The `extranonce` field carries only the ROLLABLE part; the pool
/// reconstructs `extranonce_prefix + extranonce` between the coinbase
/// prefix/suffix (verified against `ExtendedChannel::validate_share`).
async fn submit_share(
    sender: &AsyncSender<StandardEitherFrame<MiningDeviceMessages<'static>>>,
    session: &SessionState,
    share: Share,
) -> Result<()> {
    let Some(channel_id) = session.channel_id else {
        return Ok(()); // No channel yet; drop silently (mirrors SV1).
    };
    let job_id: u32 = share
        .job_id
        .parse()
        .map_err(|e| anyhow!("SV2: job id {:?}: {e}", share.job_id))?;

    // Echo exactly the extranonce2 that went into the coinbase, re-widthed
    // to the negotiated extranonce_size if it raced a renegotiation.
    let en2_size = session.extranonce_size as usize;
    let mut extranonce = vec![0u8; en2_size];
    if let Some(en2) = &share.extranonce2 {
        let raw = en2.value().to_le_bytes();
        let n = (en2.size() as usize).min(en2_size);
        extranonce[..n].copy_from_slice(&raw[..n]);
    }

    let msg = Mining::SubmitSharesExtended(SubmitSharesExtended {
        channel_id,
        sequence_number: SUBMIT_SEQUENCE.fetch_add(1, Ordering::Relaxed),
        job_id,
        nonce: share.nonce,
        ntime: share.time,
        version: share.version.to_consensus() as u32,
        extranonce: extranonce
            .try_into()
            .map_err(|e| anyhow!("SV2: extranonce: {e:?}"))?,
    });
    send(sender, MiningDeviceMessages::Mining(msg)).await
}

/// Convert SV2 prev-hash bytes to a `BlockHash` (SRI's `u256_to_block_hash`
/// semantics: raw array -> sha256d Hash -> BlockHash::from_raw_hash).
fn block_hash_from_u256_bytes(bytes: [u8; 32]) -> BlockHash {
    let h = bitcoin::hashes::sha256d::Hash::from_byte_array(bytes);
    BlockHash::from_raw_hash(h)
}

/// Build an UpdateChannel message (on hashrate change). The current target
/// is echoed so the pool sees no target-change request.
fn update_channel_msg(
    channel_id: u32,
    rate: HashRate,
    current_target_le: Option<[u8; 32]>,
) -> stratum_apps::stratum_core::mining_sv2::UpdateChannel<'static> {
    let maximum_target: Sv2U256<'static> = current_target_le
        .map(Sv2U256::from)
        .unwrap_or_else(|| Sv2U256::from([0xffu8; 32]));
    stratum_apps::stratum_core::mining_sv2::UpdateChannel {
        channel_id,
        nominal_hash_rate: rate.0 as f32,
        maximum_target,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::block::Version;

    fn job_fixture(extranonce_size: u16) -> OwnedJob {
        OwnedJob {
            channel_id: 1,
            job_id: 42,
            min_ntime: Some(1_700_000_000),
            version: 0x2000_0000,
            version_rolling_allowed: true,
            merkle_path: vec![[7u8; 32]],
            coinbase_tx_prefix: vec![0x01, 0x00, 0x00, 0x00, 0x01],
            coinbase_tx_suffix: vec![0xff, 0xff, 0xff, 0xff],
            extranonce_prefix: vec![0xaa, 0xbb],
            extranonce_size,
        }
    }

    #[test]
    fn extranonce_size_bounds_enforced() {
        let prev = BlockHash::from_byte_array([0u8; 32]);
        let nbits = CompactTarget::from_consensus(0x1d00ffff);
        // 0 bytes: software rolling impossible -> reject.
        assert!(job_fixture(0).merkle_template(prev, nbits).is_err());
        // 9 bytes: beyond Extranonce2's 8-byte max -> reject.
        assert!(job_fixture(9).merkle_template(prev, nbits).is_err());
        // 8 bytes: fine.
        assert!(job_fixture(8).merkle_template(prev, nbits).is_ok());
    }

    #[test]
    fn version_base_has_gp_region_masked() {
        let prev = BlockHash::from_byte_array([0u8; 32]);
        let nbits = CompactTarget::from_consensus(0x1d00ffff);
        // Base version with bits in the GP region must not fail
        // VersionTemplate::new (we mask them off).
        let mut job = job_fixture(4);
        job.version = 0x2fff_0000; // GP region partly set
        let tpl = job.merkle_template(prev, nbits).expect("templates ok");
        // Masked base: 0x2fff_0000 & !0x1ffe_0000 = 0x2000_0000
        assert_eq!(tpl.version.base(), Version::from_consensus(0x2000_0000));
        assert!(
            tpl.version
                .gp_bits_mask()
                .contains(&GeneralPurposeBits::full())
        );
    }

    #[test]
    fn version_rolling_disallowed_gives_empty_mask() {
        let prev = BlockHash::from_byte_array([0u8; 32]);
        let nbits = CompactTarget::from_consensus(0x1d00ffff);
        let mut job = job_fixture(4);
        job.version_rolling_allowed = false;
        let tpl = job.merkle_template(prev, nbits).expect("templates ok");
        assert_eq!(tpl.version.gp_bits_mask(), GeneralPurposeBits::none());
    }

    #[test]
    fn target_conversion_is_little_endian_lossless() {
        let mut le = [0xffu8; 32];
        le[0] = 0x00;
        let u = crate::u256::U256::from_le_bytes(le);
        let t = bitcoin::pow::Target::from(u);
        assert_eq!(t.to_le_bytes(), le);
    }

    #[test]
    fn block_hash_conversion_matches_sri() {
        // SRI: BlockHash::from_raw_hash(Hash::from_slice(bytes)) -- the SV2
        // U256 byte array IS the sha256d hash bytes.
        let bytes = [0x5au8; 32];
        let bh = block_hash_from_u256_bytes(bytes);
        assert_eq!(bh.as_byte_array(), &bytes);
    }

    #[test]
    fn scheme_stripping() {
        let mk = |url: &str| Sv2PoolConfig {
            url: url.to_string(),
            username: "u".into(),
            password: String::new(),
            user_agent: "ua".into(),
        };
        let (tx1, _rx1) = mpsc::channel(1);
        let (_tx2, rx2) = mpsc::channel(1);
        let src = StratumV2Source::new(
            mk("stratum+2://pool.example.org:3333"),
            rx2,
            tx1,
            CancellationToken::new(),
        );
        assert_eq!(src.host_port(), "pool.example.org:3333");
        assert_eq!(src.name(), "sv2:pool.example.org:3333");

        let (tx3, _rx3) = mpsc::channel(1);
        let (_tx4, rx4) = mpsc::channel(1);
        let src2 = StratumV2Source::new(
            mk("sv2://1.2.3.4:442"),
            rx4,
            tx3,
            CancellationToken::new(),
        );
        assert_eq!(src2.host_port(), "1.2.3.4:442");
    }
}
