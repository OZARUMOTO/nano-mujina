//! Daemon lifecycle management for mujina-miner.
//!
//! This module handles the core daemon functionality including initialization,
//! task management, signal handling, and graceful shutdown.

use std::env;

use tokio::signal::unix::{self, SignalKind};
use tokio::sync::{mpsc, watch};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

use crate::api_client::types::MinerTelemetry;
use crate::tracing::prelude::*;
use crate::{
    api::{self, ApiConfig, commands::SchedulerCommand},
    backplane::Backplane,
    cpu_miner::CpuMinerConfig,
    job_source::{
        SourceCommand, SourceEvent,
        dummy::DummySource,
        forced_rate::{ForcedRateConfig, ForcedRateSource},
        stratum_v1::StratumV1Source,
        stratum_v2::{StratumV2Source, Sv2PoolConfig},
    },
    scheduler::{self, SourceRegistration, ThreadRegistration},
    stratum_v1::{PoolConfig as StratumPoolConfig, TcpConnector},
    transport::{CpuDeviceInfo, TransportEvent, UsbTransport, cpu as cpu_transport},
};

/// The main daemon.
pub struct Daemon {
    shutdown: CancellationToken,
    tracker: TaskTracker,
}

impl Daemon {
    /// Create a new daemon instance.
    pub fn new() -> Self {
        Self {
            shutdown: CancellationToken::new(),
            tracker: TaskTracker::new(),
        }
    }

    /// Run the daemon until shutdown is requested.
    pub async fn run(self) -> anyhow::Result<()> {
        // Create channels for component communication. Each transport gets its
        // own event channel; the backplane waits for one enumeration completion
        // per channel.
        let (thread_tx, thread_rx) = mpsc::channel::<ThreadRegistration>(10);
        let (source_reg_tx, source_reg_rx) = mpsc::channel::<SourceRegistration>(10);
        let mut transport_rxs: Vec<mpsc::Receiver<TransportEvent>> = Vec::new();

        // Create and start USB transport discovery
        if std::env::var("MUJINA_USB_DISABLE").is_err() {
            let (usb_tx, usb_rx) = mpsc::channel::<TransportEvent>(100);
            let usb_transport = UsbTransport::new(usb_tx);
            if let Err(e) = usb_transport.start_discovery(self.shutdown.clone()).await {
                error!("Failed to start USB discovery: {}", e);
            }
            transport_rxs.push(usb_rx);
        } else {
            info!("USB discovery disabled (MUJINA_USB_DISABLE set)");
        }

        // Inject CPU miner virtual device if configured
        if let Some(config) = CpuMinerConfig::from_env() {
            info!(
                threads = config.thread_count,
                duty = config.duty_percent,
                "CPU miner enabled"
            );
            let (cpu_tx, cpu_rx) = mpsc::channel::<TransportEvent>(100);
            let device = TransportEvent::Cpu(cpu_transport::TransportEvent::CpuDeviceConnected(
                CpuDeviceInfo {
                    device_id: format!("cpu-{}x{}%", config.thread_count, config.duty_percent),
                    thread_count: config.thread_count,
                    duty_percent: config.duty_percent,
                },
            ));
            // Send the device and its enumeration completion, then drop the
            // sender; the CPU transport has no further events.
            if let Err(e) = cpu_tx.send(device).await {
                error!("Failed to send CPU miner event: {}", e);
            }
            let _ = cpu_tx
                .send(TransportEvent::InitialEnumerationComplete)
                .await;
            transport_rxs.push(cpu_rx);
        }

        // Board registration channel: backplane forwards board
        // registrations here, the API server collects and serves them.
        let (board_reg_tx, board_reg_rx) = mpsc::channel(10);

        // Create and start backplane
        let mut backplane = Backplane::new(transport_rxs, thread_tx, board_reg_tx);
        self.tracker.spawn({
            let shutdown = self.shutdown.clone();
            async move {
                tokio::select! {
                    result = backplane.run() => {
                        if let Err(e) = result {
                            error!("Backplane error: {}", e);
                        }
                    }
                    _ = shutdown.cancelled() => {}
                }

                backplane.shutdown_all_boards().await;
            }
        });

        // Create job source (Stratum v1 or Dummy)
        // Pool/identity config resolution, in precedence order:
        //   1. persisted dashboard settings file (see miner_settings) -- the
        //      GLOBAL SETTINGS modal's write path; lets the pool be changed
        //      on-device without a reflash
        //   2. MUJINA_POOL_URL / MUJINA_POOL_USER / MUJINA_POOL_PASS env vars
        //      (what tools/build_kdimg.sh --pool/--user bake into the startup
        //      script)
        // Read ONCE here: pool/identity are startup-time config. Changes take
        // effect at next daemon start -- POST /restart kills this process and
        // the startup script's supervisor loop relaunches it with the new
        // file contents.
        let settings = crate::miner_settings::MinerSettings::load();
        let pool_from_settings = settings.as_ref().and_then(|s| s.pool.clone());
        if let Some(p) = &pool_from_settings {
            info!(
                "minersettings: using persisted pool config from {} ({})",
                crate::miner_settings::SETTINGS_PATH,
                p
            );
        }

        let (source_event_tx, source_event_rx) = mpsc::channel::<SourceEvent>(100);
        let (source_cmd_tx, source_cmd_rx) = mpsc::channel(10);

        let pool_url = pool_from_settings
            .as_ref()
            .map(|p| p.url.clone())
            .or_else(|| env::var("MUJINA_POOL_URL").ok());

        if let Some(pool_url) = pool_url {
            // Use Stratum v1 source
            let mut pool_user = pool_from_settings
                .as_ref()
                .map(|p| p.user.clone())
                .or_else(|| env::var("MUJINA_POOL_USER").ok())
                .unwrap_or_else(|| "mujina-testing".to_string());
            let pool_pass = pool_from_settings
                .as_ref()
                .and_then(|p| p.password.clone())
                .or_else(|| env::var("MUJINA_POOL_PASS").ok())
                .unwrap_or_else(|| "x".to_string());

            // Miner name (settings file only -- the modal's IDENTITY field)
            // becomes the worker suffix, mirroring the dashboard's own
            // preview: skipped when the user field already ends with it.
            if let Some(name) = settings.as_ref().and_then(|s| s.name.clone()) {
                if !name.is_empty()
                    && !pool_user
                        .to_lowercase()
                        .ends_with(&format!(".{}", name.to_lowercase()))
                {
                    pool_user = format!("{pool_user}.{name}");
                }
            }

            // Stratum v2 (extended channel) when the URL scheme asks for
            // it; SV1 otherwise. Same settings file, same worker-suffix
            // logic above.
            if pool_url.starts_with("stratum+2://") || pool_url.starts_with("sv2://") {
                let sv2_config = Sv2PoolConfig {
                    url: pool_url.clone(),
                    username: pool_user,
                    password: pool_pass,
                    user_agent: "mujina-miner/0.1.0-alpha".to_string(),
                };
                let sv2_source = StratumV2Source::new(
                    sv2_config,
                    source_cmd_rx,
                    source_event_tx,
                    self.shutdown.clone(),
                );
                let sv2_name = sv2_source.name();

                source_reg_tx
                    .send(SourceRegistration {
                        name: sv2_name,
                        url: Some(pool_url.clone()),
                        event_rx: source_event_rx,
                        command_tx: source_cmd_tx,
                    })
                    .await?;

                self.tracker.spawn(async move {
                    if let Err(e) = sv2_source.run().await {
                        error!("Stratum v2 source error: {}", e);
                    }
                });
            } else if let Some(forced_rate_config) = ForcedRateConfig::from_env() {
                let stratum_config = StratumPoolConfig {
                    url: pool_url.clone(),
                    username: pool_user,
                    password: pool_pass,
                    user_agent: "mujina-miner/0.1.0-alpha".to_string(),
                };
                info!(
                    rate = %forced_rate_config.target_rate,
                    "Forced share rate wrapper enabled"
                );

                // Create inner channels (stratum <-> wrapper)
                let (inner_event_tx, inner_event_rx) = mpsc::channel::<SourceEvent>(100);
                let (inner_cmd_tx, inner_cmd_rx) = mpsc::channel::<SourceCommand>(10);

                let stratum_source = StratumV1Source::new(
                    stratum_config,
                    inner_cmd_rx,
                    inner_event_tx,
                    self.shutdown.clone(),
                    Box::new(TcpConnector::new(pool_url.clone())),
                );
                let stratum_name = stratum_source.name();

                // Spawn stratum source
                self.tracker.spawn(async move {
                    if let Err(e) = stratum_source.run().await {
                        error!("Stratum v1 source error: {}", e);
                    }
                });

                // Create and spawn wrapper (uses outer channels from above)
                let forced_rate = ForcedRateSource::new(
                    forced_rate_config,
                    inner_event_rx,
                    source_event_tx,
                    inner_cmd_tx,
                    source_cmd_rx,
                    self.shutdown.clone(),
                );

                source_reg_tx
                    .send(SourceRegistration {
                        name: format!("{} (forced-rate)", stratum_name),
                        url: Some(pool_url.clone()),
                        event_rx: source_event_rx,
                        command_tx: source_cmd_tx,
                    })
                    .await?;

                self.tracker.spawn(async move {
                    if let Err(e) = forced_rate.run().await {
                        error!("Forced rate wrapper error: {}", e);
                    }
                });
            } else {
                // Direct stratum source (no wrapper)
                let stratum_config = StratumPoolConfig {
                    url: pool_url.clone(),
                    username: pool_user,
                    password: pool_pass,
                    user_agent: "mujina-miner/0.1.0-alpha".to_string(),
                };
                let stratum_source = StratumV1Source::new(
                    stratum_config,
                    source_cmd_rx,
                    source_event_tx,
                    self.shutdown.clone(),
                    Box::new(TcpConnector::new(pool_url.clone())),
                );

                source_reg_tx
                    .send(SourceRegistration {
                        name: stratum_source.name(),
                        url: Some(pool_url),
                        event_rx: source_event_rx,
                        command_tx: source_cmd_tx,
                    })
                    .await?;

                self.tracker.spawn(async move {
                    if let Err(e) = stratum_source.run().await {
                        error!("Stratum v1 source error: {}", e);
                    }
                });
            }
        } else {
            // Use DummySource
            info!("Using dummy job source (set MUJINA_POOL_URL to use Stratum v1)");

            let dummy_source = DummySource::new(
                source_cmd_rx,
                source_event_tx,
                self.shutdown.clone(),
                tokio::time::Duration::from_secs(30),
            )?;

            source_reg_tx
                .send(SourceRegistration {
                    name: "dummy".into(),
                    url: None,
                    event_rx: source_event_rx,
                    command_tx: source_cmd_tx,
                })
                .await?;

            self.tracker.spawn(async move {
                if let Err(e) = dummy_source.run().await {
                    error!("DummySource error: {}", e);
                }
            });
        }

        // Miner state channel: scheduler publishes snapshots, API serves them.
        let (miner_telemetry_tx, miner_telemetry_rx) = watch::channel(MinerTelemetry::default());

        // Command channel: API sends commands, scheduler processes them.
        let (scheduler_cmd_tx, scheduler_cmd_rx) = mpsc::channel::<SchedulerCommand>(16);

        // Start the scheduler
        self.tracker.spawn(scheduler::task(
            self.shutdown.clone(),
            thread_rx,
            source_reg_rx,
            miner_telemetry_tx,
            scheduler_cmd_rx,
        ));

        // Start the API server
        self.tracker.spawn({
            let shutdown = self.shutdown.clone();
            async move {
                // ASCII 'M' (77) + 'U' (85) = 7785
                const API_PORT: u16 = 7785;

                let bind_addr = match env::var("MUJINA_API_LISTEN") {
                    Ok(addr) if addr.contains(':') => addr,
                    Ok(addr) => format!("{addr}:{API_PORT}"),
                    Err(_) => format!("127.0.0.1:{API_PORT}"),
                };
                let config = ApiConfig { bind_addr };
                if let Err(e) = api::serve(
                    config,
                    shutdown,
                    miner_telemetry_rx,
                    board_reg_rx,
                    scheduler_cmd_tx,
                )
                .await
                {
                    error!("API server error: {}", e);
                }
            }
        });

        self.tracker.close();

        info!("Started.");
        info!("For debugging, set MUJINA_LOG=debug or trace.");

        // Install signal handlers
        let mut sigint = unix::signal(SignalKind::interrupt())?;
        let mut sigterm = unix::signal(SignalKind::terminate())?;

        // Wait for shutdown signal
        tokio::select! {
            _ = sigint.recv() => {
                info!("Received SIGINT.");
            },
            _ = sigterm.recv() => {
                info!("Received SIGTERM.");
            },
        }

        // Initiate shutdown
        self.shutdown.cancel();

        // Wait for all tasks to complete
        self.tracker.wait().await;
        info!("Exiting.");

        Ok(())
    }
}

impl Default for Daemon {
    fn default() -> Self {
        Self::new()
    }
}
