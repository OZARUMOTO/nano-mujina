//! Synthetic SV2 downstream (mining-device stand-in) used to exercise the
//! nano-pool bridge end-to-end on regtest: Noise handshake -> SetupConnection
//! -> OpenExtendedMiningChannel -> receive job/prev-hash -> submit one
//! well-formed (non-solution) share -> expect SubmitSharesSuccess.

use anyhow::{anyhow, Result};
use noise_sv2::Initiator;
use std::time::Duration;
use stratum_apps::network_helpers::noise_connection::Connection;
use stratum_apps::stratum_core::{
    binary_sv2::{B032, Str0255, Sv2Option, U256},
    codec_sv2::{HandshakeRole, StandardEitherFrame, StandardSv2Frame},
    common_messages_sv2::{Protocol, SetupConnection},
    mining_sv2::{OpenExtendedMiningChannel, SubmitSharesExtended},
    parsers_sv2::{CommonMessages, Mining, MiningDeviceMessages},
};
use tokio::net::TcpStream;

type Frame = StandardEitherFrame<MiningDeviceMessages<'static>>;
type StdFrame = StandardSv2Frame<MiningDeviceMessages<'static>>;

async fn send(
    sender: &async_channel::Sender<Frame>,
    msg: MiningDeviceMessages<'static>,
) -> Result<()> {
    let frame: StdFrame = msg.try_into().map_err(|e| anyhow!("encode: {e:?}"))?;
    let either: Frame = frame.into();
    sender.send(either).await.map_err(|_| anyhow!("closed"))
}

#[tokio::main]
async fn main() -> Result<()> {
    let addr = std::env::args().nth(1).unwrap_or_else(|| "127.0.0.1:3334".into());
    let socket = TcpStream::connect(&addr).await?;
    println!("tcp connected: {addr}");

    let initiator = Initiator::new(None);
    let (mut reader, sender): (
        async_channel::Receiver<Frame>,
        async_channel::Sender<Frame>,
    ) = Connection::new::<MiningDeviceMessages<'static>>(
        socket,
        HandshakeRole::Initiator(initiator),
    )
    .await
    .map_err(|e| anyhow!("noise: {e:?}"))?;
    println!("noise handshake OK");

    // SetupConnection
    send(
        &sender,
        MiningDeviceMessages::Common(CommonMessages::SetupConnection(SetupConnection {
            protocol: Protocol::MiningProtocol,
            min_version: 2,
            max_version: 2,
            flags: 0,
            endpoint_host: "probe".try_into().map_err(|e| anyhow!("{e:?}"))?,
            endpoint_port: 3334,
            vendor: "probe".try_into().map_err(|e| anyhow!("{e:?}"))?,
            hardware_version: "0".try_into().map_err(|e| anyhow!("{e:?}"))?,
            firmware: "probe".try_into().map_err(|e| anyhow!("{e:?}"))?,
            device_id: "probe".try_into().map_err(|e| anyhow!("{e:?}"))?,
        })),
    )
    .await?;

    // message loop
    let mut opened = false;
    let mut submitted = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        if tokio::time::Instant::now() > deadline {
            return Err(anyhow!("timeout waiting for pool messages"));
        }
        let frame: Frame = tokio::time::timeout(Duration::from_secs(20), reader.recv())
            .await
            .map_err(|_| anyhow!("read timeout"))?
            .map_err(|_| anyhow!("channel closed"))?;
        let mut frame: StdFrame = frame.try_into().map_err(|_| anyhow!("frame kind"))?;
        let msg_type = frame
            .get_header()
            .ok_or_else(|| anyhow!("no header"))?
            .msg_type();
        let payload = frame.payload();
        let msg = match MiningDeviceMessages::try_from((msg_type, payload))
            .map_err(|e| anyhow!("parse: {e:?}"))?
        {
            MiningDeviceMessages::Mining(m) => MiningDeviceMessages::Mining(m.into_static()),
            MiningDeviceMessages::Common(m) => MiningDeviceMessages::Common(m.into_static()),
            MiningDeviceMessages::Extensions(m) => MiningDeviceMessages::Extensions(m.into_static()),
        };

        match msg {
            MiningDeviceMessages::Common(CommonMessages::SetupConnectionSuccess(m)) => {
                println!("setup success (v{})", m.used_version);
                send(
                    &sender,
                    MiningDeviceMessages::Mining(Mining::OpenExtendedMiningChannel(
                        OpenExtendedMiningChannel {
                            request_id: 1,
                            user_identity: "probe.test"
                                .try_into()
                                .map_err(|e| anyhow!("{e:?}"))?,
                            nominal_hash_rate: 1.0,
                            max_target: U256::from([0xffu8; 32]),
                            min_extranonce_size: 8,
                        },
                    )),
                )
                .await?;
            }
            MiningDeviceMessages::Mining(Mining::OpenExtendedMiningChannelSuccess(m)) => {
                println!(
                    "channel open: id={} en2={}B prefix={}",
                    m.channel_id,
                    m.extranonce_size,
                    hex::encode(m.extranonce_prefix.to_owned_bytes())
                );
                opened = true;
            }
            MiningDeviceMessages::Mining(Mining::NewExtendedMiningJob(j)) => {
                if opened {
                    println!(
                        "job received: id={} path={}",
                        j.job_id,
                        j.merkle_path.into_inner().len()
                    );
                    if !submitted {
                        submitted = true;
                        // well-formed, non-solution share (random nonce2/nonce)
                        send(
                            &sender,
                            MiningDeviceMessages::Mining(Mining::SubmitSharesExtended(
                                SubmitSharesExtended {
                                    channel_id: 1,
                                    sequence_number: 1,
                                    job_id: j.job_id,
                                    nonce: 0x1234_5678,
                                    ntime: 1789324177,
                                    version: 0x2000_0000,
                                    extranonce: B032::try_from(vec![0x2a; 8])
                                        .map_err(|e| anyhow!("{e:?}"))?,
                                },
                            )),
                        )
                        .await?;
                        println!("share submitted");
                    }
                }
            }
            MiningDeviceMessages::Mining(Mining::SetNewPrevHash(p)) => {
                println!("prev-hash received: job_id={}", p.job_id);
            }
            MiningDeviceMessages::Mining(Mining::SubmitSharesSuccess(s)) => {
                println!(
                    "✅ share ACCEPTED (seq={}, count={})",
                    s.last_sequence_number, s.new_submits_accepted_count
                );
                println!("PROBE COMPLETE: full SV2 cycle verified");
                return Ok(());
            }
            MiningDeviceMessages::Mining(Mining::SubmitSharesError(e)) => {
                return Err(anyhow!(
                    "share rejected: {}",
                    e.error_code.as_utf8_or_hex()
                ));
            }
            other => println!("other msg: {other:?}"),
        }
    }
}

// silence unused-import warnings for helpers only used in some cfgs
#[allow(unused)]
fn _t(_: Str0255, _: Sv2Option<u32>) {}
