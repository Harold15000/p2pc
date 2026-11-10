// SPDX-License-Identifier: Apache-2.0

//! Property test: every `AgentMsg` and `ServerMsg` survives `write_frame` → `read_frame` unchanged.

// Strategy helpers are not `#[test]` functions, so `allow-unwrap-in-tests` does not cover them.
#![allow(clippy::unwrap_used)]

use p2pc_proto::api::{
    Capacity, CpuInfo, Egress, GpuInfo, GpuStatus, GpuStatusKind, InputFile, Inventory, JobSpec, LogStream, OutputFile,
    Outputs, Placement, Platform, Resources, Retry, SandboxCapability, SandboxClass, Sha256Digest, SmokeResult,
    Wsl2Health,
};
use p2pc_proto::auth::JoinToken;
use p2pc_proto::ids::{AccountId, LeaseId, NodeId};
use p2pc_proto::protocol::{
    AgentMsg, HealthState, LeaseJob, LeaseRejectReason, Leave, Load, LogData, MAX_FRAME_LEN, NodeApproved, Outcome,
    RunningLease, ServerMsg, ServiceHealth, UploadAck, UploadHeader, Usage, VolumeDelete, VolumeInfo, VolumeReport,
    read_frame, write_frame,
};
use proptest::collection::{btree_map, vec};
use proptest::option;
use proptest::prelude::*;
use serde::Serialize;
use serde::de::DeserializeOwned;
use time::OffsetDateTime;
use ulid::Ulid;

fn text() -> impl Strategy<Value = String> {
    "\\PC{0,12}"
}

fn ulid() -> impl Strategy<Value = Ulid> {
    (0u64..(1 << 48), any::<u128>()).prop_map(|(ts, r)| Ulid::from_parts(ts, r))
}

fn lease_id() -> impl Strategy<Value = LeaseId> {
    ulid().prop_map(LeaseId::from_ulid)
}

/// Any instant from 1970 to 9999, with nanoseconds.
fn timestamp() -> impl Strategy<Value = OffsetDateTime> {
    (0i64..253_402_300_799, 0u32..1_000_000_000).prop_map(|(s, ns)| {
        OffsetDateTime::from_unix_timestamp(s)
            .unwrap()
            .replace_nanosecond(ns)
            .unwrap()
    })
}

/// Floats that JSON represents exactly (multiples of 1/4).
fn cpu() -> impl Strategy<Value = f64> {
    (0u32..=4096).prop_map(|q| f64::from(q) / 4.0)
}

fn capacity() -> impl Strategy<Value = Capacity> {
    (cpu(), any::<u64>(), any::<u32>(), option::of(any::<u64>())).prop_map(|(cpu, memory_mb, gpu, disk_mb)| Capacity {
        cpu,
        memory_mb,
        gpu,
        disk_mb,
    })
}

fn gpu() -> impl Strategy<Value = GpuInfo> {
    let opt = || option::of(text());
    (
        text(),
        any::<u32>(),
        text(),
        text(),
        opt(),
        opt(),
        option::of(any::<u64>()),
        opt(),
        any::<bool>(),
    )
        .prop_map(
            |(uuid, index, name, driver_version, cuda_driver_version, compute_capability, vram_mb, pci_bdf, mig)| {
                GpuInfo {
                    uuid,
                    index,
                    name,
                    driver_version,
                    cuda_driver_version,
                    compute_capability,
                    vram_mb,
                    pci_bdf,
                    mig,
                }
            },
        )
}

/// Platform, GPU status, `/dev/dxg` and the optional WSL2 health block.
fn platform_bits() -> impl Strategy<Value = (Platform, GpuStatus, bool, Option<Wsl2Health>)> {
    let status = prop_oneof![
        Just(GpuStatusKind::Ok),
        Just(GpuStatusKind::NoDriver),
        Just(GpuStatusKind::NvmlError),
        Just(GpuStatusKind::NotFound),
        Just(GpuStatusKind::CdiMissing),
        Just(GpuStatusKind::CdiStale),
    ];
    let smoke = option::of((any::<bool>(), option::of(text())).prop_map(|(ok, detail)| SmokeResult { ok, detail }));
    let wsl2 = option::of(
        (
            option::of(text()),
            option::of(text()),
            any::<bool>(),
            any::<bool>(),
            smoke,
        )
            .prop_map(
                |(distro_version, podman_version, cdi_present, cdi_stale, smoke)| Wsl2Health {
                    distro_version,
                    podman_version,
                    cdi_present,
                    cdi_stale,
                    smoke,
                },
            ),
    );
    (
        prop_oneof![Just(Platform::Linux), Just(Platform::Wsl2)],
        (status, option::of(text())).prop_map(|(status, reason)| GpuStatus { status, reason }),
        any::<bool>(),
        wsl2,
    )
}

fn inventory() -> impl Strategy<Value = Inventory> {
    let gpu = gpu();
    let sandbox = (
        text(),
        prop_oneof![Just(SandboxClass::Container), Just(SandboxClass::ContainerGvisor)],
        vec(text(), 0..3),
        any::<bool>(),
        vec(text(), 0..3),
    )
        .prop_map(|(driver, class, runtimes, ready, problems)| SandboxCapability {
            driver,
            class,
            runtimes,
            ready,
            problems,
        });
    (
        (text(), any::<u32>(), any::<u64>(), text(), text()),
        (vec(gpu, 0..3), vec(sandbox, 0..3), capacity(), text(), text()),
        (platform_bits(), option::of(any::<u64>())),
    )
        .prop_map(
            |(
                (model, cores, memory_mb, os, arch),
                (gpus, sandbox, offered, agent_version, hostname),
                ((platform, gpu_status, dxg, wsl2), disk_total_mb),
            )| Inventory {
                hostname,
                platform,
                cpu: CpuInfo { model, cores },
                memory_mb,
                os,
                arch,
                gpus,
                gpu_status,
                dxg,
                wsl2,
                sandbox,
                offered,
                disk_total_mb,
                agent_version,
            },
        )
}

fn job_spec() -> impl Strategy<Value = JobSpec> {
    let file = (text(), text()).prop_map(|(path, content_b64)| InputFile { path, content_b64 });
    let resources =
        (cpu(), any::<u64>(), any::<u32>(), any::<u64>()).prop_map(|(cpu, memory_mb, gpu, disk_mb)| Resources {
            cpu,
            memory_mb,
            gpu,
            disk_mb,
        });
    let placement = (
        vec(text(), 0..3),
        option::of(ulid().prop_map(NodeId::from_ulid)),
        btree_map(text(), text(), 0..3),
    )
        .prop_map(|(pools, node_id, labels)| Placement { pools, node_id, labels });
    let head = (
        option::of(text()),
        text(),
        vec(text(), 0..4),
        btree_map(text(), text(), 0..4),
        vec(file, 0..3),
    );
    let tail = (
        resources,
        any::<u32>(),
        vec(text(), 0..3),
        any::<u64>(),
        placement,
        any::<u32>(),
        option::of(text()),
    );
    (head, tail).prop_map(
        |((name, image, command, env, files), (resources, timeout_s, allow, max_mb, placement, max_attempts, idem))| {
            JobSpec {
                name,
                image,
                command,
                env,
                files,
                resources,
                timeout_s,
                egress: Egress { allow },
                outputs: Outputs { max_mb },
                placement,
                retry: Retry { max_attempts },
                idempotency_key: idem,
            }
        },
    )
}

fn join_token() -> impl Strategy<Value = JoinToken> {
    (
        "[a-z0-9]{32,64}",
        vec(0u8..50, 0..3),
        any::<[u8; 16]>(),
        0i64..253_402_300_799,
    )
        .prop_map(|(server, relays, code, e)| JoinToken {
            server,
            relays: relays
                .iter()
                .map(|n| url::Url::parse(&format!("https://r{n}.example.invalid/")).unwrap())
                .collect(),
            code,
            expires_at: OffsetDateTime::from_unix_timestamp(e).unwrap(),
        })
}

fn health() -> impl Strategy<Value = HealthState> {
    prop_oneof![
        Just(HealthState::Starting),
        Just(HealthState::Healthy),
        Just(HealthState::Unhealthy)
    ]
}

fn running() -> impl Strategy<Value = Vec<RunningLease>> {
    vec(
        (
            lease_id(),
            any::<u64>(),
            option::of(health()),
            option::of(any::<u64>()),
            option::of(any::<u64>()),
        )
            .prop_map(|(lease_id, epoch, health, used_cpu_ms, max_rss_mb)| RunningLease {
                health,
                used_cpu_ms,
                max_rss_mb,
                ..RunningLease::new(lease_id, epoch)
            }),
        0..4,
    )
}

fn volume_name() -> impl Strategy<Value = String> {
    prop_oneof!["[a-z0-9][a-z0-9._-]{0,20}", "tpl:[a-z-]{1,12}/[a-z]{1,8}"]
}

fn stream() -> impl Strategy<Value = LogStream> {
    prop_oneof![Just(LogStream::Stdout), Just(LogStream::Stderr)]
}

fn agent_msg() -> impl Strategy<Value = AgentMsg> {
    let reason = prop_oneof![
        Just(LeaseRejectReason::NotOwner),
        Just(LeaseRejectReason::UnsupportedSandbox),
        Just(LeaseRejectReason::InsufficientCapacity),
        Just(LeaseRejectReason::Draining),
        Just(LeaseRejectReason::InvalidJob),
        Just(LeaseRejectReason::GpuSelectionUnsupported),
        Just(LeaseRejectReason::AgentNotReady),
        Just(LeaseRejectReason::DeadlinePassed),
    ];
    let outcome = prop_oneof![
        Just(Outcome::Exited),
        Just(Outcome::TimedOut),
        Just(Outcome::Cancelled),
        Just(Outcome::Error)
    ];
    let output = (text(), any::<u64>(), any::<[u8; 32]>()).prop_map(|(path, size, d)| OutputFile {
        path,
        size,
        sha256: Sha256Digest(d),
    });
    let usage = (any::<u64>(), any::<u64>(), any::<u64>()).prop_map(|(wall_ms, cpu_used_ms, max_rss_mb)| Usage {
        wall_ms,
        cpu_used_ms,
        max_rss_mb,
    });
    prop_oneof![
        (join_token(), inventory()).prop_map(|(token, inventory)| AgentMsg::Join { token, inventory }),
        (text(), inventory(), running(), vec(text(), 0..3)).prop_map(
            |(agent_version, inventory, running, features)| AgentMsg::Hello {
                agent_version,
                inventory,
                running,
                features
            }
        ),
        Just(AgentMsg::Unknown),
        inventory().prop_map(|inventory| AgentMsg::InventoryUpdate { inventory }),
        (
            any::<u64>(),
            any::<u32>(),
            any::<u64>(),
            option::of(any::<u32>()),
            running()
        )
            .prop_map(
                |(seq, cpu_pct, mem_used_mb, gpu_util_pct, running)| AgentMsg::Heartbeat {
                    seq,
                    load: Load {
                        cpu_pct,
                        mem_used_mb,
                        gpu_util_pct
                    },
                    running
                }
            ),
        (lease_id(), any::<u64>()).prop_map(|(lease_id, epoch)| AgentMsg::LeaseAccepted { lease_id, epoch }),
        (lease_id(), any::<u64>(), reason).prop_map(|(lease_id, epoch, reason)| AgentMsg::LeaseRejected {
            lease_id,
            epoch,
            reason
        }),
        (lease_id(), any::<u64>(), timestamp()).prop_map(|(lease_id, epoch, started_at)| AgentMsg::JobStarted {
            lease_id,
            epoch,
            started_at
        }),
        (lease_id(), any::<u64>(), stream(), any::<u64>(), "[A-Za-z0-9+/]{0,40}").prop_map(
            |(lease_id, epoch, stream, seq, data_b64)| AgentMsg::LogChunk {
                lease_id,
                epoch,
                stream,
                seq,
                data_b64: LogData(data_b64)
            }
        ),
        (
            lease_id(),
            any::<u64>(),
            outcome,
            option::of(any::<i32>()),
            option::of(text()),
            usage,
            vec(output, 0..3)
        )
            .prop_map(
                |(lease_id, epoch, outcome, exit_code, error, usage, outputs)| AgentMsg::JobFinished {
                    lease_id,
                    epoch,
                    outcome,
                    exit_code,
                    error,
                    usage,
                    outputs
                }
            ),
        // H2 §6.1.
        (lease_id(), any::<u64>(), health(), timestamp(), option::of(text())).prop_map(
            |(lease_id, epoch, state, since, detail)| AgentMsg::ServiceHealth(ServiceHealth {
                lease_id,
                epoch,
                state,
                since,
                detail
            })
        ),
        vec(
            (volume_name(), any::<u64>(), timestamp(), option::of(lease_id())).prop_map(
                |(name, size_mb, last_used_at, in_use_by)| VolumeInfo {
                    name,
                    size_mb,
                    last_used_at,
                    in_use_by
                }
            ),
            0..3
        )
        .prop_map(|volumes| AgentMsg::VolumeReport(VolumeReport { volumes })),
        text().prop_map(|reason| AgentMsg::Leave(Leave { reason })),
    ]
}

fn server_msg() -> impl Strategy<Value = ServerMsg> {
    prop_oneof![
        (
            text(),
            ulid().prop_map(NodeId::from_ulid),
            ulid().prop_map(AccountId::from_ulid),
            any::<u32>(),
            any::<u32>(),
            any::<bool>()
        )
            .prop_map(
                |(server_version, node_id, account_id, heartbeat_interval_s, lease_ttl_s, pending_approval)| {
                    ServerMsg::Welcome {
                        server_version,
                        node_id,
                        account_id,
                        heartbeat_interval_s,
                        lease_ttl_s,
                        pending_approval,
                    }
                }
            ),
        any::<u64>().prop_map(|seq| ServerMsg::HeartbeatAck { seq }),
        (
            lease_id(),
            any::<u64>(),
            job_spec(),
            ulid().prop_map(AccountId::from_ulid),
            timestamp()
        )
            .prop_map(|(lease_id, epoch, job, account_id, deadline)| ServerMsg::Lease {
                lease_id,
                epoch,
                job: LeaseJob::from_spec(&job),
                account_id,
                deadline
            }),
        (lease_id(), any::<u64>(), text()).prop_map(|(lease_id, epoch, reason)| ServerMsg::Cancel {
            lease_id,
            epoch,
            reason
        }),
        Just(ServerMsg::Drain {}),
        Just(ServerMsg::Resume {}),
        Just(ServerMsg::Unknown),
        (text(), text()).prop_map(|(code, message)| ServerMsg::Error { code, message }),
        // H2 §6.1.
        volume_name().prop_map(|name| ServerMsg::VolumeDelete(VolumeDelete { name })),
        Just(ServerMsg::NodeApproved(NodeApproved {})),
    ]
}

fn round_trip<T>(msg: &T) -> T
where
    T: Serialize + DeserializeOwned,
{
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(async {
            let mut buf = Vec::new();
            write_frame(&mut buf, msg).await.unwrap();
            let mut r = buf.as_slice();
            let back = read_frame::<T, _>(&mut r, MAX_FRAME_LEN).await.unwrap().unwrap();
            assert!(r.is_empty(), "read_frame must consume exactly one frame");
            back
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn agent_messages_round_trip(msg in agent_msg()) {
        prop_assert_eq!(round_trip(&msg), msg);
    }

    #[test]
    fn server_messages_round_trip(msg in server_msg()) {
        prop_assert_eq!(round_trip(&msg), msg);
    }

    /// The lenient `Lease.job` carries every `JobSpec` through a frame unchanged: the strict parse on the agent
    /// side gives back the exact spec the server sent.
    #[test]
    fn lease_jobs_survive_the_frame_and_parse_back(spec in job_spec()) {
        let job = round_trip(&LeaseJob::from_spec(&spec));
        let back: JobSpec = serde_json::from_value(serde_json::Value::Object(job.as_object().clone())).unwrap();
        prop_assert_eq!(back, spec);
    }

    /// Spec §6: a newer peer may add fields; an older receiver decodes the same message.
    #[test]
    fn added_top_level_fields_are_ignored(agent in agent_msg(), server in server_msg(), key in "zz_[a-z]{1,8}", n in any::<u32>()) {
        let mut v = serde_json::to_value(&agent).unwrap();
        v[key.as_str()] = serde_json::json!({"future": n});
        prop_assert_eq!(serde_json::from_value::<AgentMsg>(v).unwrap(), agent);
        let mut v = serde_json::to_value(&server).unwrap();
        v[key.as_str()] = serde_json::json!([n]);
        prop_assert_eq!(serde_json::from_value::<ServerMsg>(v).unwrap(), server);
    }

    #[test]
    fn upload_frames_round_trip(
        lease_id in lease_id(), epoch in any::<u64>(), path in text(), size in any::<u64>(), d in any::<[u8; 32]>(),
        ok in any::<bool>(), reason in option::of(text()),
    ) {
        let header = UploadHeader { lease_id, epoch, path, size, sha256: Sha256Digest(d) };
        prop_assert_eq!(round_trip(&header), header);
        let ack = UploadAck { ok, reason };
        prop_assert_eq!(round_trip(&ack), ack);
    }
}
