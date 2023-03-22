// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

// Description: Client side of tls grpc comms
use crate::types::{Config, Options};
use crate::utils;
use anyhow::{anyhow, Result};
use nix::sys::socket::{connect, socket, AddressFamily, SockAddr, SockFlag, SockType};
use protocols::agent::*;
use slog::{debug, info};
use std::io;
use std::io::Write; // XXX: for flush()
use std::io::{BufRead, BufReader};
use std::path::{PathBuf};
use std::os::unix::io::RawFd;
use std::os::unix::net::UnixStream;
use std::thread::sleep;
use std::time::Duration;
use tonic;
use ttrpc::context::Context;

pub mod grpctls {
    tonic::include_proto!("grpctls");
}
use grpctls::image_client::ImageClient;
use grpctls::sec_agent_service_client::SecAgentServiceClient;

use grpctls::{
    PullImageRequest, SecCreateContainerRequest, SecExecProcessRequest, SecListContainersRequest,
    SecPauseContainerRequest, SecRemoveContainerRequest, SecResumeContainerRequest,
    SecStartContainerRequest, SecSignalProcessRequest, SecWaitProcessRequest
};

macro_rules! run_if_auto_values {
    ($ctx:expr, $closure:expr) => {{
        let cfg = $ctx.metadata.get(METADATA_CFG_NS);

        if let Some(v) = cfg {
            if v.contains(&NO_AUTO_VALUES_CFG_NAME.to_string()) {
                debug!(sl!(), "Running closure to generate values");

                $closure()?;
            }
        }
    }};
}

// Hack until the actual Context type supports this.
#[allow(dead_code)]
fn clone_context(ctx: &Context) -> Context {
    Context {
        metadata: ctx.metadata.clone(),
        timeout_nano: ctx.timeout_nano,
    }
}

// Agent command handler type
//
// Notes:
//
// - 'cmdline' is the command line (command name and optional space separate
//   arguments).
// - 'options' can be read and written to, allowing commands to pass state to
//   each other via well-known option names.
/*
type AgentCmdFp = fn(
    ctx: &Context,
    client: &AgentServiceClient,
    health: &HealthClient,
    image: &ImageClient,
    options: &mut Options,
    args: &str,
) -> Result<()>;

//
// delcaring  client as SecAgentServiceClient<tonic::transport::Channel>,
// Error::
// impl Trait` only allowed in function and inherent method return types,
// not in `fn` pointer return
//
*/

// Builtin command handler type
type BuiltinCmdFp = fn(args: &str) -> (Result<()>, bool);

#[allow(dead_code)]
enum ServiceType {
    Agent,
    //    Health,   // TBD
    Image,
}

// Agent command names *MUST* start with an upper-case letter.
// RV: removed: DEAD CODE: AgentCmd
#[allow(dead_code)]
struct AgentCmd {
    name: &'static str,
    st: ServiceType,
    //    fp: AgentCmdFp,
}

// XXX: Builtin command names *MUST* start with a lower-case letter.
struct BuiltinCmd {
    name: &'static str,
    descr: &'static str,
    fp: BuiltinCmdFp,
}

// Command that causes the agent to exit (iff tracing is enabled)
#[allow(dead_code)]
const SHUTDOWN_CMD: &str = "DestroySandbox";

// Command that requests this program ends
const CMD_QUIT: &str = "quit";
const CMD_REPEAT: &str = "repeat";

const DEFAULT_PROC_SIGNAL: &str = "SIGKILL";

//const ERR_API_FAILED: &str = "API failed";

// Value used as a "namespace" in the ttRPC Context's metadata.
const METADATA_CFG_NS: &str = "agent-ctl-cfg";

// Special value which if found means do not generate any values
// automatically.
const NO_AUTO_VALUES_CFG_NAME: &str = "no-auto-values";

/*  These host_side end-points are not supported by tenant TLS comm chan
 *
 * AddARPNeighbors  Networking  Add an ARP neighbor (netlink.rs)
 * CreateSandbox    Initialization  Initialize the sandbox (rpc.rs, mount.rs, network.rs, ..)
 * DestroySandbox   Termination Destroy the sandbox (rpc.rs, sandbox.rs)
 * GuestDetails Status / Stats  Get details on guest and agent
 * MemHotplugByProbe    Initialization  Add memory via hotplug
 * OnlineCPUMem Initialization  Add CPU via hotplug
 * UpdateInterface  Networking  Update interfaces on links
 * UpdateRoutes  Networking  Update routes on links
 *
*/

static AGENT_CMDS: &[AgentCmd] = &[
    /*
    AgentCmd {
        name: "AddSwap",
        st: ServiceType::Agent,
        fp: agent_cmd_sandbox_add_swap,
    },
    AgentCmd {
        name: "Check",
        st: ServiceType::Health,
        fp: agent_cmd_health_check,
    },
    AgentCmd {
        name: "Version",
        st: ServiceType::Health,
        fp: agent_cmd_health_version,
    },
    AgentCmd {
        name: "CloseStdin",
        st: ServiceType::Agent,
        fp: agent_cmd_container_close_stdin,
    },
    AgentCmd {
        name: "CopyFile",
        st: ServiceType::Agent,
        fp: agent_cmd_sandbox_copy_file,
    },
    */
    AgentCmd {
        name: "CreateContainer",
        st: ServiceType::Agent,
    },
    AgentCmd {
        name: "ExecProcess",
        st: ServiceType::Agent,
    },
    /*
    AgentCmd {
        name: "GetGuestDetails",
        st: ServiceType::Agent,
        fp: agent_cmd_sandbox_get_guest_details,
    },
    AgentCmd {
        name: "GetIptables",
        st: ServiceType::Agent,
        fp: agent_cmd_sandbox_get_ip_tables,
    },
    AgentCmd {
        name: "GetMetrics",
        st: ServiceType::Agent,
        fp: agent_cmd_sandbox_get_metrics,
    },
    AgentCmd {
        name: "GetOOMEvent",
        st: ServiceType::Agent,
        fp: agent_cmd_sandbox_get_oom_event,
    },
    AgentCmd {
        name: "GetVolumeStats",
        st: ServiceType::Agent,
        fp: agent_cmd_sandbox_get_volume_stats,
    },
    */
    AgentCmd {
        name: "ListContainers",
        st: ServiceType::Agent,
    },
    /*
    AgentCmd {
        name: "ListInterfaces",
        st: ServiceType::Agent,
        fp: agent_cmd_sandbox_list_interfaces,
    },
    AgentCmd {
        name: "ListRoutes",
        st: ServiceType::Agent,
        fp: agent_cmd_sandbox_list_routes,
    }, */
    AgentCmd {
        name: "PauseContainer",
        st: ServiceType::Agent,
    },
    /*
    AgentCmd {
        name: "ReadStderr",
        st: ServiceType::Agent,
        fp: agent_cmd_container_read_stderr,
    },
    AgentCmd {
        name: "ReadStdout",
        st: ServiceType::Agent,
        fp: agent_cmd_container_read_stdout,
    },
    AgentCmd {
        name: "ReseedRandomDev",
        st: ServiceType::Agent,
        fp: agent_cmd_sandbox_reseed_random_dev,
    }, */
    AgentCmd {
        name: "RemoveContainer",
        st: ServiceType::Agent,
    },
    AgentCmd {
        name: "ResumeContainer",
        st: ServiceType::Agent,
    },
    /*
    AgentCmd {
        name: "SetGuestDateTime",
        st: ServiceType::Agent,
        fp: agent_cmd_sandbox_set_guest_date_time,
    },
    AgentCmd {
        name: "SetIptables",
        st: ServiceType::Agent,
        fp: agent_cmd_sandbox_set_ip_tables,
    },
    */
    AgentCmd {
        name: "SignalProcess",
        st: ServiceType::Agent,
    },
    AgentCmd {
        name: "StartContainer",
        st: ServiceType::Agent,
    },
    /*
    AgentCmd {
        name: "TtyWinResize",
        st: ServiceType::Agent,
        fp: agent_cmd_container_tty_win_resize,
    },
    AgentCmd {
        name: "UpdateContainer",
        st: ServiceType::Agent,
        fp: agent_cmd_sandbox_update_container,
    },
    */
    AgentCmd {
        name: "WaitProcess",
        st: ServiceType::Agent,
    },
    /*
    AgentCmd {
        name: "WriteStdin",
        st: ServiceType::Agent,
        fp: agent_cmd_container_write_stdin,
    },
    */
    AgentCmd {
        name: "PullImage",
        st: ServiceType::Image,
    },
];

static BUILTIN_CMDS: & [BuiltinCmd] = &[
    BuiltinCmd {
        name: "echo",
        descr: "Display the arguments",
        fp: builtin_cmd_echo,
    },
    BuiltinCmd {
        name: "help",
        descr: "Alias for 'list'",
        fp: builtin_cmd_list,
    },
    BuiltinCmd {
        name: "list",
        descr: "List all available commands",
        fp: builtin_cmd_list,
    },
    BuiltinCmd {
        name: "repeat",
        descr: "Repeat the next command 'n' times [-1 for forever]",
        fp: builtin_cmd_repeat,
    },
    BuiltinCmd {
        name: "sleep",
        descr:
            "Pause for specified period number of nanoseconds (supports human-readable suffixes [no floating points numbers])",
        fp: builtin_cmd_sleep,
    },
    BuiltinCmd {
        name: CMD_QUIT,
        descr: "Exit this program",
        fp: builtin_cmd_quit,
    },
];

fn get_agent_cmd_names() -> Vec<String> {
    let mut names = Vec::new();

    for cmd in AGENT_CMDS {
        names.push(cmd.name.to_string());
    }

    names
}

fn get_agent_cmd_details() -> Vec<String> {
    let mut cmds = Vec::new();

    for cmd in AGENT_CMDS {
        let service = match cmd.st {
            ServiceType::Agent => "agent",
            //            ServiceType::Health => "health",
            ServiceType::Image => "image",
        };

        cmds.push(format!("{} ({} service)", cmd.name, service));
    }

    cmds
}

// REMOVE: RV DEAD CODE
#[allow(dead_code)]
fn get_agent_cmd_func(name: &str) -> Result<&str> {
    // fn get_agent_cmd_func(name: &str) -> Result<AgentCmdFp> {
    for cmd in AGENT_CMDS {
        if cmd.name.eq(name) {
            //return Ok(cmd.fp);
            // return the string instead
            return Ok(cmd.name);
        }
    }

    Err(anyhow!("Invalid command: {:?}", name))
}

#[allow(dead_code)]
fn get_builtin_cmd_details() -> Vec<String> {
    let mut cmds = Vec::new();

    for cmd in BUILTIN_CMDS {
        cmds.push(format!("{} ({})", cmd.name, cmd.descr));
    }

    cmds
}

fn get_all_cmd_details() -> Vec<String> {
    let mut cmds = get_builtin_cmd_details();

    cmds.append(&mut get_agent_cmd_names());

    cmds
}

#[allow(dead_code)]
fn get_builtin_cmd_func(name: &str) -> Result<BuiltinCmdFp> {
    for cmd in BUILTIN_CMDS {
        if cmd.name.eq(name) {
            return Ok(cmd.fp);
        }
    }

    Err(anyhow!("Invalid command: {:?}", name))
}

#[allow(dead_code)]
fn client_create_vsock_fd(cid: libc::c_uint, port: u32) -> Result<RawFd> {
    let fd = socket(
        AddressFamily::Vsock,
        SockType::Stream,
        SockFlag::SOCK_CLOEXEC,
        None,
    )
    .map_err(|e| anyhow!(e))?;

    let sock_addr = SockAddr::new_vsock(cid, port);

    connect(fd, &sock_addr).map_err(|e| anyhow!(e))?;

    Ok(fd)
}

// Setup the existing stream by making a Hybrid VSOCK host-initiated
// connection request to the Hybrid VSOCK-capable hypervisor (CLH or FC),
// asking it to route the connection to the Kata Agent running inside the VM.
#[allow(dead_code)]
fn setup_hybrid_vsock(mut stream: &UnixStream, hybrid_vsock_port: u64) -> Result<()> {
    // Challenge message sent to the Hybrid VSOCK capable hypervisor asking
    // for a connection to a real VSOCK server running in the VM on the
    // port specified as part of this message.
    const CONNECT_CMD: &str = "CONNECT";

    // Expected response message returned by the Hybrid VSOCK capable
    // hypervisor informing the client that the CONNECT_CMD was successful.
    const OK_CMD: &str = "OK";

    // Contact the agent by dialing it's port number and
    // waiting for the hybrid vsock hypervisor to route the call for us ;)
    //
    // See: https://github.com/firecracker-microvm/firecracker/blob/main/docs/vsock.md#host-initiated-connections
    let msg = format!("{} {}\n", CONNECT_CMD, hybrid_vsock_port);

    stream.write_all(msg.as_bytes())?;

    // Now, see if we get the expected response
    let stream_reader = stream.try_clone()?;
    let mut reader = BufReader::new(&stream_reader);

    let mut msg = String::new();
    reader.read_line(&mut msg)?;

    if msg.starts_with(OK_CMD) {
        let response = msg
            .strip_prefix(OK_CMD)
            .ok_or(format!("invalid response: {:?}", msg))
            .map_err(|e| anyhow!(e))?
            .trim();

        debug!(sl!(), "Hybrid VSOCK host-side port: {:?}", response);
    } else {
        return Err(anyhow!(
            "failed to setup Hybrid VSOCK connection: response was: {:?}",
            msg
        ));
    }

    // The Unix stream is now connected directly to the VSOCK socket
    // the Kata agent is listening to in the VM.
    Ok(())
}

async fn client_create_tls_channel<'a>(
    key_dir: String,
    server_address: &'a str,
    server_port: &'a str,
) -> Result<SecAgentServiceClient<tonic::transport::Channel>> {
    let str_front = "http://";

    let url_string = format!("{}{}:{}", str_front, server_address, server_port);
    println!("url_string {}", url_string);

    let mut client_cert = PathBuf::from(&key_dir);
    let mut client_key = PathBuf::from(&key_dir);
    let mut ca_cert = PathBuf::from(&key_dir);
    client_cert.push("client.pem");
    client_key.push("client.key");
    ca_cert.push("ca.pem");

    assert_eq!(((client_key.clone()).into_boxed_path()).exists(), true);
    assert_eq!(((client_cert.clone()).into_boxed_path()).exists(), true);
    assert_eq!(((ca_cert.clone()).into_boxed_path()).exists(), true);

    // Create identify from key and certificate
    let cert = tokio::fs::read(client_cert).await?;
    let key = tokio::fs::read(client_key).await?;
    let id = tonic::transport::Identity::from_pem(cert, key);

    // Get CA certificate
    let pem = tokio::fs::read(ca_cert).await?;
    let ca = tonic::transport::Certificate::from_pem(pem);

    /*
    // Create identify from key and certificate
    let cert = tokio::fs::read("grpc_tls_keys/client.pem").await?;
    let key = tokio::fs::read("grpc_tls_keys/client.key").await?;
    let id = tonic::transport::Identity::from_pem(cert, key);

    // Get CA certificate 
    let pem = tokio::fs::read("grpc_tls_keys/ca.pem").await?;
    let ca = tonic::transport::Certificate::from_pem(pem);
    */

    // Telling our client what is the identity of our server
    let tls = tonic::transport::ClientTlsConfig::new()
        .domain_name("localhost")
        .identity(id.clone())
        .ca_certificate(ca.clone());

    let channel = tonic::transport::Channel::from_shared(url_string.clone().to_string()).unwrap();
    let channel = channel.tls_config(tls)?.connect().await?;
    let client: SecAgentServiceClient<tonic::transport::Channel> =
        SecAgentServiceClient::new(channel);

    Ok(client)
}

async fn create_grpctls_client(
    key_dir: String,
    server_address: String,
    _hybrid_vsock_port: u64,
    _hybrid_vsock: bool,
) -> Result<SecAgentServiceClient<tonic::transport::Channel>> {
    let fields: Vec<&str> = server_address.split("://").collect();

    if fields.len() != 2 {
        return Err(anyhow!("invalid server address URI"));
    }

    let scheme = fields[0].to_lowercase();

    match scheme.as_str() {
        // Format: "ipaddr://ip:port"
        "ipaddr" => {
            let addr: Vec<&str> = fields[1].split(':').collect();

            let ip_address = addr[0];

            let port: u32 = match addr[1].parse::<u32>() {
                Ok(r) => r,
                Err(e) => {
                    println!("Error with port");
                    return Err(anyhow!(e).context("IPADDR port is not numeric"));
                }
            };

            let channel = client_create_tls_channel(key_dir, &ip_address, &port.to_string()).await?;
            Ok(channel)
        }
        _ => return Err(anyhow!("invalid server address URI scheme: {:?}", scheme)),
    }
}

//
// Todo: must refactor using generic fn type!
//
async fn image_create_tls_channel<'a>(
    key_dir: String,
    server_address: &'a str,
    server_port: &'a str,
) -> Result<ImageClient<tonic::transport::Channel>> {
    let str_front = "http://";

    let url_string = format!("{}{}:{}", str_front, server_address, server_port);
    println!("url_string {}", url_string);

    let mut client_cert = PathBuf::from(&key_dir);
    let mut client_key = PathBuf::from(&key_dir);
    let mut ca_cert = PathBuf::from(&key_dir);
    client_cert.push("client.pem");
    client_key.push("client.key");
    ca_cert.push("ca.pem");

    assert_eq!(((client_key.clone()).into_boxed_path()).exists(), true);
    assert_eq!(((client_cert.clone()).into_boxed_path()).exists(), true);
    assert_eq!(((ca_cert.clone()).into_boxed_path()).exists(), true);

    // Create identify from key and certificate
    let cert = tokio::fs::read(client_cert).await?;
    let key = tokio::fs::read(client_key).await?;
    let id = tonic::transport::Identity::from_pem(cert, key);

    // Get CA certificate
    let pem = tokio::fs::read(ca_cert).await?;
    let ca = tonic::transport::Certificate::from_pem(pem);

    /* 
    // Create identify from key and certificate
    let cert = tokio::fs::read("grpc_tls_keys/client.pem").await?;
    let key = tokio::fs::read("grpc_tls_keys/client.key").await?;
    let id = tonic::transport::Identity::from_pem(cert, key);

    // Get CA certificate 
    let pem = tokio::fs::read("grpc_tls_keys/ca.pem").await?;
    let ca = tonic::transport::Certificate::from_pem(pem);
    */

    // Telling our client what is the identity of our server
    let tls = tonic::transport::ClientTlsConfig::new()
        .domain_name("localhost")
        .identity(id.clone())
        .ca_certificate(ca.clone());

    let channel = tonic::transport::Channel::from_shared(url_string.clone().to_string()).unwrap();
    let channel = channel.tls_config(tls)?.connect().await?;
    let client: ImageClient<tonic::transport::Channel> = ImageClient::new(channel);

    Ok(client)
}

async fn create_grpctls_image(
    key_dir: String,
    server_address: String,
    _hybrid_vsock_port: u64,
    _hybrid_vsock: bool,
) -> Result<ImageClient<tonic::transport::Channel>> {
    let fields: Vec<&str> = server_address.split("://").collect();

    if fields.len() != 2 {
        return Err(anyhow!("invalid server address URI"));
    }

    let scheme = fields[0].to_lowercase();

    match scheme.as_str() {
        // Format: "ipaddr://ip:port"
        "ipaddr" => {
            let addr: Vec<&str> = fields[1].split(':').collect();

            let ip_address = addr[0];

            let port: u32 = match addr[1].parse::<u32>() {
                Ok(r) => r,
                Err(e) => {
                    println!("Error with port");
                    return Err(anyhow!(e).context("IPADDR port is not numeric"));
                }
            };

            let channel = image_create_tls_channel(key_dir, &ip_address, &port.to_string()).await?;
            Ok(channel)
        }
        _ => return Err(anyhow!("invalid server address URI scheme: {:?}", scheme)),
    }
}

async fn kata_service_agent(
    key_dir: String,
    server_address: String,
    hybrid_vsock_port: u64,
    hybrid_vsock: bool,
) -> Result<(SecAgentServiceClient<tonic::transport::Channel>, i32)> {
    let grpc_channel =
        create_grpctls_client(key_dir, server_address, hybrid_vsock_port, hybrid_vsock).await?;
    Ok((grpc_channel, 2))
}

async fn kata_service_image(
    key_dir: String,
    server_address: String,
    hybrid_vsock_port: u64,
    hybrid_vsock: bool,
) -> Result<(ImageClient<tonic::transport::Channel>, i32)> {
    let grpc_channel =
        create_grpctls_image(key_dir, server_address, hybrid_vsock_port, hybrid_vsock).await?;
    Ok((grpc_channel, 3))
}

/*
fn kata_service_health(
    server_address: String,
    hybrid_vsock_port: u64,
    hybrid_vsock: bool,
) -> Result<HealthClient> {
    let ttrpc_client = create_ttrpc_client(server_address, hybrid_vsock_port, hybrid_vsock)?;

    Ok(HealthClient::new(ttrpc_client))
}
*/

fn announce(cfg: &Config) {
    info!(sl!(), "announce"; "config" => format!("{:?}", cfg));
}

// pub async fn client(cfg: &Config, commands: Vec<&str>) -> Result<()> {
pub async fn client(cfg: &Config, commands: Vec<&str>) -> Result<(), anyhow::Error> {
    if commands.len() == 1 && commands[0].eq("list") {
        println!("Built-in commands:\n");

        let mut builtin_cmds = get_builtin_cmd_details();
        builtin_cmds.sort();
        builtin_cmds.iter().for_each(|n| println!("  {}", n));

        println!();

        println!("Agent API commands:\n");

        let mut agent_cmds = get_agent_cmd_details();
        agent_cmds.sort();
        agent_cmds.iter().for_each(|n| println!("  {}", n));

        println!();

        return Ok(());
    }

    announce(cfg);

    let (client, _val) = match kata_service_agent(
        cfg.key_dir.clone(),
        cfg.server_address.clone(),
        cfg.hybrid_vsock_port,
        cfg.hybrid_vsock,
    )
    .await
    {
        Ok((v, v2)) => (v, v2),
        Err(e) => return Err(anyhow!(e).context("Error setting tls channel")),
    };

    let (image, _val) = match kata_service_image(
        cfg.key_dir.clone(),
        cfg.server_address.clone(),
        cfg.hybrid_vsock_port,
        cfg.hybrid_vsock,
    )
    .await
    {
        Ok((v, v2)) => (v, v2),
        Err(e) => return Err(anyhow!(e).context("Error setting tls channel")),
    };
    /*
    let health = kata_service_health(
        cfg.server_address.clone(),
        cfg.hybrid_vsock_port,
        cfg.hybrid_vsock,
    )?;
    */

    let mut options = Options::new();

    let mut ttrpc_ctx = ttrpc::context::with_timeout(cfg.timeout_nano);

    // Allow the commands to change their behaviour based on the value
    // of this option.

    if !cfg.no_auto_values {
        ttrpc_ctx.add(METADATA_CFG_NS.into(), NO_AUTO_VALUES_CFG_NAME.to_string());

        debug!(sl!(), "Automatic value generation disabled");
    }

    // Special-case loading the OCI config file so it is accessible
    // to all commands.
    let oci_spec_json = utils::get_oci_spec_json(cfg)?;
    options.insert("spec".to_string(), oci_spec_json);

    // Convenience option
    options.insert("bundle-dir".to_string(), cfg.bundle_dir.clone());

    info!(sl!(), "client setup complete";
        "server-address" => cfg.server_address.to_string());

    // Debug print out contex
    // println!("Context out: {:?}", ttrpc_ctx);

    if cfg.interactive {
        println!("cfg.interactive not supported :");
    }

    let mut repeat_count = 1;

    for cmd in commands {
        if cmd.starts_with(CMD_REPEAT) {
            repeat_count = get_repeat_count(cmd);
            continue;
        }

        /*
        let (result, shutdown) = handle_cmd(
            cfg,
            &client,
            &health,
            &image,
            &ttrpc_ctx,
            repeat_count,
            &mut options,
            cmd,
        );
        */
        let result = handle_cmd(
            cfg,
            client.clone(),
            2,
            image.clone(),
            &ttrpc_ctx,
            repeat_count,
            &mut options,
            cmd,
        );
        // result.map_err(|e| anyhow!(e))?;
        let shutdown = match result.await {
            Ok(shutdown) => shutdown,
            Err(e) => return Err(e),
        };

        if shutdown {
            break;
        }

        // Reset
        repeat_count = 1;
    }

    Ok(())
}

//
//
//
//= note: expected reference `&Channel`
//  found reference `&impl Future<Output = Result<Channel, anyhow::Error>>`

//
// Handle internal and agent API commands.
// REMOVE unused ...
//    _client: &SecAgentServiceClient<tonic::transport::Channel>,
//
#[allow(dead_code)]
#[allow(clippy::too_many_arguments)]
//fn handle_cmd(
async fn handle_cmd(
    _cfg: &Config,
    client: SecAgentServiceClient<tonic::transport::Channel>,
    health: i32,
    image: ImageClient<tonic::transport::Channel>,
    ctx: &Context,
    repeat_count: i64,
    options: &mut Options,
    cmdline: &str,
) -> Result<bool> {
    let fields: Vec<&str> = cmdline.split_whitespace().collect();

    let cmd = fields[0];

    if cmd.is_empty() {
        // Ignore empty commands
        // return (Ok(()), false);
        return Ok(false);
    }

    let first = match cmd.chars().next() {
        Some(c) => c,
        None => return Err(anyhow!("failed to check command name")),
    };

    let args = if fields.len() > 1 {
        fields[1..].join(" ")
    } else {
        String::new()
    };

    let mut count = 0;

    let mut count_msg = String::new();

    if repeat_count < 0 {
        count_msg = "forever".to_string();
    }

    let _error_count: u64 = 0;
    let mut result: Result<bool>;

    loop {
        if repeat_count > 0 {
            count_msg = format!("{} of {}", count + 1, repeat_count);
        }

        info!(sl!(), "Run command {:} ({})", cmd, count_msg);

        if first.is_lowercase() {
            result = handle_builtin_cmd(cmd, &args);
            println!("TBD: BUILTIN NOT HANDLE");
        } else {
            result = handle_agent_cmd(
                ctx,
                client.clone(),
                health,
                image.clone(),
                options,
                cmd,
                &args,
            )
            .await;
            // result = handle_builtin_cmd(cmd, &args);
        }

        let shutdown = match result {
            Ok(shutdown) => shutdown,
            Err(e) => return Err(e),
        };
        /*
        if result.0.is_err() {
            if cfg.ignore_errors {
                error_count += 1;
                debug!(sl!(), "ignoring error for command {:}: {:?}", cmd, result.0);
            } else {
                return result;
            }
        }
        */

        info!(
            sl!(),
            "Command {:} ({}) returned {:?}", cmd, count_msg, shutdown
        );

        if repeat_count > 0 {
            count += 1;

            if count == repeat_count {
                break;
            }
        }
    }

    /*
    if cfg.ignore_errors {
        debug!(sl!(), "Error count for command {}: {}", cmd, error_count);
        (Ok(()), result.1)
    } else {
        result
    }
    */
    Ok(true)
}

#[allow(dead_code)]
fn handle_builtin_cmd(_cmd: &str, _args: &str) -> Result<bool> {
    /*
    let f = match get_builtin_cmd_func(cmd) {
        Ok(fp) => fp,
        Err(e) => return Err(e),
        //Err(e) => return (Err(e), false),
    };

    f(args)
    */
    Ok(true)
}

// Execute the ttRPC specified by the first field of "line". Return a result
// along with a bool which if set means the client should shutdown.
// REMOVE: RV: DEAD CODE: handle_agent_cmd

#[allow(dead_code)]
async fn handle_agent_cmd(
    ctx: &Context,
    client: SecAgentServiceClient<tonic::transport::Channel>,
    health: i32, // set Agent for now:  &HealthClient
    image: ImageClient<tonic::transport::Channel>,
    options: &mut Options,
    cmd: &str,
    args: &str,
) -> Result<bool> {
    // Using command to call function since fp can't have impl Trait as return type

    let fname = match get_agent_cmd_func(cmd) {
        Ok(fp) => fp,
        Err(e) => return Err(e),
    };
    match fname {
        "CreateContainer" => {
            let _result =
                agent_cmd_container_create(ctx, client, health, image, options, args).await?;
        }

        "ListContainers" => {
            let _result =
                agent_cmd_container_list(ctx, client, health, image, options, args).await?;
        }

        "StartContainer" => {
            let _result =
                agent_cmd_container_start(ctx, client, health, image, options, args).await?;
        }

        "RemoveContainer" => {
            let _result =
                agent_cmd_container_remove(ctx, client, health, image, options, args).await?;
        }

        "PauseContainer" => {
            let _result =
                agent_cmd_container_pause(ctx, client, health, image, options, args).await?;
        }

        "ResumeContainer" => {
            let _result =
                agent_cmd_container_resume(ctx, client, health, image, options, args).await?;
        }

        "ExecProcess" => {
            let _result =
                agent_cmd_container_exec(ctx, client, health, image, options, args).await?;
        }

        "SignalProcess" => {
            let _result = agent_cmd_container_signal_process(ctx, client, health, image, options, args).await?;
        }

        "WaitProcess" => {
            let _result = agent_cmd_container_wait_process(ctx, client, health, image, options, args).await?;
        }

        "PullImage" => {
            let _result = agent_cmd_pull_image(ctx, client, health, image, options, args).await?;
        }

        _ => println!("No command "),
    }

    let shutdown = cmd.eq(SHUTDOWN_CMD);
    Ok(shutdown)
}

/*
#[allow(dead_code)]
fn interactive_client_loop(
    cfg: &Config,
    options: &mut Options,
    //client: &AgentServiceClient,
    //client: &SecAgentServiceClient<Channel>,
    client: &impl Future<Output = SecAgentServiceClient<Channel>>,
    health: i32,
    image: i32,
    //health: &HealthClient,
    //image: &ImageClient,
    ctx: &Context,
) -> Result<()> {
    let result = builtin_cmd_list("");
    if result.0.is_err() {
        return result.0;
    }

    let mut repeat_count: i64 = 1;

    loop {
        let cmdline =
            readline("Enter command").map_err(|e| anyhow!(e).context("failed to read line"))?;

        if cmdline.is_empty() {
            continue;
        }

        if cmdline.starts_with(CMD_REPEAT) {
            repeat_count = get_repeat_count(&cmdline);
            continue;
        }

        let (result, shutdown) = handle_cmd(
            cfg,
            client,
            health,
            image,
            ctx,
            repeat_count,
            options,
            &cmdline,
        );

        result.map_err(|e| anyhow!(e))?;

        if shutdown {
            break;
        }

        // Reset
        repeat_count = 1;
    }

    Ok(())
}
*/

#[allow(dead_code)]
fn readline(prompt: &str) -> std::result::Result<String, String> {
    print!("{}: ", prompt);

    io::stdout()
        .flush()
        .map_err(|e| format!("failed to flush: {:?}", e))?;

    let mut line = String::new();

    std::io::stdin()
        .read_line(&mut line)
        .map_err(|e| format!("failed to read line: {:?}", e))?;

    // Remove NL
    Ok(line.trim_end().to_string())
}

/*
fn agent_cmd_health_check(
    ctx: &Context,
    _client: &AgentServiceClient,
    health: &HealthClient,
    _image: ImageClient<tonic::transport::Channel>,
    _options: &mut Options,
    args: &str,
) -> Result<()> {
    let req: CheckRequest = utils::make_request(args)?;

    let ctx = clone_context(ctx);

    debug!(sl!(), "sending request"; "request" => format!("{:?}", req));

    let reply = health
        .check(ctx, &req)
        .map_err(|e| anyhow!("{:?}", e).context(ERR_API_FAILED))?;

    info!(sl!(), "response received";
        "response" => format!("{:?}", reply));

    Ok(())
}

fn agent_cmd_health_version(
    ctx: &Context,
    _client: &AgentServiceClient,
    health: &HealthClient,
    _image: ImageClient<tonic::transport::Channel>,
    _options: &mut Options,
    args: &str,
) -> Result<()> {
    // XXX: Yes, the API is actually broken!
    let req: CheckRequest = utils::make_request(args)?;

    let ctx = clone_context(ctx);

    debug!(sl!(), "sending request"; "request" => format!("{:?}", req));

    let reply = health
        .version(ctx, &req)
        .map_err(|e| anyhow!("{:?}", e).context(ERR_API_FAILED))?;

    info!(sl!(), "response received";
        "response" => format!("{:?}", reply));

    Ok(())
}
*/

async fn agent_cmd_container_create(
    ctx: &Context,
    mut client: SecAgentServiceClient<tonic::transport::Channel>,
    _health: i32,
    _image: ImageClient<tonic::transport::Channel>,
    options: &mut Options,
    args: &str,
) -> Result<()> {
    let mut req: SecCreateContainerRequest = utils::make_request(args)?;

    let ctx = clone_context(ctx);

    // Note: container create: uses "spec=file:///" support

    run_if_auto_values!(ctx, || -> Result<()> {
        let cid = utils::get_option("cid", options, args)?;
        let exec_id = utils::get_option("exec_id", options, args)?;

        let ttrpc_spec = utils::get_ttrpc_spec(options, &cid).map_err(|e| anyhow!(e))?;
        let jstr = serde_json::to_string(&ttrpc_spec)?;
        let tls_spec: grpctls::Spec = serde_json::from_str::<grpctls::Spec>(&jstr)?;

        req.container_id = cid;
        req.exec_id = exec_id;
        req.oci = std::option::Option::Some(tls_spec);
        req.sandbox_pidns = true;

        Ok(())
    });
    let nsend = match utils::get_option("nsend", options, args) {
        Ok(v) => {
            if v.len() == 0 {
                false
            } else {
                true
            }
        }
        Err(_) => false,
    };
    debug!(sl!(), "Boolean"; "send request" => format!("{:?}", nsend));
    debug!(sl!(), "Request"; "tls rpc request" => format!("{:?}", req));

    if !nsend {
        let reply = client.sec_create_container(req).await?.into_inner();

        info!(sl!(), "response received";
            "response" => format!("{:?}", reply));
    } else {
        let mut ttrpc_req: protocols::agent::CreateContainerRequest = CreateContainerRequest::new();
        ttrpc_req.set_container_id(req.container_id);
        ttrpc_req.set_exec_id(req.exec_id);
        ttrpc_req.set_sandbox_pidns(req.sandbox_pidns);

        let oci_obj = req.oci.unwrap();
        let oci_str = serde_json::to_string(&oci_obj)?;
        let oci_spec: protocols::oci::Spec = serde_json::from_str(&oci_str)?;
        //debug!(sl!(), "K_T02 oci_ttprc"; "STR" => format!("{:?}", oci_spec));

        ttrpc_req.set_OCI(oci_spec);
        debug!(sl!(), "ttrpc  Request"; "request" => format!("{:?}", ttrpc_req));
    }
    Ok(())
}

async fn agent_cmd_container_list(
    _ctx: &Context,
    mut client: SecAgentServiceClient<tonic::transport::Channel>,
    _health: i32,
    _image: ImageClient<tonic::transport::Channel>,
    _options: &mut Options,
    _args: &str,
) -> Result<()> {
    let req = tonic::Request::new(SecListContainersRequest {});

    debug!(sl!(), "sending request"; "request" => format!("{:?}", req));

    let reply = client.sec_list_containers(req).await?.into_inner();

    println!("{}", serde_json::to_string_pretty(&reply).unwrap());

    Ok(())
}

async fn agent_cmd_container_remove(
    ctx: &Context,
    mut client: SecAgentServiceClient<tonic::transport::Channel>,
    _health: i32,
    _image: ImageClient<tonic::transport::Channel>,
    options: &mut Options,
    args: &str,
) -> Result<()> {
    let mut req: SecRemoveContainerRequest = utils::make_request(args)?;

    let ctx = clone_context(ctx);

    run_if_auto_values!(ctx, || -> Result<()> {
        let cid = utils::get_option("cid", options, args)?;
        let timeout = utils::get_option("timeout", options, args)?;

        req.container_id = cid;
        req.timeout = timeout.parse()?;

        Ok(())
    });

    debug!(sl!(), "sending request"; "request" => format!("{:?}", req));

    let reply = client.sec_remove_container(req).await?.into_inner();

    info!(sl!(), "response received";
        "response" => format!("{:?}", reply));

    Ok(())
}

async fn agent_cmd_container_exec(
    _ctx: &Context,
    mut client: SecAgentServiceClient<tonic::transport::Channel>,
    _health: i32,
    _image: ImageClient<tonic::transport::Channel>,
    _options: &mut Options,
    args: &str,
) -> Result<()> {
    let req: SecExecProcessRequest = utils::make_request(args)?;

    //let mut req: SecExecProcessRequest = utils::make_request(args)?;
    //println!("XXX after args {:?}", req);
    /*
     let ctx = clone_context(ctx);

     run_if_auto_values!(ctx, || -> Result<()> {
         let cid = utils::get_option("cid", options, args)?;
         let exec_id = utils::get_option("exec_id", options, args)?;

         let ttrpc_spec = utils::get_ttrpc_spec(options, &cid).map_err(|e| anyhow!(e))?;

         let bundle_dir = options
             .get("bundle-dir")
             .ok_or("BUG: bundle-dir missing")
             .map_err(|e| anyhow!(e))?;

         let process = ttrpc_spec
             .Process
             .into_option()
             .ok_or(format!(
                 "failed to get process from OCI spec: {}",
                 bundle_dir,
             ))
             .map_err(|e| anyhow!(e))?;

     println!("RV:: Processs {:?}", process);
         req.container_id = cid;
         req.exec_id = exec_id;
         //req.process = process;
         Ok(())
     });
    */

    debug!(sl!(), "sending request"; "request" => format!("{:?}", req));

    let reply = client.sec_exec_process(req).await?.into_inner();

    info!(sl!(), "response received";
        "response" => format!("{:?}", reply));

    Ok(())
}

/*
fn agent_cmd_container_stats(
    ctx: &Context,
    client: &AgentServiceClient,
    _health: &HealthClient,
    _image: &ImageClient,
    options: &mut Options,
    args: &str,
) -> Result<()> {
    let mut req: StatsContainerRequest = utils::make_request(args)?;

    let ctx = clone_context(ctx);

    run_if_auto_values!(ctx, || -> Result<()> {
        let cid = utils::get_option("cid", options, args)?;

        req.set_container_id(cid);
        Ok(())
    });

    debug!(sl!(), "sending request"; "request" => format!("{:?}", req));

    let reply = client
        .stats_container(ctx, &req)
        .map_err(|e| anyhow!("{:?}", e).context(ERR_API_FAILED))?;

    info!(sl!(), "response received";
        "response" => format!("{:?}", reply));

    Ok(())
}
*/

async fn agent_cmd_container_pause(
    ctx: &Context,
    mut client: SecAgentServiceClient<tonic::transport::Channel>,
    _health: i32,
    _image: ImageClient<tonic::transport::Channel>,
    //_health: &HealthClient,
    options: &mut Options,
    args: &str,
) -> Result<()> {
    let mut req: SecPauseContainerRequest = utils::make_request(args)?;
    //
    let ctx = clone_context(ctx);

    run_if_auto_values!(ctx, || -> Result<()> {
        let cid = utils::get_option("cid", options, args)?;
        req.container_id = cid;
        Ok(())
    });

    debug!(sl!(), "sending request"; "request" => format!("{:?}", req));

    let reply = client.sec_pause_container(req).await?.into_inner();

    info!(sl!(), "response received";
            "response" => format!("{:?}", reply));
    Ok(())
}

async fn agent_cmd_container_resume(
    ctx: &Context,
    mut client: SecAgentServiceClient<tonic::transport::Channel>,
    _health: i32,
    _image: ImageClient<tonic::transport::Channel>,
    options: &mut Options,
    args: &str,
) -> Result<()> {
    let mut req: SecResumeContainerRequest = utils::make_request(args)?;

    let ctx = clone_context(ctx);

    run_if_auto_values!(ctx, || -> Result<()> {
        let cid = utils::get_option("cid", options, args)?;

        req.container_id = cid;
        Ok(())
    });

    debug!(sl!(), "sending request"; "request" => format!("{:?}", req));

    let reply = client.sec_resume_container(req).await?.into_inner();

    info!(sl!(), "response received";
        "response" => format!("{:?}", reply));

    Ok(())
}

async fn agent_cmd_container_start(
    ctx: &Context,
    mut client: SecAgentServiceClient<tonic::transport::Channel>,
    _health: i32,
    _image: ImageClient<tonic::transport::Channel>,
    //health: &HealthClient,
    options: &mut Options,
    args: &str,
) -> Result<()> {
    let mut req: SecStartContainerRequest = utils::make_request(args)?;

    let ctx = clone_context(ctx);

    run_if_auto_values!(ctx, || -> Result<()> {
        let cid = utils::get_option("cid", options, args)?;

        //req.set_container_id(cid);
        req.container_id = cid;
        Ok(())
    });

    debug!(sl!(), "sending request"; "request" => format!("{:?}", req));

    let reply = client.sec_start_container(req).await?.into_inner();

    info!(sl!(), "response received";
        "response" => format!("{:?}", reply));

    Ok(())
}

/*
fn agent_cmd_sandbox_get_guest_details(
    ctx: &Context,
    client: &AgentServiceClient,
    _health: &HealthClient,
    _image: ImageClient<tonic::transport::Channel>,
    _options: &mut Options,
    args: &str,
) -> Result<()> {
    let mut req: GuestDetailsRequest = utils::make_request(args)?;

    let ctx = clone_context(ctx);

    run_if_auto_values!(ctx, || -> Result<()> {
        req.set_mem_block_size(true);
        req.set_mem_hotplug_probe(true);

        Ok(())
    });

    debug!(sl!(), "sending request"; "request" => format!("{:?}", req));

    let reply = client
        .get_guest_details(ctx, &req)
        .map_err(|e| anyhow!("{:?}", e).context(ERR_API_FAILED))?;

    info!(sl!(), "response received";
        "response" => format!("{:?}", reply));

    Ok(())
}

fn agent_cmd_sandbox_get_ip_tables(
    ctx: &Context,
    client: &AgentServiceClient,
    _health: &HealthClient,
    _image: ImageClient<tonic::transport::Channel>,
    _options: &mut Options,
    args: &str,
) -> Result<()> {
    let req: GetIPTablesRequest = utils::make_request(args)?;

    let ctx = clone_context(ctx);

    debug!(sl!(), "sending request"; "request" => format!("{:?}", req));

    let reply = client
        .get_ip_tables(ctx, &req)
        .map_err(|e| anyhow!("{:?}", e).context(ERR_API_FAILED))?;

    info!(sl!(), "response received";
        "response" => format!("{:?}", reply));

    Ok(())
}
*/
async fn agent_cmd_container_wait_process(
    ctx: &Context,
    mut client: SecAgentServiceClient<tonic::transport::Channel>,
    _health: i32,
    _image: ImageClient<tonic::transport::Channel>,
    options: &mut Options,
    args: &str,
) -> Result<()> {
    let mut req: SecWaitProcessRequest = utils::make_request(args)?;

    let ctx = clone_context(ctx);

    run_if_auto_values!(ctx, || -> Result<()> {
        let cid = utils::get_option("cid", options, args)?;
        let exec_id = utils::get_option("exec_id", options, args)?;

        req.container_id = cid;
        req.exec_id = exec_id;

        Ok(())
    });

    debug!(sl!(), "sending request"; "request" => format!("{:?}", req));
    let reply = client.sec_wait_process(req).await?.into_inner();

    info!(sl!(), "response received";
        "response" => format!("{:?}", reply));
/*
    let reply = client
        .wait_process(ctx, &req)
        .map_err(|e| anyhow!("{:?}", e).context(ERR_API_FAILED))?;

    info!(sl!(), "response received";
        "response" => format!("{:?}", reply));
*/
    Ok(())
}

async fn agent_cmd_container_signal_process(
    ctx: &Context,
    mut client: SecAgentServiceClient<tonic::transport::Channel>,
    _health: i32,
    _image: ImageClient<tonic::transport::Channel>,
    options: &mut Options,
    args: &str,
) -> Result<()> {
    let mut req: SecSignalProcessRequest = utils::make_request(args)?;

    let ctx = clone_context(ctx);

    run_if_auto_values!(ctx, || -> Result<()> {
        let cid = utils::get_option("cid", options, args)?;
        let exec_id = utils::get_option("exec_id", options, args)?;

        let mut sigstr = utils::get_option("signal", options, args)?;

        // Convert to a numeric
        if sigstr.is_empty() {
            sigstr = DEFAULT_PROC_SIGNAL.to_string();
        }

        let signum = utils::signame_to_signum(&sigstr).map_err(|e| anyhow!(e))?;

        req.container_id = cid;
        req.exec_id = exec_id;
        req.signal = signum as u32;

        Ok(())
    });

    debug!(sl!(), "sending request"; "request" => format!("{:?}", req));

    let reply = client.sec_signal_process(req).await?.into_inner();

    info!(sl!(), "response received";
        "response" => format!("{:?}", reply));
    /*
    let reply = client
        .signal_process(ctx, &req)
        .map_err(|e| anyhow!("{:?}", e).context(ERR_API_FAILED))?;

    info!(sl!(), "response received";
        "response" => format!("{:?}", reply));
        */

    Ok(())
}

/*
fn agent_cmd_sandbox_list_interfaces(
    ctx: &Context,
    client: &AgentServiceClient,
    _health: &HealthClient,
    _image: ImageClient<tonic::transport::Channel>,
    _options: &mut Options,
    args: &str,
) -> Result<()> {
    let req: ListInterfacesRequest = utils::make_request(args)?;

    let ctx = clone_context(ctx);

    debug!(sl!(), "sending request"; "request" => format!("{:?}", req));

    let reply = client
        .list_interfaces(ctx, &req)
        .map_err(|e| anyhow!("{:?}", e).context(ERR_API_FAILED))?;

    info!(sl!(), "response received";
        "response" => format!("{:?}", reply));

    Ok(())
}

fn agent_cmd_sandbox_list_routes(
    ctx: &Context,
    client: &AgentServiceClient,
    _health: &HealthClient,
    _image: ImageClient<tonic::transport::Channel>,
    _options: &mut Options,
    args: &str,
) -> Result<()> {
    let req: ListRoutesRequest = utils::make_request(args)?;

    let ctx = clone_context(ctx);

    debug!(sl!(), "sending request"; "request" => format!("{:?}", req));

    let reply = client
        .list_routes(ctx, &req)
        .map_err(|e| anyhow!("{:?}", e).context(ERR_API_FAILED))?;

    info!(sl!(), "response received";
        "response" => format!("{:?}", reply));

    Ok(())
}

fn agent_cmd_container_tty_win_resize(
    ctx: &Context,
    client: &AgentServiceClient,
    _health: &HealthClient,
    _image: ImageClient<tonic::transport::Channel>,
    options: &mut Options,
    args: &str,
) -> Result<()> {
    let mut req: TtyWinResizeRequest = utils::make_request(args)?;

    let ctx = clone_context(ctx);

    run_if_auto_values!(ctx, || -> Result<()> {
        let cid = utils::get_option("cid", options, args)?;
        let exec_id = utils::get_option("exec_id", options, args)?;

        req.set_container_id(cid);
        req.set_exec_id(exec_id);

        let rows_str = utils::get_option("row", options, args)?;

        if !rows_str.is_empty() {
            let rows = rows_str
                .parse::<u32>()
                .map_err(|e| anyhow!(e).context("invalid row size"))?;
            req.set_row(rows);
        }

        let cols_str = utils::get_option("column", options, args)?;

        if !cols_str.is_empty() {
            let cols = cols_str
                .parse::<u32>()
                .map_err(|e| anyhow!(e).context("invalid column size"))?;

            req.set_column(cols);
        }

        Ok(())
    });

    debug!(sl!(), "sending request"; "request" => format!("{:?}", req));

    let reply = client
        .tty_win_resize(ctx, &req)
        .map_err(|e| anyhow!("{:?}", e).context(ERR_API_FAILED))?;

    info!(sl!(), "response received";
        "response" => format!("{:?}", reply));

    Ok(())
}

fn agent_cmd_container_close_stdin(
    ctx: &Context,
    client: &AgentServiceClient,
    _health: &HealthClient,
    _image: ImageClient<tonic::transport::Channel>,
    options: &mut Options,
    args: &str,
) -> Result<()> {
    let mut req: CloseStdinRequest = utils::make_request(args)?;

    let ctx = clone_context(ctx);

    run_if_auto_values!(ctx, || -> Result<()> {
        let cid = utils::get_option("cid", options, args)?;
        let exec_id = utils::get_option("exec_id", options, args)?;

        req.set_container_id(cid);
        req.set_exec_id(exec_id);

        Ok(())
    });

    debug!(sl!(), "sending request"; "request" => format!("{:?}", req));

    let reply = client
        .close_stdin(ctx, &req)
        .map_err(|e| anyhow!("{:?}", e).context(ERR_API_FAILED))?;

    info!(sl!(), "response received";
        "response" => format!("{:?}", reply));

    Ok(())
}

fn agent_cmd_container_read_stdout(
    ctx: &Context,
    client: &AgentServiceClient,
    _health: &HealthClient,
    _image: ImageClient<tonic::transport::Channel>,
    options: &mut Options,
    args: &str,
) -> Result<()> {
    let mut req: ReadStreamRequest = utils::make_request(args)?;

    let ctx = clone_context(ctx);

    run_if_auto_values!(ctx, || -> Result<()> {
        let cid = utils::get_option("cid", options, args)?;
        let exec_id = utils::get_option("exec_id", options, args)?;

        req.set_container_id(cid);
        req.set_exec_id(exec_id);

        let length_str = utils::get_option("len", options, args)?;

        if !length_str.is_empty() {
            let length = length_str
                .parse::<u32>()
                .map_err(|e| anyhow!(e).context("invalid length"))?;
            req.set_len(length);
        }

        Ok(())
    });

    debug!(sl!(), "sending request"; "request" => format!("{:?}", req));

    let reply = client
        .read_stdout(ctx, &req)
        .map_err(|e| anyhow!("{:?}", e).context(ERR_API_FAILED))?;

    info!(sl!(), "response received";
        "response" => format!("{:?}", reply));

    Ok(())
}

fn agent_cmd_container_read_stderr(
    ctx: &Context,
    client: &AgentServiceClient,
    _health: &HealthClient,
    _image: ImageClient<tonic::transport::Channel>,
    options: &mut Options,
    args: &str,
) -> Result<()> {
    let mut req: ReadStreamRequest = utils::make_request(args)?;

    let ctx = clone_context(ctx);

    run_if_auto_values!(ctx, || -> Result<()> {
        let cid = utils::get_option("cid", options, args)?;
        let exec_id = utils::get_option("exec_id", options, args)?;

        req.set_container_id(cid);
        req.set_exec_id(exec_id);

        let length_str = utils::get_option("len", options, args)?;

        if !length_str.is_empty() {
            let length = length_str
                .parse::<u32>()
                .map_err(|e| anyhow!(e).context("invalid length"))?;
            req.set_len(length);
        }

        Ok(())
    });

    debug!(sl!(), "sending request"; "request" => format!("{:?}", req));

    let reply = client
        .read_stderr(ctx, &req)
        .map_err(|e| anyhow!("{:?}", e).context(ERR_API_FAILED))?;

    info!(sl!(), "response received";
        "response" => format!("{:?}", reply));

    Ok(())
}

fn agent_cmd_container_write_stdin(
    ctx: &Context,
    client: &AgentServiceClient,
    _health: &HealthClient,
    _image: ImageClient<tonic::transport::Channel>,
    options: &mut Options,
    args: &str,
) -> Result<()> {
    let mut req: WriteStreamRequest = utils::make_request(args)?;

    let ctx = clone_context(ctx);

    run_if_auto_values!(ctx, || -> Result<()> {
        let cid = utils::get_option("cid", options, args)?;
        let exec_id = utils::get_option("exec_id", options, args)?;

        let str_data = utils::get_option("data", options, args)?;
        let data = utils::str_to_bytes(&str_data)?;

        req.set_container_id(cid);
        req.set_exec_id(exec_id);
        req.set_data(data.to_vec());

        Ok(())
    });

    debug!(sl!(), "sending request"; "request" => format!("{:?}", req));

    let reply = client
        .write_stdin(ctx, &req)
        .map_err(|e| anyhow!("{:?}", e).context(ERR_API_FAILED))?;

    info!(sl!(), "response received";
        "response" => format!("{:?}", reply));

    Ok(())
}

fn agent_cmd_sandbox_get_metrics(
    ctx: &Context,
    client: &AgentServiceClient,
    _health: &HealthClient,
    _image: ImageClient<tonic::transport::Channel>,
    _options: &mut Options,
    args: &str,
) -> Result<()> {
    let req: GetMetricsRequest = utils::make_request(args)?;

    let ctx = clone_context(ctx);

    debug!(sl!(), "sending request"; "request" => format!("{:?}", req));

    let reply = client
        .get_metrics(ctx, &req)
        .map_err(|e| anyhow!("{:?}", e).context(ERR_API_FAILED))?;

    info!(sl!(), "response received";
        "response" => format!("{:?}", reply));

    Ok(())
}

fn agent_cmd_sandbox_get_oom_event(
    ctx: &Context,
    client: &AgentServiceClient,
    _health: &HealthClient,
    _image: ImageClient<tonic::transport::Channel>,
    _options: &mut Options,
    args: &str,
) -> Result<()> {
    let req: GetOOMEventRequest = utils::make_request(args)?;

    let ctx = clone_context(ctx);

    debug!(sl!(), "sending request"; "request" => format!("{:?}", req));

    let reply = client
        .get_oom_event(ctx, &req)
        .map_err(|e| anyhow!("{:?}", e).context(ERR_API_FAILED))?;

    info!(sl!(), "response received";
        "response" => format!("{:?}", reply));

    Ok(())
}

fn agent_cmd_sandbox_get_volume_stats(
    ctx: &Context,
    client: &AgentServiceClient,
    _health: &HealthClient,
    _image: ImageClient<tonic::transport::Channel>,
    _options: &mut Options,
    args: &str,
) -> Result<()> {
    let req: VolumeStatsRequest = utils::make_request(args)?;

    let ctx = clone_context(ctx);

    debug!(sl!(), "sending request"; "request" => format!("{:?}", req));

    let reply = client
        .get_volume_stats(ctx, &req)
        .map_err(|e| anyhow!(e).context(ERR_API_FAILED))?;

    info!(sl!(), "response received";
        "response" => format!("{:?}", reply));

    Ok(())
}

fn agent_cmd_sandbox_copy_file(
    ctx: &Context,
    client: &AgentServiceClient,
    _health: &HealthClient,
    _image: ImageClient<tonic::transport::Channel>,
    options: &mut Options,
    args: &str,
) -> Result<()> {
    let mut req: CopyFileRequest = utils::make_request(args)?;

    let ctx = clone_context(ctx);

    run_if_auto_values!(ctx, || -> Result<()> {
        let path = utils::get_option("path", options, args)?;
        if !path.is_empty() {
            req.set_path(path);
        }

        let file_size_str = utils::get_option("file_size", options, args)?;

        if !file_size_str.is_empty() {
            let file_size = file_size_str
                .parse::<i64>()
                .map_err(|e| anyhow!(e).context("invalid file_size"))?;

            req.set_file_size(file_size);
        }

        let file_mode_str = utils::get_option("file_mode", options, args)?;

        if !file_mode_str.is_empty() {
            let file_mode = file_mode_str
                .parse::<u32>()
                .map_err(|e| anyhow!(e).context("invalid file_mode"))?;

            req.set_file_mode(file_mode);
        }

        let dir_mode_str = utils::get_option("dir_mode", options, args)?;

        if !dir_mode_str.is_empty() {
            let dir_mode = dir_mode_str
                .parse::<u32>()
                .map_err(|e| anyhow!(e).context("invalid dir_mode"))?;

            req.set_dir_mode(dir_mode);
        }

        let uid_str = utils::get_option("uid", options, args)?;

        if !uid_str.is_empty() {
            let uid = uid_str
                .parse::<i32>()
                .map_err(|e| anyhow!(e).context("invalid uid"))?;

            req.set_uid(uid);
        }

        let gid_str = utils::get_option("gid", options, args)?;

        if !gid_str.is_empty() {
            let gid = gid_str
                .parse::<i32>()
                .map_err(|e| anyhow!(e).context("invalid gid"))?;
            req.set_gid(gid);
        }

        let offset_str = utils::get_option("offset", options, args)?;

        if !offset_str.is_empty() {
            let offset = offset_str
                .parse::<i64>()
                .map_err(|e| anyhow!(e).context("invalid offset"))?;
            req.set_offset(offset);
        }

        let data_str = utils::get_option("data", options, args)?;
        if !data_str.is_empty() {
            let data = utils::str_to_bytes(&data_str)?;
            req.set_data(data.to_vec());
        }

        Ok(())
    });

    debug!(sl!(), "sending request"; "request" => format!("{:?}", req));

    let reply = client
        .copy_file(ctx, &req)
        .map_err(|e| anyhow!("{:?}", e).context(ERR_API_FAILED))?;

    info!(sl!(), "response received";
        "response" => format!("{:?}", reply));

    Ok(())
}

fn agent_cmd_sandbox_reseed_random_dev(
    ctx: &Context,
    client: &AgentServiceClient,
    _health: &HealthClient,
    _image: ImageClient<tonic::transport::Channel>,
    options: &mut Options,
    args: &str,
) -> Result<()> {
    let mut req: ReseedRandomDevRequest = utils::make_request(args)?;

    let ctx = clone_context(ctx);

    run_if_auto_values!(ctx, || -> Result<()> {
        let str_data = utils::get_option("data", options, args)?;
        let data = utils::str_to_bytes(&str_data)?;

        req.set_data(data.to_vec());

        Ok(())
    });

    debug!(sl!(), "sending request"; "request" => format!("{:?}", req));

    let reply = client
        .reseed_random_dev(ctx, &req)
        .map_err(|e| anyhow!("{:?}", e).context(ERR_API_FAILED))?;

    info!(sl!(), "response received";
        "response" => format!("{:?}", reply));

    Ok(())
}

fn agent_cmd_sandbox_online_cpu_mem(
        let nb_cpus_str = utils::get_option("nb_cpus", options, args)?;

        if !nb_cpus_str.is_empty() {
            let nb_cpus = nb_cpus_str
                .parse::<u32>()
                .map_err(|e| anyhow!(e).context("invalid nb_cpus value"))?;

            req.set_nb_cpus(nb_cpus);
        }

        let cpu_only_str = utils::get_option("cpu_only", options, args)?;

        if !cpu_only_str.is_empty() {
            let cpu_only = cpu_only_str
                .parse::<bool>()
                .map_err(|e| anyhow!(e).context("invalid cpu_only bool"))?;

            req.set_cpu_only(cpu_only);
        }

        Ok(())
    });

    debug!(sl!(), "sending request"; "request" => format!("{:?}", req));

    let reply = client
        .online_cpu_mem(ctx, &req)
        .map_err(|e| anyhow!("{:?}", e).context(ERR_API_FAILED))?;

    info!(sl!(), "response received";
        "response" => format!("{:?}", reply));

    Ok(())
}

fn agent_cmd_sandbox_set_guest_date_time(
    ctx: &Context,
    client: &AgentServiceClient,
    _health: &HealthClient,
    _image: ImageClient<tonic::transport::Channel>,
    options: &mut Options,
    args: &str,
) -> Result<()> {
    let mut req: SetGuestDateTimeRequest = utils::make_request(args)?;

    let ctx = clone_context(ctx);

    run_if_auto_values!(ctx, || -> Result<()> {
        let secs_str = utils::get_option("sec", options, args)?;

        if !secs_str.is_empty() {
            let secs = secs_str
                .parse::<i64>()
                .map_err(|e| anyhow!(e).context("invalid seconds"))?;

            req.set_Sec(secs);
        }

        let usecs_str = utils::get_option("usec", options, args)?;

        if !usecs_str.is_empty() {
            let usecs = usecs_str
                .parse::<i64>()
                .map_err(|e| anyhow!(e).context("invalid useconds"))?;

            req.set_Usec(usecs);
        }

        Ok(())
    });

    debug!(sl!(), "sending request"; "request" => format!("{:?}", req));

    let reply = client
        .set_guest_date_time(ctx, &req)
        .map_err(|e| anyhow!("{:?}", e).context(ERR_API_FAILED))?;

    info!(sl!(), "response received";
        "response" => format!("{:?}", reply));

    Ok(())
}

fn agent_cmd_sandbox_set_ip_tables(
    ctx: &Context,
    client: &AgentServiceClient,
    _health: &HealthClient,
    _image: ImageClient<tonic::transport::Channel>,
    _options: &mut Options,
    args: &str,
) -> Result<()> {
    let req: SetIPTablesRequest = utils::make_request(args)?;

    let ctx = clone_context(ctx);

    debug!(sl!(), "sending request"; "request" => format!("{:?}", req));

    let reply = client
        .set_ip_tables(ctx, &req)
        .map_err(|e| anyhow!(e).context(ERR_API_FAILED))?;

    info!(sl!(), "response received";
        "response" => format!("{:?}", reply));

    Ok(())
}

fn agent_cmd_sandbox_update_container(
    ctx: &Context,
    client: &AgentServiceClient,
    _health: &HealthClient,
    _image: ImageClient<tonic::transport::Channel>,
    options: &mut Options,
    args: &str,
) -> Result<()> {
    let mut req: UpdateContainerRequest = utils::make_request(args)?;

    let ctx = clone_context(ctx);

    run_if_auto_values!(ctx, || -> Result<()> {
        let cid = utils::get_option("cid", options, args)?;

        req.set_container_id(cid);

        Ok(())
    });

    // FIXME: Implement fully
    eprintln!("FIXME: 'UpdateContainer' not fully implemented");

    debug!(sl!(), "sending request"; "request" => format!("{:?}", req));

    let reply = client
        .update_container(ctx, &req)
        .map_err(|e| anyhow!("{:?}", e).context(ERR_API_FAILED))?;

    info!(sl!(), "response received";
        "response" => format!("{:?}", reply));

    Ok(())
}

fn agent_cmd_sandbox_mem_hotplug_by_probe(
    ctx: &Context,
    client: &AgentServiceClient,
    _health: &HealthClient,
    _image: ImageClient<tonic::transport::Channel>,
    options: &mut Options,
    args: &str,
) -> Result<()> {
    let mut req: MemHotplugByProbeRequest = utils::make_request(args)?;

    let ctx = clone_context(ctx);

    // Expected to be a comma separated list of hex addresses
    let addr_list = utils::get_option("memHotplugProbeAddr", options, args)?;

    run_if_auto_values!(ctx, || -> Result<()> {
        if !addr_list.is_empty() {
            let addrs: Vec<u64> = addr_list
                // Convert into a list of string values.
                .split(',')
                // Convert each string element into a u8 array of bytes, ignoring
                // those elements that fail the conversion.
                .filter_map(|s| hex::decode(s.trim_start_matches("0x")).ok())
                // "Stretch" the u8 byte slice into one of length 8
                // (to allow each 8 byte chunk to be converted into a u64).
                .map(|mut v| -> Vec<u8> {
                    v.resize(8, 0x0);
                    v
                })
                // Convert the slice of u8 bytes into a u64
                .map(|b| byteorder::LittleEndian::read_u64(&b))
                .collect();

            req.set_memHotplugProbeAddr(addrs);
        }

        Ok(())
    });

    debug!(sl!(), "sending request"; "request" => format!("{:?}", req));

    let reply = client
        .mem_hotplug_by_probe(ctx, &req)
        .map_err(|e| anyhow!("{:?}", e).context(ERR_API_FAILED))?;

    info!(sl!(), "response received";
        "response" => format!("{:?}", reply));

    Ok(())
}
*/

async fn agent_cmd_pull_image(
    ctx: &Context,
    _client: SecAgentServiceClient<tonic::transport::Channel>,
    _health: i32,
    mut image_client: ImageClient<tonic::transport::Channel>,
    options: &mut Options,
    args: &str,
) -> Result<()> {
    let _ctx = clone_context(ctx);

    let image = utils::get_option("image", options, args)?;
    let container_id = utils::get_option("cid", options, args)?;
    let source_creds = utils::get_option("source_creds", options, args)?;

    let req: grpctls::PullImageRequest = PullImageRequest {
        image,
        container_id,
        source_creds,
    };
    // debug!(sl!(), "PullImage"; "request" => format!("{:?}", req));

    let nsend = match utils::get_option("nsend", options, args) {
        Ok(v) => {
            if v.len() == 0 {
               false 
            } else {
                true 
            }
        }
        Err(_) => false,
    };
    debug!(sl!(), "PullImage"; "request" => format!("{:?}", nsend));

    if !nsend {
        let reply = image_client.pull_image(req).await?.into_inner();

        info!(sl!(), "response received";
            "response" => format!("{:?}", reply));
    }
    Ok(())
}

#[inline]
fn builtin_cmd_repeat(_args: &str) -> (Result<()>, bool) {
    // XXX: NOP implementation. Due to the way repeat has to work, providing a
    // handler like this is "too late" to be useful. However, a handler
    // is required as "repeat" is a valid command.
    //
    // A cleaner approach would be to make `AgentCmd.fp` an `Option` which for
    // this command would be specified as `None`, but this is the only command
    // which doesn't need an implementation, so this approach is simpler :)

    (Ok(()), false)
}

fn builtin_cmd_sleep(args: &str) -> (Result<()>, bool) {
    let ns = match utils::human_time_to_ns(args) {
        Ok(t) => t,
        Err(e) => return (Err(e), false),
    };

    sleep(Duration::from_nanos(ns as u64));

    (Ok(()), false)
}

fn builtin_cmd_echo(args: &str) -> (Result<()>, bool) {
    println!("{}", args);

    (Ok(()), false)
}

fn builtin_cmd_quit(_args: &str) -> (Result<()>, bool) {
    (Ok(()), true)
}

fn builtin_cmd_list(_args: &str) -> (Result<()>, bool) {
    let cmds = get_all_cmd_details();

    cmds.iter().for_each(|n| println!(" - {}", n));

    println!();

    (Ok(()), false)
}

#[allow(dead_code)]
fn get_repeat_count(cmdline: &str) -> i64 {
    let default_repeat_count: i64 = 1;

    let fields: Vec<&str> = cmdline.split_whitespace().collect();

    if fields.len() < 2 {
        return default_repeat_count;
    }

    if fields[0] != CMD_REPEAT {
        return default_repeat_count;
    }

    let count = fields[1];

    match count.parse::<i64>() {
        Ok(n) => n,
        Err(_) => default_repeat_count,
    }
}

/*
fn agent_cmd_sandbox_add_swap(
    ctx: &Context,
    client: &AgentServiceClient,
    _health: &HealthClient,
    _image: &ImageClient,
    _options: &mut Options,
    _args: &str,
) -> Result<()> {
    let req = AddSwapRequest::default();

    let ctx = clone_context(ctx);

    debug!(sl!(), "sending request"; "request" => format!("{:?}", req));

    let reply = client
        .add_swap(ctx, &req)
        .map_err(|e| anyhow!("{:?}", e).context(ERR_API_FAILED))?;

    // FIXME: Implement 'AddSwap' fully.
    eprintln!("FIXME: 'AddSwap' not fully implemented");

    info!(sl!(), "response received";
        "response" => format!("{:?}", reply));

    Ok(())
} */
