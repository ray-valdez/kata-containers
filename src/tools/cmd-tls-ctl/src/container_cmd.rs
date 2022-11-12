use cmd_tls_ctl::{Config, CmdKind};
use std::env;
use std::process;

use tonic;
pub mod grpctls {
    tonic::include_proto!("grpctls");
}

use grpctls::sec_agent_service_client::SecAgentServiceClient;
use grpctls::{SecPauseContainerRequest, SecResumeContainerRequest, SecListContainersRequest};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::new(env::args()).unwrap_or_else(|err| {
        eprintln!("Problem parsing arguments: {}", err);
        process::exit(1);
    });

    println!("address      {}", config.address);
    println!("container_id {}", config.cid);
    let str_front = "http://";
    let str_end = ":50051";

    let url_string = format!("{}{}{}", str_front, config.address, str_end);
    println!("url_string {}", url_string);

    // Get certificate from disk
    let cert = include_str!("../grpc_tls_keys/client.pem");
    let key = include_str!("../grpc_tls_keys/client.key");

    // Create identify from key and certificate
    let id = tonic::transport::Identity::from_pem(cert.as_bytes(), key.as_bytes());

    // Import our certificate for CA
    let s = include_str!("../grpc_tls_keys/ca.pem");

    // Convert it into a certificate
    let ca = tonic::transport::Certificate::from_pem(s.as_bytes());

    // Telling our client what is the identity of our server
    let tls = tonic::transport::ClientTlsConfig::new()
        .domain_name("localhost")
        .identity(id)
        .ca_certificate(ca);

    let channel = tonic::transport::Channel::from_shared(url_string.to_string()).unwrap();
    let channel = channel.tls_config(tls)?.connect().await?;

    // Create gRPC client from channel
    let mut client = SecAgentServiceClient::new(channel);

    match config.cmd {
        CmdKind::LISTCONTAINERS => {
            let request = tonic::Request::new(SecListContainersRequest {
            });
            let response = client.sec_list_containers(request).await?.into_inner();
            println!("RESPONSE={:?}", response);
        }

        CmdKind::PAUSE => {
            let request = tonic::Request::new(SecPauseContainerRequest {
                container_id: config.cid,
            });
            let response = client.sec_pause_container(request).await?.into_inner();
            println!("RESPONSE={:?}", response);
        }

        CmdKind::RESUME => {
            let request = tonic::Request::new(SecResumeContainerRequest {
                container_id: config.cid,
            });
            let response = client.sec_resume_container(request).await?.into_inner();
            println!("RESPONSE={:?}", response);
        }
    }
    Ok(())
}
