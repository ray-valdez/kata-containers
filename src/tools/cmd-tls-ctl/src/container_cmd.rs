use cmd_tls_ctl::{Config, CmdKind};
use std::env;
use std::process;
use std::path::{PathBuf};
//use serde_json::json;

use tonic;
pub mod grpctls {
    tonic::include_proto!("grpctls");
}

pub mod types {
    tonic::include_proto!("types");
}


use grpctls::sec_agent_service_client::SecAgentServiceClient;
use grpctls::{PauseContainerRequest, ResumeContainerRequest, ListContainersRequest};

const SERVER_PORT: u16 = 50090; 

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::new(env::args()).unwrap_or_else(|err| {
        eprintln!("{}", err);
        process::exit(1);
    });

    let str_front = "http://";
    let str_end = SERVER_PORT.to_string();

    let url_string = format!("{}{}{}{}", str_front, config.address, ":", str_end);

    let mut client_cert = PathBuf::from(&config.key_path);
    let mut client_key = PathBuf::from(&config.key_path);
    let mut ca_cert = PathBuf::from(&config.key_path);
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

    // Tell our client what is the identity of our server
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
            let request = tonic::Request::new(ListContainersRequest {
            });
            let response = client.list_containers(request).await?.into_inner();
            //println!("RESPONSE={:?}", response);
            println!("{}", serde_json::to_string_pretty(&response).unwrap())
        }

        CmdKind::PAUSE => {
            let request = tonic::Request::new(PauseContainerRequest {
                container_id: config.cid,
            });
            let response = client.pause_container(request).await?.into_inner();
            println!("RESPONSE={:?}", response);
        }

        CmdKind::RESUME => {
            let request = tonic::Request::new(ResumeContainerRequest {
                container_id: config.cid,
            });
            let response = client.resume_container(request).await?.into_inner();
            println!("RESPONSE={:?}", response);
        }
    }
    Ok(())
}
