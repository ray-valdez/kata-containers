// Copyright (c) 2019 Ant Financial
//
// SPDX-License-Identifier: Apache-2.0
//

use std::fs;
use tokio::sync::Mutex;
use std::sync::Arc;
use anyhow::{anyhow, Result};

use protocols::agent::*; 
use crate::sandbox::Sandbox;
use crate::image_rpc::ImageService;
use rustjail::container::{Container};

use tonic::{
    transport::{
        server::{TcpConnectInfo, TlsConnectInfo},
        Server, ServerTlsConfig,
    },
};
use crate::rpc::rpctls::grpctls::{SecCreateContainerRequest, SecStartContainerRequest, SecRemoveContainerRequest, SecExecProcessRequest, SecPauseContainerRequest, SecResumeContainerRequest, 
    SecSignalProcessRequest, SecWaitProcessRequest, SecWaitProcessResponse, SecListContainersRequest, SecContainerInfoList};

use std::net::SocketAddr;

use super::AgentService;

use crate::aagent::AttestationService;

pub mod grpctls {
    tonic::include_proto!("grpctls");
}

// Convenience macro to obtain the scope logger
macro_rules! sl {
    () => {
        slog_scope::logger()
    };
}

pub const GRPC_TLS_SERVER_PORT: u16 = 50090;

#[tonic::async_trait]
impl grpctls::sec_agent_service_server::SecAgentService for AgentService {

    async fn sec_create_container(
        &self,
        req: tonic::Request<SecCreateContainerRequest>,
    ) -> Result<tonic::Response<()>, tonic::Status> {

        info!(sl!(), "grpctls: sec_create_container, string req: {:#?}", req);
        let mut ttrpc_req: protocols::agent::CreateContainerRequest = CreateContainerRequest::new(); 
        let internal = req.into_inner();
        ttrpc_req.set_container_id(internal.container_id);
        ttrpc_req.set_exec_id(internal.exec_id);
        ttrpc_req.set_sandbox_pidns(internal.sandbox_pidns);

        let oci_obj = internal.oci.unwrap();
        let oci_str = match serde_json::to_string(&oci_obj) {
            Ok(j) => j,
            Err(e) => return Err(tonic::Status::new(
                                tonic::Code::Internal,
                                format!("Unable to serialize{}", e))),
        };
        info!(sl!(), "grpctls: sec_create_container, string oci_str {:?}", oci_str);


        let roci_spec: protocols::oci::Spec = match serde_json::from_str(&oci_str) {
            Ok(k) => k,
            Err(e) => return Err(tonic::Status::new(
                                tonic::Code::Internal,
                                format!("Unable to deserialize{}", e))),
        };

        info!(sl!(), "grpctls: sec_create_container oci_spec, ttrpc oci obj: {:?}", roci_spec);
        ttrpc_req.set_OCI(roci_spec);

        info!(sl!(), "grpctls: sec_create_container, ttrpc_req: {:#?}", ttrpc_req);
        match self.do_create_container(ttrpc_req).await {
            Err(e) => Err(tonic::Status::new(
                                tonic::Code::Internal,
                                format!("{}", e))),
            Ok(_) =>Ok(tonic::Response::new(())),

        }
    }

    async fn sec_exec_process(
        &self,
        req: tonic::Request<SecExecProcessRequest>,
    ) -> Result<tonic::Response<()>, tonic::Status> {

        // TBD: Need to add trace
        // trace_rpc_call!(conn_info, "SecAgent: exec_process", req);
        // is_allowed!(req);
        //
        //

        info!(sl!(), "grpctls: do_exec_process, string req: {:#?}", req);
        let message = req.get_ref();
        let jstr = match serde_json::to_string(message) {
            Ok(j) => j,
            Err(e) => return Err(tonic::Status::new(
                                tonic::Code::Internal,
                                format!("Unable to serialize{}", e))),
        };
        info!(sl!(), "grpctls: sec_exec_process, string req: {}", jstr);

        let ttrpc_req: ExecProcessRequest = match serde_json::from_str(&jstr) {
            Ok(t) => t,
            Err(e) => return Err(tonic::Status::new(
                                tonic::Code::Internal,
                                format!("Unable to deserialize{}", e))),
        };
        info!(sl!(), "grpctls: do_exec_process, string req: {:#?}", ttrpc_req);

        match self.do_exec_process(ttrpc_req).await {
            Err(e) => Err(tonic::Status::new(
                                tonic::Code::Internal,
                                format!("{}", e))),
            Ok(_) =>Ok(tonic::Response::new(()))
        }
    }

    async fn sec_pause_container(
        &self,
        req: tonic::Request<SecPauseContainerRequest>,
    ) -> Result<tonic::Response<()>, tonic::Status> {

        let _conn_info = req
            .extensions()
            .get::<TlsConnectInfo<TcpConnectInfo>>()
            .unwrap();

        // TBD: Need to add trace
        // trace_rpc_call!(conn_info, "SecAgent: pause_container", req);
        // is_allowed!(req);

        let cid = req.into_inner().container_id;
        let s = Arc::clone(&self.sandbox);
        let mut sandbox = s.lock().await;

        let ctr = sandbox.get_container(&cid).ok_or_else(|| {
             tonic::Status::new(
                        tonic::Code::Internal,
                        format!("SA invalid container id"))
        })?;

        ctr.pause()
            .map_err(|e| {
                tonic::Status::new(
                        tonic::Code::Internal,
                        format!("Service was not ready: {:?}", e)
                )})?;

        Ok(tonic::Response::new(()))
    }
    
    async fn sec_remove_container(
        &self,
        req: tonic::Request<SecRemoveContainerRequest>,
    ) -> Result<tonic::Response<()>, tonic::Status> {
        
        // TBD: Need to add trace
        // trace_rpc_call!(conn_info, "SecAgent: remove_container", req);
        // is_allowed!(req);
        let message = req.get_ref();
        let jstr = match serde_json::to_string(message) {
            Ok(j) => j,
            Err(e) => return Err(tonic::Status::new(
                                tonic::Code::Internal,
                                format!("Unable to serialize{}", e))),
        };
        info!(sl!(), "grpctls: do_remove_container, string req: {}", jstr);

        let ttrpc_req: RemoveContainerRequest = match serde_json::from_str(&jstr) {
            Ok(t) => t,
            Err(e) => return Err(tonic::Status::new(
                                tonic::Code::Internal,
                                format!("Unable to deserialize{}", e))),
        };
        info!(sl!(), "grpctls: do_remove_container, string req: {:#?}", ttrpc_req);

        match self.do_remove_container(ttrpc_req).await {
            Err(e) => Err(tonic::Status::new(
                                tonic::Code::Internal,
                                format!("{}", e))),
            Ok(_) =>Ok(tonic::Response::new(())),
        }
    }

    async fn sec_resume_container(
        &self,
        req: tonic::Request<SecResumeContainerRequest>,
    ) -> Result<tonic::Response<()>, tonic::Status> {

        let _conn_info = req
            .extensions()
            .get::<TlsConnectInfo<TcpConnectInfo>>()
            .unwrap();

        // TBD: Need to add trace
        // trace_rpc_call!(conn_info, "SecAgent: pause_container", req);
        // is_allowed!(req);

        let cid = req.into_inner().container_id;
        let s = Arc::clone(&self.sandbox);
        let mut sandbox = s.lock().await;

        let ctr = sandbox.get_container(&cid).ok_or_else(|| {
             tonic::Status::new(
                        tonic::Code::Internal,
                        format!("SA invalid container id"))
        })?;

        ctr.resume()
            .map_err(|e| {
                tonic::Status::new(
                        tonic::Code::Internal,
                        format!("Service was not ready: {:?}", e)
                )})?;

        Ok(tonic::Response::new(()))
    }

    async fn sec_start_container(
        &self,
        req: tonic::Request<SecStartContainerRequest>,
    ) -> Result<tonic::Response<()>, tonic::Status> {

        let message = req.get_ref();
        let jstr = match serde_json::to_string(message) {
            Ok(j) => j,
            Err(e) => return Err(tonic::Status::new(
                                tonic::Code::Internal,
                                format!("Unable to serialize{}", e))),
        };
        info!(sl!(), "grpctls: do_start_container, string req: {}", jstr);

        let ttrpc_req: StartContainerRequest = match serde_json::from_str(&jstr) {
            Ok(t) => t,
            Err(e) => return Err(tonic::Status::new(
                                tonic::Code::Internal,
                                format!("Unable to deserialize{}", e))),
        };
        info!(sl!(), "grpctls: do_start_container, string req: {:?}", ttrpc_req);

        match self.do_start_container(ttrpc_req).await {
            Err(e) => Err(tonic::Status::new(
                                tonic::Code::Internal,
                                format!("{}", e))),
            Ok(_) =>Ok(tonic::Response::new(())),

        }
    }

    async fn sec_list_containers(
        &self,
        _req: tonic::Request<SecListContainersRequest>,
    ) -> Result<tonic::Response<SecContainerInfoList>, tonic::Status> {

        let s = Arc::clone(&self.sandbox);
        let sandbox = s.lock().await;
        let list = sandbox.list_containers()
            .map_err(|e| {
                tonic::Status::new(
                        tonic::Code::Internal,
                        format!("List Contianer Service was not ready: {:?}", e)
                )})?;

        Ok(tonic::Response:: new(SecContainerInfoList{
            sec_container_info_list: list.clone(),
        }))

    }

    async fn sec_signal_process(
        &self,
        req: tonic::Request<SecSignalProcessRequest>,
    ) -> Result<tonic::Response<()>, tonic::Status> {

        info!(sl!(), "grpctls: sec_signal_process, string req: {:?}", req);
        let mut ttrpc_req: protocols::agent::SignalProcessRequest = SignalProcessRequest::new(); 
        let internal = req.into_inner();
        ttrpc_req.set_container_id(internal.container_id);
        ttrpc_req.set_exec_id(internal.exec_id);
        ttrpc_req.set_signal(internal.signal);
        
        match self.do_signal_process(ttrpc_req).await {
            Err(e) => Err(tonic::Status::new(
                                tonic::Code::Internal,
                                format!("{}", e))),
            Ok(_) =>Ok(tonic::Response::new(())),

        }
    }

    async fn sec_wait_process(
        &self,
        req: tonic::Request<SecWaitProcessRequest>,
    ) -> Result<tonic::Response<SecWaitProcessResponse>, tonic::Status> {

        info!(sl!(), "grpctls: sec_wait_process, string req: {:?}", req);
        let internal = req.into_inner();
        let mut ttrpc_req: protocols::agent::WaitProcessRequest = WaitProcessRequest::new(); 
        ttrpc_req.set_container_id(internal.container_id);
        ttrpc_req.set_exec_id(internal.exec_id);

        let response = self.do_wait_process(ttrpc_req)
            .await
            .map_err(|e| {
                tonic::Status::new(
                        tonic::Code::Internal,
                        format!("{:?}", e)
                )})?;
        let status = response.get_status();
        Ok(tonic::Response:: new(SecWaitProcessResponse{status,
        }))
    }

}

fn from_file(file_path: &str) -> Result<String> {
    let file_content = fs::read_to_string(file_path)
        .map_err(|e| anyhow!("Read {:?} file failed: {:?}", file_path, e))?;

    Ok(file_content)
}

pub fn grpcstart(s: Arc<Mutex<Sandbox>>, server_address: &str, 
    aa_service: Arc<Mutex<AttestationService>>) -> Result<impl futures::Future<Output = Result<(), tonic::transport::Error>>> {

    let sec_agent = AgentService { sandbox: s.clone() };
    let sec_svc =  grpctls::sec_agent_service_server::SecAgentServiceServer::new(sec_agent);    

    let image_service = ImageService::new(s, aa_service);
    let iservice = grpctls::image_server::ImageServer::new(image_service);

    let addr = SocketAddr::from(([0, 0, 0, 0], GRPC_TLS_SERVER_PORT));

    // Config TLS
    let cert = from_file("/run/tls-keys/server.pem")?;
    let key = from_file("/run/tls-keys/server.key")?;

    // create identity from cert and key
    let id = tonic::transport::Identity::from_pem(cert.as_bytes(), key.as_bytes());

    // Reading ca root from disk
    let pem = from_file("/run/tls-keys/ca.pem")?;

    // Create certificate
    let ca = tonic::transport::Certificate::from_pem(pem.as_bytes());

    // Create tls config
    let tls = ServerTlsConfig::new()
        .identity(id)
        .client_ca_root(ca);

    //let grpc_tls: impl tonic::transport::Server = Server::builder()
    let grpc_tls = Server::builder()
        .tls_config(tls)?
        .add_service(sec_svc)
        .add_service(iservice)
        .serve(addr);

    info!(sl!(), "gRPC TLS server started"; "address" => server_address);
    Ok(grpc_tls)
}
