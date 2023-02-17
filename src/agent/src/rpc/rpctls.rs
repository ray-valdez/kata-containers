// Copyright (c) 2019 Ant Financial
//
// SPDX-License-Identifier: Apache-2.0
//

use tokio::sync::Mutex;
use std::sync::Arc;
use anyhow::{Result};
//use protocols::image;

use protocols::agent::{ 
    CreateContainerRequest, ExecProcessRequest, RemoveContainerRequest, StartContainerRequest
};

use crate::sandbox::Sandbox;
use crate::image_rpc;
use crate::image_rpc::ImageService;
use rustjail::container::{Container};

use tonic::{
    transport::{
        server::{TcpConnectInfo, TlsConnectInfo},
        Server, ServerTlsConfig,
    },
};
use crate::rpc::rpctls::grpctls::{SecCreateContainerRequest, SecStartContainerRequest, SecRemoveContainerRequest, SecExecProcessRequest, SecPauseContainerRequest, SecResumeContainerRequest, SecListContainersRequest, SecContainerInfoList, EmptyResponse};

use crate::rpc::rpctls::grpctls::{PullImageRequest, PullImageResponse};
//use grpctls::image_server::Image;

use std::net::SocketAddr;

use super::AgentService;

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
    ) -> Result<tonic::Response<EmptyResponse>, tonic::Status> {

        let message = req.get_ref();
        let jstr = match serde_json::to_string(message) {
            Ok(j) => j,
            Err(e) => return Err(tonic::Status::new(
                                tonic::Code::Internal,
                                format!("Unable to serialize{}", e))),
        };
        info!(sl!(), "grpctls: do_create_container, string req: {}", jstr);

        let ttrpc_req: CreateContainerRequest = match serde_json::from_str(&jstr) {
            Ok(t) => t,
            Err(e) => return Err(tonic::Status::new(
                                tonic::Code::Internal,
                                format!("Unable to deserialize{}", e))),
        };
        info!(sl!(), "grpctls: do_create_container, string req: {:#?}", ttrpc_req);

        match self.do_create_container(ttrpc_req).await {
            Err(e) => Err(tonic::Status::new(
                                tonic::Code::Internal,
                                format!("{}", e))),
            Ok(_) =>Ok(tonic::Response::new(EmptyResponse{})),

        }
        
    }

    async fn sec_exec_process(
        &self,
        req: tonic::Request<SecExecProcessRequest>,
    ) -> Result<tonic::Response<EmptyResponse>, tonic::Status> {

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
            Ok(_) =>Ok(tonic::Response::new(EmptyResponse{})),
        }
    }

    async fn sec_pause_container(
        &self,
        req: tonic::Request<SecPauseContainerRequest>,
    ) -> Result<tonic::Response<EmptyResponse>, tonic::Status> {

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

        Ok(tonic::Response::new(EmptyResponse{}))
    }
    
    async fn sec_remove_container(
        &self,
        req: tonic::Request<SecRemoveContainerRequest>,
    ) -> Result<tonic::Response<EmptyResponse>, tonic::Status> {
        
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
            Ok(_) =>Ok(tonic::Response::new(EmptyResponse{})),
        }
    }

    async fn sec_resume_container(
        &self,
        req: tonic::Request<SecResumeContainerRequest>,
    ) -> Result<tonic::Response<EmptyResponse>, tonic::Status> {

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

        Ok(tonic::Response::new(EmptyResponse{}))
    }

    async fn sec_start_container(
        &self,
        req: tonic::Request<SecStartContainerRequest>,
    ) -> Result<tonic::Response<EmptyResponse>, tonic::Status> {

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
        info!(sl!(), "grpctls: do_remove_container, string req: {:#?}", ttrpc_req);

        match self.do_start_container(ttrpc_req).await {
            Err(e) => Err(tonic::Status::new(
                                tonic::Code::Internal,
                                format!("{}", e))),
            Ok(_) =>Ok(tonic::Response::new(EmptyResponse{})),

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
}

#[tonic::async_trait]
impl grpctls::image_server::Image for ImageService {
    async fn pull_image(
        &self,
        _req: tonic::Request<PullImageRequest>,
    ) -> Result<tonic::Response<PullImageResponse>, tonic::Status> {

         Err(tonic::Status::new(
            tonic::Code::Internal,
           format!("Not implemented: pull image !")))
    }
}

pub fn grpcstart(s: Arc<Mutex<Sandbox>>,server_address: &str) -> Result<impl futures::Future<Output = Result<(), tonic::transport::Error>>> {

    let sec_agent = AgentService { sandbox: s.clone() };
    let sec_svc =  grpctls::sec_agent_service_server::SecAgentServiceServer::new(sec_agent);

    let image_service = image_rpc::ImageService::new(s);

    //let iservice = <dyn grpctls::image_server::Image>::new(image_service);
    //let iservice = grpctls::image_server::ImageServer::<image_rpc::ImageService>::new(image_service);
    let iservice = grpctls::image_server::ImageServer::new(image_service);
    
    //let addr: SocketAddr = "0.0.0.0:50051".parse().unwrap();
    //let addr: SocketAddr = "0.0.0.0:50051".parse().unwrap();
    //
    let addr = SocketAddr::from(([0, 0, 0, 0], GRPC_TLS_SERVER_PORT));
    // Config TLS
    let cert = include_str!("../../grpc_tls_keys/server.pem");
    let key = include_str!("../../grpc_tls_keys/server.key");

    // create identity from cert and key
    let id = tonic::transport::Identity::from_pem(cert.as_bytes(), key.as_bytes());

    // Reading ca root from disk
    let pem = include_str!("../../grpc_tls_keys/ca.pem");

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
