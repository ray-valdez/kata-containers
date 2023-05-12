// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::{collections::HashMap, path::Path};
use std::{thread, time};
use std::io;

use anyhow::*;
use serde::{Deserialize, Serialize};
use tokio::fs;
use tonic::transport::Channel;

use crate::AGENT_CONFIG;

use self::get_resource::{
    get_resource_service_client::GetResourceServiceClient, GetResourceRequest,
};

mod get_resource {
    #![allow(unknown_lints)]
    #![allow(clippy::derive_partial_eq_without_eq)]
    tonic::include_proto!("getresource");
}
use std::result::Result::Ok;


/// Attestation Agent's GetResource gRPC address.
/// It's given <https://github.com/confidential-containers/attestation-agent#run>
// pub const AA_GETRESOURCE_ADDR: &str = "http://127.0.0.1:50001";
const AA_GETRESOURCE_URI: &str =
    "unix:///run/confidential-containers/attestation-agent/getresource.sock";

pub const TLS_KEYS_CONFIG_DIR: &str = "/run/tls-keys";
pub const TLS_KEYS_FILE_PATH: &str = "/run/tls-keys/tls_key.zip";
pub const KBS_RESOURCE_PATH: &str = "/default/tenant-keys/tls_keys.zip";

macro_rules! sl {
    () => {
        slog_scope::logger()
    };
}

/// Signature submodule agent for image signature veriication.
#[allow(dead_code)]
pub struct Agent {
    /// Get Resource Service client.
    client: GetResourceServiceClient<Channel>,
    kbc_name: String,
    kbc_uri: String,
}

/// The resource description that will be passed to AA when get resource.
#[derive(Serialize, Deserialize, Debug)]
struct ResourceDescription {
    name: String,
    optional: HashMap<String, String>,
}

impl ResourceDescription {
    /// Create a new ResourceDescription with resource name.
    pub fn new(name: &str) -> Self {
        ResourceDescription {
            name: name.to_string(),
            optional: HashMap::new(),
        }
    }
}

impl Agent {
    /// Create a new signature-agent, the input parameter:
    /// * `aa_kbc_params`: s string with format `<kbc_name>::<kbs_uri>`.
    pub async fn new(aa_kbc_params: &str) -> Result<Self> {
        // unzip here is unstable
        if let Some((kbc_name, kbs_uri)) = aa_kbc_params.split_once("::") {
            if kbc_name.is_empty() {
                return Err(anyhow!("aa_kbc_params: missing KBC name"));
            }

            if kbs_uri.is_empty() {
                return Err(anyhow!("aa_kbc_params: missing KBS URI"));
            }

            let mut attestation_conn = GetResourceServiceClient::connect(AA_GETRESOURCE_URI).await;

            let one_second = time::Duration::from_millis(1000);

            // wait here until the attestation agent is not ready and running
            while !attestation_conn.is_ok() {
                attestation_conn = GetResourceServiceClient::connect(AA_GETRESOURCE_URI).await;
                //println!("Attestation agent is not ready, waiting for it...");
                thread::sleep(one_second);
            }

            // attestation agent is running at this point
            Ok(Self {
                client: attestation_conn.unwrap(),
                kbc_name: kbc_name.into(),
                kbc_uri: kbs_uri.into(),
            })
        } else {
            Err(anyhow!("aa_kbc_params: KBC/KBS pair not found"))
        }
    }

    /// Get resource from using, using `resource_name` as `name` in a ResourceDescription.
    /// Please refer to https://github.com/confidential-containers/image-rs/blob/main/docs/ccv1_image_security_design.md#get-resource-service
    /// for more information.
    /// Then save the gathered data into `path`
    async fn get_resource(&mut self, resource_name: &str, path: &str) -> Result<()> {

        let resource_description = serde_json::to_string(&ResourceDescription::new(resource_name))?;

        let req = tonic::Request::new(GetResourceRequest {
            kbc_name: self.kbc_name.clone(),
            kbs_uri: self.kbc_uri.clone(),
            resource_description,
        });

        // request sent to attestation agent
        //
        // let res  = match self.client.get_resource(&self.kbc_name, &resource_name, &self.kbs_uri)

        info!(sl!(), "RV get_res kbc_name: {}", &self.kbc_name);
        let res = match self.client.get_resource(req)
         .await {
            Ok(data) => data,
            Err(e) => { println!("Error: {:?}", e);
                        // return Err(e)
                        return Err(anyhow!("Wrong")).context("From a useless function")
                      }
        };


        // response received from attestation agent, and storing 
        // the resonse in the tls config directory as a zipped file
        fs::write(path, res.into_inner().resource).await?;

        Ok(())
    }

    // the source code of this function is obtained from 
    // the example file of zip crate
    pub fn extract_zip_file(&mut self) -> Result<()> {

        let fname = std::path::Path::new(TLS_KEYS_FILE_PATH);
        let outdir = std::path::Path::new(TLS_KEYS_CONFIG_DIR);
        let file = std::fs::File::open(fname).unwrap();

        let mut archive = zip::ZipArchive::new(file).unwrap();

        for i in 0..archive.len() {
            let mut file = archive.by_index(i).unwrap();
            let outpath = match file.enclosed_name() {
                Some(path) => outdir.join(path).to_owned(),
                None => continue,
            };

            if (*file.name()).ends_with('/') {
                std::fs::create_dir_all(&outpath).unwrap();
            } else {
                if let Some(p) = outpath.parent() {
                    if !p.exists() {
                        std::fs::create_dir_all(p).unwrap();
                    }
                }
                let mut outfile = std::fs::File::create(&outpath).unwrap();
                io::copy(&mut file, &mut outfile).unwrap();
            }

            // Get and Set permissions
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;

                if let Some(mode) = file.unix_mode() {
                    std::fs::set_permissions(&outpath, std::fs::Permissions::from_mode(mode)).unwrap();
                }
            }
        }

        Ok(())

    }

    pub async fn get_tls_keys(&mut self) -> Result<()> {
        if !Path::new(TLS_KEYS_CONFIG_DIR).exists() {
            fs::create_dir_all(TLS_KEYS_CONFIG_DIR)
                .await
                .map_err(|e| anyhow!("Create tls keys runtime config dir failed: {:?}", e))?;
        }

        // obtain the tls keys from KBS through attestation agent
        //self.get_resource("Secrets", TLS_KEYS_FILE_PATH).await?;
        self.get_resource(KBS_RESOURCE_PATH, TLS_KEYS_FILE_PATH).await?;

        // zip the tls zipped file: /run/tls-keys/tls_key.zip
        // and storing the extracted files in /run/tls-keys
        self.extract_zip_file()?;

        Ok(())
    }
}

pub async fn retrieve_secrets() -> Result<()> {
    let aa_kbc_params = &AGENT_CONFIG.read().await.aa_kbc_params;
    if !aa_kbc_params.is_empty() {
        let resource_config = format!("provider:attestation-agent:{}", aa_kbc_params);
        if let Some(wrapped_aa_kbc_params) = &Some(&resource_config) {
            let wrapped_aa_kbc_params = wrapped_aa_kbc_params.to_string();
            let m_aa_kbc_params = wrapped_aa_kbc_params.trim_start_matches("provider:attestation-agent:");

            let mut m_agent = Agent::new(m_aa_kbc_params).await?;
            m_agent.get_tls_keys().await?;
        }
    }
    Ok(())
}

pub fn tls_keys_exist() -> bool {
    // check if the directory of tls keys exists
    if Path::new(TLS_KEYS_CONFIG_DIR).exists() {
        // check if all the necessary tls keys are downloaded and extracted
        if Path::new(TLS_KEYS_CONFIG_DIR).join("server.key").exists() 
            && Path::new(TLS_KEYS_CONFIG_DIR).join("server.pem").exists() 
            && Path::new(TLS_KEYS_CONFIG_DIR).join("ca.pem").exists() {
            
            return true;
        }
    }

    return false;
}
