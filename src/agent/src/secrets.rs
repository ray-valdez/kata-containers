// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::env;
use std::io;
use std::path::Path;
use std::result::Result::Ok;

use anyhow::*;
use tokio::fs;

use crate::AGENT_CONFIG;
use anyhow::Result;
/* Sample */
use attestation_agent::AttestationAPIs;
use attestation_agent::AttestationAgent;

/// Attestation Agent's GetResource gRPC address.
/// It's given <https://github.com/confidential-containers/attestation-agent#run>
pub const TLS_KEYS_CONFIG_DIR: &str = "/run/tls-keys";
pub const TLS_KEYS_FILE_PATH: &str = "/run/tls-keys/tls-key.zip";
pub const KBS_RESOURCE_PATH: &str = "/default/tenant-keys/tls-keys.zip";

// Convenience macro to obtain the scope logger
macro_rules! sl {
    () => {
        slog_scope::logger()
    };
}

/// To provision secrets from kbs
pub struct Retriever {
    kbc_name: String,
    kbs_uri: String,
}

impl Retriever {
    /// Create a new retriver, the input parameter:
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

            // attestation agent is running at this point
            Ok(Self {
                kbc_name: kbc_name.into(),
                kbs_uri: kbs_uri.into(),
            })
        } else {
            Err(anyhow!("aa_kbc_params: KBC/KBS pair not found"))
        }
    }

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
                    std::fs::set_permissions(&outpath, std::fs::Permissions::from_mode(mode))
                        .unwrap();
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

        info!(sl!(), "get_tls_key: kbc_name: {}", &self.kbc_name);
        info!(sl!(), "get_tls_key: kbc_uri: {}", &self.kbs_uri);
        info!(
            sl!(),
            "get_tls_key: KBS_RESOURCE_PATH: {}", KBS_RESOURCE_PATH
        );

        // FIXME: Hard-coded sample attester for now!
        let key = "AA_SAMPLE_ATTESTER_TEST";
        env::set_var(key, "yes");
        if env::var(key).is_ok() {
            info!(sl!(), "get_tls_key: AA_SAMPLE_ATTESTER_TEST is set!");
        }
        // obtain the tls keys from KBS through attestation agent
        let mut attestation_agent = AttestationAgent::new();

        let resource_bytes = match attestation_agent
            .download_confidential_resource(
                &self.kbc_name.to_string(),
                KBS_RESOURCE_PATH,
                &self.kbs_uri.to_string(),
            )
            .await
        {
            Ok(data) => data,
            Err(e) => {
                println!("get_tls_key: Error: {:?}", e);
                return Err(e);
            }
        };

        println!("get_tls_key: print keys {:?}", &resource_bytes);
        fs::write(TLS_KEYS_FILE_PATH, resource_bytes).await?;
        self.extract_zip_file()?;

        Ok(())
    }
}

pub async fn retrieve_secrets() -> Result<()> {
    let aa_kbc_params = &AGENT_CONFIG.aa_kbc_params;

    if !aa_kbc_params.is_empty() {
        let resource_config = format!("provider:attestation-agent:{}", aa_kbc_params);
        if let Some(wrapped_aa_kbc_params) = &Some(&resource_config) {
            let wrapped_aa_kbc_params = wrapped_aa_kbc_params.to_string();
            let m_aa_kbc_params =
                wrapped_aa_kbc_params.trim_start_matches("provider:attestation-agent:");

            let mut retriver = Retriever::new(m_aa_kbc_params).await?;
            retriver.get_tls_keys().await?;
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
            && Path::new(TLS_KEYS_CONFIG_DIR).join("ca.pem").exists()
        {
            return true;
        }
    }

    false
}
