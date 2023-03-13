// Copyright (c) 2021 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::fs;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::io::Write;

use anyhow::Result;
use crate::AGENT_CONFIG;

const AA_PATH: &str = "/usr/local/bin/attestation-agent";
const AA_KEYPROVIDER_PORT: &str = "127.0.0.1:50000";
const AA_GETRESOURCE_PORT: &str = "127.0.0.1:50001";
const OCICRYPT_CONFIG_PATH: &str = "/tmp/ocicrypt_config.json";

// Convenience macro to obtain the scope logger
macro_rules! sl {
    () => {
        slog_scope::logger()
    };
}

pub struct AttestationService {
    pub attestation_agent_started: AtomicBool
}

impl AttestationService {
    pub fn new() -> Self {
        Self {
            attestation_agent_started: AtomicBool::new(false)
        }
    }

    // If we fail to start the AA, Skopeo/ocicrypt won't be able to unwrap keys
    // and container decryption will fail.
    fn init_attestation_agent() -> Result<()> {
        println!("salman: inside init attestation agent");
        let config_path = OCICRYPT_CONFIG_PATH;

        // The image will need to be encrypted using a keyprovider
        // that has the same name (at least according to the config).
        let ocicrypt_config = serde_json::json!({
            "key-providers": {
                "attestation-agent":{
                    "grpc":AA_KEYPROVIDER_PORT
                }
            }
        });

        let mut config_file = fs::File::create(config_path)?;
        config_file.write_all(ocicrypt_config.to_string().as_bytes())?;

        // The Attestation Agent will run for the duration of the guest.
        Command::new(AA_PATH)
            .arg("--keyprovider_sock")
            .arg(AA_KEYPROVIDER_PORT)
            .arg("--getresource_sock")
            .arg(AA_GETRESOURCE_PORT)
            .spawn()?;
        Ok(())
    }

    pub async fn start_attestation_agent(&self) -> Result<()> {
        let aa_kbc_params = &AGENT_CONFIG.read().await.aa_kbc_params;
        if !aa_kbc_params.is_empty() {
            match self.attestation_agent_started.compare_exchange_weak(
                false,
                true,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => Self::init_attestation_agent()?,
                Err(_) => info!(sl!(), "Attestation Agent already running"),
            }
        }
        Ok(())
    }
}