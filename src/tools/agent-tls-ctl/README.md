# Agent TLS Control tool

## Overview

The Kata Containers agent TLS control tool (`kata-agent-tls-ctl`) is derived from the [`kata-agent-ctl`](../agent-tls-ctl/) tool. This tool communicates over a grpc tls channel with the `kata-agent` that runs inside the virtual machine (VM). Similar to the `kata-agent-ctl` tool, the same warning applies; this tool is for advance users! 

## Build from Source

Since the agent is written in the Rust language this section assumes the tool
chain has been installed using standard Rust`rustup`tool.

### Prerequisites

Because this tool uses generated code from `src/libs/protocols/secprotos/secagent.proto`, set environmental variable to the generated protocol files:

```bash
$ export OUT_DIR=${KATA_DIR}/src/libs/protocols/src/grpctls
```
    
Similar to the `kata-agent-ctl`, this tool requires an OCI bundle, please see `kata-agent-ctl`'s [prerequisites](../agent-ctl/README.md/#prerequisites).

The tool also requires a set of client public and private key pair and the
server's CA public key certificate to establish a TLS connection with the `kata-agent`.  
 - Set TLS environmental key variable, `key_dir`,  e.g., set to $KATA_DIR/src/agent/grpc_tls_keys directory, expecting to find the following files: ca.pem, client.pem, and client.key

### Compile tool

```bash
$ make
```   

## Run the tool

### Connect to a real Kata Container

The method used to connect to Kata Containers agent is TCP/IP. 

#### Retrieve Sandbox VM IP Address 

1. Start a Kata Container and save sandbox ID (pod ID) in `POD_ID`

   ```sh
   $ export POD_ID=<GET_FROM_CRI_RUNTIME>
   ```
2.	Retrieve the sandbox VM’s IP address; use for example `crictl` to get the address of the pod. This may require running `crictl` with `–runtime-point` value (`-r`) for customized installation 

   ```sh
	$ crictl inspectp --output table $POD_ID | grep Address
   # or
	$ crictl -r "unix://${CONTAINERD_SOCK}" inspectp --output table ${POD_ID} | grep Address
  ```

3.	Run the tool to connect the agent and list running containers.  Note the `kata-agent-tls-ctl` listens on port `50090` for grpc tls requests

   ```sh
   $ export guest_port=50090
   $ export guest_addr=< Set from step two >
   $ export ctl=./target/x86_64-unknown-linux-musl/release/kata-agent-tls-ctl

   ${ctl} -l trace connect --no-auto-values  --key-dir "${key_dir}" --bundle-dir "${bundle_dir}" --server-address "ipaddr://${guest_addr}:${guest_port}" -c "ListContainers"
   ```

## Examples

### QEMU examples

The following examples assume you have:
- Installed bundle, and set the `bundle_dir` environmental variable,
- Set TLS keys environmental variable, `key_dir`,  
- Built `kata-agent` with grpc-tls support, 
- Created a pod runs, returning POD ID a1fd4b9e93af1fab760edc706eaa1fad339125efaabcf95846fea1b10ae0ff75.
- Retrieved guest_address, e.g., `10.89.0.28`, and set environmental variables according 
   ```sh
   export guest_addr=10.89.0.28
   export guest_port=50090
   ```


#### Pull image
Pull the image `ghcr.io/ray-valdez/alpine`

```bash
${ctl} -l trace connect --key-dir "${key_dir}" --bundle-dir "${bundle_dir}" --server-address "ipaddr://${guest_addr}:${guest_port}" -c "PullImage cid=${container_id} image="ghcr.io/ray-valdez/alpine”
```

#### Create a container
Specify a uuid as container ID and use the sample OCI config file in the directory, setting the following environment variables:

```bash
# randomly generate container 
export container_id=9e3d1d4750e4e20945d22c358e13c85c6b88922513bce2832c0cf403f065dc6

export OCI_SPEC_CONFIG=${KATA_DIR}/src/tools/agent-tls-ctl/config.json

${ctl} -l trace connect --key-dir "${key_dir}" --bundle-dir "${bundle_dir}" --server-address "ipaddr://${guest_addr}:${guest_port}" -c "CreateContainer cid=${container_id} spec=file:///${OCI_SPEC_CONFIG}"
```

#### Start a container

```bash
${ctl} -l trace connect --no-auto-values --key-dir "${key_dir}" --bundle-dir "${bundle_dir}" --server-address "ipaddr://${guest_addr}:${guest_port}" -c "StartContainer json://{\"container_id\": \"${container_id}\"}"
```

#### List running containers 

```bash
${ctl} -l trace connect --no-auto-values --key-dir "${key_dir}" --bundle-dir "${bundle_dir}" --server-address "ipaddr://${guest_addr}:${guest_port}" -c "ListContainers"
```

#### Pause a container

```bash
${ctl} -l trace connect --no-auto-values --key-dir "${key_dir}" --bundle-dir "${bundle_dir}" --server-address "ipaddr://${guest_addr}:${guest_port}" -c "PauseContainer json://{\"container_id\": \"${container_id}\"}"
```

#### Resume a paused container

```bash
${ctl} -l trace connect --no-auto-values --key-dir "${key_dir}" --bundle-dir "${bundle_dir}" --server-address "ipaddr://${guest_addr}:${guest_port}" -c "ResumeContainer json://{\"container_id\": \"${container_id}\"}"

```
