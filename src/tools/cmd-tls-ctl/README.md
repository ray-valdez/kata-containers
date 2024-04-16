# Command Control tool

## Overview

The Kata Containers command control tool (`cmd-tls-ctl`) is a low-level test
tool. It currently supports two endpoint commands, `pause`, `resume`, and` list_containers`, with
the Kata Containers agent, `kata-agent`, that runs inside the virtual machine (VM).

## Audience and environment

> **Warning:**
>
> This tool is for testing interaction with`kata-agent`over a grpc tls channel.
> It is designed to be run on test and development systems **only**.

## Build from Source

Since the agent is written in the Rust language this section assumes the tool
chain has been installed using standard Rust`rustup`tool.

### Prerequisites

The tool requires a set of client public and private key pair and the
server's CA public key certificate to establish a TLS connection with the `kata-agent`. Link tool with generated TLS keys and certificates:

```bash
$ ln -s ../../agent/grpc_tls_keys .
```

> **Note:**
>
> This step assumes that the TLS keys and certificates have been generated.
>
> To generate the TLS key pairs and certificates, execute the following: 
>```sh 
>$ pushd $KATA_DIR/src/agent/grpc_tls_keys
>$ ./gen_key_cert.sh
>$ popd
>```

### Compile tool

```bash
$ make
```   
        
## Run

The tool currently supports container `pause`, `resume`, and `list_containers` commands. Running the tool requires specifying the IP address of the VM where the `kata-agent` runs and the ID of an executing container.

Use `crictl` to get the address of the Pod:

```sh
$ crictl inspectp --output table $POD_ID | grep Address
```

> **Note:**
>
> Command Usage : 
>
> `cmd-tls-ctl <CLIENT_TLS_KEY_PATH> <pause | resume> $POD_IP  $CONTAINER_ID`    
> `cmd-tls-ctl <CLIENT_TLS_KEY_PATH> list_containers $POD_IP`      
         

### Examples

The following examples assume you have:

- generated TLS keys in `$KATA_DIR/src/agent/grpc_tls_keys` directory, expecting to find the following files: `ca.pem`, `client.pem`, and `client.key`
- built `kata-agent`with grpc-tls support, and
- created a pod runs that a container with ID `a1fd4b9e93af1fab760edc706eaa1fad339125efaabcf95846fea1b10ae0ff75`.

#### Pause a running container 

```bash
$ ./target/x86_64-unknown-linux-musl/release/cmd-tls-ctl ./grpc_tls_keys pause 10.89.0.18 a1fd4b9e93af1fab760edc706eaa1fad339125efaabcf95846fea1b10ae0ff75
 ```
    
#### Resume a paused container 

```bash
$ ./target/x86_64-unknown-linux-musl/release/cmd-tls-ctl ./grpc_tls_keys resume 10.89.0.18 a1fd4b9e93af1fab760edc706eaa1fad339125efaabcf95846fea1b10ae0ff75
```

#### List containers running on the sandbox 
```bash
$ ./target/x86_64-unknown-linux-musl/release/cmd-tls-ctl ./grpc_tls_keys listcontainers 10.89.0.18 
```



