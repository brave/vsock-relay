/* Copyright (c) 2023 The Brave Authors. All rights reserved.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at https://mozilla.org/MPL/2.0/. */

use std::{io, sync::Arc};

use agnostic::{shutdown_enclave_stream, EnclaveAddr, EnclaveStream, DEFAULT_DEST_ADDR};
use anyhow::{Context, Result};
use bytes::BytesMut;
use clap::{command, Parser};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Semaphore,
    task::JoinSet,
};
use tracing::{debug, error, info, metadata::LevelFilter};
use tracing_subscriber::EnvFilter;

use crate::agnostic::{connect_to_enclave, listen_on_port, parse_enclave_addr};

#[cfg(not(feature = "mock-vsock"))]
mod agnostic {
    use std::net::Shutdown;

    use anyhow::{anyhow, Result};
    use tokio_vsock::{VsockAddr, VsockListener, VsockStream, VMADDR_CID_ANY};

    pub type EnclaveStream = VsockStream;
    pub type EnclaveAddr = VsockAddr;
    pub type EnclaveListener = VsockListener;

    pub const DEFAULT_DEST_ADDR: &str = "4:8443";

    pub fn parse_enclave_addr(address: &str) -> Result<EnclaveAddr> {
        let mut address_split = address.split(':');
        let cid = address_split
            .next()
            .ok_or(anyhow!("missing cid from vsock addr: {address}"))?
            .parse()?;
        let port = address_split
            .next()
            .ok_or(anyhow!("missing port from vsock addr: {address}"))?
            .parse()?;
        Ok(VsockAddr::new(cid, port))
    }

    pub async fn connect_to_enclave(address: EnclaveAddr) -> Result<EnclaveStream> {
        Ok(VsockStream::connect(address).await?)
    }

    pub async fn shutdown_enclave_stream(stream: &mut EnclaveStream) {
        stream.shutdown(Shutdown::Both).ok();
    }

    pub async fn listen_on_port(port: u16) -> Result<EnclaveListener> {
        Ok(VsockListener::bind(VsockAddr::new(
            VMADDR_CID_ANY,
            port as u32,
        ))?)
    }
}

#[cfg(feature = "mock-vsock")]
mod agnostic {
    use std::{net::SocketAddr, str::FromStr};

    use anyhow::{Context, Result};
    use tokio::{
        io::AsyncWriteExt,
        net::{TcpListener, TcpStream},
    };

    pub type EnclaveStream = TcpStream;
    pub type EnclaveAddr = SocketAddr;
    pub type EnclaveListener = TcpListener;

    pub const DEFAULT_DEST_ADDR: &str = "127.0.0.1:9443";

    pub fn parse_enclave_addr(address: &str) -> Result<EnclaveAddr> {
        Ok(SocketAddr::from_str(address).context("error parsing destination address")?)
    }

    pub async fn connect_to_enclave(address: EnclaveAddr) -> Result<EnclaveStream> {
        Ok(TcpStream::connect(address).await?)
    }

    pub async fn shutdown_enclave_stream(stream: &mut EnclaveStream) {
        stream.shutdown().await.ok();
    }

    pub async fn listen_on_port(port: u16) -> Result<EnclaveListener> {
        Ok(TcpListener::bind(("0.0.0.0", port)).await?)
    }
}

/// Relays TCP connections from IPV4/IPV6 to VSOCK.
#[derive(Clone, Parser, Debug)]
#[command(version)]
struct Cli {
    /// Buffer size to use when reading/writing data between peers
    #[arg(long, default_value_t = 8192)]
    buffer_size: usize,

    /// IPV4/IPV6 addresses/ports to listen on (comma separated)
    #[arg(
        short = 's',
        long,
        default_value = "0.0.0.0:8443",
        value_delimiter = ','
    )]
    source_addresses: Vec<String>,

    /// VSOCK addresses/ports to connect to (comma separated)
    #[arg(short = 'd', long, default_value = DEFAULT_DEST_ADDR, value_delimiter=',')]
    destination_addresses: Vec<String>,

    /// Maximum amount of allowed concurrent connections
    #[arg(short = 'c', long, default_value_t = 1250)]
    max_concurrent_connections: usize,

    /// Use port & enable the host IP provider server, so the
    /// enclave can detect the IP of the host
    #[arg(long)]
    host_ip_provider_port: Option<u16>,
}

struct RelayTask {
    src_conn: TcpStream,
    dest_conn: EnclaveStream,
    src_rx_bytes: BytesMut,
    dest_rx_bytes: BytesMut,
}

impl RelayTask {
    pub async fn new(
        src_conn: TcpStream,
        dest_addr: EnclaveAddr,
        buffer_size: usize,
    ) -> Result<Self> {
        let dest_conn = connect_to_enclave(dest_addr).await?;

        Ok(Self {
            src_conn,
            dest_conn,
            src_rx_bytes: BytesMut::with_capacity(buffer_size),
            dest_rx_bytes: BytesMut::with_capacity(buffer_size),
        })
    }

    async fn shutdown(&mut self) {
        self.src_conn.shutdown().await.ok();
        shutdown_enclave_stream(&mut self.dest_conn).await;
    }

    async fn handle_rx_result(&mut self, rx_result: io::Result<usize>) -> Result<bool> {
        match rx_result {
            Ok(bytes_read) => {
                // If bytes_read == 0, assume connection has terminated
                if bytes_read == 0 {
                    self.shutdown().await;
                    return Ok(false);
                }
            }
            Err(e) => {
                self.shutdown().await;
                return Err(e.into());
            }
        }
        Ok(true)
    }

    async fn handle_dest_conn_rx(&mut self, rx_result: io::Result<usize>) -> Result<bool> {
        if !self.handle_rx_result(rx_result).await? {
            debug!("recv empty buf from dest connection, quitting comm");
            return Ok(false);
        }
        self.src_conn.write_buf(&mut self.dest_rx_bytes).await?;
        Ok(true)
    }

    async fn handle_src_conn_rx(&mut self, rx_result: io::Result<usize>) -> Result<bool> {
        if !self.handle_rx_result(rx_result).await? {
            debug!("recv empty buf from src connection, quitting comm");
            return Ok(false);
        }
        self.dest_conn.write_buf(&mut self.src_rx_bytes).await?;
        Ok(true)
    }

    pub async fn run(mut self) -> Result<()> {
        let mut should_continue = true;
        while should_continue {
            should_continue = tokio::select! {
                result = self.src_conn.read_buf(&mut self.src_rx_bytes) => self.handle_src_conn_rx(result).await,
                result = self.dest_conn.read_buf(&mut self.dest_rx_bytes) => self.handle_dest_conn_rx(result).await,
            }?;
        }
        Ok(())
    }
}

async fn handle_host_ip_provider_conn(
    mut stream: EnclaveStream,
    host_ip_address: &str,
) -> Result<()> {
    stream.write_all(host_ip_address.as_bytes()).await?;
    stream.flush().await?;
    Ok(())
}

async fn host_ip_provider_server(port: u16) -> Result<()> {
    let host_ip_address = local_ip_address::local_ip()?.to_string();

    let mut listener = listen_on_port(port).await?;
    info!("Host IP provider listening on port {}", port);

    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                if let Err(e) = handle_host_ip_provider_conn(stream, &host_ip_address).await {
                    error!("error handling host ip request: {e}");
                }
            }
            Err(e) => {
                error!("error accepting host ip connection: {e}");
            }
        }
    }
}

async fn listen_and_serve(
    source_address: String,
    destination_address: String,
    args: Cli,
) -> Result<()> {
    let host_listener = TcpListener::bind(&source_address)
        .await
        .context("failed to start source listener")?;
    let conn_count_semaphore = Arc::new(Semaphore::new(args.max_concurrent_connections));
    let destination_address = parse_enclave_addr(&destination_address)?;
    info!("Listening on tcp {}...", source_address);

    // Use semaphore to limit active connection count
    while let Ok(semaphore_permit) = conn_count_semaphore.clone().acquire_owned().await {
        match host_listener.accept().await {
            Ok((tcp_stream, _)) => {
                let buf_size = args.buffer_size;

                // Spawn new task to handle connection, task will now own semaphore
                // for the duration of the connection.
                tokio::spawn(async move {
                    let result = async {
                        let task =
                            RelayTask::new(tcp_stream, destination_address, buf_size).await?;
                        task.run().await
                    };
                    if let Err(e) = result.await {
                        error!("relay task failed: {e}");
                    }
                    drop(semaphore_permit);
                });
            }
            Err(e) => error!("failed to accept connection: {e}"),
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Cli::parse();

    assert_eq!(
        args.source_addresses.len(),
        args.destination_addresses.len(),
        "amount of source and destination addresses must match"
    );

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env()
                .expect("should create tracing subscriber env filter"),
        )
        .init();

    if let Some(port) = args.host_ip_provider_port {
        tokio::spawn(async move {
            if let Err(e) = host_ip_provider_server(port).await {
                error!("host ip provider server error: {e}");
            }
        });
    }

    let mut join_set = args
        .source_addresses
        .clone()
        .into_iter()
        .zip(args.destination_addresses.clone().into_iter())
        .map(|(source_address, destination_address)| {
            let args = args.clone();
            tokio::spawn(async move {
                listen_and_serve(
                    source_address.to_string(),
                    destination_address.to_string(),
                    args,
                )
                .await
            })
        })
        .collect::<JoinSet<_>>();
    join_set.join_next().await.unwrap().unwrap().unwrap()
}
