/* Copyright (c) 2023 The Brave Authors. All rights reserved.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at https://mozilla.org/MPL/2.0/. */

use std::{io, sync::Arc};

use agnostic::{shutdown_enclave_stream, EnclaveStream, DEFAULT_DEST_ADDR};
use anyhow::{Context, Result};
use bytes::BytesMut;
use clap::{command, Parser};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Semaphore,
};
use tracing::{debug, error, info, metadata::LevelFilter};
use tracing_subscriber::EnvFilter;

use crate::agnostic::connect_to_enclave;

#[cfg(not(feature = "mock-vsock"))]
mod agnostic {
    use std::net::Shutdown;

    use anyhow::{anyhow, Result};
    use tokio_vsock::{VsockAddr, VsockStream};

    pub type EnclaveStream = VsockStream;

    pub const DEFAULT_DEST_ADDR: &str = "4:8443";

    pub fn parse_vsock_addr(address: &str) -> Result<VsockAddr> {
        let mut address_split = address.split(":");
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

    pub async fn connect_to_enclave(address: &str) -> Result<EnclaveStream> {
        let addr = parse_vsock_addr(address)?;
        Ok(VsockStream::connect(addr.cid(), addr.port()).await?)
    }

    pub async fn shutdown_enclave_stream(stream: &mut EnclaveStream) {
        stream.shutdown(Shutdown::Both).ok();
    }
}

#[cfg(feature = "mock-vsock")]
mod agnostic {
    use anyhow::Result;
    use tokio::{io::AsyncWriteExt, net::TcpStream};

    pub type EnclaveStream = TcpStream;

    pub const DEFAULT_DEST_ADDR: &str = "127.0.0.1:9443";

    pub async fn connect_to_enclave(address: &str) -> Result<EnclaveStream> {
        Ok(TcpStream::connect(address).await?)
    }

    pub async fn shutdown_enclave_stream(stream: &mut EnclaveStream) {
        stream.shutdown().await.ok();
    }
}

/// Relays TCP connections from IPV4/IPV6 to VSOCK.
#[derive(Parser, Debug)]
#[command(version)]
struct Cli {
    /// Buffer size to use when reading/writing data between peers
    #[arg(long, default_value_t = 8192)]
    buffer_size: usize,

    /// IPV4/IPV6 address/port to listen on
    #[arg(short = 's', long, default_value = "0.0.0.0:8443")]
    source_address: String,

    /// VSOCK address/port to connect to
    #[arg(short = 'l', long, default_value = DEFAULT_DEST_ADDR)]
    destination_address: String,

    /// Maximum amount of allowed concurrent connections
    #[arg(short = 'c', long, default_value_t = 1250)]
    max_concurrent_connections: usize,
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
        destination_address: &str,
        buffer_size: usize,
    ) -> Result<Self> {
        let dest_conn = connect_to_enclave(&destination_address).await?;
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
async fn listen_and_serve(args: &Cli) -> Result<()> {
    let host_listener = TcpListener::bind(&args.source_address)
        .await
        .context("failed to start source listener")?;
    let conn_count_semaphore = Arc::new(Semaphore::new(args.max_concurrent_connections));
    info!("Listening on tcp {}...", args.source_address);

    // Use semaphore to limit active connection count
    while let Ok(semaphore_permit) = conn_count_semaphore.clone().acquire_owned().await {
        match host_listener.accept().await {
            Ok((tcp_stream, _)) => {
                let buf_size = args.buffer_size;
                let destination_address = args.destination_address.clone();

                // Spawn new task to handle connection, task will now own semaphore
                // for the duration of the connection.
                tokio::spawn(async move {
                    let result = async {
                        let task =
                            RelayTask::new(tcp_stream, &destination_address, buf_size).await?;
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

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env()
                .expect("should create tracing subscriber env filter"),
        )
        .init();

    listen_and_serve(&args).await
}
