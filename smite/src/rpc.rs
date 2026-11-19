//! Clients for target node RPC (JSON-RPC over Unix socket, JSON over HTTP).
//!
//! An unreachable target is returned as an [`io::Error`]. Any other failure
//! means the call itself is wrong and panics.

use std::io::{self, BufRead, BufReader, ErrorKind, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Read/write timeout for RPC I/O, so a hung target cannot block forever.
const RPC_IO_TIMEOUT: Duration = Duration::from_secs(1);

/// Passes through errors caused by an unreachable target.
///
/// # Panics
///
/// Panics on any other error, i.e., a malformed request or response.
fn unreachable(e: io::Error, request: &str) -> io::Error {
    match e.kind() {
        ErrorKind::ConnectionRefused
        | ErrorKind::ConnectionReset
        | ErrorKind::ConnectionAborted
        | ErrorKind::BrokenPipe
        | ErrorKind::WouldBlock
        | ErrorKind::TimedOut
        | ErrorKind::UnexpectedEof => e,
        _ => panic!("malformed {request} request or response: {e}"),
    }
}

/// Sends a JSON-RPC request over the Unix socket at `socket` and returns the
/// response's `result`.
///
/// # Errors
///
/// Returns an error if the target is unreachable: the connection fails, or the
/// response times out or is cut short.
///
/// # Panics
///
/// - If `params` cannot be serialized or the response is not valid JSON-RPC.
/// - If the target answers with a JSON-RPC `error`.
pub fn unix_rpc(socket: &Path, method: &str, params: impl Serialize) -> io::Result<Value> {
    /// A JSON-RPC response from target. `jsonrpc` and `id` are echoed
    /// back but unused, and exactly one of `result` or `error` is set.
    #[derive(Deserialize)]
    struct RpcResponse {
        #[serde(default)]
        result: Value,
        error: Option<Value>,
    }

    let response = (|| -> io::Result<RpcResponse> {
        // Connect to target's RPC socket.
        let mut sock = UnixStream::connect(socket)?;
        sock.set_read_timeout(Some(RPC_IO_TIMEOUT))
            .expect("valid timeout");
        sock.set_write_timeout(Some(RPC_IO_TIMEOUT))
            .expect("valid timeout");

        // Write the request to the socket.
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": "smite",
            "method": method,
            "params": params,
        });
        serde_json::to_writer(&mut sock, &request)?;

        // Read the response.
        serde_json::Deserializer::from_reader(&mut sock)
            .into_iter()
            .next()
            .transpose()?
            .ok_or_else(|| {
                io::Error::new(
                    ErrorKind::UnexpectedEof,
                    format!("target closed the socket without answering {method}"),
                )
            })
    })()
    .map_err(|e| unreachable(e, method))?;

    if let Some(error) = response.error {
        panic!("target rejected {method}: {error}");
    }

    Ok(response.result)
}

/// Sends an HTTP POST to `localhost:{port}{path}` and returns the JSON response
/// body.
///
/// # Errors
///
/// Returns an error if the target is unreachable: the connection fails, or the
/// response times out or is cut short.
///
/// # Panics
///
/// - If the response lacks a `Content-Length` or its body is not valid JSON.
/// - If the response status is not 2xx.
pub fn http_post(port: u16, path: &str, headers: &[(&str, &str)], body: &str) -> io::Result<Value> {
    let (status, response) = (|| -> io::Result<(String, Vec<u8>)> {
        // Connect to target's HTTP port.
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        let sock = TcpStream::connect_timeout(&addr, RPC_IO_TIMEOUT)?;
        sock.set_read_timeout(Some(RPC_IO_TIMEOUT))
            .expect("valid timeout");
        sock.set_write_timeout(Some(RPC_IO_TIMEOUT))
            .expect("valid timeout");
        let mut conn = BufReader::new(sock);

        // Write the request to the socket.
        let mut request = format!("POST {path} HTTP/1.1\r\nHost: localhost\r\n").into_bytes();
        for (name, value) in headers {
            write!(request, "{name}: {value}\r\n")?;
        }
        write!(request, "Content-Length: {}\r\n\r\n{body}", body.len())?;
        conn.get_mut().write_all(&request)?;

        // Read the response length.
        let mut lines = conn.by_ref().lines();
        let status = lines.next().ok_or(ErrorKind::UnexpectedEof)??;
        let mut content_length = None;
        loop {
            let line = lines.next().ok_or(ErrorKind::UnexpectedEof)??;
            if line.is_empty() {
                break;
            }

            if let Some(value) = line.strip_prefix("Content-Length:") {
                content_length = Some(value.trim().parse().map_err(io::Error::other)?);
            }
        }

        // Read the response.
        let len = content_length.ok_or_else(|| io::Error::other("no Content-Length"))?;
        let mut response = vec![0; len];
        conn.read_exact(&mut response)?;

        Ok((status, response))
    })()
    .map_err(|e| unreachable(e, path))?;

    // Check status after reading the body to surface rejections as panics.
    assert!(
        status
            .split_whitespace()
            .nth(1)
            .is_some_and(|code| code.starts_with('2')),
        "target rejected {path}: {}",
        String::from_utf8_lossy(&response)
    );

    Ok(serde_json::from_slice(&response).expect("valid JSON response"))
}
