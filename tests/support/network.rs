//! Local protocol fixtures. No external services or host commands are used.
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub struct Server {
    pub address: String,
    stop: tokio::sync::watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.stop.send(true);
        self.task.abort();
    }
}

#[allow(dead_code)]
pub async fn grpc<F>(handler: F) -> Server
where
    F: Fn(http::Request<Vec<u8>>) -> (u32, Vec<u8>) + Send + Sync + 'static,
{
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let handler = Arc::new(handler);
    let (stop, receiver) = tokio::sync::watch::channel(false);
    let task = tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let handler = handler.clone();
            let mut receiver = receiver.clone();
            tokio::spawn(async move {
                let serve = async move {
                    let mut connection = h2::server::handshake(socket).await.unwrap();
                    while let Some(Ok((request, mut response))) = connection.accept().await {
                        let handler = handler.clone();
                        tokio::spawn(async move {
                            let (parts, mut body) = request.into_parts();
                            let mut data = Vec::new();
                            while let Some(Ok(bytes)) = body.data().await {
                                data.extend_from_slice(&bytes);
                                let _ = body.flow_control().release_capacity(bytes.len());
                                if data.len() >= 5
                                    && data.len()
                                        >= 5 + u32::from_be_bytes(data[1..5].try_into().unwrap())
                                            as usize
                                {
                                    break;
                                }
                            }
                            let (status, payload) = handler(http::Request::from_parts(parts, data));
                            let headers = http::Response::builder()
                                .status(200)
                                .header("content-type", "application/grpc")
                                .body(())
                                .unwrap();
                            let Ok(mut stream) = response.send_response(headers, false) else {
                                return;
                            };
                            if status == 0 {
                                let mut frame = vec![0];
                                frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
                                frame.extend_from_slice(&payload);
                                if stream.send_data(frame.into(), false).is_err() {
                                    return;
                                }
                            }
                            let mut trailers = http::HeaderMap::new();
                            trailers.insert("grpc-status", status.to_string().parse().unwrap());
                            let _ = stream.send_trailers(trailers);
                        });
                    }
                };
                tokio::select! { _ = serve => {}, _ = receiver.changed() => {} }
            });
        }
    });
    Server {
        address,
        stop,
        task,
    }
}

#[allow(dead_code)]
pub async fn http<F>(handler: F) -> Server
where
    F: Fn(http::Request<Vec<u8>>) -> (u16, Vec<u8>) + Send + Sync + 'static,
{
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let handler = Arc::new(handler);
    let (stop, receiver) = tokio::sync::watch::channel(false);
    let task = tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let handler = handler.clone();
            let mut receiver = receiver.clone();
            tokio::spawn(async move {
                let serve = async move {
                    let mut data = Vec::new();
                    let boundary = loop {
                        let mut bytes = [0; 4096];
                        let count = socket.read(&mut bytes).await.unwrap();
                        if count == 0 || data.len() > 1024 * 1024 {
                            return;
                        }
                        data.extend_from_slice(&bytes[..count]);
                        if let Some(offset) = data.windows(4).position(|w| w == b"\r\n\r\n") {
                            break offset + 4;
                        }
                    };
                    let headers = String::from_utf8_lossy(&data[..boundary]);
                    let mut lines = headers.lines();
                    let mut first = lines.next().unwrap().split_whitespace();
                    let mut request = http::Request::builder()
                        .method(first.next().unwrap())
                        .uri(first.next().unwrap());
                    let mut length = 0;
                    for line in lines {
                        if let Some((name, value)) = line.split_once(':') {
                            if name.eq_ignore_ascii_case("content-length") {
                                length = value.trim().parse().unwrap();
                            }
                            request = request.header(name, value.trim());
                        }
                    }
                    while data.len() - boundary < length {
                        let mut bytes = [0; 4096];
                        let count = socket.read(&mut bytes).await.unwrap();
                        if count == 0 {
                            return;
                        }
                        data.extend_from_slice(&bytes[..count]);
                    }
                    let (status, response) = handler(
                        request
                            .body(data[boundary..boundary + length].to_vec())
                            .unwrap(),
                    );
                    let header = format!("HTTP/1.1 {status} Result\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", response.len());
                    socket.write_all(header.as_bytes()).await.unwrap();
                    socket.write_all(&response).await.unwrap();
                };
                tokio::select! { _ = serve => {}, _ = receiver.changed() => {} }
            });
        }
    });
    Server {
        address,
        stop,
        task,
    }
}

pub struct Directory(pub std::path::PathBuf);
impl Default for Directory {
    fn default() -> Self {
        Self::new()
    }
}
impl Directory {
    pub fn new() -> Self {
        let directory =
            Self(std::env::temp_dir().join(format!("dodo-contract-{}", uuid::Uuid::new_v4())));
        std::fs::create_dir_all(&directory.0).unwrap();
        directory
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
