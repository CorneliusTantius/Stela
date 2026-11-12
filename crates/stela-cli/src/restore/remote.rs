//! An IPSW on Apple's servers read by byte ranges, so setup copies the
//! members a recovery medium needs ([`super::payload::trim`]) without
//! downloading the whole image.
//!
//! The first range answer pins the object's ETag and length. Every later
//! request carries `If-Range` with that ETag, so a server that holds a
//! different object answers with the whole thing (200) and the read fails
//! instead of joining two versions. A request that fails in transit is
//! retried a few times, from the same offset.
use anyhow::{Context, Result, bail, ensure};
use reqwest::{StatusCode, blocking::Client, header};
use std::{
    io::{self, Read, Seek, SeekFrom},
    time::Duration,
};

/// Bytes fetched per request: large enough that a member streams at the
/// connection's speed, small enough that a retry repeats little.
const CHUNK: u64 = 16 * 1024 * 1024;
/// Attempts per range before the read fails: with waits of 2, 4, 8, 16 and
/// 30 s between them, a connection that drops for about a minute, as Wi-Fi
/// changing access points does, pauses the download instead of ending it.
const ATTEMPTS: u32 = 6;
/// The longest wait between two attempts.
const MAX_WAIT: Duration = Duration::from_secs(30);
/// How long the first request, one byte, may take.
const OPEN_TIMEOUT: Duration = Duration::from_secs(60);
/// How long one range may take: a [`CHUNK`] at about 56 kB/s. A connection
/// that stalls is dropped and the range asked again, rather than waiting on
/// it for the client's whole-download limit.
const RANGE_TIMEOUT: Duration = Duration::from_secs(300);

pub struct Remote {
    client: Client,
    url: String,
    etag: String,
    len: u64,
    position: u64,
    /// The last range fetched and where it starts.
    chunk: Vec<u8>,
    chunk_start: u64,
}

impl Remote {
    /// Open `url`, pinning its ETag and length from a first range answer.
    pub fn open(client: Client, url: &str) -> Result<Self> {
        let response = crate::net::send(&format!("reading {url}"), || {
            client
                .get(url)
                .header(header::ACCEPT_ENCODING, "identity")
                .header(header::RANGE, "bytes=0-0")
                .timeout(OPEN_TIMEOUT)
        })?
        .error_for_status()?;
        ensure!(
            response.status() == StatusCode::PARTIAL_CONTENT,
            "{url} does not serve byte ranges (status {}); download the whole image instead",
            response.status()
        );
        let etag = response
            .headers()
            .get(header::ETAG)
            .context("the server named no ETag, so a changed image could not be detected")?
            .to_str()?
            .to_owned();
        ensure!(
            !etag.starts_with("W/"),
            "the server's ETag {etag} is weak and cannot pin ranges"
        );
        let (_, len) = content_range(&response)?;
        Ok(Self {
            client,
            url: url.into(),
            etag,
            len,
            position: 0,
            chunk: Vec::new(),
            chunk_start: 0,
        })
    }

    /// The pinned entity tag.
    pub fn etag(&self) -> &str {
        &self.etag
    }

    /// The object's length.
    pub fn size(&self) -> u64 {
        self.len
    }

    /// Fetch `[start, start + bytes)` into the chunk.
    fn fetch(&mut self, start: u64, bytes: u64) -> Result<()> {
        let end = start + bytes - 1;
        let mut last = None;
        for attempt in 0..ATTEMPTS {
            if attempt > 0 {
                let wait = Duration::from_secs(1 << attempt).min(MAX_WAIT);
                note!(
                    "bytes {start}-{end} of {}: {}; trying again in {} s",
                    self.url,
                    last.as_ref()
                        .map_or(String::new(), |e: &anyhow::Error| format!("{e:#}")),
                    wait.as_secs()
                );
                std::thread::sleep(if cfg!(test) {
                    Duration::from_millis(10)
                } else {
                    wait
                });
            }
            match self.try_fetch(start, end) {
                Ok(chunk) => {
                    self.chunk = chunk;
                    self.chunk_start = start;
                    return Ok(());
                }
                Err(Retry::Never(error)) => return Err(error),
                Err(Retry::Again(error)) => last = Some(error),
            }
        }
        Err(last.expect("attempted").context(format!(
            "bytes {start}-{end} of {} failed {ATTEMPTS} times",
            self.url
        )))
    }

    fn try_fetch(&self, start: u64, end: u64) -> Result<Vec<u8>, Retry> {
        let mut response = self
            .client
            .get(&self.url)
            .header(header::ACCEPT_ENCODING, "identity")
            .header(header::RANGE, format!("bytes={start}-{end}"))
            .header(header::IF_RANGE, &self.etag)
            .timeout(RANGE_TIMEOUT)
            .send()
            .map_err(|e| Retry::Again(anyhow::anyhow!(crate::net::explain(&e))))?;
        let status = response.status();
        if crate::net::transient_status(status) {
            return Err(Retry::Again(anyhow::anyhow!(
                "{} answered {status}",
                self.url
            )));
        }
        if status != StatusCode::PARTIAL_CONTENT {
            return Err(Retry::Never(anyhow::anyhow!(
                "{} answered {status} to a range pinned to ETag {}: the image changed on the \
                 server; run setup again",
                self.url,
                self.etag
            )));
        }
        let (span, len) = content_range(&response).map_err(Retry::Never)?;
        if span != (start, end) || len != self.len {
            return Err(Retry::Never(anyhow::anyhow!(
                "{} answered bytes {}-{}/{len} to a request for {start}-{end}/{}",
                self.url,
                span.0,
                span.1,
                self.len
            )));
        }
        let mut chunk = Vec::with_capacity((end - start + 1) as usize);
        response
            .read_to_end(&mut chunk)
            .map_err(|e| Retry::Again(anyhow::anyhow!("{} broke off: {e}", self.url)))?;
        if chunk.len() as u64 != end - start + 1 {
            return Err(Retry::Again(anyhow::anyhow!(
                "{} sent {} of {} bytes",
                self.url,
                chunk.len(),
                end - start + 1
            )));
        }
        Ok(chunk)
    }
}

enum Retry {
    /// A transport failure: the same request may succeed.
    Again(anyhow::Error),
    /// The server's answer is wrong, not lost.
    Never(anyhow::Error),
}

/// A 206 answer's span and the object's whole length.
fn content_range(response: &reqwest::blocking::Response) -> Result<((u64, u64), u64)> {
    let value = response
        .headers()
        .get(header::CONTENT_RANGE)
        .context("a range answer without Content-Range")?
        .to_str()?;
    let Some((span, len)) = value
        .strip_prefix("bytes ")
        .and_then(|rest| rest.split_once('/'))
    else {
        bail!("invalid Content-Range {value:?}");
    };
    let (start, end) = span
        .split_once('-')
        .with_context(|| format!("invalid Content-Range {value:?}"))?;
    let (start, end, len): (u64, u64, u64) = (start.parse()?, end.parse()?, len.parse()?);
    ensure!(start <= end && end < len, "invalid Content-Range {value:?}");
    Ok(((start, end), len))
}

impl Read for Remote {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() || self.position >= self.len {
            return Ok(0);
        }
        let cached = self.position >= self.chunk_start
            && self.position < self.chunk_start + self.chunk.len() as u64;
        if !cached {
            let bytes = CHUNK.min(self.len - self.position);
            self.fetch(self.position, bytes).map_err(io::Error::other)?;
        }
        let offset = (self.position - self.chunk_start) as usize;
        let count = buffer.len().min(self.chunk.len() - offset);
        buffer[..count].copy_from_slice(&self.chunk[offset..offset + count]);
        self.position += count as u64;
        Ok(count)
    }
}

impl Seek for Remote {
    fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
        let position = match to {
            SeekFrom::Start(offset) => Some(offset),
            SeekFrom::End(delta) => self.len.checked_add_signed(delta),
            SeekFrom::Current(delta) => self.position.checked_add_signed(delta),
        }
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "seek before the start"))?;
        self.position = position;
        Ok(position)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{BufRead, BufReader, Write},
        net::TcpListener,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };

    /// Serve `body` with ranges under `etag`, answering 200 to any request
    /// once `changed_after` range requests were served. Returns the URL and
    /// the request count.
    fn serve(
        body: Vec<u8>,
        etag: &'static str,
        changed_after: usize,
    ) -> (String, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let served = Arc::new(AtomicUsize::new(0));
        let count = served.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let mut stream = stream.unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut range = None;
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap() == 0 || line == "\r\n" {
                        break;
                    }
                    if let Some(value) = line.to_ascii_lowercase().strip_prefix("range: bytes=") {
                        let (start, end) = value.trim().split_once('-').unwrap();
                        range = Some((
                            start.parse::<usize>().unwrap(),
                            end.parse::<usize>().unwrap(),
                        ));
                    }
                }
                let n = count.fetch_add(1, Ordering::SeqCst);
                let reply = match range {
                    Some((start, end)) if n < changed_after => {
                        let end = end.min(body.len() - 1);
                        let mut reply = format!(
                            "HTTP/1.1 206 Partial Content\r\nETag: {etag}\r\nContent-Range: bytes {start}-{end}/{}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len(),
                            end - start + 1
                        )
                        .into_bytes();
                        reply.extend_from_slice(&body[start..=end]);
                        reply
                    }
                    _ => {
                        let mut reply = format!(
                            "HTTP/1.1 200 OK\r\nETag: \"other\"\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        )
                        .into_bytes();
                        reply.extend_from_slice(&body);
                        reply
                    }
                };
                let _ = stream.write_all(&reply);
            }
        });
        (format!("http://{address}/Restore.ipsw"), served)
    }

    fn body() -> Vec<u8> {
        (0..(CHUNK as usize + 1000))
            .map(|i| (i % 251) as u8)
            .collect()
    }

    #[test]
    fn ranges_read_any_offset_across_chunks() -> Result<()> {
        let body = body();
        let (url, served) = serve(body.clone(), "\"pinned\"", usize::MAX);
        let mut remote = Remote::open(Client::new(), &url)?;
        assert_eq!(remote.seek(SeekFrom::End(0))?, body.len() as u64);
        remote.seek(SeekFrom::End(-1500))?;
        let mut tail = Vec::new();
        remote.read_to_end(&mut tail)?;
        assert_eq!(tail, body[body.len() - 1500..]);
        remote.seek(SeekFrom::Start(10))?;
        let mut head = vec![0; 20];
        remote.read_exact(&mut head)?;
        assert_eq!(head, body[10..30]);
        // Reads within a fetched chunk need no request.
        let before = served.load(Ordering::SeqCst);
        remote.read_exact(&mut head)?;
        assert_eq!(head, body[30..50]);
        assert_eq!(served.load(Ordering::SeqCst), before);
        Ok(())
    }

    #[test]
    fn remote_read_rejects_changed_image() -> Result<()> {
        let (url, _) = serve(body(), "\"pinned\"", 2);
        let mut remote = Remote::open(Client::new(), &url)?;
        let mut byte = [0];
        remote.read_exact(&mut byte)?;
        remote.seek(SeekFrom::End(-1))?;
        let error = remote.read_exact(&mut byte).unwrap_err().to_string();
        assert!(error.contains("the image changed"), "{error}");
        Ok(())
    }

    #[test]
    fn a_failed_open_or_range_is_asked_again_from_the_same_offset() -> Result<()> {
        let body: String = (0..100)
            .map(|i| char::from(b'a' + (i % 26) as u8))
            .collect();
        let range = |span: &str, bytes: &str, length: usize| {
            format!(
                "HTTP/1.1 206 Partial Content\r\nETag: \"e\"\r\nContent-Range: bytes \
                 {span}/100\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n{bytes}"
            )
        };
        let unavailable =
            "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        let (url, served) = crate::net::tests::serve(vec![
            unavailable.into(),
            range("0-0", &body[..1], 1),
            unavailable.into(),
            // A range that breaks off part way.
            range("0-99", &body[..10], 100),
            range("0-99", &body, 100),
        ]);
        let mut remote = Remote::open(Client::new(), &url)?;
        let mut read = String::new();
        remote.read_to_string(&mut read)?;
        assert_eq!(read, body);
        assert_eq!(served.load(Ordering::SeqCst), 5);
        Ok(())
    }

    #[test]
    fn remote_server_requires_ranges_and_strong_etag() {
        let (url, _) = serve(body(), "\"pinned\"", 0);
        let error = Remote::open(Client::new(), &url).err().unwrap().to_string();
        assert!(error.contains("does not serve byte ranges"), "{error}");
        let (url, _) = serve(body(), "W/\"weak\"", usize::MAX);
        let error = Remote::open(Client::new(), &url).err().unwrap().to_string();
        assert!(error.contains("weak"), "{error}");
    }
}
