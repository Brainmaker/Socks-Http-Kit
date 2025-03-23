//! A mock implementation of a bidirectional stream that can be used for testing.

use std::{
    collections::VecDeque,
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

/// A mock implementation of a bidirectional stream that can be used for testing
/// asynchronous network code without requiring actual network connections.
#[derive(Debug)]
pub struct MockStream {
    rx: Arc<Mutex<SharedState>>,
    tx: Arc<Mutex<SharedState>>,
}

/// Internal shared state for the stream's read and write buffers.
#[derive(Debug, Default)]
struct SharedState {
    buffer: VecDeque<u8>,
    closed: bool,
    waker: Option<Waker>,
}

/// Creates a pair of connected mock streams for testing bidirectional communication.
///
/// Returns a tuple of two `MockStream` instances that are connected to each other.
/// Data written to one stream can be read from the other.
pub fn create_mock_stream() -> (MockStream, MockStream) {
    let state1 = Arc::new(Mutex::new(SharedState::default()));
    let state2 = Arc::new(Mutex::new(SharedState::default()));

    // read from state1, write to state2
    let stream1 = MockStream {
        rx: state1.clone(),
        tx: state2.clone(),
    };

    // read from state2, write to state1
    let stream2 = MockStream {
        rx: state2,
        tx: state1,
    };

    (stream1, stream2)
}

impl AsyncRead for MockStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut rx = self.rx.lock().unwrap();

        if !rx.buffer.is_empty() {
            // Check if there's data available to read
            let to_read = std::cmp::min(buf.remaining(), rx.buffer.len());
            let unfilled = buf.initialize_unfilled();
            for x in &mut unfilled[..to_read] {
                if let Some(byte) = rx.buffer.pop_front() {
                    *x = byte;
                }
            }
            buf.advance(to_read);
            Poll::Ready(Ok(()))
        } else if rx.closed {
            // If the channel is closed and no data is available, return EOF.
            Poll::Ready(Ok(()))
        } else {
            // No data available, register waker for notification
            rx.waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }
}

impl AsyncWrite for MockStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut tx = self.tx.lock().unwrap();

        // If the channel is closed, return an error
        if tx.closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "writing to a closed stream",
            )));
        }

        tx.buffer.extend(buf.iter().cloned());

        // Notify any reader waiting for data
        if let Some(waker) = tx.waker.take() {
            waker.wake();
        }

        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Data is written directly to the buffer, so no additional flush operation is needed
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut tx = self.tx.lock().unwrap();
        tx.closed = true;

        // Notify any reader waiting for data (possibly waiting for EOF)
        if let Some(waker) = tx.waker.take() {
            waker.wake();
        }

        Poll::Ready(Ok(()))
    }
}

impl MockStream {
    /// Immediately writes data to the stream without using async operations.
    ///
    /// Useful for test setup and verification.
    pub fn write_immediate(&self, data: &[u8]) -> io::Result<usize> {
        let mut tx = self.tx.lock().unwrap();

        if tx.closed {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "writing to a closed stream",
            ));
        }

        tx.buffer.extend(data.iter().cloned());

        // Notify any reader waiting for data
        if let Some(waker) = tx.waker.take() {
            waker.wake();
        }

        Ok(data.len())
    }

    /// Immediately reads all available data from the stream without using async operations.
    ///
    /// Returns all bytes currently in the buffer without waiting.
    pub fn read_available(&self) -> io::Result<Vec<u8>> {
        let mut rx = self.rx.lock().unwrap();

        let available: Vec<u8> = rx.buffer.drain(..).collect();

        Ok(available)
    }

    /// Checks if the stream has been closed for reading.
    ///
    /// Returns true if the peer has shut down its writing end.
    pub fn is_closed(&self) -> bool {
        let rx = self.rx.lock().unwrap();
        rx.closed
    }
}

// Implement Send and Sync to make MockStream thread-safe
unsafe impl Send for MockStream {}
unsafe impl Sync for MockStream {}

#[tokio::test]
async fn test_basic_read_write() {
    let (mut stream1, mut stream2) = create_mock_stream();

    // 在stream1中写入数据
    let data = b"Hello, world!";
    let write_len = stream1.write(data).await.unwrap();
    assert_eq!(write_len, data.len());

    // 从stream2中读取数据
    let mut buf = vec![0u8; 20];
    let read_len = stream2.read(&mut buf).await.unwrap();
    assert_eq!(read_len, data.len());
    assert_eq!(&buf[..read_len], data);
}

#[tokio::test]
async fn test_bidirectional_communication() {
    let (mut stream1, mut stream2) = create_mock_stream();

    // stream1 -> stream2
    let data1 = b"Message from stream1";
    stream1.write_all(data1).await.unwrap();

    // stream2 -> stream1
    let data2 = b"Reply from stream2";
    stream2.write_all(data2).await.unwrap();

    let mut buf1 = vec![0u8; 30];
    let read_len1 = stream2.read(&mut buf1).await.unwrap();
    assert_eq!(&buf1[..read_len1], data1);

    let mut buf2 = vec![0u8; 30];
    let read_len2 = stream1.read(&mut buf2).await.unwrap();
    assert_eq!(&buf2[..read_len2], data2);
}

#[tokio::test]
async fn test_multiple_writes_single_read() {
    let (mut stream1, mut stream2) = create_mock_stream();

    stream1.write_all(b"Part1").await.unwrap();
    stream1.write_all(b"Part2").await.unwrap();
    stream1.write_all(b"Part3").await.unwrap();

    let mut buf = vec![0u8; 15];
    let read_len = stream2.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..read_len], b"Part1Part2Part3");
}

#[tokio::test]
async fn test_shutdown() {
    let (mut stream1, mut stream2) = create_mock_stream();

    stream1.write_all(b"Last message").await.unwrap();
    stream1.shutdown().await.unwrap();

    let mut buf = vec![0u8; 20];
    let read_len = stream2.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..read_len], b"Last message");

    let read_len = stream2.read(&mut buf).await.unwrap();
    assert_eq!(read_len, 0);
}

#[tokio::test]
async fn test_concurrent_operations() {
    use tokio::task;

    let (mut stream1, mut stream2) = create_mock_stream();

    let writer = task::spawn(async move {
        for i in 0..5 {
            let msg = format!("Message {}", i);
            stream1.write_all(msg.as_bytes()).await.unwrap();
            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        }
        stream1.shutdown().await.unwrap();
        "writing complete"
    });

    let reader = task::spawn(async move {
        let mut results = Vec::new();
        let mut buf = vec![0u8; 20];
        loop {
            match stream2.read(&mut buf).await {
                Ok(0) => break, // EOF
                Ok(n) => {
                    let msg = String::from_utf8_lossy(&buf[..n]).to_string();
                    results.push(msg);
                }
                Err(e) => panic!("read error: {}", e),
            }
        }
        results
    });

    let (write_result, read_results) = tokio::join!(writer, reader);

    assert_eq!(write_result.unwrap(), "writing complete");
    let messages = read_results.unwrap();
    assert_eq!(messages.len(), 5);
    for (i, m) in messages.iter().enumerate() {
        assert_eq!(m, &format!("Message {}", i));
    }
}
