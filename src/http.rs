use std::{
    fmt::{self, Display, Formatter},
    io::{Error, ErrorKind, Result},
};

use base64::engine::{Engine, general_purpose::STANDARD};
use futures_util::StreamExt;
use httparse::{EMPTY_HEADER, Request, Response, Status};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio_util::codec::{BytesCodec, FramedRead};

use crate::{Address, AuthMethod};

const MAX_HEADER_SIZE: usize = 8192;

/// HTTP proxy response status codes as defined in RFC 7231.
///
/// These status codes represent the standard HTTP responses for proxy operations:
/// - 200 OK: Connection established successfully
/// - 403 Forbidden: Access denied
/// - 407 Proxy Authentication Required: Authentication needed
/// - 502 Bad Gateway: Connection to target failed
/// - 504 Gateway Timeout: Connection to target timed out
///
/// Reference: <https://datatracker.ietf.org/doc/html/rfc7231#section-6>
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum HttpReply {
    #[allow(missing_docs)]
    Ok = 200,
    #[allow(missing_docs)]
    Forbidden = 403,
    #[allow(missing_docs)]
    ProxyAuthenticationRequired = 407,
    #[allow(missing_docs)]
    BadGateway = 502,
    #[allow(missing_docs)]
    GatewayTimeout = 504,
}

/// Accepts an HTTP proxy connection request from a client.
///
/// This function reads and processes an HTTP CONNECT request from the client,
/// validates authentication if required, and extracts the target address.
///
/// # Arguments
/// * `stream` - A mutable reference to an asynchronous stream implementing `AsyncRead` + `Unpin`.
/// * `auth_method` - The authentication method required for this connection.
///
/// # Returns
/// * `Result<Address>` - The parsed target address on success, or an error if the request
///   is invalid, authentication fails, or the connection cannot be established.
///
pub async fn http_accept<T>(stream: &mut T, auth_method: &AuthMethod) -> Result<Address>
where
    T: AsyncRead + Unpin,
{
    read_client_request(stream, auth_method).await
}

/// Completes an HTTP proxy connection by sending a response to the client.
///
/// After processing a client's HTTP CONNECT request with `http_accept`, this function
/// sends the appropriate HTTP response to indicate success or failure.
///
/// # Arguments
/// * `stream` - A mutable reference to an asynchronous stream.
/// * `reply` - The HTTP reply status to send to the client.
///
/// # Returns
/// * `Result<()>` - Success if the response is sent, or an IO error if writing fails.
///
pub async fn http_finalize_accept<T>(stream: &mut T, reply: &HttpReply) -> Result<()>
where
    T: AsyncWrite + Unpin,
{
    write_server_response(stream, reply).await
}

/// Establishes an HTTP proxy connection to a target server.
///
/// This function sends an HTTP CONNECT request to a proxy server with the specified
/// target address and authentication credentials, then verifies the response.
///
/// # Arguments
/// * `stream` - A mutable reference to an asynchronous stream implementing `AsyncRead` + `AsyncWrite` + `Unpin`.
/// * `address` - The target address to connect to.
/// * `auth_method` - The authentication method to use for this connection.
///
/// # Returns
/// * `Result<()>` - Success if the connection is established, or an error if the request
///   fails, authentication is rejected, or the server returns a non-200 status code.
///
pub async fn http_connect<T>(
    stream: &mut T,
    address: &Address,
    auth_method: &AuthMethod,
) -> Result<()>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    write_client_request(stream, address, auth_method).await?;
    read_server_response(stream).await?;
    Ok(())
}

/// The HTTP CONNECT request format complies with RFC 7231:
///
/// ```text
/// CONNECT example.com:80 HTTP/1.1
/// Host: example.com:80
/// [Proxy-Authorization: Basic base64(username:password)]
/// Connection: keep-alive
/// ```
async fn read_client_request<T>(reader: &mut T, auth_method: &AuthMethod) -> Result<Address>
where
    T: AsyncRead + Unpin,
{
    let mut framed = FramedRead::new(reader, BytesCodec::new());
    let mut buffer = Vec::with_capacity(MAX_HEADER_SIZE);

    let (path, auth_header_value) = loop {
        let mut headers = [EMPTY_HEADER; 32];
        let mut req = Request::new(&mut headers);
        match req.parse(&buffer).map_err(HttpError::ParseRequestFailed)? {
            Status::Complete(_) => {
                let method = req.method.ok_or(HttpError::MissingMethod)?;
                let path = req.path.ok_or(HttpError::MissingTargetPath)?;
                let auth_header_value = headers
                    .iter()
                    .find(|h| h.name.eq_ignore_ascii_case("proxy-authorization"))
                    .and_then(|h| std::str::from_utf8(h.value).ok())
                    .map(String::from);

                // Check and process extracted information
                if method != "CONNECT" {
                    return Err(HttpError::OnlyConnectSupported.into());
                }

                break (path, auth_header_value);
            }
            Status::Partial if buffer.len() >= MAX_HEADER_SIZE => {
                return Err(HttpError::HeaderTooLong.into());
            }
            Status::Partial => match framed.next().await {
                Some(Ok(bytes)) => buffer.extend_from_slice(&bytes),
                Some(Err(e)) => return Err(e),
                None => return Err(HttpError::ConnectionClosedHeaderIncomplete.into()),
            },
        }
    };

    // Verify authentication
    if let AuthMethod::UserPass { username, password } = auth_method {
        let Some(auth) = auth_header_value else {
            return Err(HttpError::AuthenticationRequired.into());
        };

        if !auth.starts_with("Basic ") {
            return Err(HttpError::OnlyBasicAuthSupported.into());
        }

        let base64_value = auth.trim_start_matches("Basic ").trim();
        let decoded = STANDARD
            .decode(base64_value)
            .map_err(|_| HttpError::InvalidBase64Encoding)?;

        let decoded_str = String::from_utf8_lossy(&decoded);
        let creds: Vec<&str> = decoded_str.split(':').collect();

        if creds.len() < 2 || creds[0] != username || creds[1] != password {
            return Err(HttpError::InvalidCredentials.into());
        }
    }

    // Parse the target address
    Ok(Address::try_from(path)?)
}

async fn write_client_request<T>(
    writer: &mut T,
    address: &Address,
    auth_method: &AuthMethod,
) -> Result<()>
where
    T: AsyncWrite + Unpin,
{
    let target: String = address.into();

    // Construct CONNECT request
    let mut request = format!("CONNECT {} HTTP/1.1\r\n", target);

    // Add Host header
    request.push_str(&format!("Host: {}\r\n", target));

    // Add authentication header (if required)
    match auth_method {
        AuthMethod::UserPass { username, password } => {
            let credentials = format!("{}:{}", username, password);
            let encoded = STANDARD.encode(credentials);
            request.push_str(&format!("Proxy-Authorization: Basic {}\r\n", encoded));
        }
        AuthMethod::NoAuth => {} // No authentication required
    }

    // Add Connection header and end headers
    request.push_str("Connection: keep-alive\r\n\r\n");

    // Write the request
    writer.write_all(request.as_bytes()).await
}

/// The HTTP response format complies with RFC 7231:
///
/// Successful response:
/// ```text
/// HTTP/1.1 200 OK
/// Connection: keep-alive
/// Content-Length: 0
/// ```
///
/// Authentication required response:
/// ```text
/// HTTP/1.1 407 Proxy Authentication Required
/// Proxy-Authenticate: Basic realm="Proxy"
/// Connection: keep-alive
/// Content-Length: 0
/// ```
async fn read_server_response<T>(reader: &mut T) -> Result<()>
where
    T: AsyncRead + Unpin,
{
    let mut framed = FramedRead::new(reader, BytesCodec::new());
    let mut buffer = Vec::with_capacity(MAX_HEADER_SIZE);

    loop {
        let mut headers = [EMPTY_HEADER; 32];
        let mut resp = Response::new(&mut headers);

        match resp
            .parse(&buffer)
            .map_err(HttpError::ParseResponseFailed)?
        {
            Status::Complete(_) => {
                let status_code = resp.code.ok_or(HttpError::MissingStatusCode)?;
                let reason = String::from(resp.reason.unwrap_or("Unknown error"));

                // Determine if status code indicates success
                if status_code != 200 {
                    return Err(HttpError::HttpError(status_code, reason).into());
                }
                return Ok(());
            }
            Status::Partial if buffer.len() >= MAX_HEADER_SIZE => {
                return Err(HttpError::HeaderTooLong.into());
            }
            Status::Partial => match framed.next().await {
                Some(Ok(bytes)) => buffer.extend_from_slice(&bytes),
                Some(Err(e)) => return Err(e),
                None => return Err(HttpError::ConnectionClosedHeaderIncomplete.into()),
            },
        }
    }
}

async fn write_server_response<T>(writer: &mut T, reply: &HttpReply) -> Result<()>
where
    T: AsyncWrite + Unpin,
{
    // Get status code
    let status_code = *reply as u16;

    // Get status text
    let status_text = match reply {
        HttpReply::Ok => "OK",
        HttpReply::Forbidden => "Forbidden",
        HttpReply::ProxyAuthenticationRequired => "Proxy Authentication Required",
        HttpReply::BadGateway => "Bad Gateway",
        HttpReply::GatewayTimeout => "Gateway Timeout",
    };

    // Construct response
    let mut response = format!("HTTP/1.1 {} {}\r\n", status_code, status_text);

    // Add appropriate headers based on status code
    if *reply == HttpReply::ProxyAuthenticationRequired {
        response.push_str("Proxy-Authenticate: Basic realm=\"Proxy\"\r\n");
    }

    // Add standard headers
    response.push_str("Connection: keep-alive\r\n");
    response.push_str("Content-Length: 0\r\n\r\n");

    // Write the response
    writer.write_all(response.as_bytes()).await
}

/// Errors that can occur during HTTP proxy protocol operations.
///
/// Each variant represents a specific error condition that may arise when implementing
/// or using the HTTP proxy protocol, particularly with the CONNECT method.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum HttpError {
    /// Failed to parse the HTTP request due to a specific httparse error.
    ParseRequestFailed(httparse::Error),
    /// Failed to parse the HTTP response due to a specific httparse error.
    ParseResponseFailed(httparse::Error),
    /// HTTP header section exceeds the maximum buffer size.
    HeaderTooLong,
    /// Connection was closed before the complete HTTP header was received.
    ConnectionClosedHeaderIncomplete,
    /// HTTP request is missing the method field.
    MissingMethod,
    /// HTTP proxy implementation only supports the CONNECT method.
    OnlyConnectSupported,
    /// HTTP proxy authentication only supports the Basic scheme.
    OnlyBasicAuthSupported,
    /// Provided authorization header contains invalid Base64 encoding.
    InvalidBase64Encoding,
    /// Provided username/password combination is incorrect.
    InvalidCredentials,
    /// Proxy requires authentication but no credentials were provided.
    AuthenticationRequired,
    /// HTTP CONNECT request is missing the target host:port path.
    MissingTargetPath,
    /// HTTP response is missing the status code.
    MissingStatusCode,
    /// Server returned an HTTP error with specific status code and reason.
    HttpError(u16, String),
}

impl Display for HttpError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::ParseRequestFailed(reason) => {
                write!(f, "Failed to parse HTTP request: {}", reason)
            }
            Self::ParseResponseFailed(reason) => {
                write!(f, "Failed to parse HTTP response: {}", reason)
            }
            Self::HeaderTooLong => write!(f, "HTTP header exceeds maximum length"),
            Self::ConnectionClosedHeaderIncomplete => {
                write!(f, "Connection closed, HTTP header incomplete")
            }
            Self::MissingMethod => write!(f, "Missing HTTP method"),
            Self::OnlyConnectSupported => write!(f, "Only CONNECT method is supported"),
            Self::OnlyBasicAuthSupported => write!(f, "Only Basic authentication is supported"),
            Self::InvalidBase64Encoding => write!(f, "Invalid Base64 encoding"),
            Self::InvalidCredentials => write!(f, "Invalid credentials"),
            Self::AuthenticationRequired => write!(f, "Authentication required"),
            Self::MissingTargetPath => write!(f, "Missing target path"),
            Self::MissingStatusCode => write!(f, "Missing status code"),
            Self::HttpError(code, reason) => write!(f, "HTTP error: {} {}", code, reason),
        }
    }
}

impl std::error::Error for HttpError {}

impl From<HttpError> for Error {
    fn from(e: HttpError) -> Self {
        match e {
            HttpError::ParseRequestFailed(_) => Error::new(ErrorKind::InvalidData, e),
            HttpError::ParseResponseFailed(_) => Error::new(ErrorKind::InvalidData, e),
            HttpError::HeaderTooLong => Error::new(ErrorKind::InvalidData, e),
            HttpError::ConnectionClosedHeaderIncomplete => Error::new(ErrorKind::UnexpectedEof, e),
            HttpError::MissingMethod => Error::new(ErrorKind::InvalidData, e),
            HttpError::OnlyConnectSupported => Error::new(ErrorKind::InvalidData, e),
            HttpError::OnlyBasicAuthSupported => Error::new(ErrorKind::PermissionDenied, e),
            HttpError::InvalidBase64Encoding => Error::new(ErrorKind::InvalidData, e),
            HttpError::InvalidCredentials => Error::new(ErrorKind::PermissionDenied, e),
            HttpError::AuthenticationRequired => Error::new(ErrorKind::PermissionDenied, e),
            HttpError::MissingTargetPath => Error::new(ErrorKind::InvalidData, e),
            HttpError::MissingStatusCode => Error::new(ErrorKind::InvalidData, e),
            HttpError::HttpError(..) => Error::new(ErrorKind::Other, e),
        }
    }
}

#[cfg(test)]
mod test {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;
    use crate::test_utils::create_mock_stream;

    #[tokio::test]
    async fn test_client_request_write_read() {
        let (mut stream1, mut stream2) = create_mock_stream();
        let all_addresses = [
            Address::IPv4((Ipv4Addr::new(192, 168, 1, 1), 8080)),
            Address::DomainName(("example.com".to_string(), 443)),
            Address::IPv6((
                Ipv6Addr::new(0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x01),
                8080,
            )),
        ];
        let all_auth_methods = [
            AuthMethod::UserPass {
                username: "user".to_string(),
                password: "pass".to_string(),
            },
            AuthMethod::NoAuth,
        ];
        for address in all_addresses.iter() {
            for auth_method in all_auth_methods.iter() {
                write_client_request(&mut stream1, address, auth_method)
                    .await
                    .unwrap();
                let received_addr = read_client_request(&mut stream2, auth_method)
                    .await
                    .unwrap();
                assert_eq!(address, &received_addr);
            }
        }
    }

    #[tokio::test]
    async fn test_server_response_write_read() {
        let (mut stream1, mut stream2) = create_mock_stream();
        write_server_response(&mut stream1, &HttpReply::Ok)
            .await
            .unwrap();
        read_server_response(&mut stream2).await.unwrap();
    }

    #[tokio::test]
    async fn test_read_client_request_missing_method() {
        // Construct a request with missing method
        let test_input = b"HTTP/1.1\r\nHost: example.com:80\r\n\r\n";

        let (client, mut server) = create_mock_stream();
        client.write_immediate(test_input).unwrap();

        let result = read_client_request(&mut server, &AuthMethod::NoAuth).await;

        let err = result.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);
        assert!(matches!(
            err.get_ref().unwrap().downcast_ref::<HttpError>().unwrap(),
            &HttpError::ParseRequestFailed(_)
        ));
    }

    #[tokio::test]
    async fn test_read_client_request_missing_path() {
        // Construct a request with missing target path
        let test_input = b"CONNECT HTTP/1.1\r\nHost: example.com:80\r\n\r\n";

        let (client, mut server) = create_mock_stream();
        client.write_immediate(test_input).unwrap();

        let result = read_client_request(&mut server, &AuthMethod::NoAuth).await;

        let err = result.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);
        assert!(matches!(
            err.get_ref().unwrap().downcast_ref::<HttpError>().unwrap(),
            &HttpError::ParseRequestFailed(_)
        ));
    }

    #[tokio::test]
    async fn test_read_client_request_non_connect_method() {
        // Construct a request with non-CONNECT method (using GET instead)
        let test_input = b"GET example.com:80 HTTP/1.1\r\nHost: example.com:80\r\n\r\n";

        let (client, mut server) = create_mock_stream();
        client.write_immediate(test_input).unwrap();

        let result = read_client_request(&mut server, &AuthMethod::NoAuth).await;

        let err = result.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);
        assert_eq!(
            err.get_ref().unwrap().downcast_ref::<HttpError>().unwrap(),
            &HttpError::OnlyConnectSupported
        );
    }

    #[tokio::test]
    async fn test_read_client_request_very_large_header() {
        // Construct a request with extremely large header (exceeding MAX_HEADER_SIZE bytes)
        let mut large_header = Vec::with_capacity(10000);
        large_header
            .extend_from_slice(b"CONNECT example.com:80 HTTP/1.1\r\nHost: example.com:80\r\n");
        large_header.extend_from_slice(b"X-Custom-Header: ");
        large_header.extend_from_slice(&vec![b'A'; MAX_HEADER_SIZE]);
        large_header.extend_from_slice(b"\r\n\r\n");

        let (client, mut server) = create_mock_stream();
        client.write_immediate(&large_header).unwrap();

        let result = read_client_request(&mut server, &AuthMethod::NoAuth).await;

        let err = result.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);
        assert_eq!(
            err.get_ref().unwrap().downcast_ref::<HttpError>().unwrap(),
            &HttpError::HeaderTooLong
        );
    }

    #[tokio::test]
    async fn test_read_client_request_incomplete_header() {
        // Write incomplete header without the final \r\n
        let test_input = b"CONNECT example.com:80 HTTP/1.1\r\nHost: example.com:80\r\n";

        let (mut client, mut server) = create_mock_stream();
        client.write_immediate(test_input).unwrap();

        // Close the connection to simulate incomplete header scenario
        client.shutdown().await.unwrap();

        let result = read_client_request(&mut server, &AuthMethod::NoAuth).await;

        let err = result.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::UnexpectedEof);
        assert_eq!(
            err.get_ref().unwrap().downcast_ref::<HttpError>().unwrap(),
            &HttpError::ConnectionClosedHeaderIncomplete
        );
    }

    #[tokio::test]
    async fn test_read_client_request_no_auth_but_required() {
        // Construct a normal CONNECT request without auth header
        let test_input = b"CONNECT example.com:80 HTTP/1.1\r\nHost: example.com:80\r\n\r\n";

        let (client, mut server) = create_mock_stream();
        client.write_immediate(test_input).unwrap();

        // Request should be rejected because auth is required
        let auth_method = AuthMethod::UserPass {
            username: "user".to_string(),
            password: "pass".to_string(),
        };

        let result = read_client_request(&mut server, &auth_method).await;

        let err = result.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::PermissionDenied);
        assert_eq!(
            err.get_ref().unwrap().downcast_ref::<HttpError>().unwrap(),
            &HttpError::AuthenticationRequired
        );
    }

    #[tokio::test]
    async fn test_read_client_request_non_basic_auth() {
        // Construct a request with non-Basic authentication
        let test_input = b"CONNECT example.com:80 HTTP/1.1\r\n\
        Host: example.com:80\r\n\
        Proxy-Authorization: Digest username=\"user\", realm=\"proxy\"\r\n\r\n";

        let (client, mut server) = create_mock_stream();
        client.write_immediate(test_input).unwrap();

        // Auth method requires Basic auth
        let auth_method = AuthMethod::UserPass {
            username: "user".to_string(),
            password: "pass".to_string(),
        };

        let result = read_client_request(&mut server, &auth_method).await;

        let err = result.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::PermissionDenied);
        assert_eq!(
            err.get_ref().unwrap().downcast_ref::<HttpError>().unwrap(),
            &HttpError::OnlyBasicAuthSupported
        );
    }

    #[tokio::test]
    async fn test_read_client_request_invalid_base64() {
        // Construct a request with invalid Base64 in auth header
        let test_input = b"CONNECT example.com:80 HTTP/1.1\r\n\
        Host: example.com:80\r\n\
        Proxy-Authorization: Basic !@#$%^&*\r\n\r\n";

        let (client, mut server) = create_mock_stream();
        client.write_immediate(test_input).unwrap();

        // Auth method requires Basic auth
        let auth_method = AuthMethod::UserPass {
            username: "user".to_string(),
            password: "pass".to_string(),
        };

        let result = read_client_request(&mut server, &auth_method).await;

        let err = result.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);
        assert_eq!(
            err.get_ref().unwrap().downcast_ref::<HttpError>().unwrap(),
            &HttpError::InvalidBase64Encoding
        );
    }

    #[tokio::test]
    async fn test_read_client_request_invalid_credentials() {
        // Encode invalid credentials in Base64
        let encoded = STANDARD.encode("wrong:credentials");

        // Construct a request with valid Base64 but wrong credentials
        let request = format!(
            "CONNECT example.com:80 HTTP/1.1\r\n\
        Host: example.com:80\r\n\
        Proxy-Authorization: Basic {}\r\n\r\n",
            encoded
        );

        let (client, mut server) = create_mock_stream();
        client.write_immediate(request.as_bytes()).unwrap();

        // Auth method requires specific credentials
        let auth_method = AuthMethod::UserPass {
            username: "user".to_string(),
            password: "pass".to_string(),
        };

        let result = read_client_request(&mut server, &auth_method).await;

        let err = result.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::PermissionDenied);
        assert_eq!(
            err.get_ref().unwrap().downcast_ref::<HttpError>().unwrap(),
            &HttpError::InvalidCredentials
        );
    }

    #[tokio::test]
    async fn test_read_server_response_missing_status_code() {
        // Construct a response with missing status code
        let test_input = b"HTTP/1.1 OK\r\nContent-Length: 0\r\n\r\n";

        let (client, mut server) = create_mock_stream();
        client.write_immediate(test_input).unwrap();

        let result = read_server_response(&mut server).await;

        let err = result.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);
        assert!(matches!(
            err.get_ref().unwrap().downcast_ref::<HttpError>().unwrap(),
            &HttpError::ParseResponseFailed(_)
        ));
    }

    #[tokio::test]
    async fn test_read_server_response_http_error() {
        // Construct a response with error status code
        let test_input = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n";

        let (client, mut server) = create_mock_stream();
        client.write_immediate(test_input).unwrap();

        let result = read_server_response(&mut server).await;

        let err = result.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Other);

        // Check the error contains the status code and reason
        if let Some(http_err) = err.get_ref().unwrap().downcast_ref::<HttpError>() {
            match http_err {
                HttpError::HttpError(code, reason) => {
                    assert_eq!(*code, 403);
                    assert_eq!(reason, "Forbidden");
                }
                _ => panic!("Expected HttpError::HttpError variant"),
            }
        } else {
            panic!("Expected HttpError");
        }
    }

    #[tokio::test]
    async fn test_read_server_header_too_large() {
        // Construct a response with extremely large header
        let mut large_header = Vec::with_capacity(10000);
        large_header.extend_from_slice(b"HTTP/1.1 200 OK\r\n");
        large_header.extend_from_slice(b"X-Custom-Header: ");
        large_header.extend_from_slice(&vec![b'A'; MAX_HEADER_SIZE]);
        large_header.extend_from_slice(b"\r\n\r\n");

        let (client, mut server) = create_mock_stream();
        client.write_immediate(&large_header).unwrap();

        let result = read_server_response(&mut server).await;

        let err = result.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);
        assert_eq!(
            err.get_ref().unwrap().downcast_ref::<HttpError>().unwrap(),
            &HttpError::HeaderTooLong
        );
    }

    #[tokio::test]
    async fn test_read_server_response_incomplete_header() {
        // Write incomplete header without the final \r\n
        let test_input = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n";

        let (mut client, mut server) = create_mock_stream();
        client.write_immediate(test_input).unwrap();

        // Close the connection to simulate incomplete header scenario
        client.shutdown().await.unwrap();

        let result = read_server_response(&mut server).await;

        let err = result.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::UnexpectedEof);
        assert_eq!(
            err.get_ref().unwrap().downcast_ref::<HttpError>().unwrap(),
            &HttpError::ConnectionClosedHeaderIncomplete
        );
    }
}
