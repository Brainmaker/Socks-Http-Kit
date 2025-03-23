//! A lightweight library for SOCKS5 and HTTP proxy protocol encoding and parsing,
//! designed to facilitate complex proxy applications.
//!
//! This library serves as a foundation layer for higher-level proxy protocols.
//! It provides a set of Tokio-based asynchronous functions specifically for
//! parsing and processing SOCKS5 and HTTP proxy protocol requests and responses.
//! The library employs I/O-agnostic design, meaning it doesn't spawn internal
//! threads, establish network connections, or perform DNS resolution.
//! Instead, it delegates these controls entirely to the user code,
//! enabling flexible integration with various proxy applications.
//!
//! Socks-Http-Kit supports:
//!
//! - SOCKS5 client and server implementations
//!     - Full support for CONNECT, BIND, and UDP_ASSOCIATE commands.
//!     - Username/password authentication mechanism.
//!
//! - HTTP proxy client and server implementations.
//!     - HTTP BASIC authentication support.
//!
//! ### SOCKS5
//!
//! - Use [`socks5_connect`] to send handshake to SOCKS5 servers,
//!   with optional authentication information.
//! - Use [`socks5_accept`] to receive and parse handshake from SOCKS5 clients,
//!   returning the SOCKS5 command type and target address.
//! - Use [`socks5_finalize_accept`] to send request processing results back
//!   to SOCKS5 clients, completing the handshake process.
//! - [`socks5_read_udp_header`] parses SOCKS5 UDP protocol headers from
//!   UDP packet buffers.
//! - [`socks5_write_udp_header`] writes SOCKS5 UDP protocol headers to
//!   specified buffers.
//!
//! ### HTTP
//!
//! - Use [`http_connect`] to send handshake to HTTP proxy servers,
//!   with optional authentication information.
//! - Use [`http_accept`] to receive and parse handshake from HTTP clients,
//!   extracting target address information.
//! - Use [`http_finalize_accept`] to send processing results back to HTTP clients,
//!   completing the proxy handshake process.
//!
//! ### Address
//!
//! - [`decode_from_reader`] and [`encode_to_writer`] provide functionality
//!   to decode/encode SOCKS5-style addresses from asynchronous streams.
//! - [`decode_from_buf`] and [`encode_to_buf`] support decoding/encoding
//!   SOCKS5-style addresses in memory buffers, suitable for UDP transport and similar scenarios.
//!
//! # Cargo Features
//! The library provides two optional features, both disabled by default:
//!
//! - `socks5`: Enables SOCKS5 proxy protocol functionality, including client
//!   and server communication, authentication, and UDP parsing and encoding functions.
//! - `http`: Enables HTTP proxy protocol functionality.
//!
//! [`decode_from_reader`]: Address::decode_from_reader
//! [`encode_to_writer`]: Address::encode_to_writer
//! [`decode_from_buf`]: Address::decode_from_buf
//! [`encode_to_buf`]: Address::encode_to_buf
#![warn(missing_debug_implementations, missing_docs, unreachable_pub)]
#![cfg_attr(docsrs, feature(doc_cfg))]
use std::{
    fmt::{Display, Formatter},
    io::{Error, ErrorKind, Result},
    net::{Ipv4Addr, Ipv6Addr},
    result,
};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[cfg(feature = "http")]
mod http;

#[cfg(feature = "socks5")]
mod socks5;

#[cfg(test)]
#[doc(hidden)]
pub mod test_utils;

#[cfg(feature = "http")]
#[cfg_attr(docsrs, doc(cfg(feature = "http")))]
pub use http::{HttpError, HttpReply, http_accept, http_connect, http_finalize_accept};
#[cfg(feature = "socks5")]
#[cfg_attr(docsrs, doc(cfg(feature = "socks5")))]
pub use socks5::{
    Socks5Command,
    Socks5Error,
    Socks5Reply,
    socks5_accept,
    socks5_connect,
    socks5_finalize_accept,
    socks5_read_udp_header,
    socks5_write_udp_header,
};

/// Represents a network address in various supported formats.
///
/// This enum is used to specify target addresses for SOCKS5 and HTTP proxy connections,
/// supporting IPv4, IPv6, and domain name address types as defined in RFC 1928.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum Address {
    /// An IPv4 address with a port number.
    IPv4((Ipv4Addr, u16)),

    /// A domain name with a port number.
    DomainName((String, u16)),

    /// An IPv6 address with a port number.
    IPv6((Ipv6Addr, u16)),
}

impl Address {
    /// Decodes a SOCKS5-like address from an asynchronous reader.
    ///
    /// This method reads a network address from the provided asynchronous reader using the
    /// SOCKS5 address format (RFC 1928). It reads the address type byte, followed by the
    /// appropriate address data and port number.
    ///
    /// According to RFC 1928, SOCKS5 address format is:
    /// ```text
    /// +------+----------+----------+
    /// | ATYP | DST.ADDR | DST.PORT |
    /// +------+----------+----------+
    /// |  1   | Variable |    2     |
    /// +------+----------+----------+
    /// ```
    /// `ATYP`: Address type - 0x01 (IPv4), 0x03 (domain name), 0x04 (IPv6)
    ///
    /// `ADDR`: Destination address, format depends on ATYP
    ///
    /// `PORT`: Destination port, network byte order (big-endian)
    pub async fn decode_from_reader<T>(reader: &mut T) -> Result<(Self, usize)>
    where
        T: AsyncRead + Unpin,
    {
        let addr_type = AddressType::try_from(reader.read_u8().await?)?;
        match addr_type {
            AddressType::IPv4 => {
                let mut ip = [0u8; 4];
                reader.read_exact(&mut ip).await?;
                let port = reader.read_u16().await?;

                // len(addr_type) + len(ip) + len(port)
                Ok((Address::IPv4((Ipv4Addr::from(ip), port)), 1 + 4 + 2))
            }
            AddressType::DomainName => {
                let len = reader.read_u8().await? as usize;
                let mut domain = vec![0u8; len];
                reader.read_exact(&mut domain).await?;
                let domain_str =
                    String::from_utf8(domain).map_err(|_| AddrError::InvalidDomainNameEncoding)?;
                let port = reader.read_u16().await?;

                // len(addr_type) + len(domain_len) + len(domain) + len(port)
                Ok((Address::DomainName((domain_str, port)), 1 + 1 + len + 2))
            }
            AddressType::IPv6 => {
                let mut ip = [0u8; 16];
                reader.read_exact(&mut ip).await?;
                let port = reader.read_u16().await?;

                // len(addr_type) + len(ip) + len(port)
                Ok((Address::IPv6((Ipv6Addr::from(ip), port)), 1 + 16 + 2))
            }
        }
    }

    /// Encodes the address to a SOCKS5-like format and writes it to an asynchronous writer.
    pub async fn encode_to_writer<T>(&self, writer: &mut T) -> Result<usize>
    where
        T: AsyncWrite + Unpin,
    {
        match self {
            Address::IPv4((ip, port)) => {
                writer.write_u8(AddressType::IPv4 as u8).await?;
                writer.write_all(&ip.octets()).await?;
                writer.write_u16(*port).await?;
                Ok(1 + 4 + 2)
            }
            Address::DomainName((domain, port)) => {
                let domain_bytes = domain.as_bytes();
                if domain_bytes.len() > 255 {
                    return Err(AddrError::DomainNameTooLong.into());
                }
                writer.write_u8(AddressType::DomainName as u8).await?;
                writer.write_u8(domain_bytes.len() as u8).await?;
                writer.write_all(domain_bytes).await?;
                writer.write_u16(*port).await?;
                Ok(1 + 1 + domain_bytes.len() + 2)
            }
            Address::IPv6((ip, port)) => {
                writer.write_u8(AddressType::IPv6 as u8).await?;
                writer.write_all(&ip.octets()).await?;
                writer.write_u16(*port).await?;
                Ok(1 + 16 + 2)
            }
        }
    }

    /// Decodes a SOCKS5-like address from a byte buffer.
    pub fn decode_from_buf(buf: &[u8]) -> Result<(Self, usize)> {
        let mut cursor = Cursor::new(buf);

        let addr_type = AddressType::try_from(cursor.read_u8()?)?;
        match addr_type {
            AddressType::IPv4 => {
                let mut ip = [0u8; 4];
                cursor.read_slice(&mut ip)?;
                let port = cursor.read_u16()?;

                // len(addr_type) + len(ip) + len(port)
                Ok((Address::IPv4((Ipv4Addr::from(ip), port)), 1 + 4 + 2))
            }
            AddressType::DomainName => {
                let len = cursor.read_u8()? as usize;
                let mut domain = vec![0u8; len];
                cursor.read_slice(&mut domain)?;
                let domain_str =
                    String::from_utf8(domain).map_err(|_| AddrError::InvalidDomainNameEncoding)?;
                let port = cursor.read_u16()?;

                // len(addr_type) + len(domain_len) + len(domain) + len(port)
                Ok((Address::DomainName((domain_str, port)), 1 + 1 + len + 2))
            }
            AddressType::IPv6 => {
                let mut ip = [0u8; 16];
                cursor.read_slice(&mut ip)?;
                let port = cursor.read_u16()?;

                // len(addr_type) + len(ip) + len(port)
                Ok((Address::IPv6((Ipv6Addr::from(ip), port)), 1 + 16 + 2))
            }
        }
    }

    /// Encodes the address to a SOCKS5-like format and writes it to a byte buffer.
    pub fn encode_to_buf(&self, buf: &mut [u8]) -> Result<usize> {
        let mut cursor = CursorMut::new(buf);
        match self {
            Address::IPv4((ip, port)) => {
                cursor.write_u8(AddressType::IPv4 as u8)?;
                cursor.write_slice(&ip.octets())?;
                cursor.write_u16(*port)?;
                Ok(1 + 4 + 2)
            }
            Address::DomainName((domain, port)) => {
                let domain_bytes = domain.as_bytes();
                if domain_bytes.len() > 255 {
                    return Err(AddrError::DomainNameTooLong.into());
                }
                cursor.write_u8(AddressType::DomainName as u8)?;
                cursor.write_u8(domain_bytes.len() as u8)?;
                cursor.write_slice(domain_bytes)?;
                cursor.write_u16(*port)?;
                Ok(1 + 1 + domain_bytes.len() + 2)
            }
            Address::IPv6((ip, port)) => {
                cursor.write_u8(AddressType::IPv6 as u8)?;
                cursor.write_slice(&ip.octets())?;
                cursor.write_u16(*port)?;
                Ok(1 + 16 + 2)
            }
        }
    }
}

impl From<Address> for String {
    /// Converts an `Address` into an HTTP-style text representation.
    ///
    /// This implementation formats the address in HTTP-style notation:
    /// - IPv4: "`192.168.1.1:8080`"
    /// - IPv6: "`[2001:db8::1]:8080`"
    /// - Domain: "`example.com:443`"
    ///
    /// This format is suitable for use in HTTP headers and other textual representations.
    fn from(value: Address) -> Self {
        (&value).into()
    }
}

impl From<&Address> for String {
    /// Converts an `&Address` into an HTTP-style text representation.
    fn from(address: &Address) -> Self {
        match address {
            Address::IPv4((ip, port)) => format!("{}:{}", ip, port),
            // IPv6 addresses need to be enclosed in square brackets
            Address::IPv6((ip, port)) => format!("[{}]:{}", ip, port),
            Address::DomainName((domain, port)) => format!("{}:{}", domain, port),
        }
    }
}

impl TryFrom<String> for Address {
    type Error = AddrError;

    /// Attempts to parse an HTTP-style text address into an `Address`.
    fn try_from(value: String) -> result::Result<Self, Self::Error> {
        Address::try_from(value.as_str())
    }
}

impl TryFrom<&str> for Address {
    type Error = AddrError;

    /// Attempts to parse an HTTP-style text address into an `Address`.
    fn try_from(string: &str) -> result::Result<Self, Self::Error> {
        if string.starts_with('[') {
            // IPv6 format: [IPv6]:port
            let end_bracket_pos = string
                .rfind(']')
                .ok_or(AddrError::InvalidIPv6MissingClosingBracket)?;

            if end_bracket_pos + 1 >= string.len()
                || &string[end_bracket_pos + 1..end_bracket_pos + 2] != ":"
            {
                return Err(AddrError::InvalidIPv6MissingPortSeparator);
            }

            let host = &string[1..end_bracket_pos]; // Remove brackets
            let port_str = &string[end_bracket_pos + 2..];

            // Parse port and IPv6 address
            let port = port_str
                .parse::<u16>()
                .map_err(|_| AddrError::InvalidPortNumber)?;
            let ipv6 = host
                .parse::<Ipv6Addr>()
                .map_err(|_| AddrError::InvalidIPv6Address)?;

            Ok(Address::IPv6((ipv6, port)))
        } else {
            // IPv4 or domain name format: host:port
            let last_colon_pos = string
                .rfind(':')
                .ok_or(AddrError::InvalidTargetAddressMissingPortSeparator)?;

            let host = &string[0..last_colon_pos];
            let port_str = &string[last_colon_pos + 1..];

            // Parse port
            let port = port_str
                .parse::<u16>()
                .map_err(|_| AddrError::InvalidPortNumber)?;

            // Try to parse as IPv4 address, otherwise treat as domain name
            if let Ok(ipv4) = host.parse::<Ipv4Addr>() {
                Ok(Address::IPv4((ipv4, port)))
            } else {
                Ok(Address::DomainName((host.to_string(), port)))
            }
        }
    }
}

/// Authentication methods supported by the proxy protocol.
///
/// This enum represents the authentication methods that can be used
/// for SOCKS5 (as defined in RFC 1928 and RFC 1929) and HTTP proxy protocols.
#[derive(Clone, Debug, Default, Eq, PartialEq, Hash)]
pub enum AuthMethod {
    /// No authentication required. This is the default method.
    #[default]
    NoAuth,
    /// Username and password authentication.
    UserPass {
        /// Username. Must be a valid UTF-8 string with length not exceeding 255 bytes.
        username: String,

        /// Password. Must be a valid UTF-8 string with length not exceeding 255 bytes.
        password: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum AddressType {
    IPv4 = 0x01,
    DomainName = 0x03,
    IPv6 = 0x04,
}

impl TryFrom<u8> for AddressType {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0x01 => Ok(AddressType::IPv4),
            0x03 => Ok(AddressType::DomainName),
            0x04 => Ok(AddressType::IPv6),
            _ => Err(AddrError::UnsupportedAddressType.into()),
        }
    }
}

/// Errors that can occur address decoding operations.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum AddrError {
    /// The address type byte is not a supported address type.
    UnsupportedAddressType,
    /// The domain name exceeds maximum allowed length (255 bytes).
    DomainNameTooLong,
    /// The domain name contains invalid UTF-8 encoding.
    InvalidDomainNameEncoding,

    /// IPv6 address format is missing the closing bracket.
    InvalidIPv6MissingClosingBracket,
    /// IPv6 address format is missing the port separator after the closing bracket.
    InvalidIPv6MissingPortSeparator,
    /// Target address is missing the port separator.
    InvalidTargetAddressMissingPortSeparator,
    /// Port number is not a valid integer between 0-65535.
    InvalidPortNumber,
    /// IPv6 address contains invalid format or characters.
    InvalidIPv6Address,
}

impl Display for AddrError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedAddressType => write!(f, "Unsupported address type"),
            Self::DomainNameTooLong => write!(f, "Domain name too long"),
            Self::InvalidDomainNameEncoding => write!(f, "Invalid domain name encoding"),
            Self::InvalidIPv6MissingClosingBracket => {
                write!(f, "Invalid IPv6 address format: missing closing bracket")
            }
            Self::InvalidIPv6MissingPortSeparator => {
                write!(f, "Invalid IPv6 address format: missing port separator")
            }
            Self::InvalidTargetAddressMissingPortSeparator => {
                write!(f, "Invalid target address format: missing port separator")
            }
            Self::InvalidPortNumber => write!(f, "Invalid port number"),
            Self::InvalidIPv6Address => write!(f, "Invalid IPv6 address"),
        }
    }
}

impl std::error::Error for AddrError {}

impl From<AddrError> for Error {
    fn from(e: AddrError) -> Self {
        match e {
            AddrError::UnsupportedAddressType => Error::new(ErrorKind::InvalidData, e),
            AddrError::DomainNameTooLong => Error::new(ErrorKind::InvalidInput, e),
            AddrError::InvalidDomainNameEncoding => Error::new(ErrorKind::InvalidData, e),
            AddrError::InvalidIPv6MissingClosingBracket => Error::new(ErrorKind::InvalidData, e),
            AddrError::InvalidIPv6MissingPortSeparator => Error::new(ErrorKind::InvalidData, e),
            AddrError::InvalidTargetAddressMissingPortSeparator => {
                Error::new(ErrorKind::InvalidData, e)
            }
            AddrError::InvalidPortNumber => Error::new(ErrorKind::InvalidData, e),
            AddrError::InvalidIPv6Address => Error::new(ErrorKind::InvalidData, e),
        }
    }
}

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn read_u8(&mut self) -> Result<u8> {
        let p = self
            .buf
            .get(self.pos)
            .ok_or(Error::new(ErrorKind::UnexpectedEof, "buffer underflow"))?;
        self.pos += 1;
        Ok(*p)
    }

    fn read_u16(&mut self) -> Result<u16> {
        let p = self
            .buf
            .get(self.pos..self.pos + 2)
            .ok_or(Error::new(ErrorKind::UnexpectedEof, "buffer underflow"))?;
        self.pos += 2;
        Ok(u16::from_be_bytes(p.try_into().unwrap()))
    }

    fn read_slice(&mut self, buf: &mut [u8]) -> Result<()> {
        let p = self
            .buf
            .get(self.pos..self.pos + buf.len())
            .ok_or(Error::new(ErrorKind::UnexpectedEof, "buffer underflow"))?;
        self.pos += buf.len();
        buf.copy_from_slice(p);
        Ok(())
    }
}

struct CursorMut<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> CursorMut<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn write_u8(&mut self, value: u8) -> Result<()> {
        let p = self
            .buf
            .get_mut(self.pos)
            .ok_or(Error::new(ErrorKind::WriteZero, "buffer overflow"))?;
        *p = value;
        self.pos += 1;
        Ok(())
    }

    fn write_u16(&mut self, value: u16) -> Result<()> {
        let p = self
            .buf
            .get_mut(self.pos..self.pos + 2)
            .ok_or(Error::new(ErrorKind::WriteZero, "buffer overflow"))?;
        p.copy_from_slice(&value.to_be_bytes());
        self.pos += 2;
        Ok(())
    }

    fn write_slice(&mut self, value: &[u8]) -> Result<()> {
        let p = self
            .buf
            .get_mut(self.pos..self.pos + value.len())
            .ok_or(Error::new(ErrorKind::WriteZero, "buffer overflow"))?;
        p.copy_from_slice(value);
        self.pos += value.len();
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use std::net::Ipv4Addr;

    use tokio::task;

    use super::*;
    use crate::test_utils::*;

    #[tokio::test]
    async fn test_http_connect_accept_finalize_no_auth() {
        let target_addresses = [
            Address::IPv4((Ipv4Addr::new(192, 168, 1, 1), 8080)),
            Address::DomainName(("example.com".to_string(), 443)),
            Address::IPv6((
                Ipv6Addr::new(0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x01),
                8080,
            )),
        ];
        let auth_method = AuthMethod::NoAuth;

        for target in target_addresses {
            let (mut client_stream, mut server_stream) = create_mock_stream();

            let target_s = target.clone();
            let target_c = target.clone();
            let auth_s = auth_method.clone();
            let auth_c = auth_method.clone();

            let server_task = task::spawn(async move {
                let received_addr = http_accept(&mut server_stream, &auth_s).await?;
                assert_eq!(received_addr, target_s);

                http_finalize_accept(&mut server_stream, &HttpReply::Ok).await?;
                Ok::<_, Error>(())
            });

            let client_task = task::spawn(async move {
                http_connect(&mut client_stream, &target_c, &auth_c).await?;
                Ok::<_, Error>(())
            });

            let (server_result, client_result) = tokio::join!(server_task, client_task);
            server_result.unwrap().unwrap();
            client_result.unwrap().unwrap();
        }
    }

    #[tokio::test]
    async fn test_http_connect_accept_finalize_userpass() {
        let target_addresses = [
            Address::IPv4((Ipv4Addr::new(192, 168, 1, 1), 8080)),
            Address::DomainName(("example.com".to_string(), 443)),
            Address::IPv6((
                Ipv6Addr::new(0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x01),
                8080,
            )),
        ];
        let auth_method = AuthMethod::UserPass {
            username: "user".to_string(),
            password: "pass".to_string(),
        };

        for target in target_addresses {
            let (mut client_stream, mut server_stream) = create_mock_stream();

            let target_s = target.clone();
            let target_c = target.clone();
            let auth_s = auth_method.clone();
            let auth_c = auth_method.clone();

            let server_task = task::spawn(async move {
                let received_addr = http_accept(&mut server_stream, &auth_s).await?;
                assert_eq!(received_addr, target_s);

                http_finalize_accept(&mut server_stream, &HttpReply::Ok).await?;
                Ok::<_, Error>(())
            });

            let client_task = task::spawn(async move {
                http_connect(&mut client_stream, &target_c, &auth_c).await?;
                Ok::<_, Error>(())
            });

            let (server_result, client_result) = tokio::join!(server_task, client_task);
            server_result.unwrap().unwrap();
            client_result.unwrap().unwrap();
        }
    }

    #[tokio::test]
    async fn test_socks5_connect_accept_finalize_no_auth() {
        let target_addresses = [
            Address::IPv4((Ipv4Addr::new(192, 168, 1, 1), 8080)),
            Address::DomainName(("example.com".to_string(), 443)),
            Address::IPv6((
                Ipv6Addr::new(0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x01),
                8080,
            )),
        ];
        let auth_method = AuthMethod::NoAuth;
        let commands = [
            Socks5Command::Connect,
            Socks5Command::Bind,
            Socks5Command::UdpAssociate,
        ];

        for target in target_addresses {
            for commmand in commands {
                let (mut client_stream, mut server_stream) = create_mock_stream();

                let target_s = target.clone();
                let target_c = target.clone();
                let auth_s = auth_method.clone();
                let auth_c = auth_method.clone();

                let server_task = task::spawn(async move {
                    let (cmd, received_addr) = socks5_accept(&mut server_stream, &auth_s).await?;
                    assert_eq!(cmd, commmand);
                    assert_eq!(received_addr, target_s);

                    socks5_finalize_accept(
                        &mut server_stream,
                        &Socks5Reply::Succeeded,
                        &received_addr,
                    )
                    .await?;
                    Ok::<_, Error>(())
                });

                let client_task = task::spawn(async move {
                    let received_addr =
                        socks5_connect(&mut client_stream, &commmand, &target_c, &[auth_c]).await?;
                    assert_eq!(received_addr, target_c);
                    Ok::<_, Error>(())
                });

                let (server_result, client_result) = tokio::join!(server_task, client_task);
                server_result.unwrap().unwrap();
                client_result.unwrap().unwrap();
            }
        }
    }

    #[tokio::test]
    async fn test_socks5_connect_accept_finalize_userpass() {
        let target_addresses = [
            Address::IPv4((Ipv4Addr::new(192, 168, 1, 1), 8080)),
            Address::DomainName(("example.com".to_string(), 443)),
            Address::IPv6((
                Ipv6Addr::new(0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x01),
                8080,
            )),
        ];
        let auth_method = AuthMethod::UserPass {
            username: "user".to_string(),
            password: "pass".to_string(),
        };
        let commands = [
            Socks5Command::Connect,
            Socks5Command::Bind,
            Socks5Command::UdpAssociate,
        ];

        for target in target_addresses {
            for commmand in commands {
                let (mut client_stream, mut server_stream) = create_mock_stream();

                let target_s = target.clone();
                let target_c = target.clone();
                let auth_s = auth_method.clone();
                let auth_c = auth_method.clone();

                let server_task = task::spawn(async move {
                    let (cmd, received_addr) = socks5_accept(&mut server_stream, &auth_s).await?;
                    assert_eq!(cmd, commmand);
                    assert_eq!(received_addr, target_s);

                    socks5_finalize_accept(
                        &mut server_stream,
                        &Socks5Reply::Succeeded,
                        &received_addr,
                    )
                    .await?;
                    Ok::<_, Error>(())
                });

                let client_task = task::spawn(async move {
                    let received_addr =
                        socks5_connect(&mut client_stream, &commmand, &target_c, &[auth_c]).await?;
                    assert_eq!(received_addr, target_c);
                    Ok::<_, Error>(())
                });

                let (server_result, client_result) = tokio::join!(server_task, client_task);
                server_result.unwrap().unwrap();
                client_result.unwrap().unwrap();
            }
        }
    }

    #[test]
    fn test_socks5_udp_encode_decode() {
        let addresses = [
            Address::IPv4((Ipv4Addr::new(192, 168, 1, 1), 8080)),
            Address::DomainName(("example.com".to_string(), 443)),
            Address::IPv6((
                Ipv6Addr::new(0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x01),
                8080,
            )),
        ];

        for original_addr in addresses {
            let mut buffer = vec![0u8; 300];

            let write_len = socks5_write_udp_header(&original_addr, &mut buffer).unwrap();

            // Verify that the first 3 bytes of the header are [0, 0, 0]
            // (two reserved bytes and the fragment byte)
            assert_eq!(&buffer[0..3], &[0, 0, 0]);

            let (decoded_addr, read_len) = socks5_read_udp_header(&buffer).unwrap();

            assert_eq!(write_len, read_len);
            assert_eq!(original_addr, decoded_addr);
        }
    }

    #[tokio::test]
    async fn test_encode_decode_with_stream() {
        let addresses = [
            Address::IPv4((Ipv4Addr::new(192, 168, 1, 1), 8080)),
            Address::DomainName(("example.com".to_string(), 443)),
            Address::IPv6((
                Ipv6Addr::new(0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x01),
                8080,
            )),
        ];

        for original_addr in addresses {
            let (mut stream1, mut stream2) = create_mock_stream();

            let write_len = original_addr.encode_to_writer(&mut stream1).await.unwrap();
            let (decoded_addr, read_len) = Address::decode_from_reader(&mut stream2).await.unwrap();

            assert_eq!(write_len, read_len);
            assert_eq!(original_addr, decoded_addr);
        }
    }

    #[test]
    fn test_encode_decode_with_buffer() {
        let addresses = [
            Address::IPv4((Ipv4Addr::new(192, 168, 1, 1), 8080)),
            Address::DomainName(("example.com".to_string(), 443)),
            Address::IPv6((
                Ipv6Addr::new(0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x01),
                8080,
            )),
        ];

        for original_addr in addresses {
            let mut buffer = vec![0u8; 300];

            let write_len = original_addr.encode_to_buf(&mut buffer).unwrap();
            let (decoded_addr, read_len) = Address::decode_from_buf(&buffer).unwrap();

            assert_eq!(write_len, read_len);
            assert_eq!(original_addr, decoded_addr);
        }
    }

    #[test]
    fn test_encode_decode_text() {
        let address_pairs = [
            (
                Address::IPv4((Ipv4Addr::new(192, 168, 1, 1), 8080)),
                "192.168.1.1:8080",
            ),
            (
                Address::DomainName(("example.com".to_string(), 443)),
                "example.com:443",
            ),
            (
                Address::IPv6((
                    Ipv6Addr::new(0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x01),
                    8080,
                )),
                "[20:1:d:b8::1]:8080",
            ),
        ];

        for (addr, expected_str) in address_pairs {
            let addr_to_string = String::from(&addr);
            assert_eq!(addr_to_string, expected_str);

            let string_to_addr = Address::try_from(expected_str).unwrap();
            assert_eq!(string_to_addr, addr);

            let round_trip = Address::try_from(String::from(&addr)).unwrap();
            assert_eq!(round_trip, addr);
        }
    }
}
