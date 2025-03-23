use std::{
    fmt::{self, Display, Formatter},
    io::{Error, ErrorKind, Result},
};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{Address, AuthMethod};

const SOCKS5_VER: u8 = 0x05;
const SOCKS5_AUTH_VER: u8 = 0x01;

/// SOCKS5 commands as defined in RFC 1928 section 4.
///
/// These commands specify the type of proxy operation requested by the client:
/// - `CONNECT`: Establish a TCP/IP connection to the target.
/// - `BIND`: Request the server to bind to a port for incoming connections.
/// - `UDP_ASSOCIATE`: Establish a UDP relay.
///
/// Reference: <https://datatracker.ietf.org/doc/html/rfc1928#section-4>
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum Socks5Command {
    #[allow(missing_docs)]
    Connect = 0x01,
    #[allow(missing_docs)]
    Bind = 0x02,
    #[allow(missing_docs)]
    UdpAssociate = 0x03,
}

impl TryFrom<u8> for Socks5Command {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0x01 => Ok(Socks5Command::Connect),
            0x02 => Ok(Socks5Command::Bind),
            0x03 => Ok(Socks5Command::UdpAssociate),
            _ => Err(Socks5Error::InvalidCommand.into()),
        }
    }
}

/// SOCKS5 server reply codes as defined in RFC 1928 section 6.
///
/// These reply codes indicate the status of a client's request:
/// - Succeeded (0x00): Request granted.
/// - Various error codes (0x01-0x08): Different failure reasons.
///
/// Reference: <https://datatracker.ietf.org/doc/html/rfc1928#section-6>
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum Socks5Reply {
    #[allow(missing_docs)]
    Succeeded = 0x00,
    #[allow(missing_docs)]
    GeneralFailure = 0x01,
    #[allow(missing_docs)]
    ConnectionNotAllowed = 0x02,
    #[allow(missing_docs)]
    NetworkUnreachable = 0x03,
    #[allow(missing_docs)]
    HostUnreachable = 0x04,
    #[allow(missing_docs)]
    ConnectionRefused = 0x05,
    #[allow(missing_docs)]
    TTLExpired = 0x06,
    #[allow(missing_docs)]
    CommandNotSupported = 0x07,
    #[allow(missing_docs)]
    AddressTypeNotSupported = 0x08,
}

impl TryFrom<u8> for Socks5Reply {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0x00 => Ok(Socks5Reply::Succeeded),
            0x01 => Ok(Socks5Reply::GeneralFailure),
            0x02 => Ok(Socks5Reply::ConnectionNotAllowed),
            0x03 => Ok(Socks5Reply::NetworkUnreachable),
            0x04 => Ok(Socks5Reply::HostUnreachable),
            0x05 => Ok(Socks5Reply::ConnectionRefused),
            0x06 => Ok(Socks5Reply::TTLExpired),
            0x07 => Ok(Socks5Reply::CommandNotSupported),
            0x08 => Ok(Socks5Reply::AddressTypeNotSupported),
            _ => Err(Socks5Error::InvalidReply.into()),
        }
    }
}

/// Accepts a SOCKS5 proxy connection request from a client.
///
/// This function reads, responses and processes an SOCKS5 handshake from the client,
/// validates authentication if required, and extracts the command and target address.
///
/// # Arguments
/// * `stream` - A mutable reference to an asynchronous stream.
/// * `auth_method` - The authentication method required for this connection.
///
/// # Returns
/// * `Result<(Socks5Command, Address)>` - The requested command and target address on success,
///   or an error if the handshake fails, authentication fails, or the request is invalid.
pub async fn socks5_accept<T>(
    stream: &mut T,
    auth_method: &AuthMethod,
) -> Result<(Socks5Command, Address)>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    // Read client greeting
    let client_auth_method = read_client_hello(stream).await?;

    if !client_auth_method.contains(&auth_method.into()) {
        // Write server greeting
        write_server_hello(stream, &Socks5AuthOption::NoAcceptable).await?;
        return Err(Socks5Error::NoAcceptableAuthMethod.into());
    }

    // Write server greeting
    write_server_hello(stream, &auth_method.into()).await?;

    // Handle authentication
    match auth_method {
        AuthMethod::NoAuth => (), // No authentication required
        AuthMethod::UserPass { username, password } => {
            let auth = read_auth_request(stream).await?;
            if &auth.username != username || &auth.password != password {
                write_auth_response(stream, false).await?;
                return Err(Socks5Error::AuthenticationFailed.into());
            } else {
                write_auth_response(stream, true).await?;
            }
        }
    }

    // Read connection request
    let (command, address) = read_connection_request(stream).await?;
    Ok((command, address))
}

/// Completes a SOCKS5 proxy connection by sending a reply to the client.
///
/// After processing a client's SOCKS5 connection request with `socks5_accept`,
/// this function sends the appropriate response to indicate success or failure.
///
/// # Arguments
/// * `stream` - A mutable reference to an asynchronous stream.
/// * `reply` - The SOCKS5 reply code to send to the client.
/// * `address` - The bound address to include in the response.
///
/// # Returns
/// * `Result<()>` - Success if the response is sent, or an IO error if writing fails.
pub async fn socks5_finalize_accept<T>(
    stream: &mut T,
    reply: &Socks5Reply,
    address: &Address,
) -> Result<()>
where
    T: AsyncWrite + Unpin,
{
    // Write connection response
    write_connection_response(stream, reply, address).await?;

    Ok(())
}

/// Establishes a SOCKS5 proxy connection to a target server.
///
/// This function sends an SOCKS5 handshake to a proxy server with the specified
/// target address and authentication credentials, then verifies the response.
///
/// # Arguments
/// * `stream` - A mutable reference to an asynchronous stream.
/// * `command` - The SOCKS5 command to execute (Connect, Bind, or UdpAssociate).
/// * `address` - The target address to connect to.
/// * `auth` - An array of supported authentication methods.
///
/// # Returns
/// * `Result<Address>` - The bound address returned by the server on success,
///   or an error if the connection fails or is rejected by the server.
pub async fn socks5_connect<T>(
    stream: &mut T,
    command: &Socks5Command,
    address: &Address,
    auth: &[AuthMethod],
) -> Result<Address>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let client_auth_methods = auth.iter().map(|a| a.into()).collect::<Vec<_>>();
    if client_auth_methods.len() > 255 {
        return Err(Socks5Error::TooManyAuthMethods.into());
    }

    // Write client greeting
    write_client_hello(stream, &client_auth_methods).await?;

    // Read server greeting
    let server_auth_method = read_server_hello(stream).await?;

    let auth_method = match client_auth_methods
        .iter()
        .position(|c| c == &server_auth_method)
    {
        Some(i) => auth[i].clone(),
        None => {
            return Err(Socks5Error::NoAcceptableAuthMethod.into());
        }
    };

    // Handle authentication
    match auth_method {
        AuthMethod::NoAuth => (), // No authentication required
        AuthMethod::UserPass { username, password } => {
            write_auth_request(stream, &UserPassAuth { username, password }).await?;
            read_auth_response(stream).await?;
        }
    }

    // Write connection request
    write_connection_request(stream, command, address).await?;

    // Read connection response
    let (reply, address) = read_connection_response(stream).await?;

    // Handle connection response
    if reply != Socks5Reply::Succeeded {
        return Err(Socks5Error::ConnectionFailed.into());
    }

    Ok(address)
}

/// Reads and parses the SOCKS5 UDP header information and destination address from a UDP packet buffer.
///
/// Per RFC 1928 Section 7, SOCKS5 UDP requests/responses contain a header in the following format:
/// ```text
/// +----+------+------+----------+----------+----------+
/// |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
/// +----+------+------+----------+----------+----------+
/// | 2  |  1   |  1   | Variable |    2     | Variable |
/// +----+------+------+----------+----------+----------+
/// ```
/// RSV: Reserved field, must be 0
/// FRAG: Fragment number (currently unused, set to 0)
/// ATYP/DST.ADDR/DST.PORT: Destination address encoded in the same format as SOCKS5 requests
///
/// # Arguments
/// * `buf` - A buffer slice containing the UDP packet
///
/// # Returns
/// * `Result<(Address, usize)>` - On success, returns the parsed destination
///   address and the total header length in bytes, or an IO error on failure
///
pub fn socks5_read_udp_header(buf: &[u8]) -> Result<(Address, usize)> {
    let first = buf
        .first_chunk::<3>()
        .ok_or(Error::new(ErrorKind::UnexpectedEof, "buffer too short"))?;
    if first != &[0, 0, 0] {
        return Err(Error::new(ErrorKind::InvalidData, "invalid UDP header"));
    }
    let (address, len) = Address::decode_from_buf(&buf[3..])?;
    Ok((address, 2 + 1 + len))
}

/// Writes the SOCKS5 UDP header and destination address into a buffer.
///
/// # Arguments
/// * `address` - The destination address to encode
/// * `buf` - A mutable buffer slice to write the UDP header into
///
/// # Returns
/// * `Result<usize>` - On success, returns the total header length written in bytes,
///   or an IO error on failure
///
pub fn socks5_write_udp_header(address: &Address, buf: &mut [u8]) -> Result<usize> {
    let first = buf
        .first_chunk_mut::<3>()
        .ok_or(Error::new(ErrorKind::UnexpectedEof, "buffer too short"))?;
    *first = [0, 0, 0];
    let len = address.encode_to_buf(&mut buf[3..])?;
    Ok(2 + 1 + len)
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum Socks5AuthOption {
    NoAuth = 0x00,
    GssApi = 0x01,
    UserPass = 0x02,
    NoAcceptable = 0xFF,
}

impl TryFrom<u8> for Socks5AuthOption {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0x00 => Ok(Socks5AuthOption::NoAuth),
            0x01 => Ok(Socks5AuthOption::GssApi),
            0x02 => Ok(Socks5AuthOption::UserPass),
            0xFF => Ok(Socks5AuthOption::NoAcceptable),
            _ => Err(Socks5Error::InvalidAuthMethod.into()),
        }
    }
}

impl From<&AuthMethod> for Socks5AuthOption {
    fn from(value: &AuthMethod) -> Self {
        match value {
            AuthMethod::NoAuth => Socks5AuthOption::NoAuth,
            AuthMethod::UserPass { .. } => Socks5AuthOption::UserPass,
        }
    }
}

#[derive(Debug)]
struct UserPassAuth {
    username: String,
    password: String,
}

/// According to RFC 1928, client hello format is:
/// ```text
/// +----+----------+----------+
/// |VER | NMETHODS | METHODS  |
/// +----+----------+----------+
/// | 1  |    1     | 1 to 255 |
/// +----+----------+----------+
/// ```
/// VER: SOCKS protocol version, must be 0x05
/// NMETHODS: Number of authentication methods supported by client
/// METHODS: List of authentication methods supported by client
async fn read_client_hello<T>(reader: &mut T) -> Result<Vec<Socks5AuthOption>>
where
    T: AsyncRead + Unpin,
{
    // Read version number
    let ver = reader.read_u8().await?;
    if ver != SOCKS5_VER {
        return Err(Socks5Error::InvalidSocksVersion.into());
    }

    // Read number of authentication methods
    let nmethods = reader.read_u8().await?;
    if nmethods == 0 {
        return Err(Socks5Error::NoAuthMethods.into());
    }

    // Read authentication methods list
    let mut methods = Vec::with_capacity(nmethods as usize);
    for _ in 0..nmethods {
        let method_byte = reader.read_u8().await?;
        match Socks5AuthOption::try_from(method_byte) {
            Ok(method) => methods.push(method),
            Err(_) => continue, // Ignore unsupported authentication methods
        }
    }

    if methods.is_empty() {
        return Err(Socks5Error::NoSupportedAuthMethods.into());
    }

    Ok(methods)
}

async fn write_client_hello<T>(writer: &mut T, auth_method: &[Socks5AuthOption]) -> Result<()>
where
    T: AsyncWrite + Unpin,
{
    if auth_method.is_empty() {
        return Err(Socks5Error::NoAuthMethods.into());
    }

    // Write version number
    writer.write_u8(SOCKS5_VER).await?;

    // Write number of authentication methods
    writer.write_u8(auth_method.len() as u8).await?;

    // Write authentication methods list
    for method in auth_method {
        writer.write_u8(*method as u8).await?;
    }

    writer.flush().await?;
    Ok(())
}

/// According to RFC 1928, server hello format is:
/// ```text
/// +----+--------+
/// |VER | METHOD |
/// +----+--------+
/// | 1  |   1    |
/// +----+--------+
/// ```
/// VER: SOCKS protocol version, must be 0x05
/// METHOD: Server's selected authentication method, 0xFF means none of the client's methods are acceptable
async fn read_server_hello<T>(reader: &mut T) -> Result<Socks5AuthOption>
where
    T: AsyncRead + Unpin,
{
    // Read version number
    let ver = reader.read_u8().await?;
    if ver != SOCKS5_VER {
        return Err(Socks5Error::InvalidSocksVersion.into());
    }

    // Read server's selected authentication method
    let method_byte = reader.read_u8().await?;
    Socks5AuthOption::try_from(method_byte)
}

async fn write_server_hello<T>(writer: &mut T, auth_method: &Socks5AuthOption) -> Result<()>
where
    T: AsyncWrite + Unpin,
{
    // Write version number
    writer.write_u8(SOCKS5_VER).await?;

    // Write selected authentication method
    writer.write_u8(*auth_method as u8).await?;

    writer.flush().await?;
    Ok(())
}

/// According to RFC 1929, username/password authentication request format is:
/// ```text
/// +----+------+----------+------+----------+
/// |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
/// +----+------+----------+------+----------+
/// | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
/// +----+------+----------+------+----------+
/// ```
/// VER: Authentication sub-protocol version, must be 0x01.
/// ULEN: Username length (1-255 bytes).
/// UNAME: Username.
/// PLEN: Password length (1-255 bytes).
/// PASSWD: Password.
async fn read_auth_request<T>(reader: &mut T) -> Result<UserPassAuth>
where
    T: AsyncRead + Unpin,
{
    // Read authentication sub-protocol version number
    let ver = reader.read_u8().await?;
    if ver != SOCKS5_AUTH_VER {
        return Err(Socks5Error::InvalidAuthVersion.into());
    }

    // Read username
    let ulen = reader.read_u8().await? as usize;
    let mut uname = vec![0u8; ulen];
    reader.read_exact(&mut uname).await?;
    let username = String::from_utf8(uname).map_err(|_| Socks5Error::InvalidUsernameEncoding)?;

    // Read password
    let plen = reader.read_u8().await? as usize;
    let mut passwd = vec![0u8; plen];
    reader.read_exact(&mut passwd).await?;
    let password = String::from_utf8(passwd).map_err(|_| Socks5Error::InvalidPasswordEncoding)?;

    Ok(UserPassAuth { username, password })
}

async fn write_auth_request<T>(writer: &mut T, auth: &UserPassAuth) -> Result<()>
where
    T: AsyncWrite + Unpin,
{
    // Write authentication sub-protocol version number
    writer.write_u8(SOCKS5_AUTH_VER).await?;

    // Write username
    let username_bytes = auth.username.as_bytes();
    if username_bytes.len() > 255 {
        return Err(Socks5Error::UsernameTooLong.into());
    }
    writer.write_u8(username_bytes.len() as u8).await?;
    writer.write_all(username_bytes).await?;

    // Write password
    let password_bytes = auth.password.as_bytes();
    if password_bytes.len() > 255 {
        return Err(Socks5Error::PasswordTooLong.into());
    }
    writer.write_u8(password_bytes.len() as u8).await?;
    writer.write_all(password_bytes).await?;

    writer.flush().await?;
    Ok(())
}

/// According to RFC 1929, username/password authentication response format is:
/// ```text
/// +----+--------+
/// |VER | STATUS |
/// +----+--------+
/// | 1  |   1    |
/// +----+--------+
/// ```
/// VER: Authentication sub-protocol version, must be 0x01.
/// STATUS: Authentication result, 0x00 means success, other values mean failure.
async fn read_auth_response<T>(reader: &mut T) -> Result<()>
where
    T: AsyncRead + Unpin,
{
    // Read authentication sub-protocol version number
    let ver = reader.read_u8().await?;
    if ver != SOCKS5_AUTH_VER {
        return Err(Socks5Error::InvalidAuthVersion.into());
    }

    // Read authentication result
    let status = reader.read_u8().await?;
    if status != 0 {
        return Err(Socks5Error::AuthenticationFailed.into());
    }

    Ok(())
}

async fn write_auth_response<T>(writer: &mut T, is_ok: bool) -> Result<()>
where
    T: AsyncWrite + Unpin,
{
    // Write authentication sub-protocol version number
    writer.write_u8(SOCKS5_AUTH_VER).await?;

    // Write authentication result
    writer.write_u8(if is_ok { 0 } else { 1 }).await?;

    writer.flush().await?;
    Ok(())
}

/// According to RFC 1928, connection request format is:
/// ```text
/// +----+-----+-------+------+----------+----------+
/// |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
/// +----+-----+-------+------+----------+----------+
/// | 1  |  1  | X'00' |  1   | Variable |    2     |
/// +----+-----+-------+------+----------+----------+
/// ```
/// VER: SOCKS protocol version, must be 0x05.
/// CMD: Command code - 0x01 (CONNECT), 0x02 (BIND), 0x03 (UDP ASSOCIATE).
/// RSV: Reserved field, must be 0x00.
/// ATYP: Address type - 0x01 (IPv4), 0x03 (domain name), 0x04 (IPv6).
/// DST.ADDR: Destination address, format depends on ATYP.
/// DST.PORT: Destination port, network byte order (big-endian).
async fn read_connection_request<T>(reader: &mut T) -> Result<(Socks5Command, Address)>
where
    T: AsyncRead + Unpin,
{
    // Read version number
    let ver = reader.read_u8().await?;
    if ver != SOCKS5_VER {
        return Err(Socks5Error::InvalidSocksVersion.into());
    }

    // Read command
    let cmd = Socks5Command::try_from(reader.read_u8().await?)?;

    // Read reserved field
    let rsv = reader.read_u8().await?;
    if rsv != 0 {
        return Err(Socks5Error::InvalidRsvValue.into());
    }

    // Read address type and address
    let (address, _) = Address::decode_from_reader(reader).await?;

    Ok((cmd, address))
}

async fn write_connection_request<T>(
    writer: &mut T,
    command: &Socks5Command,
    address: &Address,
) -> Result<()>
where
    T: AsyncWrite + Unpin,
{
    // Write version number
    writer.write_u8(SOCKS5_VER).await?;

    // Write command
    writer.write_u8(*command as u8).await?;

    // Write reserved field
    writer.write_u8(0).await?;

    // Write address type and address
    address.encode_to_writer(writer).await?;

    writer.flush().await?;
    Ok(())
}

/// According to RFC 1928, the connection response format is:
/// ```text
/// +----+-----+-------+------+----------+----------+
/// |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
/// +----+-----+-------+------+----------+----------+
/// | 1  |  1  | X'00' |  1   | Variable |    2     |
/// +----+-----+-------+------+----------+----------+
/// ```
/// VER: SOCKS protocol version, must be 0x05.
/// REP: Reply code - 0x00 (succeeded), 0x01-0x08 (various errors).
/// RSV: Reserved field, must be 0x00.
/// ATYP: Address type - 0x01 (IPv4), 0x03 (domain name), 0x04 (IPv6).
/// BND.ADDR: Server bound address, format depends on ATYP.
/// BND.PORT: Server bound port, network byte order (big-endian).
async fn read_connection_response<T>(reader: &mut T) -> Result<(Socks5Reply, Address)>
where
    T: AsyncRead + Unpin,
{
    // Read version number
    let ver = reader.read_u8().await?;
    if ver != SOCKS5_VER {
        return Err(Socks5Error::InvalidSocksVersion.into());
    }

    // Read reply code
    let reply = Socks5Reply::try_from(reader.read_u8().await?)?;

    // Read reserved field
    let rsv = reader.read_u8().await?;
    if rsv != 0 {
        return Err(Socks5Error::InvalidRsvValue.into());
    }

    // Read address type and address (though we might not need to use them)
    let (address, _) = Address::decode_from_reader(reader).await?;

    Ok((reply, address))
}

async fn write_connection_response<T>(
    writer: &mut T,
    reply: &Socks5Reply,
    address: &Address,
) -> Result<()>
where
    T: AsyncWrite + Unpin,
{
    // Write version number
    writer.write_u8(SOCKS5_VER).await?;

    // Write reply code
    writer.write_u8(*reply as u8).await?;

    // Write reserved field
    writer.write_u8(0).await?;

    // Write address type and address
    address.encode_to_writer(writer).await?;

    writer.flush().await?;
    Ok(())
}

/// Errors that can occur during SOCKS5 protocol operations.
///
/// Each variant represents a specific error condition that may arise when implementing
/// or using the SOCKS5 protocol, as defined in RFC 1928 and RFC 1929.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Socks5Error {
    /// Server reports no acceptable authentication methods from those offered by client.
    NoAcceptableAuthMethod,
    /// User credentials were rejected during authentication phase.
    AuthenticationFailed,
    /// Connection to the target host could not be established.
    ConnectionFailed,
    /// Client sent an incorrect SOCKS version (expected 0x05).
    InvalidSocksVersion,
    /// Client sent an incorrect authentication subprotocol version.
    InvalidAuthVersion,
    /// Client did not provide any authentication methods.
    NoAuthMethods,
    /// None of the client's offered authentication methods are supported.
    NoSupportedAuthMethods,
    /// The authentication method byte value is not recognized.
    InvalidAuthMethod,
    /// The command byte is not a valid SOCKS5 command.
    InvalidCommand,
    /// The reply byte is not a valid SOCKS5 reply code.
    InvalidReply,
    /// The reserved field contains a non-zero value.
    InvalidRsvValue,
    /// The username contains invalid UTF-8 encoding.
    InvalidUsernameEncoding,
    /// The password contains invalid UTF-8 encoding.
    InvalidPasswordEncoding,
    /// The username exceeds maximum allowed length (255 bytes).
    UsernameTooLong,
    /// The password exceeds maximum allowed length (255 bytes).
    PasswordTooLong,
    /// Client offered more than 255 authentication methods.
    TooManyAuthMethods,
}

impl Display for Socks5Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoAcceptableAuthMethod => write!(f, "No acceptable authentication method"),
            Self::AuthenticationFailed => write!(f, "Authentication failed"),
            Self::ConnectionFailed => write!(f, "Connection failed"),
            Self::InvalidSocksVersion => write!(f, "Invalid SOCKS version"),
            Self::InvalidAuthVersion => write!(f, "Invalid auth version"),
            Self::NoAuthMethods => write!(f, "No authentication methods provided"),
            Self::NoSupportedAuthMethods => write!(f, "No supported authentication methods"),
            Self::InvalidAuthMethod => write!(f, "Invalid AuthMethod"),
            Self::InvalidCommand => write!(f, "Invalid Command"),

            Self::InvalidReply => write!(f, "Invalid Reply"),
            Self::InvalidRsvValue => write!(f, "Invalid RSV value"),
            Self::InvalidUsernameEncoding => write!(f, "Invalid username encoding"),
            Self::InvalidPasswordEncoding => write!(f, "Invalid password encoding"),
            Self::UsernameTooLong => write!(f, "Username too long"),
            Self::PasswordTooLong => write!(f, "Password too long"),
            Self::TooManyAuthMethods => write!(f, "Too many authentication methods"),
        }
    }
}

impl std::error::Error for Socks5Error {}

impl From<Socks5Error> for Error {
    fn from(e: Socks5Error) -> Self {
        match e {
            Socks5Error::NoAcceptableAuthMethod => Error::new(ErrorKind::PermissionDenied, e),
            Socks5Error::AuthenticationFailed => Error::new(ErrorKind::PermissionDenied, e),
            Socks5Error::ConnectionFailed => Error::new(ErrorKind::ConnectionRefused, e),
            Socks5Error::InvalidSocksVersion => Error::new(ErrorKind::InvalidData, e),
            Socks5Error::InvalidAuthVersion => Error::new(ErrorKind::InvalidData, e),
            Socks5Error::NoAuthMethods => Error::new(ErrorKind::InvalidInput, e),
            Socks5Error::NoSupportedAuthMethods => Error::new(ErrorKind::InvalidData, e),
            Socks5Error::InvalidAuthMethod => Error::new(ErrorKind::InvalidData, e),
            Socks5Error::InvalidCommand => Error::new(ErrorKind::InvalidData, e),
            Socks5Error::InvalidReply => Error::new(ErrorKind::InvalidData, e),
            Socks5Error::InvalidRsvValue => Error::new(ErrorKind::InvalidData, e),
            Socks5Error::InvalidUsernameEncoding => Error::new(ErrorKind::InvalidData, e),
            Socks5Error::InvalidPasswordEncoding => Error::new(ErrorKind::InvalidData, e),
            Socks5Error::UsernameTooLong => Error::new(ErrorKind::InvalidInput, e),
            Socks5Error::PasswordTooLong => Error::new(ErrorKind::InvalidInput, e),
            Socks5Error::TooManyAuthMethods => Error::new(ErrorKind::InvalidInput, e),
        }
    }
}

#[cfg(test)]
mod test {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;
    use crate::test_utils::create_mock_stream;

    #[tokio::test]
    async fn test_client_hello_write_read() {
        let all_methods = [
            vec![Socks5AuthOption::NoAuth],
            vec![
                Socks5AuthOption::NoAuth,
                Socks5AuthOption::UserPass,
                Socks5AuthOption::GssApi,
            ],
        ];
        for methods in all_methods {
            let (mut stream1, mut stream2) = create_mock_stream();
            write_client_hello(&mut stream1, &methods).await.unwrap();
            let recevied_methods = read_client_hello(&mut stream2).await.unwrap();
            assert_eq!(methods.as_slice(), recevied_methods.as_slice());
        }
    }

    #[tokio::test]
    async fn test_server_hello_write_read() {
        let (mut stream1, mut stream2) = create_mock_stream();
        write_server_hello(&mut stream1, &Socks5AuthOption::NoAuth)
            .await
            .unwrap();
        let method = read_server_hello(&mut stream2).await.unwrap();
        assert_eq!(Socks5AuthOption::NoAuth, method);
    }

    #[tokio::test]
    async fn test_auth_request_write_read() {
        let (mut stream1, mut stream2) = create_mock_stream();
        let auth = UserPassAuth {
            username: "test_user".to_string(),
            password: "test_pass".to_string(),
        };
        write_auth_request(&mut stream1, &auth).await.unwrap();
        let received_auth = read_auth_request(&mut stream2).await.unwrap();
        assert_eq!(auth.username, received_auth.username);
        assert_eq!(auth.password, received_auth.password);
    }

    #[tokio::test]
    async fn test_auth_response_write_read() {
        // Authentication success
        let (mut stream1, mut stream2) = create_mock_stream();
        write_auth_response(&mut stream1, true).await.unwrap();
        read_auth_response(&mut stream2).await.unwrap();

        // Authentication failure
        let (mut stream1, mut stream2) = create_mock_stream();
        write_auth_response(&mut stream1, false).await.unwrap();
        let err = read_auth_response(&mut stream2).await.unwrap_err();
        assert_eq!(
            err.downcast::<Socks5Error>().unwrap(),
            Socks5Error::AuthenticationFailed
        );
    }

    #[tokio::test]
    async fn test_connection_request_write_read() {
        let all_commands = [
            Socks5Command::Connect,
            Socks5Command::Bind,
            Socks5Command::UdpAssociate,
        ];
        let all_addresses = [
            Address::IPv4((Ipv4Addr::new(192, 168, 1, 1), 8080)),
            Address::DomainName(("example.com".to_string(), 443)),
            Address::IPv6((
                Ipv6Addr::new(0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x01),
                8080,
            )),
        ];
        for command in all_commands {
            for address in all_addresses.iter() {
                let (mut stream1, mut stream2) = create_mock_stream();
                write_connection_request(&mut stream1, &command, address)
                    .await
                    .unwrap();
                let (received_command, received_address) =
                    read_connection_request(&mut stream2).await.unwrap();
                assert_eq!(command, received_command);
                assert_eq!(address, &received_address);
            }
        }
    }

    #[tokio::test]
    async fn test_connection_response_write_read() {
        let all_replies = [
            Socks5Reply::Succeeded,
            Socks5Reply::GeneralFailure,
            Socks5Reply::ConnectionNotAllowed,
            Socks5Reply::NetworkUnreachable,
            Socks5Reply::HostUnreachable,
            Socks5Reply::ConnectionRefused,
            Socks5Reply::TTLExpired,
            Socks5Reply::CommandNotSupported,
            Socks5Reply::AddressTypeNotSupported,
        ];
        let all_addresses = [
            Address::IPv4((Ipv4Addr::new(192, 168, 1, 1), 8080)),
            Address::DomainName(("example.com".to_string(), 443)),
            Address::IPv6((
                Ipv6Addr::new(0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x01),
                8080,
            )),
        ];
        for reply in all_replies {
            for address in all_addresses.iter() {
                let (mut stream1, mut stream2) = create_mock_stream();
                write_connection_response(&mut stream1, &reply, address)
                    .await
                    .unwrap();
                let (received_reply, received_address) =
                    read_connection_response(&mut stream2).await.unwrap();
                assert_eq!(reply, received_reply);
                assert_eq!(address, &received_address);
            }
        }
    }

    #[tokio::test]
    async fn test_read_client_hello_invalid_version() {
        let (mut client, server) = create_mock_stream();

        // Invalid SOCKS version: 0x04 instead of 0x05
        server.write_immediate(&[0x04, 0x01, 0x00]).unwrap();

        let result = read_client_hello(&mut client).await;

        let err = result.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);
        assert_eq!(
            err.downcast::<Socks5Error>().unwrap(),
            Socks5Error::InvalidSocksVersion
        );
    }

    #[tokio::test]
    async fn test_read_client_hello_no_auth_method() {
        let (mut client, server) = create_mock_stream();

        // No authentication methods: NMETHODS is 0
        server.write_immediate(&[0x05, 0x00]).unwrap();

        let result = read_client_hello(&mut client).await;

        let err = result.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidInput);
        assert_eq!(
            err.downcast::<Socks5Error>().unwrap(),
            Socks5Error::NoAuthMethods
        );
    }

    #[tokio::test]
    async fn test_read_client_hello_unsupported_auth_methods() {
        let (mut client, server) = create_mock_stream();

        // Only unsupported auth method: 0x80 is not a valid SOCKS5 auth method
        server.write_immediate(&[0x05, 0x01, 0x80]).unwrap();

        let result = read_client_hello(&mut client).await;

        let err = result.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);
        assert_eq!(
            err.downcast::<Socks5Error>().unwrap(),
            Socks5Error::NoSupportedAuthMethods
        );
    }

    #[tokio::test]
    async fn test_write_client_hello_no_auth_method() {
        let (mut client, _server) = create_mock_stream();

        let result = write_client_hello(&mut client, &[]).await;

        let err = result.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidInput);
        assert_eq!(
            err.downcast::<Socks5Error>().unwrap(),
            Socks5Error::NoAuthMethods
        );
    }

    #[tokio::test]
    async fn test_read_server_hello_invalid_version() {
        let (mut client, server) = create_mock_stream();

        // Invalid SOCKS version: 0x04 instead of 0x05
        server.write_immediate(&[0x04, 0x00]).unwrap();

        let result = read_server_hello(&mut client).await;

        let err = result.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);
        assert_eq!(
            err.downcast::<Socks5Error>().unwrap(),
            Socks5Error::InvalidSocksVersion
        );
    }

    #[tokio::test]
    async fn test_read_auth_request_invalid_version() {
        let (mut client, server) = create_mock_stream();

        // Invalid auth version: 0x02 instead of 0x01
        // Format: [version, username length, username, password length, password]
        server
            .write_immediate(&[
                0x02, 0x04, b'u', b's', b'e', b'r', 0x04, b'p', b'a', b's', b's',
            ])
            .unwrap();

        let result = read_auth_request(&mut client).await;

        let err = result.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);
        assert_eq!(
            err.downcast::<Socks5Error>().unwrap(),
            Socks5Error::InvalidAuthVersion
        );
    }

    #[tokio::test]
    async fn test_read_auth_request_invalid_username_encoding() {
        let (mut client, server) = create_mock_stream();

        // Invalid UTF-8 sequence for username
        server
            .write_immediate(&[
                0x01, 0x04, 0xFF, 0xFF, 0xFF, 0xFF, // Invalid UTF-8 sequence
                0x04, b'p', b'a', b's', b's',
            ])
            .unwrap();

        let result = read_auth_request(&mut client).await;

        let err = result.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);
        assert_eq!(
            err.downcast::<Socks5Error>().unwrap(),
            Socks5Error::InvalidUsernameEncoding
        );
    }

    #[tokio::test]
    async fn test_read_auth_request_invalid_password_encoding() {
        let (mut client, server) = create_mock_stream();

        // Invalid UTF-8 sequence for password
        server
            .write_immediate(&[
                0x01, 0x04, b'u', b's', b'e', b'r', 0x04, 0xFF, 0xFF, 0xFF,
                0xFF, // Invalid UTF-8 sequence
            ])
            .unwrap();

        let result = read_auth_request(&mut client).await;

        let err = result.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);
        assert_eq!(
            err.downcast::<Socks5Error>().unwrap(),
            Socks5Error::InvalidPasswordEncoding
        );
    }

    #[tokio::test]
    async fn test_write_auth_request_username_too_long() {
        let (mut client, _server) = create_mock_stream();

        // Username length of 256 bytes (exceeds max of 255)
        let long_username = "a".repeat(256);
        let auth = UserPassAuth {
            username: long_username,
            password: "password".to_string(),
        };

        let result = write_auth_request(&mut client, &auth).await;

        let err = result.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidInput);
        assert_eq!(
            err.downcast::<Socks5Error>().unwrap(),
            Socks5Error::UsernameTooLong
        );
    }

    #[tokio::test]
    async fn test_write_auth_request_password_too_long() {
        let (mut client, _server) = create_mock_stream();

        // Password length of 256 bytes (exceeds max of 255)
        let long_password = "a".repeat(256);
        let auth = UserPassAuth {
            username: "username".to_string(),
            password: long_password,
        };

        let result = write_auth_request(&mut client, &auth).await;

        let err = result.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidInput);
        assert_eq!(
            err.downcast::<Socks5Error>().unwrap(),
            Socks5Error::PasswordTooLong
        );
    }

    #[tokio::test]
    async fn test_read_auth_response_invalid_auth_version() {
        let (mut client, server) = create_mock_stream();

        // Invalid auth version: 0x02 instead of 0x01
        server.write_immediate(&[0x02, 0x00]).unwrap();

        let result = read_auth_response(&mut client).await;

        let err = result.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);
        assert_eq!(
            err.downcast::<Socks5Error>().unwrap(),
            Socks5Error::InvalidAuthVersion
        );
    }

    #[tokio::test]
    async fn test_read_auth_response_auth_failed() {
        let (mut client, server) = create_mock_stream();

        // Status 0x01 indicates authentication failure
        server.write_immediate(&[0x01, 0x01]).unwrap();

        let result = read_auth_response(&mut client).await;

        let err = result.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::PermissionDenied);
        assert_eq!(
            err.downcast::<Socks5Error>().unwrap(),
            Socks5Error::AuthenticationFailed
        );
    }

    #[tokio::test]
    async fn test_read_connection_request_invalid_version() {
        let (mut client, server) = create_mock_stream();

        // Invalid SOCKS version: 0x04 instead of 0x05
        server
            .write_immediate(&[
                0x04, 0x01, // CONNECT command
                0x00, // Reserved field
                0x01, // IPv4 address type
                0x7F, 0x00, 0x00, 0x01, // 127.0.0.1
                0x00, 0x50, // Port 80
            ])
            .unwrap();

        let result = read_connection_request(&mut client).await;

        let err = result.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);
        assert_eq!(
            err.downcast::<Socks5Error>().unwrap(),
            Socks5Error::InvalidSocksVersion
        );
    }

    #[tokio::test]
    async fn test_read_connection_request_invalid_rsv() {
        let (mut client, server) = create_mock_stream();

        // Invalid reserved field: 0x01 instead of 0x00
        server
            .write_immediate(&[
                0x05, // SOCKS5 version
                0x01, // CONNECT command
                0x01, // Invalid reserved field
                0x01, // IPv4 address type
                0x7F, 0x00, 0x00, 0x01, // 127.0.0.1
                0x00, 0x50, // Port 80
            ])
            .unwrap();

        let result = read_connection_request(&mut client).await;

        let err = result.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);
        assert_eq!(
            err.downcast::<Socks5Error>().unwrap(),
            Socks5Error::InvalidRsvValue
        );
    }

    #[tokio::test]
    async fn test_read_connection_response_invalid_version() {
        let (mut client, server) = create_mock_stream();

        // Invalid SOCKS version: 0x04 instead of 0x05
        server
            .write_immediate(&[
                0x04, // Invalid SOCKS version
                0x00, // Success reply
                0x00, // Reserved field
                0x01, // IPv4 address type
                0x7F, 0x00, 0x00, 0x01, // 127.0.0.1
                0x00, 0x50, // Port 80
            ])
            .unwrap();

        let result = read_connection_response(&mut client).await;

        let err = result.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);
        assert_eq!(
            err.downcast::<Socks5Error>().unwrap(),
            Socks5Error::InvalidSocksVersion
        );
    }

    #[tokio::test]
    async fn test_read_connection_response_invalid_rsv() {
        let (mut client, server) = create_mock_stream();

        // Invalid reserved field: 0x01 instead of 0x00
        server
            .write_immediate(&[
                0x05, // SOCKS5 version
                0x00, // Success reply
                0x01, // Invalid reserved field
                0x01, // IPv4 address type
                0x7F, 0x00, 0x00, 0x01, // 127.0.0.1
                0x00, 0x50, // Port 80
            ])
            .unwrap();

        let result = read_connection_response(&mut client).await;

        let err = result.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);
        assert_eq!(
            err.downcast::<Socks5Error>().unwrap(),
            Socks5Error::InvalidRsvValue
        );
    }
}
