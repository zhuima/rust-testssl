use std::fmt;
use trust_dns_resolver::error::ResolveError;

#[derive(Debug)]
pub enum ScanError {
    Connection(std::io::Error),
    TlsHandshake(String),
    Rustls(rustls::Error),
    InvalidHostname,
    HttpRequest(reqwest::Error),
    HttpResponseParse,
    TimeParse(chrono::ParseError),
    Other(anyhow::Error),
    TlsError(String),
    CertificateParse,
}

impl fmt::Display for ScanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScanError::Connection(e) => write!(f, "连接错误: {}", e),
            ScanError::TlsHandshake(e) => write!(f, "TLS 握手错误: {}", e),
            ScanError::Rustls(e) => write!(f, "Rustls 错误: {}", e),
            ScanError::InvalidHostname => write!(f, "无效的主机名"),
            ScanError::HttpRequest(e) => write!(f, "HTTP 请求错误: {}", e),
            ScanError::HttpResponseParse => write!(f, "HTTP 响应解析错误"),
            ScanError::TimeParse(e) => write!(f, "时间解析错误: {}", e),
            ScanError::Other(e) => write!(f, "其他错误: {}", e),
            ScanError::TlsError(e) => write!(f, "TLS 错误: {}", e),
            ScanError::CertificateParse => write!(f, "证书解析错误"),
        }
    }
}

impl std::error::Error for ScanError {}

// 提供从各种错误类型到 ScanError 的转换
impl From<std::io::Error> for ScanError {
    fn from(err: std::io::Error) -> Self {
        ScanError::Connection(err)
    }
}

impl From<rustls::Error> for ScanError {
    fn from(err: rustls::Error) -> Self {
        ScanError::Rustls(err)
    }
}

impl From<reqwest::Error> for ScanError {
    fn from(err: reqwest::Error) -> Self {
        ScanError::HttpRequest(err)
    }
}

impl From<chrono::ParseError> for ScanError {
    fn from(err: chrono::ParseError) -> Self {
        ScanError::TimeParse(err)
    }
}

impl From<anyhow::Error> for ScanError {
    fn from(err: anyhow::Error) -> Self {
        ScanError::Other(err)
    }
}

impl From<ResolveError> for ScanError {
    fn from(err: ResolveError) -> Self {
        ScanError::Other(anyhow::anyhow!("DNS resolution error: {}", err))
    }
}

pub type Result<T> = std::result::Result<T, ScanError>;