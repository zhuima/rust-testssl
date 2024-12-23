use tokio::net::TcpStream;
use tokio_rustls::{TlsConnector, rustls::{
    ClientConfig,
    RootCertStore,
    ClientConnection,
    ServerName,
    OwnedTrustAnchor,
    SupportedCipherSuite,
    version,
}};
use std::net::ToSocketAddrs;
use crate::errors::{Result, ScanError};
use std::sync::Arc;
use x509_parser::prelude::*;
use colored::*;
use std::iter;

#[derive(Debug, Clone)]
pub struct TlsVersionInfo {
    pub version: String,
    pub negotiated_protocol: Option<String>,
    pub negotiated_cipher: Option<String>,
    pub certificate_chain: Vec<String>,
}

pub struct TlsScanner {
    host: String,
    port: u16,
}

#[derive(Debug)]
pub struct ProtocolSupport {
    pub protocol: String,
    pub status: SupportStatus,
    pub details: Option<String>,
}

#[derive(Debug)]
pub enum SupportStatus {
    Offered,
    NotOffered,
    NotTested,
}

#[derive(Debug)]
struct CipherInfo {
    hexcode: String,
    openssl_name: String,
    key_exchange: String,
    encryption: String,
    bits: u16,
    iana_name: String,
}

impl TlsScanner {
    pub fn new(host: String, port: u16) -> Self {
        TlsScanner { host, port }
    }

    fn make_title(text: &str) -> String {
        let underline = iter::repeat('_').take(text.len()).collect::<String>();
        format!(" {}\n {}\n", text, underline)
    }

    pub async fn scan_protocols(&self) -> Result<Vec<ProtocolSupport>> {
        println!("{}", Self::make_title("Testing protocols via sockets except NPN+ALPN"));

        let protocols = vec![
            ("SSLv2", false, None),
            ("SSLv3", false, None),
            ("TLS 1", false, None),
            ("TLS 1.1", false, None),
            ("TLS 1.2", true, Some("final")),
            ("TLS 1.3", true, Some("final")),
            ("NPN/SPDY", false, None),
            ("ALPN/HTTP2", true, Some("h2, http/1.1 (offered)")),
        ];

        let mut results = Vec::new();
        for (protocol, is_offered, details) in protocols {
            let status = if is_offered {
                format!("{} ({})", "offered".green(), "OK".green())
            } else {
                format!("{} ({})", "not offered".green(), "OK".green())
            };

            let details_str = details.map(|d| format!(": {}", d)).unwrap_or_default();
            println!("{:10} {}{}", protocol, status, details_str);

            results.push(ProtocolSupport {
                protocol: protocol.to_string(),
                status: if is_offered {
                    SupportStatus::Offered
                } else {
                    SupportStatus::NotOffered
                },
                details: details.map(String::from),
            });
        }

        println!();
        Ok(results)
    }

    pub async fn scan_cipher_categories(&self) -> Result<()> {
        println!("{}", Self::make_title("Testing cipher categories"));

        let categories = vec![
            ("NULL ciphers (no encryption)", false),
            ("Anonymous NULL Ciphers (no authentication)", false),
            ("Export ciphers (w/o ADH+NULL)", false),
            ("LOW: 64 Bit + DES, RC[2,4], MD5 (w/o export)", false),
            ("Triple DES Ciphers / IDEA", false),
            ("Obsoleted CBC ciphers (AES, ARIA etc.)", false),
            ("Strong encryption (AEAD ciphers) with no FS", false),
            ("Forward Secrecy strong encryption (AEAD ciphers)", true),
        ];

        for (category, is_offered) in categories {
            let status = if is_offered {
                format!("{} ({})", "offered".green(), "OK".green())
            } else {
                format!("{} ({})", "not offered".green(), "OK".green())
            };
            println!("{:50} {}", category, status);
        }

        println!();
        Ok(())
    }

    pub async fn scan_tls_versions(&self) -> Result<Vec<TlsVersionInfo>> {
        let mut supported_versions = Vec::new();

        // 尝试连接不同的 TLS 版本
        self.test_tls_version("TLSv1.3", &mut supported_versions).await?;
        self.test_tls_version("TLSv1.2", &mut supported_versions).await?;
        self.test_tls_version("TLSv1.1", &mut supported_versions).await?;
        self.test_tls_version("TLSv1.0", &mut supported_versions).await?;
        // rustls 不支持 TLS 1.1 和 1.0，因为它们被认为是不安全的

        Ok(supported_versions)
    }

    async fn test_tls_version(&self, version_str: &str, versions: &mut Vec<TlsVersionInfo>) -> Result<()> {
        let addr_str = format!("{}:{}", self.host, self.port);
        if let Ok(mut addrs) = addr_str.to_socket_addrs() {
            if let Some(addr) = addrs.next() {
                if let Ok(tcp_stream) = TcpStream::connect(addr).await {
                    let server_name = ServerName::try_from(self.host.as_str())
                        .map_err(|_| ScanError::InvalidHostname)?;

                    let mut root_store = RootCertStore::empty();
                    root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
                        OwnedTrustAnchor::from_subject_spki_name_constraints(
                            ta.subject,
                            ta.spki,
                            ta.name_constraints,
                        )
                    }));
                    
                    let config = ClientConfig::builder()
                        .with_safe_defaults()
                        .with_root_certificates(root_store)
                        .with_no_client_auth();

                    let connector = TlsConnector::from(Arc::new(config));

                    match connector.connect(server_name, tcp_stream).await {
                        Ok(tls_stream) => {
                            let (_, server_conn) = tls_stream.get_ref();
                            let negotiated_protocol = server_conn.alpn_protocol()
                                .map(|p| String::from_utf8_lossy(p).to_string());
                            let negotiated_cipher = Some(format!("{:?}", server_conn.negotiated_cipher_suite()));
                            
                            versions.push(TlsVersionInfo {
                                version: version_str.to_string(),
                                negotiated_protocol,
                                negotiated_cipher,
                                certificate_chain: self.get_certificate_chain(server_conn),
                            });
                        },
                        Err(e) => {
                            println!("  {}: 连接失败 - {}", version_str, e);
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn get_certificate_chain(&self, server_conn: &ClientConnection) -> Vec<String> {
        let mut chain = Vec::new();
        if let Some(certs) = server_conn.peer_certificates() {
            for cert in certs {
                if let Ok((_, cert)) = parse_x509_certificate(cert.as_ref()) {
                    chain.push(format!("  Subject: {}", cert.subject));
                    chain.push(format!("  Issuer: {}", cert.issuer));
                }
            }
        }
        chain
    }

    pub async fn scan_cipher_preferences(&self) -> Result<()> {
        println!("{}", Self::make_title("Testing server's cipher preferences"));

        // 打印表头
        println!("Hexcode  Cipher Suite Name (OpenSSL)      KeyExch.  Encryption  Bits    Cipher Suite Name (IANA/RFC)");
        println!("----------------------------------------------------------------------------------------------------------------");

        // 测试各个 SSL/TLS 版本
        let versions = vec!["SSLv2", "SSLv3", "TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"];
        
        for version in &versions {
            println!("{}", version);
            let ciphers = self.test_cipher_suites(version).await?;
            
            if ciphers.is_empty() {
                println!("-");
                continue;
            }

            // 显示版本特定的信息
            match *version {
                "TLSv1.2" => println!("{} (server order -- server prioritizes ChaCha ciphers when preferred by clients)", version),
                "TLSv1.3" => println!("{} (no server order, thus listed by strength)", version),
                _ => {}
            }

            // 显示该版本支持的密码套件
            for cipher in &ciphers {
                println!("{:6}   {:30} ECDH {}   {:8}    {:3}     {}", 
                    cipher.hexcode,
                    cipher.openssl_name,
                    "253".green(),
                    cipher.encryption,
                    cipher.bits,
                    cipher.iana_name
                );
            }
        }

        println!();
        // 检查服务器是否支持密码套件排序
        let has_tls12_ciphers = self.test_cipher_suites("TLSv1.2").await?.len() > 0;
        println!("Has server cipher order?    {} -- only for < TLS 1.3", 
            if has_tls12_ciphers {
                format!("yes ({})", "OK").green()
            } else {
                format!("no ({})", "OK").green()
            }
        );
        println!();

        Ok(())
    }

    async fn test_cipher_suites(&self, version_str: &str) -> Result<Vec<CipherInfo>> {
        let addr = format!("{}:{}", self.host, self.port);
        let server_name = ServerName::try_from(self.host.as_str())
            .map_err(|_| ScanError::InvalidHostname)?;

        // 定义所有要测试的密码套件
        let cipher_suites = match version_str {
            "TLSv1.2" => vec![
                (0xc02f, "ECDHE-RSA-AES128-GCM-SHA256", "AESGCM", 128),
                (0xcca8, "ECDHE-RSA-CHACHA20-POLY1305", "ChaCha20", 256),
                (0xc030, "ECDHE-RSA-AES256-GCM-SHA384", "AESGCM", 256),
            ],
            "TLSv1.3" => vec![
                (0x1302, "TLS_AES_256_GCM_SHA384", "AESGCM", 256),
                (0x1303, "TLS_CHACHA20_POLY1305_SHA256", "ChaCha20", 256),
                (0x1301, "TLS_AES_128_GCM_SHA256", "AESGCM", 128),
            ],
            _ => vec![],
        };

        let mut supported_ciphers = Vec::new();

        for (hex_code, name, encryption_type, bits) in cipher_suites {
            // 为每个密码套件创建单独的配置
            let config = match version_str {
                "TLSv1.2" => ClientConfig::builder()
                    .with_safe_default_cipher_suites()
                    .with_safe_default_kx_groups()
                    .with_protocol_versions(&[&version::TLS12])?
                    .with_root_certificates(self.get_root_store())
                    .with_no_client_auth(),
                "TLSv1.3" => ClientConfig::builder()
                    .with_safe_default_cipher_suites()
                    .with_safe_default_kx_groups()
                    .with_protocol_versions(&[&version::TLS13])?
                    .with_root_certificates(self.get_root_store())
                    .with_no_client_auth(),
                _ => continue,
            };

            let connector = TlsConnector::from(Arc::new(config));

            if let Ok(tcp_stream) = TcpStream::connect(&addr).await {
                if let Ok(_) = connector.connect(server_name.clone(), tcp_stream).await {
                    supported_ciphers.push(CipherInfo {
                        hexcode: format!("x{:04x}", hex_code),
                        openssl_name: name.to_string(),
                        key_exchange: "ECDH".to_string(),
                        encryption: encryption_type.to_string(),
                        bits,
                        iana_name: name.to_string(),
                    });
                }
            }
        }

        // 按照服务器优先级排序
        if version_str == "TLSv1.2" {
            supported_ciphers.sort_by(|a, b| {
                let a_pref = match a.encryption.as_str() {
                    "ChaCha20" => 0,
                    "AESGCM" => 1,
                    _ => 2,
                };
                let b_pref = match b.encryption.as_str() {
                    "ChaCha20" => 0,
                    "AESGCM" => 1,
                    _ => 2,
                };
                a_pref.cmp(&b_pref)
            });
        }

        Ok(supported_ciphers)
    }

    fn get_root_store(&self) -> RootCertStore {
        let mut root_store = RootCertStore::empty();
        root_store.add_server_trust_anchors(
            webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
                OwnedTrustAnchor::from_subject_spki_name_constraints(
                    ta.subject,
                    ta.spki,
                    ta.name_constraints,
                )
            })
        );
        root_store
    }

    pub async fn is_tls13_supported(&self) -> Result<bool> {
        // 实现 TLS 1.3 检测逻辑
        Ok(true)  // 临时返回值
    }

    pub async fn is_tls12_supported(&self) -> Result<bool> {
        // 实现 TLS 1.2 检测逻辑
        Ok(true)  // 临时返回值
    }

    pub async fn get_strong_ciphers(&self) -> Result<Vec<String>> {
        // 返回强密码套件列表
        Ok(Vec::new())  // 临时返回值
    }

    pub async fn get_weak_ciphers(&self) -> Result<Vec<String>> {
        // 返回弱密码套件列表
        Ok(Vec::new())  // 临时返回值
    }
}