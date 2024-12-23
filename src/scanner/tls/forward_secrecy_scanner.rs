use crate::errors::{Result, ScanError};
use colored::*;
use std::iter;
use tokio::net::TcpStream;
use tokio_rustls::{TlsConnector, rustls::{
    ClientConfig, 
    RootCertStore, 
    ServerName,
    OwnedTrustAnchor,
}};
use rustls::{SignatureScheme, NamedGroup};
use std::sync::Arc;

// 创建新类型来包装外部类型
#[derive(Clone, Copy)]
struct SignatureSchemeStr(&'static str);
#[derive(Clone, Copy)]
struct NamedGroupStr(&'static str);

impl From<SignatureScheme> for SignatureSchemeStr {
    fn from(scheme: SignatureScheme) -> Self {
        match scheme {
            SignatureScheme::RSA_PSS_SHA256 => SignatureSchemeStr("RSA-PSS-RSAE+SHA256"),
            SignatureScheme::RSA_PSS_SHA384 => SignatureSchemeStr("RSA-PSS-RSAE+SHA384"),
            SignatureScheme::RSA_PSS_SHA512 => SignatureSchemeStr("RSA-PSS-RSAE+SHA512"),
            _ => SignatureSchemeStr("Unknown"),
        }
    }
}

impl From<NamedGroup> for NamedGroupStr {
    fn from(group: NamedGroup) -> Self {
        match group {
            NamedGroup::secp256r1 => NamedGroupStr("prime256v1"),
            NamedGroup::X25519 => NamedGroupStr("X25519"),
            _ => NamedGroupStr("Unknown"),
        }
    }
}

impl ToString for SignatureSchemeStr {
    fn to_string(&self) -> String {
        self.0.to_string()
    }
}

impl ToString for NamedGroupStr {
    fn to_string(&self) -> String {
        self.0.to_string()
    }
}

pub struct ForwardSecrecyScanner {
    host: String,
    port: u16,
}

impl ForwardSecrecyScanner {
    pub fn new(host: String, port: u16) -> Self {
        Self { host, port }
    }

    fn make_title(text: &str) -> String {
        let underline = iter::repeat('_').take(text.len()).collect::<String>();
        format!(" {}\n {}\n", text, underline)
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

    async fn check_cipher_suites(&self) -> Result<Vec<String>> {
        let addr = format!("{}:{}", self.host, self.port);
        let server_name = ServerName::try_from(self.host.as_str())
            .map_err(|_| ScanError::InvalidHostname)?;
        let mut supported_ciphers = Vec::new();

        // TLS 1.3 密码套件
        let tls13_suites = vec![
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256",
            "TLS_AES_128_GCM_SHA256",
        ];

        // TLS 1.2 密码套件
        let tls12_suites = vec![
            "ECDHE-RSA-AES256-GCM-SHA384",
            "ECDHE-RSA-CHACHA20-POLY1305",
            "ECDHE-RSA-AES128-GCM-SHA256",
        ];

        // 测试 TLS 1.3 密码套件
        let config = ClientConfig::builder()
            .with_safe_default_cipher_suites()
            .with_safe_default_kx_groups()
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| ScanError::TlsError(e.to_string()))?
            .with_root_certificates(self.get_root_store())
            .with_no_client_auth();

        let connector = TlsConnector::from(Arc::new(config));

        if let Ok(tcp_stream) = TcpStream::connect(&addr).await {
            if let Ok(tls_stream) = connector.connect(server_name.clone(), tcp_stream).await {
                let (_, server_conn) = tls_stream.get_ref();
                if let Some(cipher) = server_conn.negotiated_cipher_suite() {
                    if let Some(suite_str) = cipher.suite().as_str() {
                        if tls13_suites.contains(&suite_str) {
                            supported_ciphers.extend(tls13_suites.iter().map(|s| s.to_string()));
                        }
                    }
                }
            }
        }

        // 测试 TLS 1.2 密码套件
        let config = ClientConfig::builder()
            .with_safe_default_cipher_suites()
            .with_safe_default_kx_groups()
            .with_protocol_versions(&[&rustls::version::TLS12])
            .map_err(|e| ScanError::TlsError(e.to_string()))?
            .with_root_certificates(self.get_root_store())
            .with_no_client_auth();

        let connector = TlsConnector::from(Arc::new(config));

        if let Ok(tcp_stream) = TcpStream::connect(&addr).await {
            if let Ok(tls_stream) = connector.connect(server_name.clone(), tcp_stream).await {
                let (_, server_conn) = tls_stream.get_ref();
                if let Some(cipher) = server_conn.negotiated_cipher_suite() {
                    if let Some(suite_str) = cipher.suite().as_str() {
                        if tls12_suites.contains(&suite_str) {
                            supported_ciphers.extend(tls12_suites.iter().map(|s| s.to_string()));
                        }
                    }
                }
            }
        }

        // 按照 testssl.sh 的顺序排序
        supported_ciphers.sort_by(|a, b| {
            let order = vec![
                "TLS_AES_256_GCM_SHA384",
                "TLS_CHACHA20_POLY1305_SHA256",
                "ECDHE-RSA-AES256-GCM-SHA384",
                "ECDHE-RSA-CHACHA20-POLY1305",
                "TLS_AES_128_GCM_SHA256",
                "ECDHE-RSA-AES128-GCM-SHA256",
            ];
            let a_pos = order.iter().position(|&x| x == a).unwrap_or(usize::MAX);
            let b_pos = order.iter().position(|&x| x == b).unwrap_or(usize::MAX);
            a_pos.cmp(&b_pos)
        });

        Ok(supported_ciphers)
    }

    async fn test_curve(&self, curve: NamedGroup) -> Result<bool> {
        // 实现曲线测试逻辑
        Ok(true) // 临时返回，需要实际实现
    }

    async fn test_signature_algorithm(&self, alg: SignatureScheme) -> Result<bool> {
        // 实现签名算法测试逻辑
        Ok(true) // 临时返回，需要实际实现
    }

    pub async fn scan_forward_secrecy(&self) -> Result<()> {
        println!("{}", Self::make_title(
            "Testing robust forward secrecy (FS) -- omitting Null Authentication/Encryption, 3DES, RC4"
        ));

        // 检测支持的密码套件
        let ciphers = self.check_cipher_suites().await?;
        let has_fs = ciphers.iter().any(|c| c.contains("ECDHE"));

        println!("{:<20} {}", 
            "FS is offered",
            if has_fs {
                format!("({})", "OK".green())
            } else {
                format!("({})", "NOT offered".red())
            }
        );

        if !ciphers.is_empty() {
            println!("{:<20} {}", "", ciphers.join(" "));
        }

        // 检测支持的椭圆曲线
        let curves = self.get_supported_curves().await?;
        if !curves.is_empty() {
            println!("{:<20} {}", 
                "Elliptic curves offered:",
                curves.iter()
                    .map(|c| c.to_string())
                    .collect::<Vec<_>>()
                    .join(" ")
                    .green()
            );
        }

        // 检测 TLS 1.2 签名算法
        let tls12_algs = self.get_signature_algorithms("TLS 1.2").await?;
        if !tls12_algs.is_empty() {
            println!("{:<20} {}", 
                "TLS 1.2 sig_algs offered:",
                tls12_algs.iter()
                    .map(|&a| SignatureSchemeStr::from(a).to_string())
                    .collect::<Vec<_>>()
                    .join(" ")
            );
        }

        // 检测 TLS 1.3 签名算法
        let tls13_algs = self.get_signature_algorithms("TLS 1.3").await?;
        if !tls13_algs.is_empty() {
            println!("{:<20} {}", 
                "TLS 1.3 sig_algs offered:",
                tls13_algs.iter()
                    .map(|&a| SignatureSchemeStr::from(a).to_string())
                    .collect::<Vec<_>>()
                    .join(" ")
            );
        }

        println!();
        Ok(())
    }

    pub async fn has_forward_secrecy(&self) -> Result<bool> {
        let ciphers = self.check_cipher_suites().await?;
        Ok(ciphers.iter().any(|c| c.contains("ECDHE")))
    }

    pub async fn get_supported_curves(&self) -> Result<Vec<String>> {
        let curves = vec![
            NamedGroup::secp256r1,
            NamedGroup::X25519,
        ];
        
        let mut supported_curves = Vec::new();
        for curve in curves {
            if self.test_curve(curve).await? {
                supported_curves.push(NamedGroupStr::from(curve).to_string());
            }
        }
        
        Ok(supported_curves)
    }

    async fn get_signature_algorithms(&self, version: &str) -> Result<Vec<SignatureScheme>> {
        let test_algs = match version {
            "TLS 1.2" => vec![
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PSS_SHA384,
                SignatureScheme::RSA_PSS_SHA512,
            ],
            "TLS 1.3" => vec![
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PSS_SHA384,
                SignatureScheme::RSA_PSS_SHA512,
            ],
            _ => vec![],
        };

        let mut supported_algs = Vec::new();
        for alg in test_algs {
            if self.test_signature_algorithm(alg).await? {
                supported_algs.push(alg);
            }
        }

        Ok(supported_algs)
    }
} 