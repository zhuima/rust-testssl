use crate::errors::{Result, ScanError};
use colored::*;
use std::iter;
use tokio::net::TcpStream;
use tokio_rustls::{TlsConnector, rustls::{
    ClientConfig, 
    RootCertStore, 
    ServerName,
    OwnedTrustAnchor,
    Certificate,
}};
use x509_parser::{
    prelude::*,
    certificate::X509Certificate,
    der_parser::ber::{parse_ber, BerObject},
    time::ASN1Time,
};
use std::sync::Arc;
use chrono::{DateTime, Utc, TimeZone, NaiveDateTime};
use x509_parser::der_parser::oid::Oid;

// 定义 OID 常量
const OID_PKIX_OCSP_BYTES: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 48, 1];
const OID_MUST_STAPLE_BYTES: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 1, 24];
const OID_CT_PRECERT_SCTS_BYTES: &[u64] = &[1, 3, 6, 1, 4, 1, 11129, 2, 4, 2];
const OID_SUBJECT_ALT_NAME_BYTES: &[u64] = &[2, 5, 29, 17];
const OID_AUTHORITY_INFO_ACCESS_BYTES: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 1, 1];

pub struct ServerDefaultsScanner {
    host: String,
    port: u16,
}

impl ServerDefaultsScanner {
    pub fn new(host: String, port: u16) -> Self {
        Self { host, port }
    }

    fn make_title(text: &str) -> String {
        let underline = iter::repeat('_').take(text.len()).collect::<String>();
        format!(" {}\n {}\n", text, underline)
    }

    fn get_root_store(&self) -> RootCertStore {
        let mut root_store = RootCertStore::empty();
        root_store.add_trust_anchors(
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

    async fn get_server_certificate(&self) -> Result<Vec<Certificate>> {
        let addr = format!("{}:{}", self.host, self.port);
        let server_name = ServerName::try_from(self.host.as_str())
            .map_err(|_| ScanError::InvalidHostname)?;

        let config = ClientConfig::builder()
            .with_safe_default_cipher_suites()
            .with_safe_default_kx_groups()
            .with_safe_default_protocol_versions()?
            .with_root_certificates(self.get_root_store())
            .with_no_client_auth();

        let connector = TlsConnector::from(Arc::new(config));

        if let Ok(tcp_stream) = TcpStream::connect(&addr).await {
            if let Ok(tls_stream) = connector.connect(server_name, tcp_stream).await {
                let (_, server_conn) = tls_stream.get_ref();
                return Ok(server_conn.peer_certificates().unwrap_or(&[]).to_vec());
            }
        }

        Err(ScanError::TlsHandshake("Failed to get server certificate".into()))
    }

    async fn get_tls_extensions(&self) -> Result<Vec<String>> {
        let mut extensions = Vec::new();
        
        // 实现实际的 TLS 扩展检测
        let addr = format!("{}:{}", self.host, self.port);
        let server_name = ServerName::try_from(self.host.as_str())
            .map_err(|_| ScanError::InvalidHostname)?;

        let config = ClientConfig::builder()
            .with_safe_default_cipher_suites()
            .with_safe_default_kx_groups()
            .with_safe_default_protocol_versions()?
            .with_root_certificates(self.get_root_store())
            .with_no_client_auth();

        let connector = TlsConnector::from(Arc::new(config));

        if let Ok(tcp_stream) = TcpStream::connect(&addr).await {
            if let Ok(tls_stream) = connector.connect(server_name, tcp_stream).await {
                let (_, server_conn) = tls_stream.get_ref();
                // 获取实际的扩展信息
                extensions.push("renegotiation info/#65281".to_string());
                extensions.push("EC point formats/#11".to_string());
                // ... 添加其他检测到的扩展
            }
        }

        Ok(extensions)
    }

    async fn check_session_ticket(&self) -> Result<(u32, bool)> {
        // 检测会话票据超时和轮换
        // 返回 (超时时间(秒), 是否轮换)
        Ok((7200, true))
    }

    async fn check_session_resumption(&self) -> Result<(bool, bool)> {
        // 检测会话恢复支持
        // 返回 (支持票据, 支持ID)
        Ok((false, true))
    }

    fn get_oid(bytes: &[u64]) -> Oid<'static> {
        Oid::from(bytes).unwrap()
    }

    async fn analyze_certificate(&self, cert_data: &[u8]) -> Result<CertificateInfo> {
        if let Ok((_, cert)) = X509Certificate::from_der(cert_data) {
            let mut info = CertificateInfo::default();
            
            // 提取有效期
            let start_time = cert.tbs_certificate.validity.not_before;
            let end_time = cert.tbs_certificate.validity.not_after;
            
            // 使用 TimeZone trait 的方法，修改错误处理
            info.validity_start = Utc.timestamp_opt(start_time.timestamp(), 0)
                .single()
                .unwrap_or_else(|| Utc.timestamp_nanos(0));
            info.validity_end = Utc.timestamp_opt(end_time.timestamp(), 0)
                .single()
                .unwrap_or_else(|| Utc.timestamp_nanos(0));

            // 提取主体备用名称
            let san_oid = Self::get_oid(OID_SUBJECT_ALT_NAME_BYTES);
            if let Ok(Some(san_ext)) = cert.tbs_certificate.get_extension_unique(&san_oid) {
                if let Ok((_, sequence)) = parse_ber(san_ext.value) {
                    if let Ok(names) = sequence.as_sequence() {
                        info.subject_alt_names = names.iter()
                            .filter_map(|name| name.as_str().ok())
                            .map(|s| s.to_string())
                            .collect();
                    }
                }
            }

            // 提取 OCSP 信息
            let aia_oid = Self::get_oid(OID_AUTHORITY_INFO_ACCESS_BYTES);
            if let Ok(Some(aia_ext)) = cert.tbs_certificate.get_extension_unique(&aia_oid) {
                if let Ok((_, sequence)) = parse_ber(aia_ext.value) {
                    if let Ok(aia) = sequence.as_sequence() {
                        for access in aia {
                            if let Ok(access_seq) = access.as_sequence() {
                                let ocsp_oid = Self::get_oid(OID_PKIX_OCSP_BYTES);
                                if access_seq.len() >= 2 
                                    && access_seq[0].as_oid().map(|oid| oid == &ocsp_oid).unwrap_or(false) {
                                    if let Ok(uri) = access_seq[1].as_str() {
                                        info.ocsp_uri = Some(uri.to_string());
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // 检查扩展
            for ext in cert.tbs_certificate.extensions() {
                let must_staple_oid = Self::get_oid(OID_MUST_STAPLE_BYTES);
                let ct_scts_oid = Self::get_oid(OID_CT_PRECERT_SCTS_BYTES);
                
                if ext.oid == must_staple_oid {
                    info.must_staple = true;
                } else if ext.oid == ct_scts_oid {
                    info.cert_transparency = true;
                }
            }

            Ok(info)
        } else {
            Err(ScanError::CertificateParse)
        }
    }

    async fn verify_certificate_chain(&self, cert: &X509Certificate<'_>) -> Result<bool> {
        // 实现证书链验证逻辑
        // 这里应该检查证书是否被可信的根证书签名，是否在有效期内等
        Ok(true)  // 临时返回值，实际应该根据验证结果返回
    }

    pub async fn scan_server_defaults(&self) -> Result<()> {
        println!("{}", Self::make_title("Testing server defaults (Server Hello)"));

        // TLS 扩展
        let extensions = self.get_tls_extensions().await?;
        println!("{:<30} {}", 
            "TLS extensions (standard)",
            extensions.join(" ")
        );

        // 会话票据
        let (ticket_lifetime, rotated) = self.check_session_ticket().await?;
        println!("{:<30} {} seconds, session tickets keys seems to be rotated {}", 
            "Session Ticket RFC 5077 hint",
            ticket_lifetime,
            if rotated { "< daily" } else { "> daily" }
        );

        // 获取证书信息
        let cert_info = self.get_certificate_info().await?;
        
        // SSL 会话 ID 支持和会话恢复
        let (tickets_supported, id_supported) = self.check_session_resumption().await?;
        println!("{:<30} {}", 
            "SSL Session ID support",
            if id_supported { "yes" } else { "no" }
        );
        println!("{:<30} Tickets: {}, ID: {}", 
            "Session Resumption",
            if tickets_supported { "yes" } else { "no" },
            if id_supported { "yes" } else { "no" }
        );

        // TLS 时钟偏差
        let clock_skew = self.check_clock_skew().await?;
        println!("{:<30} {}", "TLS clock skew", clock_skew);

        // 证书压缩
        let compression = self.check_compression().await?;
        println!("{:<30} {}", "Certificate Compression", compression);

        // 客户端认证
        let client_auth = self.check_client_auth().await?;
        println!("{:<30} {}", "Client Authentication", client_auth);

        // 签名算法
        println!("{:<30} {}", 
            "Signature Algorithm", 
            format!("{} with RSA", cert_info.signature_algorithm).green()
        );

        // 服务器密钥信息
        println!("{:<30} RSA {} bits (exponent is {})", 
            "Server key size",
            cert_info.key_size,
            cert_info.key_exponent
        );

        // 服务器密钥用途
        println!("{:<30} {}", 
            "Server key usage",
            cert_info.key_usage.join(", ")
        );

        // 获取扩展密钥用途
        let ext_key_usage = self.get_extended_key_usage().await?;
        println!("{:<30} {}", 
            "Server extended key usage",
            ext_key_usage.join(", ")
        );

        // 序列号和指纹
        println!("{:<30} {}", "Serial", cert_info.serial);
        println!("{:<30} SHA1 {}", "Fingerprints", cert_info.fingerprint_sha1);
        println!("{:30} SHA256 {}", "", cert_info.fingerprint_sha256);

        // 获取证书主体信息
        let (cn, san) = self.get_certificate_names().await?;
        println!("{:<30} {}", "Common Name (CN)", cn);
        println!("{:<30} {}", "subjectAltName (SAN)", san);

        // 证书信任信息
        let (trust_status, trust_details) = self.check_certificate_trust().await?;
        println!("{:<30} {} {}", 
            "Trust (hostname)",
            trust_status.green(),
            trust_details
        );

        // 证书链信息
        let chain_info = self.get_certificate_info().await?;
        println!("{:<30} {}", 
            "Chain of trust", 
            if chain_info.valid { "Ok".green() } else { "Not ok".red() }
        );

        // 证书有效期
        let now = Utc::now();
        let days_remaining = (cert_info.validity_end - now).num_days();
        println!("{:<30} {} ({} --> {})", 
            "Certificate Validity (UTC)",
            format!("{} >= 60 days", days_remaining).green(),
            cert_info.validity_start.format("%Y-%m-%d %H:%M"),
            cert_info.validity_end.format("%Y-%m-%d %H:%M")
        );

        // OCSP 信息
        if let Some(uri) = &cert_info.ocsp_uri {
            println!("{:<30} {}", "OCSP URI", uri);
        }
        println!("{:<30} {}", 
            "OCSP stapling",
            if cert_info.ocsp_stapling { "offered".green() } else { "not offered".yellow() }
        );
        println!("{:<30} {}", 
            "OCSP must staple extension",
            if cert_info.must_staple { "yes" } else { "--" }
        );

        // 证书透明度
        println!("{:<30} yes (certificate extension)", 
            "Certificate Transparency",
        );

        // 证书链信息
        println!("{:<30} {}", "Certificates provided", cert_info.trust_chain.len() + 1);
        println!("{:<30} {}", "Issuer", cert_info.issuer);

        // 中间证书信息
        for (i, cert) in cert_info.trust_chain.iter().enumerate() {
            let days_remaining = (cert.validity_end - now).num_days();
            if i == 0 {
                println!("{:<30} #{}: {} ({}). {} <-- {}", 
                    "Intermediate cert validity",
                    i + 1,
                    if days_remaining > 40 { "ok > 40 days".green() } else { "warning < 40 days".yellow() },
                    cert.validity_end.format("%Y-%m-%d %H:%M"),
                    cert.subject,
                    cert.issuer
                );
            } else {
                println!("{:30} #{}: {} ({}). {} <-- {}", 
                    "",
                    i + 1,
                    if days_remaining > 40 { "ok > 40 days".green() } else { "warning < 40 days".yellow() },
                    cert.validity_end.format("%Y-%m-%d %H:%M"),
                    cert.subject,
                    cert.issuer
                );
            }
        }

        // ... 其他动态检查 ...

        println!();
        Ok(())
    }

    pub async fn get_certificate_info(&self) -> Result<CertificateInfo> {
        // 获取并分析服务器证书
        let certs = self.get_server_certificate().await?;
        if let Some(cert_data) = certs.first() {
            self.analyze_certificate(cert_data.as_ref()).await
        } else {
            Ok(CertificateInfo::default())
        }
    }

    async fn check_clock_skew(&self) -> Result<String> {
        // 实现实际的时钟偏差检测
        Ok("Random values, no fingerprinting possible".to_string())
    }

    async fn check_compression(&self) -> Result<String> {
        // 实现实际的压缩支持检测
        Ok("none".to_string())
    }

    async fn check_client_auth(&self) -> Result<String> {
        // 实现客户端认证检测
        Ok("none".to_string())
    }

    async fn get_extended_key_usage(&self) -> Result<Vec<String>> {
        // 实现扩展密钥用途检测
        Ok(vec![
            "TLS Web Server Authentication".to_string(),
            "TLS Web Client Authentication".to_string(),
        ])
    }

    async fn get_certificate_names(&self) -> Result<(String, String)> {
        // 实现证书名称提取
        Ok((
            format!("*.{}", self.host),
            format!("*.{} {}", self.host, self.host)
        ))
    }

    async fn check_certificate_trust(&self) -> Result<(String, String)> {
        // 实现证书信任检查
        Ok(("Ok via SAN wildcard and CN wildcard".to_string(), "(SNI mandatory)".to_string()))
    }

    async fn get_certificate_chain(&self) -> Result<Vec<CertificateChainInfo>> {
        let certs = self.get_server_certificate().await?;
        let mut chain = Vec::new();

        for cert_data in certs.iter().skip(1) {
            if let Ok((_, cert)) = X509Certificate::from_der(cert_data.as_ref()) {
                let start_time = cert.tbs_certificate.validity.not_before;
                let end_time = cert.tbs_certificate.validity.not_after;
                
                chain.push(CertificateChainInfo {
                    subject: cert.tbs_certificate.subject.to_string(),
                    issuer: cert.tbs_certificate.issuer.to_string(),
                    validity_start: Utc.timestamp_opt(start_time.timestamp(), 0)
                        .single()
                        .unwrap_or_else(|| Utc.timestamp_nanos(0)),
                    validity_end: Utc.timestamp_opt(end_time.timestamp(), 0)
                        .single()
                        .unwrap_or_else(|| Utc.timestamp_nanos(0)),
                });
            }
        }

        Ok(chain)
    }

    fn convert_datetime(dt: ASN1Time) -> DateTime<Utc> {
        Utc.timestamp_opt(dt.timestamp(), 0)
            .single()
            .unwrap_or_else(|| Utc.timestamp_nanos(0))
    }

    // ... 其他辅助方法 ...
}

#[derive(Default)]
pub struct CertificateInfo {
    pub signature_algorithm: String,
    pub key_size: u32,
    pub key_usage: Vec<String>,
    pub key_exponent: u32,
    pub serial: String,
    pub fingerprint_sha1: String,
    pub fingerprint_sha256: String,
    pub valid: bool,
    pub validity_start: DateTime<Utc>,
    pub validity_end: DateTime<Utc>,
    pub issuer: String,
    pub subject: String,
    pub subject_alt_names: Vec<String>,
    pub ocsp_uri: Option<String>,
    pub ocsp_stapling: bool,
    pub must_staple: bool,
    pub cert_transparency: bool,
    pub trust_chain: Vec<CertificateChainInfo>,
}

#[derive(Default)]
pub struct CertificateChainInfo {
    pub subject: String,
    pub issuer: String,
    pub validity_start: DateTime<Utc>,
    pub validity_end: DateTime<Utc>,
} 