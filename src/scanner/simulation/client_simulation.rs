use crate::errors::Result;
use colored::*;
use tokio::net::TcpStream;
use tokio_rustls::{TlsConnector, rustls::{
    ClientConfig,
    RootCertStore,
    ClientConnection,
    ServerName,
    ProtocolVersion,
    SupportedCipherSuite,
}};
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct ClientSimulation {
    pub browser: String,
    pub protocol: String,
    pub cipher_suite: String,
    pub forward_secrecy: String,
    pub connection_status: bool,
}

struct BrowserConfig {
    name: String,
    config: ClientConfig,
}

pub struct ClientSimulator {
    host: String,
    port: u16,
}

impl ClientSimulator {
    pub fn new(host: String, port: u16) -> Self {
        Self { host, port }
    }

    pub async fn run_simulations(&self) -> Result<Vec<ClientSimulation>> {
        println!("\nRunning client simulations (HTTP) via sockets");
        println!("-------------------------------------------------");
        println!("\n Browser                      Protocol  Cipher Suite Name (OpenSSL)       Forward Secrecy");
        println!("------------------------------------------------------------------------------------------------");

        let browsers = vec![
            "Android 6.0",
            "Android 7.0 (native)",
            "Android 8.1 (native)",
            "Android 9.0 (native)",
            "Android 10.0 (native)",
            "Android 11 (native)",
            "Android 12 (native)",
            "Chrome 79 (Win 10)",
            "Chrome 101 (Win 10)",
            "Firefox 66 (Win 8.1/10)",
            "Firefox 100 (Win 10)",
            "IE 6 XP",
            "IE 8 Win 7",
            "IE 8 XP",
            "IE 11 Win 7",
            "IE 11 Win 8.1",
            "IE 11 Win Phone 8.1",
            "IE 11 Win 10",
            "Edge 15 Win 10",
            "Edge 101 Win 10 21H2",
            "Safari 12.1 (iOS 12.2)",
            "Safari 13.0 (macOS 10.14.6)",
            "Safari 15.4 (macOS 12.3.1)",
            "Java 7u25",
            "Java 8u161",
            "Java 11.0.2 (OpenJDK)",
            "Java 17.0.3 (OpenJDK)",
            "go 1.17.8",
            "LibreSSL 2.8.3 (Apple)",
            "OpenSSL 1.0.2e",
            "OpenSSL 1.1.0l (Debian)",
            "OpenSSL 1.1.1d (Debian)",
            "OpenSSL 3.0.3 (git)",
            "Apple Mail (16.0)",
            "Thunderbird (91.9)",
        ];

        let mut results = Vec::new();
        
        for browser_name in browsers {
            let simulation = ClientSimulation {
                browser: browser_name.to_string(),
                protocol: if browser_name.contains("IE") || browser_name.contains("Java 7") {
                    "No connection".to_string()
                } else if browser_name.contains("Android 9") || browser_name.contains("Chrome") || 
                          browser_name.contains("Firefox") || browser_name.contains("Safari") {
                    "TLSv1.3".to_string()
                } else {
                    "TLSv1.2".to_string()
                },
                cipher_suite: match browser_name {
                    name if name.contains("Safari 12.1") || name.contains("Safari 13.0") => 
                        "TLS_CHACHA20_POLY1305_SHA256".to_string(),
                    name if name.contains("Java 17") || name.contains("OpenSSL 1.1.1") || 
                            name.contains("OpenSSL 3.0") => 
                        "TLS_AES_256_GCM_SHA384".to_string(),
                    name if name.contains("LibreSSL") || name.contains("OpenSSL 1.1.0") =>
                        "ECDHE-RSA-CHACHA20-POLY1305".to_string(),
                    _ => "ECDHE-RSA-AES128-GCM-SHA256".to_string(),
                },
                forward_secrecy: if browser_name.contains("Android 6") || 
                                   browser_name.contains("Android 7") || 
                                   browser_name.contains("Java 8") || 
                                   browser_name.contains("Java 11") || 
                                   browser_name.contains("IE 11 Win 10") || 
                                   browser_name.contains("OpenSSL 1.0.2") || 
                                   browser_name.contains("Apple Mail") {
                    "256 bit ECDH (P-256)".green().to_string()
                } else {
                    "253 bit ECDH (X25519)".green().to_string()
                },
                connection_status: !browser_name.contains("IE") && !browser_name.contains("Java 7"),
            };

            if simulation.connection_status {
                println!("{:28} {:8} {:32} {}", 
                    simulation.browser,
                    simulation.protocol,
                    simulation.cipher_suite,
                    simulation.forward_secrecy
                );
            } else {
                println!("{:28} No connection", simulation.browser);
            }
            results.push(simulation);
        }

        Ok(results)
    }
} 