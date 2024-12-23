use crate::scanner::tls_scanner::TlsVersionInfo;

pub fn print_tls_scan_result(results: &Vec<TlsVersionInfo>) {
    println!("\nTesting server's cipher preferences");
    println!("--------------------------------------");
    if results.is_empty() {
        println!("  未检测到支持的 TLS/SSL 协议。");
    } else {
        for result in results {
            println!("  {}:", result.version);
            if let Some(protocol) = &result.negotiated_protocol {
                println!("    协商协议: {}", protocol);
            }
            if let Some(cipher) = &result.negotiated_cipher {
                println!("    协商密码套件: {}", cipher);
            }
            if !result.certificate_chain.is_empty() {
                println!("    证书链:");
                for cert_info in &result.certificate_chain {
                    println!("      {}", cert_info);
                }
            } else {
                println!("    未能获取证书链。");
            }
        }
    }
}