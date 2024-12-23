use clap::Parser;
use anyhow::Result;
use rust_testssl::{
    scanner::{
        tls_scanner::TlsScanner,
        http_scanner::HttpScanner,
        client_simulation::ClientSimulator,
        dns_scanner::DnsScanner,
        vulnerability_scanner::VulnerabilityScanner,
        forward_secrecy_scanner::ForwardSecrecyScanner,
        server_defaults_scanner::ServerDefaultsScanner,
    },
    rating::SslRating,
    output,
};

/// 一个简单的 testssl.sh 克隆
#[derive(Parser, Debug)]
#[command(author = "Your Name", version, about = "一个用 Rust 编写的 testssl.sh 克隆", long_about = None)]
struct Cli {
    /// 目标主机名或 IP 地址
    #[arg(value_parser)]
    host: String,

    /// 目标端口 (默认为 443)
    #[arg(short, long, default_value_t = 443)]
    port: u16,

    /// 启用详细输出
    #[arg(short, long)]
    verbose: bool,

    // 可以在这里添加更多的命令行参数，例如指定要测试的协议、密码套件等
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // 创建一个 DNS 扫描器实例
    let dns_scanner = DnsScanner::new(cli.host.clone(), cli.port);
    
    // 只在开始时打印一次 banner
    dns_scanner.print_start_banner().await?;

    // 其他扫描器的执行
    let tls_scanner = TlsScanner::new(cli.host.clone(), cli.port);
    tls_scanner.scan_protocols().await?;
    tls_scanner.scan_cipher_categories().await?;
    tls_scanner.scan_cipher_preferences().await?;

    let fs_scanner = ForwardSecrecyScanner::new(cli.host.clone(), cli.port);
    fs_scanner.scan_forward_secrecy().await?;

    let server_defaults_scanner = ServerDefaultsScanner::new(cli.host.clone(), cli.port);
    server_defaults_scanner.scan_server_defaults().await?;

    let http_scanner = HttpScanner::new(cli.host.clone(), cli.port);
    http_scanner.scan_http_headers().await?;

    let vulnerability_scanner = VulnerabilityScanner::new(cli.host.clone(), cli.port);
    vulnerability_scanner.scan_vulnerabilities().await?;
    
    let simulator = ClientSimulator::new(cli.host.clone(), cli.port);
    simulator.run_simulations().await?;

    // 收集所有扫描结果
    let mut rating = SslRating::default();
    
    // 更新协议评分
    rating.protocols.tls13_supported = tls_scanner.is_tls13_supported().await?;
    rating.protocols.tls12_supported = tls_scanner.is_tls12_supported().await?;
    // ... 其他协议检测结果

    // 更新密码套件评分
    rating.cipher_suites.strong_ciphers = tls_scanner.get_strong_ciphers().await?;
    rating.cipher_suites.weak_ciphers = tls_scanner.get_weak_ciphers().await?;
    // ... 其他密码套件检测结果

    // 更新前向保密评分
    rating.forward_secrecy.fs_available = fs_scanner.has_forward_secrecy().await?;
    rating.forward_secrecy.supported_curves = fs_scanner.get_supported_curves().await?;
    // ... 其他前向保密检测结果

    // 更新证书评分
    let cert_info = server_defaults_scanner.get_certificate_info().await?;
    rating.certificate.key_size = cert_info.key_size;
    rating.certificate.signature_algorithm = cert_info.signature_algorithm;
    // ... 其他证书检测结果

    // 更新漏洞评分
    rating.vulnerabilities.heartbleed = vulnerability_scanner.check_heartbleed().await?;
    rating.vulnerabilities.ccs_injection = vulnerability_scanner.check_ccs_injection().await?;
    // ... 其他漏洞检测结果

    // 显示最终评分
    rating.display();

    // 只在结束时打印一次 banner
    dns_scanner.print_end_banner().await?;

    Ok(())
}