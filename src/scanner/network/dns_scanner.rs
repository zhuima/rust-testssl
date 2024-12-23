use std::time::{SystemTime, UNIX_EPOCH};
use chrono::{DateTime, Local};
use trust_dns_resolver::TokioAsyncResolver;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use colored::*;
use crate::errors::{Result, ScanError};
use std::iter;

pub struct DnsScanner {
    host: String,
    port: u16,
    start_time: DateTime<Local>,
}

impl DnsScanner {
    pub fn new(host: String, port: u16) -> Self {
        Self {
            host,
            port,
            start_time: Local::now(),
        }
    }

    fn make_title(text: &str) -> String {
        let underline = iter::repeat('_').take(text.len()).collect::<String>();
        format!(" {}\n {}\n", text, underline)
    }

    pub async fn print_start_banner(&self) -> Result<()> {
        println!("{}", "#".repeat(75));
        println!(" rust-testssl version 0.1.0 from https://github.com/zhuima/rust-testssl");
        let timestamp = Local::now();
        println!(" ({:x} {})", timestamp.timestamp(), timestamp.format("%Y-%m-%d %H:%M:%S"));
        println!();
        println!(" This is a Rust implementation of SSL/TLS scanning tool.");
        println!(" Licensed under MIT. USE IT AT YOUR OWN RISK!");
        println!();
        println!(" Please file issues @ https://github.com/zhuima/rust-testssl/issues");
        println!();
        println!("{}", "#".repeat(75));
        println!();
        println!(" Using rustls v0.21");
        println!(" on {} {}", std::env::consts::OS, std::env::consts::ARCH);
        println!();

        let start_line = format!("Start {}", self.start_time.format("%Y-%m-%d %H:%M:%S"));
        println!();
        println!("{:28} -->> {} <<--", 
            start_line,
            self.get_dns_info().await?.green()
        );
        println!("{}", "#".repeat(75));
        println!();

        self.print_dns_info().await?;

        Ok(())
    }

    pub async fn print_end_banner(&self) -> Result<()> {
        let end_time = Local::now();
        let duration = end_time.signed_duration_since(self.start_time).num_seconds();
        
        println!();
        println!("{}", "#".repeat(75));

        println!("Done {:<28}[ {}s] -->> {} <<--",
            end_time.format("%Y-%m-%d %H:%M:%S"),
            duration,
            self.get_dns_info().await?.green()
        );
        println!();
        Ok(())
    }

    async fn get_dns_info(&self) -> Result<String> {
        let resolver = TokioAsyncResolver::tokio(
            ResolverConfig::default(),
            ResolverOpts::default(),
        ).map_err(|e| anyhow::anyhow!("Failed to create resolver: {}", e))?;

        let ip = resolver.lookup_ip(&self.host)
            .await?
            .iter()
            .next()
            .ok_or_else(|| anyhow::anyhow!("No IP found"))?;

        let rdns = match resolver.reverse_lookup(ip).await {
            Ok(result) => result
                .iter()
                .next()
                .map(|name| name.to_string())
                .unwrap_or_else(|| "no PTR".to_string()),
            Err(_) => "no PTR".to_string()
        };

        // println!("rDNS ({}): {}", ip, rdns);
        // println!("Service detected: HTTP");
        // println!();

        Ok(format!("{}:{} ({})", ip, self.port, self.host))
    }

    pub async fn print_dns_info(&self) -> Result<()> {
        let resolver = TokioAsyncResolver::tokio(
            ResolverConfig::default(),
            ResolverOpts::default(),
        ).map_err(|e| anyhow::anyhow!("Failed to create resolver: {}", e))?;

        let ip = resolver.lookup_ip(&self.host)
            .await?
            .iter()
            .next()
            .ok_or_else(|| anyhow::anyhow!("No IP found"))?;

        let rdns = match resolver.reverse_lookup(ip).await {
            Ok(result) => result
                .iter()
                .next()
                .map(|name| name.to_string())
                .unwrap_or_else(|| "no PTR".to_string()),
            Err(_) => "no PTR".to_string()
        };

        println!("rDNS ({}): {}", ip, rdns);
        println!("Service detected: HTTP");
        println!();

        Ok(())
    }
} 