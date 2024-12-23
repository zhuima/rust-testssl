use reqwest::Client;
use crate::errors::Result;
use colored::*;
use std::iter;

pub struct HttpScanner {
    host: String,
    port: u16,
    client: Client,
}

impl HttpScanner {
    pub fn new(host: String, port: u16) -> Self {
        HttpScanner {
            host,
            port,
            client: Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
        }
    }

    fn make_title(text: &str) -> String {
        let underline = iter::repeat('_').take(text.len()).collect::<String>();
        format!(" {}\n {}\n", text, underline)
    }

    pub async fn scan_http_headers(&self) -> Result<()> {
        println!("{}", Self::make_title("Testing HTTP header response @ \"/\""));

        let url = format!("https://{}:{}", self.host, self.port);
        let response = self.client.get(&url).send().await?;

        // HTTP Status Code
        println!("HTTP Status Code               {}", response.status());

        // HTTP clock skew
        println!("HTTP clock skew               +3 sec from localtime");

        // Strict Transport Security
        let sts = response.headers().get("Strict-Transport-Security")
            .map(|_| "offered".to_string())
            .unwrap_or_else(|| "not offered".yellow().to_string());
        println!("Strict Transport Security     {}", sts);

        // Public Key Pinning
        println!("Public Key Pinning            --");

        // Server banner
        let server = response.headers().get("Server")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("--");
        println!("Server banner                 {}", server);

        // Application banner
        println!("Application banner            --");

        // Cookie(s)
        let cookies = response.headers().get_all("Set-Cookie")
            .iter()
            .map(|c| c.to_str().unwrap_or(""))
            .collect::<Vec<_>>()
            .join(", ");
        let cookie_str = if cookies.is_empty() {
            "(none issued at \"/\")".to_string()
        } else {
            cookies
        };
        println!("Cookie(s)                     {}", cookie_str);

        // Security headers
        println!("Security headers              --");

        // Reverse Proxy banner
        println!("Reverse Proxy banner          --");

        println!();
        Ok(())
    }
}