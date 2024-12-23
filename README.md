# Rust-TestSSL

A Rust implementation of the popular [testssl.sh](https://github.com/drwetter/testssl.sh) tool for testing TLS/SSL security and configuration.

## Project Structure

```
src/
├── certificates/     # 证书分析模块
├── ciphers/         # 密码套件测试模块
├── protocols/       # 协议支持检测模块
├── vulnerabilities/ # 漏洞检测模块
├── scanner/         # 核心扫描功能
│   ├── mod.rs
│   ├── tls_scanner.rs
│   ├── server_defaults_scanner.rs
│   └── forward_secrecy_scanner.rs
├── errors.rs        # 错误处理
├── output.rs        # 输出格式化
└── main.rs          # 程序入口
```

## Modules

### certificates
证书分析模块，负责：
- 证书链验证
- 证书信息提取
- OCSP 状态检查
- CT 日志检查

### ciphers
密码套件测试模块，包含：
- 支持的密码套件检测
- 密码套件优先级分析
- 密钥交换算法测试

### protocols
协议支持检测模块，实现：
- TLS/SSL 版本支持检测
- 协议降级保护检查
- 协议扩展支持分析

### vulnerabilities
漏洞检测模块，用于：
- 已知 TLS/SSL 漏洞检测
- 安全配置评估
- 最佳实践检查

### scanner
核心扫描功能模块：
- TLS 连接建立
- 服务器配置分析
- 前向安全性测试

## Key Components

### ServerDefaultsScanner
服务器默认配置扫描器，检测：
- TLS 扩展支持
- 会话恢复能力
- 证书压缩支持
- 时钟偏差

### TlsScanner
TLS 协议扫描器，负责：
- 协议版本协商
- 密码套件选择
- 证书链获取

### ForwardSecrecyScanner
前向安全性扫描器，测试：
- 密钥交换算法
- 签名算法支持
- 椭圆曲线支持

## Output Format

输出示例：
```
Testing server defaults (Server Hello)
_____________________________________

TLS extensions (standard)      renegotiation info/#65281
Session Ticket RFC 5077 hint   7200 seconds
SSL Session ID support         yes
Session Resumption            Tickets: yes, ID: yes
...
```

## Development Status

- [x] 基础框架搭建
- [x] TLS 连接建立
- [x] 证书分析
- [ ] 密码套件测试
- [ ] 漏洞扫描
- [ ] 完整性测试

## Contributing

1. 遵循 Rust 编码规范
2. 添加必要的测试用例
3. 更新相关文档
4. 提交 PR 前进行本地测试