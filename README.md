# LLM Proxy

A high-performance LLM (Large Language Model) proxy server written in Rust, designed to intelligently route requests between multiple LLM providers with advanced features like weighted load balancing, health checks, and connection pooling.

## Features

- **Multi-Provider Support**: Seamlessly proxy requests to OpenAI, Gemini, and Anthropic APIs
- **Intelligent Load Balancing**: Weighted provider selection algorithm for optimal resource utilization
- **Health Monitoring**: Automatic health checks with configurable intervals and failure recovery
- **Connection Pooling**: Efficient connection reuse to minimize latency and resource usage
- **Authentication & Authorization**: Flexible API key management with per-provider and global authentication
- **Protocol Support**: Full HTTP/1.1 and HTTP/2 support with automatic protocol negotiation
- **TLS Encryption**: Secure communication using [rustls](https://crates.io/crates/tokio-rustls) with modern cipher suites
- **Configuration Management**: YAML-based configuration with hot-reload capability (SIGHUP)
- **Structured Logging**: Comprehensive logging for monitoring and debugging
- **Container Ready**: Docker support for easy deployment and scaling

## Installation

### From Source

```bash
git clone https://github.com/x5iu/llm-proxy.git
cd llm-proxy
cargo build --release
```

### Docker

```bash
# Pull and run the pre-built image
docker run -d \
  --name llm-proxy \
  -p 443:443 \
  -v /path/to/config.yml:/config.yml \
  -v /path/to/certificate.pem:/certs/certificate.pem \
  -v /path/to/private-key.pem:/certs/private-key.pem \
  x5iu/llm-proxy:latest
```

## Configuration

### TLS Certificates

The proxy requires TLS certificates for secure HTTPS communication. You need two files:

- `certificate.pem` - Your TLS certificate (public key)
- `private-key.pem` - Your TLS private key

### Configuration File

Create a `config.yml` file with your LLM provider configurations:

```yaml
# TLS Configuration
cert_file: "/certs/certificate.pem"
private_key_file: "/certs/private-key.pem"

# Global Authentication Keys
auth_keys:
  - "client-api-key-1"
  - "client-api-key-2"

# Health Check Interval (seconds)
health_check_interval: 60

# Provider Configuration
providers:
  # OpenAI Configuration
  - type: "openai"
    host: "openai.example.com"       # Client uses "Host: openai.example.com" header to route to this provider
    endpoint: "api.openai.com"       # Actual OpenAI API endpoint
    port: 443
    tls: true
    weight: 1.0
    api_key: "sk-your-openai-api-key"
    health_check:
      method: "GET"
      path: "/v1/models"
      body: "{}"
      headers:
        - "Content-Type: application/json"

  # Gemini Configuration
  - type: "gemini"
    host: "gemini.example.com"       # Client uses "Host: gemini.example.com" header to route to this provider
    endpoint: "generativelanguage.googleapis.com"  # Actual Google API endpoint
    port: 443
    tls: true
    weight: 1.5
    api_key: "your-gemini-api-key"
    health_check:
      method: "GET"
      path: "/v1beta/models"
      body: "{}"

  # Anthropic Configuration
  - type: "anthropic"
    host: "anthropic.example.com"    # Client uses "Host: anthropic.example.com" header to route to this provider
    endpoint: "api.anthropic.com"    # Actual Anthropic API endpoint
    port: 443
    tls: true
    weight: 1.2
    api_key: "sk-ant-your-anthropic-api-key"
    health_check:
      method: "POST"
      path: "/v1/messages"
      body: '{"model":"claude-3-haiku-20240307","max_tokens":1,"messages":[{"role":"user","content":"ping"}]}'
      headers:
        - "Content-Type: application/json"
        - "anthropic-version: 2023-06-01"

  # Multiple API Keys for Load Distribution
  - type: "openai"
    host: "openai-backup.example.com"  # Different host name for separate routing
    endpoint: "api.openai.com"
    api_keys:
      - key: "sk-key-1"
        weight: 1.0
      - key: "sk-key-2"
        weight: 2.0
    auth_keys:
      - "provider-specific-auth-key"
```

## Usage

### Start the Proxy Server

```bash
# Basic usage
./llm-proxy start -c config.yml

# With health checks enabled
./llm-proxy start -c config.yml --enable-health-check
```

### Making Requests

The proxy server listens on port 443 and routes requests based on the `Host` header:

```bash
# OpenAI API request
curl -X POST https://localhost/v1/chat/completions \
  -H "Host: openai.example.com" \
  -H "Authorization: Bearer client-api-key-1" \
  -H "Content-Type: application/json" \
  -d '{"model": "gpt-3.5-turbo", "messages": [{"role": "user", "content": "Hello!"}]}'

# Gemini API request
curl -X POST https://localhost/v1/models/gemini-pro:generateContent \
  -H "Host: gemini.example.com" \
  -H "x-goog-api-key: client-api-key-1" \
  -H "Content-Type: application/json" \
  -d '{"contents": [{"parts": [{"text": "Hello!"}]}]}'

# Anthropic API request
curl -X POST https://localhost/v1/messages \
  -H "Host: anthropic.example.com" \
  -H "X-API-Key: client-api-key-1" \
  -H "Content-Type: application/json" \
  -d '{"model": "claude-3-haiku-20240307", "max_tokens": 100, "messages": [{"role": "user", "content": "Hello!"}]}'
```

## Performance

- **Concurrent Requests**: Handles thousands of concurrent connections
- **Low Latency**: Connection pooling minimizes request overhead
- **Memory Efficient**: Streaming request/response processing
- **CPU Optimized**: Async I/O with minimal thread overhead

## Security

- **TLS 1.3**: Modern encryption standards with forward secrecy
- **API Key Validation**: Multi-layer authentication system
- **No Key Logging**: Secure handling of sensitive credentials
- **Rate Limiting**: Built-in protection against abuse

## Signal Handling

- **SIGTERM/SIGINT**: Graceful shutdown
- **SIGHUP**: Reload configuration without restart

## License

This project is licensed under the MIT License - see the LICENSE file for details.