
# ngx-waf-protect

`ngx-waf-protect` is a custom NGINX module that provides advanced web application firewall (WAF) protection. It integrates with NGINX to detect and mitigate various web-based attacks, including SQL Injection, Cross-Site Scripting (XSS), Remote Command Execution (RCE), and more. This module can be built as part of a custom NGINX build or as a dynamic module.

## Status

This module is production-ready.

## Synopsis

```nginx
http {
    server {
        listen 80;
        server_name localhost;

        location / {
            clrh_waf_handler;

            enable_protocol_attack on;
            enable_general_rules off;
            enable_sql_injection off;
            enable_xss off;
            enable_rce_php_node off;
            enable_session_rules off;
        }

        error_page 500 502 503 504 /50x.html;
        location = /50x.html {
            root html;
        }
    }
}
```

## Description

`ngx-waf-protect` provides an advanced set of rules and capabilities to protect web applications from various attacks:

- **SQL Injection Protection:** Detects and blocks SQL injection attacks.
- **Cross-Site Scripting (XSS) Protection:** Prevents malicious scripts from being executed.
- **Protocol Attack Protection:** Mitigates attacks that exploit vulnerabilities in protocols.
- **Remote Command Execution (RCE) Protection:** Detects and blocks RCE attempts.
- **Session Rules Enforcement:** Ensures secure session management.
- **General Security Rules:** Provides a baseline of security measures to protect against common threats.

## Directives

### `enable_protocol_attack`
- **Syntax:** `enable_protocol_attack on | off;`
- **Default:** `off`
- **Context:** `http, server, location`
- **Description:** Enables or disables protocol attack protection.

### `enable_sql_injection`
- **Syntax:** `enable_sql_injection on | off;`
- **Default:** `off`
- **Context:** `http, server, location`
- **Description:** Enables or disables SQL injection protection.

### `enable_xss`
- **Syntax:** `enable_xss on | off;`
- **Default:** `off`
- **Context:** `http, server, location`
- **Description:** Enables or disables Cross-Site Scripting (XSS) protection.

### `enable_rce_php_node`
- **Syntax:** `enable_rce_php_node on | off;`
- **Default:** `off`
- **Context:** `http, server, location`
- **Description:** Enables or disables Remote Command Execution (RCE) protection for PHP and Node.js environments.

### `enable_session_rules`
- **Syntax:** `enable_session_rules on | off;`
- **Default:** `off`
- **Context:** `http, server, location`
- **Description:** Enables or disables session management rules.

### `enable_general_rules`
- **Syntax:** `enable_general_rules on | off;`
- **Default:** `on`
- **Context:** `http, server, location`
- **Description:** Enables or disables general security rules.

## Rule Groups and Supported Rules

### 1. General Rules
- **920100 - Invalid HTTP Request Line**: Protects against malformed HTTP request lines.
- **920300 - Request Missing a Host Header**: Ensures requests include a valid Host header to prevent protocol attacks.
- **920310 - Request with Invalid Host Header**: Validates the Host header against allowed domain patterns.
- **921110 - HTTP Protocol Anomaly: Request with Content-Length Header and Chunked Transfer-Encoding**: Detects conflicting HTTP headers that could indicate an attack.
- **920420 - Request Contains Multiple Content-Length Headers**: Prevents requests with multiple conflicting Content-Length headers.

### 2. SQL Injection Rules
- **942100 - SQL Injection Attack Detected via LibInjection**: Uses libInjection to detect SQL injection patterns.
- **942110 - SQL Injection Attempt Detected**: Identifies attempts to execute SQL commands.
- **942190 - SQL Injection Attack Identified by Conditional Statements**: Looks for SQL injection patterns using conditional statements like 'IF', 'CASE', etc.
- **942200 - SQL Injection Bypass Using Comments**: Prevents SQL injection attempts using SQL comments for bypass techniques.

### 3. Cross-Site Scripting (XSS) Rules
- **941100 - XSS Attack Detected via LibInjection**: Uses libInjection to identify common XSS attack patterns.
- **941130 - XSS Attack via HTML Tags**: Identifies malicious use of HTML tags for scripting attacks.
- **941180 - XSS Attack Detected Using JavaScript URIs**: Blocks malicious use of JavaScript URIs in links or other attributes.
- **941160 - XSS Detected by Event Handlers**: Detects malicious scripts embedded in HTML event handlers.

### 4. Remote Command Execution (RCE) and File Inclusion
- **932100 - Remote Command Execution: Unix Commands**: Detects attempts to execute shell commands via Unix systems.
- **932110 - Remote Command Execution: Windows Commands**: Identifies attempts to execute Windows-specific commands.
- **931100 - Local File Inclusion Attempt**: Blocks attempts to include local files on the server, a common method for accessing sensitive information.
- **931120 - Remote File Inclusion Attempt**: Detects attempts to include remote files, which can lead to unauthorized code execution.

### 5. Protocol Attack Rules
- **921130 - Request Contains Content-Length but Not Allowed Method**: Ensures only valid HTTP methods can carry a Content-Length header.
- **921150 - Invalid HTTP Version Number**: Blocks requests using invalid or unsupported HTTP versions.
- **921180 - Invalid Request Line Format**: Detects malformed request lines that can be used to exploit servers.

### 6. Path Traversal and File Access Control
- **930100 - Path Traversal Attempt Detected**: Identifies attempts to navigate directories improperly to access restricted files.
- **930110 - File Access Attempt to Restricted Files**: Prevents unauthorized access to critical system or application files.

### 7. Malicious User-Agent Patterns
- **913100 - Malicious User-Agent Detected**: Identifies known malicious or suspicious user-agent patterns.
- **913110 - User-Agent Indicates Automation Tool**: Blocks requests from known automation tools or bots that are often used in attacks.

### 8. URL Encoding Abuse
- **920430 - Multiple URL Encoding Detected**: Detects requests with multiple levels of URL encoding, often used to bypass input validation.
- **920440 - URL Encoding Abuse Detected**: Identifies improper use of encoding to conceal malicious requests.

## Installation

### Building as a Static Module

To build `ngx-waf-protect` as part of a custom NGINX build:

1. Clone the repository:
   ```bash
   git clone https://github.com/cloudrhinoltd/ngx-waf-protect.git
   cd ngx-waf-protect
   ```

2. Download and extract the NGINX source code:
   ```bash
   wget 'http://nginx.org/download/nginx-1.27.1.tar.gz'
   tar -xzvf nginx-1.27.1.tar.gz
   cd nginx-1.27.1
   ```

3. Configure and build NGINX with the `ngx-waf-protect` module:
   ```bash
   ./configure --prefix=/opt/nginx                --with-http_ssl_module                --add-module=/path/to/ngx-waf-protect
   make -j$(nproc)
   make install
   ```

### Building as a Dynamic Module

Starting with NGINX 1.9.11, `ngx-waf-protect` can also be built as a dynamic module:

1. Follow steps 1 and 2 above.

2. Configure NGINX with `--add-dynamic-module`:
   ```bash
   ./configure --prefix=/opt/nginx                --with-http_ssl_module                --add-dynamic-module=/path/to/ngx-waf-protect
   make -j$(nproc)
   make install
   ```

3. Load the module in `nginx.conf`:
   ```nginx
   load_module /path/to/modules/ngx_waf_protect.so;
   ```

## Requirements

To build `ngx-waf-protect`, you need the following:

- **C++ Compiler:** Ensure that gcc or clang is installed.
- **NGINX Source Code:** Download from nginx.org.
- **Build Tools:** `make`, `autoconf`, and `libtool`.
- **OpenSSL:** Required for SSL support in NGINX.
- **PCRE:** Required for regex support in NGINX.

## Building

To build `ngx-waf-protect`, use the provided build script:

```bash
./scripts/build.sh
```

This script will download and compile all necessary dependencies and build the custom NGINX with the `ngx-waf-protect` module integrated.

## License

This project is licensed under the Apache License 2.0. Note that the `ngx-waf-protect` module contains specific directives that are dual-licensed:

- **Apache License 2.0:** Applies to the following directives:
  - `enable_protocol_attack`
  - `enable_general_rules`
- **Enterprise License:** Required for the following directives:
  - `enable_sql_injection`
  - `enable_xss`
  - `enable_rce_php_node`
  - `enable_session_rules`

For more information on obtaining an enterprise license, please contact Cloud Rhino Pty Ltd.

## Source Repository

Available on GitHub at [cloudrhinoltd/ngx-waf-protect](https://github.com/cloudrhinoltd/ngx-waf-protect).

## Author

Cloud Rhino Pty Ltd  
[cloudrhinoltd@gmail.com](mailto:cloudrhinoltd@gmail.com)

## See Also

- [NGINX](https://nginx.org/)
- [OpenSSL](https://www.openssl.org/)
