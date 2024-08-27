
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
