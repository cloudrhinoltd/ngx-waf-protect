#!/bin/bash
set -ex

# Define variables
HOME_DIR=$(pwd)
NGINX_VERSION="1.27.1"
PROJECT_NAME="ngx_http_waf_module"
NGINX_SRC_DIR="$HOME_DIR/nginx-$NGINX_VERSION"
NGINX_EXEC="$NGINX_SRC_DIR/objs/nginx"
NGINX_LOG_DIR="$HOME_DIR/logs"
NGINX_TEMP_DIR="$HOME_DIR/temp"
GEOIP_DB_PATH="$HOME_DIR/build/geoip/GeoLite2-City.mmdb"
BUILD_DIR="$HOME_DIR/build"
NGINX_CONF="$BUILD_DIR/nginx.conf"

# Ensure directories exist
mkdir -p "$BUILD_DIR"
mkdir -p "$NGINX_LOG_DIR"
mkdir -p "$NGINX_TEMP_DIR/client_body_temp"
mkdir -p "$NGINX_TEMP_DIR/proxy_temp"
mkdir -p "$NGINX_TEMP_DIR/fastcgi_temp"
mkdir -p "$NGINX_TEMP_DIR/uwsgi_temp"
mkdir -p "$NGINX_TEMP_DIR/scgi_temp"

# Download and extract the latest NGINX core
if [ ! -d "$NGINX_SRC_DIR" ]; then
    wget "http://nginx.org/download/nginx-$NGINX_VERSION.tar.gz" -O nginx.tar.gz
    tar -zxvf nginx.tar.gz -C "$HOME_DIR"
    rm nginx.tar.gz
fi

# Navigate to the NGINX source directory
cd "$NGINX_SRC_DIR"

# Configure and build NGINX with your custom WAF module
./configure --prefix='' \
            --conf-path="$NGINX_CONF" \
            --error-log-path="$NGINX_LOG_DIR/error.log" \
            --http-log-path="$NGINX_LOG_DIR/access.log" \
            --pid-path='./nginx.pid' \
            --lock-path='./nginx.lock' \
            --modules-path='./modules' \
            --http-client-body-temp-path="$NGINX_TEMP_DIR/client_body_temp" \
            --http-proxy-temp-path="$NGINX_TEMP_DIR/proxy_temp" \
            --http-fastcgi-temp-path="$NGINX_TEMP_DIR/fastcgi_temp" \
            --http-uwsgi-temp-path="$NGINX_TEMP_DIR/uwsgi_temp" \
            --http-scgi-temp-path="$NGINX_TEMP_DIR/scgi_temp" \
            --with-debug \
            --with-compat \
            --with-pcre-jit \
            --with-http_ssl_module \
            --with-http_stub_status_module \
            --with-http_realip_module \
            --with-http_auth_request_module \
            --with-http_addition_module \
            --with-http_gzip_static_module \
            --with-http_sub_module \
            --with-http_v2_module \
            --with-http_v3_module \
            --with-stream \
            --with-stream_ssl_module \
            --with-stream_realip_module \
            --with-stream_ssl_preread_module \
            --with-threads \
            --with-http_secure_link_module \
            --with-http_gunzip_module \
            --with-file-aio \
            --without-mail_pop3_module \
            --without-mail_smtp_module \
            --without-mail_imap_module \
            --add-module="$HOME_DIR/$PROJECT_NAME" \
            --with-cc-opt='-I/usr/local/include -I/usr/include/openssl -I/usr/include/pcre -g -O2 -fPIE -fstack-protector-strong -Wformat -Werror=format-security -Wno-deprecated-declarations -fno-strict-aliasing -D_FORTIFY_SOURCE=2 --param=ssp-buffer-size=4 -DTCP_FASTOPEN=23 -fPIC -Wno-cast-function-type -m64 -mtune=generic' \
            --with-ld-opt='-Wl,-z,relro -lmaxminddb -Wl,-z,now'

make -j$(nproc)

# Check if NGINX binary exists
if [ ! -f "$NGINX_EXEC" ]; then
    echo "NGINX binary not found! Build might have failed."
    exit 1
fi

# Copy the NGINX binary to the build directory
cd $HOME_DIR
build/nginx -s stop || true

cp "$NGINX_EXEC" "$BUILD_DIR/nginx"
cp "$NGINX_SRC_DIR/conf/mime.types" "$BUILD_DIR"

# Create a simple NGINX configuration file
cat << EOF > "$BUILD_DIR/nginx.conf"
pid /tmp/nginx/nginx.pid;

worker_processes  1;

events {
    worker_connections  1024;
}

http {
    error_log stderr;

    include       mime.types;
    default_type  application/octet-stream;

    sendfile        on;
    keepalive_timeout  65;

    client_body_temp_path temp/client_body_temp;
    proxy_temp_path temp/proxy_temp;
    fastcgi_temp_path temp/fastcgi_temp;
    uwsgi_temp_path temp/uwsgi_temp;
    scgi_temp_path temp/scgi_temp;

    server {
        listen       8080;
        server_name  localhost;

        location / {
            clrh_waf_handler;

            # WAF Rules Configuration
            enable_general_rules on;          # Apache License 2.0
            enable_protocol_attack on;        # Apache License 2.0
            enable_sql_injection off;         # Requires Commercial License
            enable_xss off;                   # Requires Commercial License
            enable_rce_php_node off;          # Requires Commercial License
            enable_session_rules off;         # Requires Commercial License

            geoip_db_path "$GEOIP_DB_PATH";
            sql_injection_common_testing_pattern "(union.*select|select.*from|drop.*table|insert.*into|or.*=.*|--|;|exec|union|select|concat|information_schema)";
            xss_pattern "(<script.*?>.*?</script.*?>|onload=.*?|javascript:|alert\()";

            root   $BUILD_DIR/html;
            index  index.html index.htm;
        }

        error_page   500 502 503 504  /50x.html;
        location = /50x.html {
            root   html;
        }
    }
}
EOF

# Create a simple HTML file for testing
mkdir -p "$BUILD_DIR/html"
echo "<html><body><h1>CLRH NGINX WAF Module Test</h1></body></html>" > "$BUILD_DIR/html/index.html"

# Output success message
echo "Custom NGINX with WAF module built successfully and located at $BUILD_DIR."
cd $HOME_DIR
build/nginx
