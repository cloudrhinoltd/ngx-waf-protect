/*
 * Copyright (C) 2024 Cloud Rhino Pty Ltd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * This module contains parts under a dual-license:
 * Only the 'enable_protocol_attack' and 'enable_general_rules' features are
 * covered by the Apache 2.0 License, other features require a commercial license.
 *
 * GitHub Repo: https://github.com/cloudrhinoltd/ngx-waf-protect
 * Contact Email: cloudrhinoltd@gmail.com
 */

#include "../include/ngx_http_waf_module.h"
#include "waf_utils.cpp"
#include "general_rules.cpp"
#include "protocol_attack.cpp"
#include "xss_rules.cpp"
#include "rce_php_node_rules.cpp"
#include "sql_injection_rules.cpp"
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <unordered_map>
#include <string>
#include <vector>
#include <sstream>
#include <chrono>
#include <ctime>
#include <cstring>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_string.h>
#include <atomic>

// Global atomic pointers for lock-free access
std::atomic<std::unordered_map<std::string, std::pair<int, std::chrono::steady_clock::time_point>> *> rate_limit_map_ptr(new std::unordered_map<std::string, std::pair<int, std::chrono::steady_clock::time_point>>());
std::atomic<std::unordered_map<std::string, std::chrono::steady_clock::time_point> *> blocked_ips_ptr(new std::unordered_map<std::string, std::chrono::steady_clock::time_point>());

unsigned char key[32];
unsigned char iv[16];

// Global atomic counter for generating unique IDs
std::atomic<uint64_t> request_counter(0);
std::string generate_request_id()
{
    auto now = std::chrono::steady_clock::now().time_since_epoch().count();
    uint64_t counter = request_counter++;

    std::ostringstream ss;
    ss << now << "-" << counter;

    return ss.str();
}

ngx_http_waf_request_ctx_t *ngx_http_waf_create_request_ctx(ngx_http_request_t *r)
{
    ngx_http_waf_request_ctx_t *ctx;

    ctx = (ngx_http_waf_request_ctx_t *)ngx_pcalloc(r->pool, sizeof(ngx_http_waf_request_ctx_t));
    if (ctx == NULL)
    {
        return NULL;
    }

    // Generate and store a unique request ID
    ctx->request_id = generate_request_id();
    ngx_http_set_ctx(r, ctx, ngx_http_waf_module);

    return ctx;
}

void generate_key_and_iv()
{
    RAND_bytes(key, sizeof(key));
    RAND_bytes(iv, sizeof(iv));
}

std::string base64_encode(const std::string &input)
{
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    BIO_push(b64, bio);

    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(b64, input.data(), input.size());
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bufferPtr);
    BIO_set_close(b64, BIO_NOCLOSE);
    BIO_free_all(b64);

    std::string encoded_data(bufferPtr->data, bufferPtr->length);
    BUF_MEM_free(bufferPtr);

    return encoded_data;
}

std::string base64_decode(const std::string &input)
{
    BIO *bio, *b64;
    char *buffer = (char *)malloc(input.size());
    memset(buffer, 0, input.size());

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_mem_buf(input.data(), input.size());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    int decoded_length = BIO_read(bio, buffer, input.size());
    BIO_free_all(bio);

    std::string decoded_data(buffer, decoded_length);
    free(buffer);

    return decoded_data;
}

std::string encrypt_session_value(const std::string &plaintext)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len;
    int ciphertext_len;
    std::string ciphertext(plaintext.size() + EVP_MAX_BLOCK_LENGTH, '\0');

    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, reinterpret_cast<unsigned char *>(&ciphertext[0]), &len, reinterpret_cast<const unsigned char *>(plaintext.c_str()), plaintext.size());
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, reinterpret_cast<unsigned char *>(&ciphertext[0]) + len, &len);
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    ciphertext.resize(ciphertext_len);
    return base64_encode(ciphertext);
}

std::string decrypt_session_value(const std::string &ciphertext)
{
    std::string decoded_ciphertext = base64_decode(ciphertext);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len;
    int plaintext_len;
    std::string plaintext(decoded_ciphertext.size(), '\0');

    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char *>(&plaintext[0]), &len, reinterpret_cast<const unsigned char *>(decoded_ciphertext.c_str()), decoded_ciphertext.size());
    plaintext_len = len;
    EVP_DecryptFinal_ex(ctx, reinterpret_cast<unsigned char *>(&plaintext[0]) + len, &len);
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    plaintext.resize(plaintext_len);
    return plaintext;
}

std::string generate_session_id(const std::string &client_ip, const std::string &user_agent, const std::string &uri, const std::string &geo_location, int ttl)
{
    std::time_t now = std::time(nullptr);
    std::time_t valid_till = now + ttl * 60;
    return client_ip + "|" + std::to_string(now) + "|" + std::to_string(valid_till) + "|" + user_agent + "|" + uri + "|" + geo_location;
}

static void log_brute_force_attempt(ngx_http_request_t *r, const std::string &ip)
{
    std::string log_message = "Blocked Brute Force attempt from IP: " + ip;
    ngx_waf_log_access(r, log_message.c_str());
}

ngx_int_t ngx_http_waf_handler_response(ngx_http_request_t *r, ngx_int_t rc)
{
    if (r->header_sent)
    {
        ngx_waf_log_access(r, "Headers already sent, skipping finalization");
        return NGX_DONE;
    }

    ngx_waf_log_access(r, "Setting status and finalizing request: " + std::to_string(rc));
    r->headers_out.status = rc;
    ngx_waf_log_access(r, "Request finalized with status: " + std::to_string(rc));
    ngx_http_finalize_request(r, rc);
    return NGX_DONE;
}

ngx_int_t ngx_http_waf_handler(ngx_http_request_t *r)
{
    try
    {
        ngx_http_waf_request_ctx_t *ctx;

        ngx_waf_log_access(r, "Entering WAF handler, phase: " + std::to_string(r->phase_handler));

        // Check if the request context already exists
        ctx = (ngx_http_waf_request_ctx_t *)ngx_http_get_module_ctx(r, ngx_http_waf_module);
        if (ctx == NULL)
        {
            ctx = ngx_http_waf_create_request_ctx(r);
            if (ctx == NULL)
            {
                ngx_waf_log_access(r, "Failed to create request context");
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
        }

        // If the request has already been processed, skip further processing
        if (ctx->processed)
        {
            ngx_waf_log_access(r, "Request already processed, skipping");
            return NGX_DECLINED;
        }

        // Mark the request as processed
        ctx->processed = 1;

        // Ensure it's the main request
        if (r != r->main)
        {
            ngx_waf_log_access(r, "Subrequest detected, skipping");
            return NGX_DONE;
        }

        ngx_http_waf_loc_conf_t *wlcf = (ngx_http_waf_loc_conf_t *)ngx_http_get_module_loc_conf(r, ngx_http_waf_module);
        if (!wlcf)
        {
            ngx_waf_log_access(r, "Failed to retrieve location configuration");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        std::string client_ip(reinterpret_cast<const char *>(r->connection->addr_text.data), r->connection->addr_text.len);

        // Skip processing if the client IP is 127.0.0.1
        if (client_ip == "127.0.0.1" && wlcf->skip_local)
        {
            ngx_waf_log_access(r, "Request from localhost (127.0.0.1), skipping processing.");
            return NGX_DECLINED;
        }

        ngx_waf_log_access(r, ("Checking if IP is blocked: " + client_ip).c_str());
        if (is_blocked_ip(r, client_ip))
        {
            ngx_waf_log_access(r, ("Blocked IP: " + client_ip).c_str());
            r->headers_out.status = NGX_HTTP_FORBIDDEN;
            ngx_http_finalize_request(r, NGX_HTTP_FORBIDDEN);
            return NGX_DONE;
        }

        ngx_waf_log_access(r, "Checking for brute force attack");
        if (is_brute_force(r, client_ip))
        {
            log_brute_force_attempt(r, client_ip);
            ngx_waf_log_access(r, "Returning NGX_HTTP_FORBIDDEN due to Brute Force");
            r->headers_out.status = NGX_HTTP_FORBIDDEN;
            ngx_http_finalize_request(r, NGX_HTTP_FORBIDDEN);
            return NGX_DONE;
        }

        std::string session_value;
        bool new_session_created = check_or_create_session(r, session_value, (const char *)wlcf->geoip_db_path.data);
        ngx_waf_log_access(r, ("Session valid: " + std::to_string(new_session_created)).c_str());

        // Ensure r->uri and other headers are valid before processing
        if (r->uri.data == NULL)
        {
            ngx_waf_log_access(r, "Invalid or missing URI.");
            return NGX_HTTP_BAD_REQUEST;
        }
        std::string uri(reinterpret_cast<const char *>(r->uri.data), r->uri.len);

        if (r->args.data == NULL && r->args.len > 0)
        {
            ngx_waf_log_access(r, "Invalid or missing query string.");
            return NGX_HTTP_BAD_REQUEST;
        }

        std::string query(reinterpret_cast<const char *>(r->args.data), r->args.len);

        if (r->headers_in.user_agent == NULL || r->headers_in.user_agent->value.data == NULL)
        {
            ngx_waf_log_access(r, "Invalid or missing User-Agent header.");
            return NGX_HTTP_BAD_REQUEST;
        }
        std::string user_agent(reinterpret_cast<const char *>(r->headers_in.user_agent->value.data), r->headers_in.user_agent->value.len);

        ngx_waf_log_access(r, "GeoIP database path: " + std::string((const char *)wlcf->geoip_db_path.data));

        std::string geo_location = get_geo_location(client_ip, (const char *)wlcf->geoip_db_path.data, r);

        ngx_waf_log_access(r, ("URI: " + uri).c_str());
        ngx_waf_log_access(r, ("Query: " + query).c_str());
        ngx_waf_log_access(r, ("User-Agent: " + user_agent).c_str());
        ngx_waf_log_access(r, ("Client IP: " + client_ip).c_str());
        ngx_waf_log_access(r, ("Client Geo Location: " + geo_location).c_str());

        ngx_int_t rc;

        if (wlcf->enable_general_rules)
        {
            // Execute generic rules
            rc = generic_rules_entry_point(r);
            if (rc != NGX_DECLINED)
            {
                return ngx_http_waf_handler_response(r, rc);
            }
            ngx_waf_log_access(r, "Generic rules returned rc: " + std::to_string(rc));
        }

        if (wlcf->enable_rce_php_node)
        {
            rc = rce_php_node_rules_entry_point(r);
            ngx_waf_log_access(r, ("rce_php_node_rules_entry_point Entry point returned: " + std::to_string(rc)).c_str());
            if (rc != NGX_DECLINED)
            {
                return ngx_http_waf_handler_response(r, rc);
            }
        }

        if (wlcf->enable_protocol_attack)
        {
            // Execute protocol attack rules
            rc = protocol_attack_entry_point(r);
            if (rc != NGX_DECLINED)
            {
                return ngx_http_waf_handler_response(r, rc);
            }
        }

        if (wlcf->enable_xss)
        {
            // Execute XSS rules
            rc = xss_rules_entry_point(r);
            ngx_waf_log_access(r, ("xss_rules_entry_point returned: " + std::to_string(rc)).c_str());
            if (rc != NGX_DECLINED)
            {
                return ngx_http_waf_handler_response(r, rc);
            }
        }

        if (wlcf->enable_sql_injection)
        {
            rc = sqli_rules_entry_point(r);
            if (rc != NGX_DECLINED)
            {
                return ngx_http_waf_handler_response(r, rc);
            }
        }

        ngx_waf_log_access(r, "Request passed WAF checks");

        ngx_waf_log_access(r, "Exiting WAF handler");
        return NGX_DECLINED;
    }
    catch (const std::exception &e)
    {
        ngx_waf_log_access(r, (std::string("Exception caught in WAF handler: ") + e.what()).c_str());
        r->headers_out.status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NGX_DONE;
    }
    catch (...)
    {
        ngx_waf_log_access(r, "Unknown exception caught in WAF handler");
        r->headers_out.status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NGX_DONE;
    }
}

bool is_session_valid(ngx_http_request_t *r, std::string &session_id, int ttl)
{
    if (r->headers_in.cookie)
    {
        std::string cookie_str(reinterpret_cast<const char *>(r->headers_in.cookie->value.data), r->headers_in.cookie->value.len);
        size_t pos = cookie_str.find("faw_nginx_session_id=");
        if (pos != std::string::npos)
        {
            std::string encrypted_session_id = cookie_str.substr(pos + strlen("faw_nginx_session_id="));
            session_id = decrypt_session_value(encrypted_session_id);
            size_t idx = 0;
            std::string token;
            std::vector<std::string> tokens;
            while ((idx = session_id.find('|')) != std::string::npos)
            {
                token = session_id.substr(0, idx);
                tokens.push_back(token);
                session_id.erase(0, idx + 1);
            }
            tokens.push_back(session_id);

            std::string client_ip = tokens[0];
            std::time_t now = std::time(nullptr);
            std::time_t session_start_time = std::stol(tokens[1]);
            std::time_t session_valid_till = std::stol(tokens[2]);
            std::string user_agent = tokens[3];
            std::string geo_location = tokens[4];

            if (now <= session_valid_till && (now - session_start_time) <= ttl * 60)
            {
                std::string current_client_ip(reinterpret_cast<const char *>(r->connection->addr_text.data), r->connection->addr_text.len);
                std::string current_user_agent(reinterpret_cast<const char *>(r->headers_in.user_agent->value.data), r->headers_in.user_agent->value.len);
                std::string current_geo_location = "unknown"; // Placeholder for actual geo-location logic

                if (client_ip != current_client_ip || user_agent != current_user_agent || geo_location != current_geo_location)
                {
                    block_ip(current_client_ip);
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Session hijacking detected, blocking IP: %s", current_client_ip.c_str());
                    return false;
                }
                return true;
            }
        }
    }
    return false;
}

bool set_session_cookie(ngx_http_request_t *r, const std::string &session_id)
{
    // Check if the Set-Cookie header already exists in the response
    ngx_list_part_t *part = &r->headers_out.headers.part;
    ngx_table_elt_t *header = (ngx_table_elt_t *)part->elts;
    for (ngx_uint_t i = 0; /* void */; i++)
    {
        if (i >= part->nelts)
        {
            if (part->next == NULL)
            {
                break;
            }
            part = part->next;
            header = (ngx_table_elt_t *)part->elts;
            i = 0;
        }

        if (ngx_strncmp(header[i].key.data, "Set-Cookie", header[i].key.len) == 0)
        {
            std::string cookie_str(reinterpret_cast<const char *>(header[i].value.data), header[i].value.len);
            if (cookie_str.find("faw_nginx_session_id=") != std::string::npos)
            {
                ngx_waf_log_access(r, "Session cookie already set in response, skipping");
                return false;
            }
        }
    }

    // Add the Set-Cookie header if not already set
    ngx_table_elt_t *cookie = (ngx_table_elt_t *)ngx_list_push(&r->headers_out.headers);
    if (cookie)
    {
        cookie->hash = 1;
        ngx_str_set(&cookie->key, "Set-Cookie");
        std::string encrypted_session_id = encrypt_session_value(session_id);
        std::string cookie_value = "faw_nginx_session_id=" + encrypted_session_id;
        cookie->value.len = cookie_value.size();
        cookie->value.data = (u_char *)ngx_pnalloc(r->pool, cookie->value.len);
        if (cookie->value.data)
        {
            ngx_memcpy(cookie->value.data, cookie_value.c_str(), cookie_value.size());
        }
    }
    ngx_waf_log_access(r, "New session created");
    return true;
}

bool check_or_create_session(ngx_http_request_t *r, std::string &session_value, const std::string &db_path)
{
    ngx_http_waf_loc_conf_t *wlcf = (ngx_http_waf_loc_conf_t *)ngx_http_get_module_loc_conf(r, ngx_http_waf_module);
    bool session_found = false;

    try
    {
        // Extract client IP, User-Agent, and URI
        std::string client_ip(reinterpret_cast<const char *>(r->connection->addr_text.data), r->connection->addr_text.len);
        std::string user_agent;
        std::string uri(reinterpret_cast<const char *>(r->uri.data), r->uri.len);

        // Validate User-Agent header
        if (r->headers_in.user_agent == NULL || r->headers_in.user_agent->value.data == NULL)
        {
            ngx_waf_log_access(r, "Invalid or missing User-Agent header.");
            return false;
        }
        user_agent = std::string(reinterpret_cast<const char *>(r->headers_in.user_agent->value.data), r->headers_in.user_agent->value.len);

        ngx_waf_log_access(r, "Extracted client information: IP, User-Agent, and URI.");

        // Check for the session cookie
        if (r->headers_in.cookie)
        {
            std::string cookie_str(reinterpret_cast<const char *>(r->headers_in.cookie->value.data), r->headers_in.cookie->value.len);
            ngx_waf_log_access(r, ("Cookie string received: " + cookie_str).c_str());

            size_t session_pos = cookie_str.find("faw_nginx_session_id=");
            if (session_pos != std::string::npos)
            {
                session_value = cookie_str.substr(session_pos + strlen("faw_nginx_session_id="));
                session_found = true;
                ngx_waf_log_access(r, ("Session ID found in cookie: " + session_value).c_str());
            }
            else
            {
                ngx_waf_log_access(r, "Session ID not found in cookies.");
            }
        }
        else
        {
            ngx_waf_log_access(r, "No cookies found in the HTTP request.");
        }

        std::string session_id;
        if (session_found)
        {
            try
            {
                // Split session_id by '|'
                std::vector<std::string> tokens;
                std::string delimiter = "|";
                size_t pos = 0;
                while ((pos = session_value.find(delimiter)) != std::string::npos)
                {
                    tokens.push_back(session_value.substr(0, pos));
                    session_value.erase(0, pos + delimiter.length());
                }
                tokens.push_back(session_value); // Add the last token

                if (tokens.size() < 3)
                {
                    throw std::runtime_error("Session ID has an invalid format: " + session_value);
                }

                std::string client_ip_from_session = tokens[0];
                std::string session_start_time_str = tokens[1];
                std::string session_valid_till_str = tokens[2];

                // Validate that these are numeric before conversion
                if (!std::all_of(session_start_time_str.begin(), session_start_time_str.end(), ::isdigit) ||
                    !std::all_of(session_valid_till_str.begin(), session_valid_till_str.end(), ::isdigit))
                {
                    throw std::runtime_error("Session timestamps are not numeric: " + session_start_time_str + " " + session_valid_till_str);
                }

                std::time_t session_start_time = std::stol(session_start_time_str);
                std::time_t session_valid_till = std::stol(session_valid_till_str);

                // Check if the session is still valid
                std::time_t now = std::time(nullptr);
                if (now <= session_valid_till && (now - session_start_time) <= wlcf->session_ttl * 60)
                {
                    ngx_waf_log_access(r, "Existing session is valid.");
                    return true;
                }
                else
                {
                    ngx_waf_log_access(r, "Session has expired.");
                }
            }
            catch (const std::exception &e)
            {
                ngx_waf_log_access(r, (std::string("Exception during session validation: ") + e.what()).c_str());
            }
        }

        ngx_waf_log_access(r, "Session is not valid or not found. Creating a new session.");
        session_value = create_session_value(client_ip, user_agent, uri, db_path, r);

        if (set_session_cookie(r, session_value))
        {
            ngx_waf_log_access(r, "New session created and cookie set successfully.");
            return true;
        }
        else
        {
            ngx_waf_log_access(r, "Failed to set session cookie.");
            return false;
        }
    }
    catch (const std::exception &e)
    {
        ngx_waf_log_access(r, (std::string("Exception caught in check_or_create_session: ") + e.what()).c_str());
        return false;
    }
    catch (...)
    {
        ngx_waf_log_access(r, "Unknown exception caught in check_or_create_session.");
        return false;
    }

    return false;
}

std::string get_geo_location(const std::string &ip, const char *db_path, ngx_http_request_t *r)
{
    MMDB_s mmdb;
    ngx_waf_log_access(r, ("Attempting to open GeoIP database at path: " + std::string(db_path)).c_str());

    int status = MMDB_open(db_path, MMDB_MODE_MMAP, &mmdb);
    if (status != MMDB_SUCCESS)
    {
        ngx_waf_log_access(r, ("Failed to open GeoIP database. Status: " + std::string(MMDB_strerror(status))).c_str());
        return "unknown";
    }

    ngx_waf_log_access(r, ("GeoIP database opened successfully. Looking up IP: " + ip).c_str());

    int gai_error, mmdb_error;
    MMDB_lookup_result_s result = MMDB_lookup_string(&mmdb, ip.c_str(), &gai_error, &mmdb_error);

    if (gai_error != 0)
    {
        ngx_waf_log_access(r, ("GeoIP lookup failed due to address error: " + std::string(gai_strerror(gai_error))).c_str());
        MMDB_close(&mmdb);
        return "unknown";
    }

    if (mmdb_error != MMDB_SUCCESS)
    {
        ngx_waf_log_access(r, ("GeoIP lookup failed with error: " + std::string(MMDB_strerror(mmdb_error))).c_str());
        MMDB_close(&mmdb);
        return "unknown";
    }

    if (!result.found_entry)
    {
        ngx_waf_log_access(r, "GeoIP lookup did not find the entry.");
        MMDB_close(&mmdb);
        return "unknown";
    }

    MMDB_entry_data_s entry_data;
    status = MMDB_get_value(&result.entry, &entry_data, "city", "names", "en", NULL);
    if (status != MMDB_SUCCESS)
    {
        ngx_waf_log_access(r, ("Failed to retrieve GeoIP city name. Status: " + std::string(MMDB_strerror(status))).c_str());
        MMDB_close(&mmdb);
        return "unknown";
    }

    if (!entry_data.has_data)
    {
        ngx_waf_log_access(r, "GeoIP city name data not found.");
        MMDB_close(&mmdb);
        return "unknown";
    }

    std::string city(entry_data.utf8_string, entry_data.data_size);
    ngx_waf_log_access(r, ("GeoIP lookup successful. City: " + city).c_str());

    MMDB_close(&mmdb);
    return city;
}

std::string create_session_value(const std::string &ip, const std::string &user_agent, const std::string &uri, const std::string &db_path, ngx_http_request_t *r)
{
    auto now = std::chrono::system_clock::now();
    auto now_time_t = std::chrono::system_clock::to_time_t(now);
    auto expire_time_t = now_time_t + 1800; // 30 minutes

    std::stringstream ss;
    ss << ip << "|" << now_time_t << "|" << expire_time_t << "|" << user_agent << "|" << uri << "|" << get_geo_location(ip, db_path.c_str(), r);

    return encrypt_session_value(ss.str());
}

bool is_blocked_ip(ngx_http_request_t *r, const std::string &ip)
{
    auto now = std::chrono::steady_clock::now();
    ngx_http_waf_loc_conf_t *wlcf = (ngx_http_waf_loc_conf_t *)ngx_http_get_module_loc_conf(r, ngx_http_waf_module);

    auto *local_blocked_ips = blocked_ips_ptr.load(std::memory_order_acquire);
    auto it = local_blocked_ips->find(ip);

    ngx_waf_log_access(r, ("Checking blocked IP list for IP: " + ip).c_str());

    if (it != local_blocked_ips->end())
    {
        if (std::chrono::duration_cast<std::chrono::seconds>(now - it->second).count() <= wlcf->block_duration)
        {
            ngx_waf_log_access(r, ("IP is still within the blocked duration: " + ip).c_str());
            return true;
        }
        else
        {
            ngx_waf_log_access(r, ("IP block duration has expired, removing from blocked list: " + ip).c_str());

            auto *new_map = new std::unordered_map<std::string, std::chrono::steady_clock::time_point>(*local_blocked_ips);
            new_map->erase(it);

            auto *old_map = blocked_ips_ptr.exchange(new_map, std::memory_order_acq_rel);
            delete old_map;
        }
    }
    else
    {
        ngx_waf_log_access(r, ("IP not found in blocked list: " + ip).c_str());
    }
    return false;
}

void block_ip(const std::string &ip)
{
    auto now = std::chrono::steady_clock::now();

    auto *local_blocked_ips = blocked_ips_ptr.load(std::memory_order_acquire);
    auto *new_map = new std::unordered_map<std::string, std::chrono::steady_clock::time_point>(*local_blocked_ips);
    (*new_map)[ip] = now;

    auto *old_map = blocked_ips_ptr.exchange(new_map, std::memory_order_acq_rel);
    delete old_map;

    ngx_waf_log_access(nullptr, ("IP blocked: " + ip).c_str());
}

bool is_brute_force(ngx_http_request_t *r, const std::string &ip)
{
    auto now = std::chrono::steady_clock::now();
    ngx_http_waf_loc_conf_t *wlcf = (ngx_http_waf_loc_conf_t *)ngx_http_get_module_loc_conf(r, ngx_http_waf_module);

    auto *local_rate_limit_map = rate_limit_map_ptr.load(std::memory_order_acquire);
    auto it = local_rate_limit_map->find(ip);

    if (it == local_rate_limit_map->end())
    {
        auto *new_map = new std::unordered_map<std::string, std::pair<int, std::chrono::steady_clock::time_point>>(*local_rate_limit_map);
        (*new_map)[ip] = {1, now};

        auto *old_map = rate_limit_map_ptr.exchange(new_map, std::memory_order_acq_rel);
        delete old_map;

        ngx_waf_log_access(r, ("New IP entry: " + ip + " with request count: 1").c_str());
        return false;
    }

    auto &data = it->second;
    auto time_diff = std::chrono::duration_cast<std::chrono::seconds>(now - data.second).count();

    ngx_waf_log_access(r, ("IP: " + ip + ", current request count: " + std::to_string(data.first) + ", time since first request: " + std::to_string(time_diff) + " seconds").c_str());

    if (time_diff > 60)
    {
        auto *new_map = new std::unordered_map<std::string, std::pair<int, std::chrono::steady_clock::time_point>>(*local_rate_limit_map);
        (*new_map)[ip] = {1, now};

        auto *old_map = rate_limit_map_ptr.exchange(new_map, std::memory_order_acq_rel);
        delete old_map;

        ngx_waf_log_access(r, ("Time window exceeded for IP: " + ip + ". Resetting request count to 1.").c_str());
        return false;
    }

    auto *new_map = new std::unordered_map<std::string, std::pair<int, std::chrono::steady_clock::time_point>>(*local_rate_limit_map);
    (*new_map)[ip].first++;

    auto *old_map = rate_limit_map_ptr.exchange(new_map, std::memory_order_acq_rel);
    delete old_map;

    ngx_waf_log_access(r, ("Incremented request count for IP: " + ip + " to " + std::to_string((*new_map)[ip].first)).c_str());

    if ((*new_map)[ip].first > wlcf->max_requests_per_minute && wlcf->max_requests_per_minute != NGX_CONF_UNSET)
    {
        ngx_waf_log_access(r, ("IP: " + ip + " has exceeded the maximum requests per minute: " + std::to_string(wlcf->max_requests_per_minute)).c_str());
        return true;
    }

    return false;
}

void *ngx_http_waf_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_waf_loc_conf_t *conf;
    conf = (ngx_http_waf_loc_conf_t *)ngx_pcalloc(cf->pool, sizeof(ngx_http_waf_loc_conf_t));
    if (conf == NULL)
    {
        return NULL;
    }

    // Initialize string configuration fields to ngx_null_string
    conf->geoip_db_path = ngx_null_string;
    conf->sql_injection_pattern = ngx_null_string;
    conf->xss_pattern = ngx_null_string;
    conf->file_inclusion_pattern = ngx_null_string;
    conf->command_injection_pattern = ngx_null_string;
    conf->directory_traversal_pattern = ngx_null_string;
    conf->parameter_tampering_pattern = ngx_null_string;
    conf->protocol_anomaly_pattern = ngx_null_string;
    conf->malicious_user_agent_pattern = ngx_null_string;
    conf->url_encoding_abuse_pattern = ngx_null_string;
    conf->invalid_request_line_pattern = ngx_null_string;
    conf->multipart_bypass_pattern = ngx_null_string;
    conf->invalid_range_pattern = ngx_null_string;
    conf->multiple_url_encoding_pattern = ngx_null_string;
    conf->unicode_abuse_pattern = ngx_null_string;
    conf->invalid_content_type_pattern = ngx_null_string;
    conf->invalid_charset_pattern = ngx_null_string;
    conf->backup_file_pattern = ngx_null_string;

    // Initialize the new fields to ngx_null_string
    conf->ldap_injection_pattern = ngx_null_string;
    conf->path_traversal_pattern = ngx_null_string;
    conf->os_file_access_pattern = ngx_null_string;
    conf->restricted_file_access_pattern = ngx_null_string;
    conf->rfi_ip_pattern = ngx_null_string;
    conf->rfi_common_param_pattern = ngx_null_string;
    conf->rfi_trailing_question_mark_pattern = ngx_null_string;
    conf->rfi_off_domain_pattern = ngx_null_string;

    // Initialize RCE (Remote Code Execution) related patterns
    conf->rce_unix_command_injection_pattern = ngx_null_string;
    conf->rce_windows_command_injection_pattern = ngx_null_string;
    conf->rce_windows_powershell_pattern = ngx_null_string;
    conf->rce_unix_shell_expression_pattern = ngx_null_string;
    conf->rce_windows_for_if_pattern = ngx_null_string;
    conf->rce_direct_unix_command_pattern = ngx_null_string;
    conf->rce_unix_shell_code_pattern = ngx_null_string;
    conf->rce_shellshock_pattern = ngx_null_string;
    conf->restricted_file_upload_pattern = ngx_null_string;

    // Initialize PHP Injection Patterns
    conf->php_opening_closing_tag_pattern = ngx_null_string;
    conf->php_script_file_upload_pattern = ngx_null_string;
    conf->php_config_directive_pattern = ngx_null_string;
    conf->php_variables_pattern = ngx_null_string;
    conf->php_io_stream_pattern = ngx_null_string;
    conf->php_high_risk_function_name_pattern = ngx_null_string;
    conf->php_medium_risk_function_name_pattern = ngx_null_string;
    conf->php_high_risk_function_call_pattern = ngx_null_string;
    conf->php_serialized_object_injection_pattern = ngx_null_string;
    conf->php_variable_function_call_pattern = ngx_null_string;
    conf->php_wrapper_scheme_pattern = ngx_null_string;

    // Initialize Node.js Injection Patterns
    conf->nodejs_injection_pattern = ngx_null_string;

    // Initialize XSS Patterns
    conf->xss_libinjection_pattern = ngx_null_string;
    conf->xss_libinjection_101_pattern = ngx_null_string;
    conf->xss_script_tag_vector_pattern = ngx_null_string;
    conf->xss_event_handler_vector_pattern = ngx_null_string;
    conf->xss_attribute_vector_pattern = ngx_null_string;
    conf->xss_js_uri_vector_pattern = ngx_null_string;
    conf->xss_disallowed_html_attributes_pattern = ngx_null_string;
    conf->xss_html_injection_pattern = ngx_null_string;
    conf->xss_attribute_injection_pattern = ngx_null_string;
    conf->xss_node_validator_blocklist_pattern = ngx_null_string;
    conf->xss_using_stylesheets_pattern = ngx_null_string;
    conf->xss_using_vml_frames_pattern = ngx_null_string;
    conf->xss_obfuscated_javascript_pattern = ngx_null_string;
    conf->xss_obfuscated_vbscript_pattern = ngx_null_string;
    conf->xss_using_embed_tag_pattern = ngx_null_string;
    conf->xss_using_import_attribute_pattern = ngx_null_string;
    conf->xss_ie_filters_pattern = ngx_null_string;
    conf->xss_using_meta_tag_pattern = ngx_null_string;
    conf->xss_using_link_href_pattern = ngx_null_string;
    conf->xss_using_base_tag_pattern = ngx_null_string;
    conf->xss_using_applet_tag_pattern = ngx_null_string;
    conf->xss_us_ascii_encoding_pattern = ngx_null_string;
    conf->xss_html_tag_handler_pattern = ngx_null_string;
    conf->xss_ie_filters_320_pattern = ngx_null_string;
    conf->xss_ie_filters_330_pattern = ngx_null_string;
    conf->xss_ie_filters_340_pattern = ngx_null_string;
    conf->xss_utf7_encoding_pattern = ngx_null_string;
    conf->xss_js_obfuscation_pattern = ngx_null_string;
    conf->xss_js_global_variable_pattern = ngx_null_string;
    conf->xss_angularjs_template_injection_pattern = ngx_null_string;

    // Initialize SQL Injection Patterns
    conf->sqli_mysql_comment_obfuscation_pattern = ngx_null_string;
    conf->sqli_benchmark_sleep_pattern = ngx_null_string;
    conf->sqli_operator_pattern = ngx_null_string;
    conf->sqli_libinjection_pattern = ngx_null_string;
    conf->sqli_common_injection_testing_pattern = ngx_null_string;
    conf->sqli_common_db_names_pattern = ngx_null_string;
    conf->sqli_blind_sqli_testing_pattern = ngx_null_string;
    conf->sqli_authentication_bypass_1_pattern = ngx_null_string;
    conf->sqli_mssql_code_execution_pattern = ngx_null_string;
    conf->sqli_chained_injection_1_pattern = ngx_null_string;
    conf->sqli_integer_overflow_pattern = ngx_null_string;
    conf->sqli_conditional_injection_pattern = ngx_null_string;
    conf->sqli_mysql_charset_switch_pattern = ngx_null_string;
    conf->sqli_match_against_pattern = ngx_null_string;
    conf->sqli_authentication_bypass_2_pattern = ngx_null_string;
    conf->sqli_basic_injection_pattern = ngx_null_string;
    conf->sqli_postgres_sleep_pattern = ngx_null_string;
    conf->sqli_mongodb_injection_pattern = ngx_null_string;
    conf->sqli_mysql_comment_condition_pattern = ngx_null_string;
    conf->sqli_chained_injection_2_pattern = ngx_null_string;
    conf->sqli_mysql_postgres_function_pattern = ngx_null_string;
    conf->sqli_classic_injection_1_pattern = ngx_null_string;
    conf->sqli_authentication_bypass_3_pattern = ngx_null_string;
    conf->sqli_mysql_udf_injection_pattern = ngx_null_string;
    conf->sqli_concatenated_injection_pattern = ngx_null_string;
    conf->sqli_keyword_alter_union_pattern = ngx_null_string;
    conf->sqli_classic_injection_2_pattern = ngx_null_string;
    conf->sqli_attack_pattern = ngx_null_string;
    conf->sqli_restricted_character_pattern = ngx_null_string;
    conf->sqli_comment_sequence_pattern = ngx_null_string;
    conf->sqli_hex_encoding_pattern = ngx_null_string;
    conf->sqli_meta_character_pattern = ngx_null_string;
    conf->sqli_bypass_ticks_pattern = ngx_null_string;
    conf->sqli_mysql_inline_comment_pattern = ngx_null_string;

    conf->skip_local = NGX_CONF_UNSET;

    // Initialize the enable flags to NGX_CONF_UNSET
    conf->enable_sql_injection = NGX_CONF_UNSET;
    conf->enable_session_rules = NGX_CONF_UNSET;
    conf->enable_xss = NGX_CONF_UNSET;
    conf->enable_protocol_attack = NGX_CONF_UNSET;
    conf->enable_rce_php_node = NGX_CONF_UNSET;
    conf->enable_general_rules = NGX_CONF_UNSET;

    // Initialize the session and rate-limiting related fields
    conf->session_ttl = NGX_CONF_UNSET;
    conf->log_decisions = NGX_CONF_UNSET;
    conf->max_requests_per_minute = NGX_CONF_UNSET;
    conf->block_duration = NGX_CONF_UNSET;

    conf->path_traversal_evasion_header_pattern = ngx_null_string;
    conf->path_traversal_evasion_body_pattern = ngx_null_string;

    // New MS-ThreatIntel-SQLI patterns
    conf->sql_injection_common_testing_pattern = ngx_null_string;
    conf->sql_injection_comment_sequence_pattern = ngx_null_string;
    conf->sql_injection_attack_pattern = ngx_null_string;
    conf->sql_authentication_bypass_pattern = ngx_null_string;

    return conf;
}

// Helper function to merge string patterns with memory allocation
void merge_pattern(ngx_conf_t *cf, ngx_str_t &conf_pattern, ngx_str_t &prev_pattern, ngx_http_waf_loc_conf_t *conf, const char *pattern_name)
{
    std::string pattern = get_pattern_from_conf_loc(conf, pattern_name, false);

    // Allocate memory from the NGINX pool for the string and copy the data into it
    conf_pattern.data = (u_char *)ngx_palloc(cf->pool, pattern.length() + 1);
    if (conf_pattern.data != NULL)
    {
        ngx_memcpy(conf_pattern.data, pattern.c_str(), pattern.length() + 1);
        conf_pattern.len = pattern.length();
    }

    // Now merge with the previous value
    ngx_conf_merge_str_value(conf_pattern, prev_pattern, "");

    // Log the final merged pattern
    // ngx_waf_log_access(NGX_LOG_ERR, "Final merged %s: %s", pattern_name, conf_pattern.data);
}

char *ngx_http_waf_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_waf_loc_conf_t *prev = (ngx_http_waf_loc_conf_t *)parent;
    ngx_http_waf_loc_conf_t *conf = (ngx_http_waf_loc_conf_t *)child;

    ngx_conf_merge_str_value(conf->geoip_db_path, prev->geoip_db_path, "./geoip/GeoLite2-City.mmdb");

    // Use the helper function to merge all patterns
    merge_pattern(cf, conf->sql_injection_pattern, prev->sql_injection_pattern, conf, "sql_injection_pattern");
    merge_pattern(cf, conf->xss_pattern, prev->xss_pattern, conf, "xss_pattern");
    merge_pattern(cf, conf->file_inclusion_pattern, prev->file_inclusion_pattern, conf, "file_inclusion_pattern");
    merge_pattern(cf, conf->command_injection_pattern, prev->command_injection_pattern, conf, "command_injection_pattern");
    merge_pattern(cf, conf->directory_traversal_pattern, prev->directory_traversal_pattern, conf, "directory_traversal_pattern");
    merge_pattern(cf, conf->parameter_tampering_pattern, prev->parameter_tampering_pattern, conf, "parameter_tampering_pattern");
    merge_pattern(cf, conf->protocol_anomaly_pattern, prev->protocol_anomaly_pattern, conf, "protocol_anomaly_pattern");
    merge_pattern(cf, conf->malicious_user_agent_pattern, prev->malicious_user_agent_pattern, conf, "malicious_user_agent_pattern");
    merge_pattern(cf, conf->url_encoding_abuse_pattern, prev->url_encoding_abuse_pattern, conf, "url_encoding_abuse_pattern");
    merge_pattern(cf, conf->invalid_request_line_pattern, prev->invalid_request_line_pattern, conf, "invalid_request_line_pattern");
    merge_pattern(cf, conf->multipart_bypass_pattern, prev->multipart_bypass_pattern, conf, "multipart_bypass_pattern");
    merge_pattern(cf, conf->invalid_range_pattern, prev->invalid_range_pattern, conf, "invalid_range_pattern");
    merge_pattern(cf, conf->multiple_url_encoding_pattern, prev->multiple_url_encoding_pattern, conf, "multiple_url_encoding_pattern");
    merge_pattern(cf, conf->unicode_abuse_pattern, prev->unicode_abuse_pattern, conf, "unicode_abuse_pattern");
    merge_pattern(cf, conf->invalid_content_type_pattern, prev->invalid_content_type_pattern, conf, "invalid_content_type_pattern");
    merge_pattern(cf, conf->invalid_charset_pattern, prev->invalid_charset_pattern, conf, "invalid_charset_pattern");
    merge_pattern(cf, conf->backup_file_pattern, prev->backup_file_pattern, conf, "backup_file_pattern");
    merge_pattern(cf, conf->ldap_injection_pattern, prev->ldap_injection_pattern, conf, "ldap_injection_pattern");
    merge_pattern(cf, conf->path_traversal_pattern, prev->path_traversal_pattern, conf, "path_traversal_pattern");
    merge_pattern(cf, conf->os_file_access_pattern, prev->os_file_access_pattern, conf, "os_file_access_pattern");
    merge_pattern(cf, conf->restricted_file_access_pattern, prev->restricted_file_access_pattern, conf, "restricted_file_access_pattern");
    merge_pattern(cf, conf->rfi_ip_pattern, prev->rfi_ip_pattern, conf, "rfi_ip_pattern");
    merge_pattern(cf, conf->rfi_common_param_pattern, prev->rfi_common_param_pattern, conf, "rfi_common_param_pattern");
    merge_pattern(cf, conf->rfi_trailing_question_mark_pattern, prev->rfi_trailing_question_mark_pattern, conf, "rfi_trailing_question_mark_pattern");
    merge_pattern(cf, conf->rfi_off_domain_pattern, prev->rfi_off_domain_pattern, conf, "rfi_off_domain_pattern");
    merge_pattern(cf, conf->rce_unix_command_injection_pattern, prev->rce_unix_command_injection_pattern, conf, "rce_unix_command_injection_pattern");
    merge_pattern(cf, conf->rce_windows_command_injection_pattern, prev->rce_windows_command_injection_pattern, conf, "rce_windows_command_injection_pattern");
    merge_pattern(cf, conf->rce_windows_powershell_pattern, prev->rce_windows_powershell_pattern, conf, "rce_windows_powershell_pattern");
    merge_pattern(cf, conf->rce_unix_shell_expression_pattern, prev->rce_unix_shell_expression_pattern, conf, "rce_unix_shell_expression_pattern");
    merge_pattern(cf, conf->rce_windows_for_if_pattern, prev->rce_windows_for_if_pattern, conf, "rce_windows_for_if_pattern");
    merge_pattern(cf, conf->rce_direct_unix_command_pattern, prev->rce_direct_unix_command_pattern, conf, "rce_direct_unix_command_pattern");
    merge_pattern(cf, conf->rce_unix_shell_code_pattern, prev->rce_unix_shell_code_pattern, conf, "rce_unix_shell_code_pattern");
    merge_pattern(cf, conf->rce_shellshock_pattern, prev->rce_shellshock_pattern, conf, "rce_shellshock_pattern");
    merge_pattern(cf, conf->restricted_file_upload_pattern, prev->restricted_file_upload_pattern, conf, "restricted_file_upload_pattern");
    merge_pattern(cf, conf->php_opening_closing_tag_pattern, prev->php_opening_closing_tag_pattern, conf, "php_opening_closing_tag_pattern");
    merge_pattern(cf, conf->php_script_file_upload_pattern, prev->php_script_file_upload_pattern, conf, "php_script_file_upload_pattern");
    merge_pattern(cf, conf->php_config_directive_pattern, prev->php_config_directive_pattern, conf, "php_config_directive_pattern");
    merge_pattern(cf, conf->php_variables_pattern, prev->php_variables_pattern, conf, "php_variables_pattern");
    merge_pattern(cf, conf->php_io_stream_pattern, prev->php_io_stream_pattern, conf, "php_io_stream_pattern");
    merge_pattern(cf, conf->php_high_risk_function_name_pattern, prev->php_high_risk_function_name_pattern, conf, "php_high_risk_function_name_pattern");
    merge_pattern(cf, conf->php_medium_risk_function_name_pattern, prev->php_medium_risk_function_name_pattern, conf, "php_medium_risk_function_name_pattern");
    merge_pattern(cf, conf->php_high_risk_function_call_pattern, prev->php_high_risk_function_call_pattern, conf, "php_high_risk_function_call_pattern");
    merge_pattern(cf, conf->php_serialized_object_injection_pattern, prev->php_serialized_object_injection_pattern, conf, "php_serialized_object_injection_pattern");
    merge_pattern(cf, conf->php_variable_function_call_pattern, prev->php_variable_function_call_pattern, conf, "php_variable_function_call_pattern");
    merge_pattern(cf, conf->php_wrapper_scheme_pattern, prev->php_wrapper_scheme_pattern, conf, "php_wrapper_scheme_pattern");
    merge_pattern(cf, conf->nodejs_injection_pattern, prev->nodejs_injection_pattern, conf, "nodejs_injection_pattern");
    merge_pattern(cf, conf->xss_libinjection_pattern, prev->xss_libinjection_pattern, conf, "xss_libinjection_pattern");
    merge_pattern(cf, conf->xss_libinjection_101_pattern, prev->xss_libinjection_101_pattern, conf, "xss_libinjection_101_pattern");
    merge_pattern(cf, conf->xss_script_tag_vector_pattern, prev->xss_script_tag_vector_pattern, conf, "xss_script_tag_vector_pattern");
    merge_pattern(cf, conf->xss_event_handler_vector_pattern, prev->xss_event_handler_vector_pattern, conf, "xss_event_handler_vector_pattern");
    merge_pattern(cf, conf->xss_attribute_vector_pattern, prev->xss_attribute_vector_pattern, conf, "xss_attribute_vector_pattern");
    merge_pattern(cf, conf->xss_js_uri_vector_pattern, prev->xss_js_uri_vector_pattern, conf, "xss_js_uri_vector_pattern");
    merge_pattern(cf, conf->xss_disallowed_html_attributes_pattern, prev->xss_disallowed_html_attributes_pattern, conf, "xss_disallowed_html_attributes_pattern");
    merge_pattern(cf, conf->xss_html_injection_pattern, prev->xss_html_injection_pattern, conf, "xss_html_injection_pattern");
    merge_pattern(cf, conf->xss_attribute_injection_pattern, prev->xss_attribute_injection_pattern, conf, "xss_attribute_injection_pattern");
    merge_pattern(cf, conf->xss_node_validator_blocklist_pattern, prev->xss_node_validator_blocklist_pattern, conf, "xss_node_validator_blocklist_pattern");
    merge_pattern(cf, conf->xss_using_stylesheets_pattern, prev->xss_using_stylesheets_pattern, conf, "xss_using_stylesheets_pattern");
    merge_pattern(cf, conf->xss_using_vml_frames_pattern, prev->xss_using_vml_frames_pattern, conf, "xss_using_vml_frames_pattern");
    merge_pattern(cf, conf->xss_obfuscated_javascript_pattern, prev->xss_obfuscated_javascript_pattern, conf, "xss_obfuscated_javascript_pattern");
    merge_pattern(cf, conf->xss_obfuscated_vbscript_pattern, prev->xss_obfuscated_vbscript_pattern, conf, "xss_obfuscated_vbscript_pattern");
    merge_pattern(cf, conf->xss_using_embed_tag_pattern, prev->xss_using_embed_tag_pattern, conf, "xss_using_embed_tag_pattern");
    merge_pattern(cf, conf->xss_using_import_attribute_pattern, prev->xss_using_import_attribute_pattern, conf, "xss_using_import_attribute_pattern");
    merge_pattern(cf, conf->xss_ie_filters_pattern, prev->xss_ie_filters_pattern, conf, "xss_ie_filters_pattern");
    merge_pattern(cf, conf->xss_using_meta_tag_pattern, prev->xss_using_meta_tag_pattern, conf, "xss_using_meta_tag_pattern");
    merge_pattern(cf, conf->xss_using_link_href_pattern, prev->xss_using_link_href_pattern, conf, "xss_using_link_href_pattern");
    merge_pattern(cf, conf->xss_using_base_tag_pattern, prev->xss_using_base_tag_pattern, conf, "xss_using_base_tag_pattern");
    merge_pattern(cf, conf->xss_using_applet_tag_pattern, prev->xss_using_applet_tag_pattern, conf, "xss_using_applet_tag_pattern");
    merge_pattern(cf, conf->xss_us_ascii_encoding_pattern, prev->xss_us_ascii_encoding_pattern, conf, "xss_us_ascii_encoding_pattern");
    merge_pattern(cf, conf->xss_html_tag_handler_pattern, prev->xss_html_tag_handler_pattern, conf, "xss_html_tag_handler_pattern");
    merge_pattern(cf, conf->xss_ie_filters_320_pattern, prev->xss_ie_filters_320_pattern, conf, "xss_ie_filters_320_pattern");
    merge_pattern(cf, conf->xss_ie_filters_330_pattern, prev->xss_ie_filters_330_pattern, conf, "xss_ie_filters_330_pattern");
    merge_pattern(cf, conf->xss_ie_filters_340_pattern, prev->xss_ie_filters_340_pattern, conf, "xss_ie_filters_340_pattern");
    merge_pattern(cf, conf->xss_utf7_encoding_pattern, prev->xss_utf7_encoding_pattern, conf, "xss_utf7_encoding_pattern");
    merge_pattern(cf, conf->xss_js_obfuscation_pattern, prev->xss_js_obfuscation_pattern, conf, "xss_js_obfuscation_pattern");
    merge_pattern(cf, conf->xss_js_global_variable_pattern, prev->xss_js_global_variable_pattern, conf, "xss_js_global_variable_pattern");
    merge_pattern(cf, conf->xss_angularjs_template_injection_pattern, prev->xss_angularjs_template_injection_pattern, conf, "xss_angularjs_template_injection_pattern");

    merge_pattern(cf, conf->sqli_mysql_comment_obfuscation_pattern, prev->sqli_mysql_comment_obfuscation_pattern, conf, "sqli_mysql_comment_obfuscation_pattern");
    merge_pattern(cf, conf->sqli_benchmark_sleep_pattern, prev->sqli_benchmark_sleep_pattern, conf, "sqli_benchmark_sleep_pattern");
    merge_pattern(cf, conf->sqli_operator_pattern, prev->sqli_operator_pattern, conf, "sqli_operator_pattern");
    merge_pattern(cf, conf->sql_injection_pattern, prev->sql_injection_pattern, conf, "sql_injection_pattern");
    merge_pattern(cf, conf->sqli_libinjection_pattern, prev->sqli_libinjection_pattern, conf, "sqli_libinjection_pattern");
    merge_pattern(cf, conf->sqli_common_injection_testing_pattern, prev->sqli_common_injection_testing_pattern, conf, "sqli_common_injection_testing_pattern");
    merge_pattern(cf, conf->sqli_common_db_names_pattern, prev->sqli_common_db_names_pattern, conf, "sqli_common_db_names_pattern");
    merge_pattern(cf, conf->sqli_blind_sqli_testing_pattern, prev->sqli_blind_sqli_testing_pattern, conf, "sqli_blind_sqli_testing_pattern");
    merge_pattern(cf, conf->sqli_authentication_bypass_1_pattern, prev->sqli_authentication_bypass_1_pattern, conf, "sqli_authentication_bypass_1_pattern");
    merge_pattern(cf, conf->sqli_mssql_code_execution_pattern, prev->sqli_mssql_code_execution_pattern, conf, "sqli_mssql_code_execution_pattern");
    merge_pattern(cf, conf->sqli_chained_injection_1_pattern, prev->sqli_chained_injection_1_pattern, conf, "sqli_chained_injection_1_pattern");
    merge_pattern(cf, conf->sqli_integer_overflow_pattern, prev->sqli_integer_overflow_pattern, conf, "sqli_integer_overflow_pattern");
    merge_pattern(cf, conf->sqli_conditional_injection_pattern, prev->sqli_conditional_injection_pattern, conf, "sqli_conditional_injection_pattern");
    merge_pattern(cf, conf->sqli_mysql_charset_switch_pattern, prev->sqli_mysql_charset_switch_pattern, conf, "sqli_mysql_charset_switch_pattern");
    merge_pattern(cf, conf->sqli_match_against_pattern, prev->sqli_match_against_pattern, conf, "sqli_match_against_pattern");
    merge_pattern(cf, conf->sqli_authentication_bypass_2_pattern, prev->sqli_authentication_bypass_2_pattern, conf, "sqli_authentication_bypass_2_pattern");
    merge_pattern(cf, conf->sqli_basic_injection_pattern, prev->sqli_basic_injection_pattern, conf, "sqli_basic_injection_pattern");
    merge_pattern(cf, conf->sqli_postgres_sleep_pattern, prev->sqli_postgres_sleep_pattern, conf, "sqli_postgres_sleep_pattern");
    merge_pattern(cf, conf->sqli_mongodb_injection_pattern, prev->sqli_mongodb_injection_pattern, conf, "sqli_mongodb_injection_pattern");
    merge_pattern(cf, conf->sqli_mysql_comment_condition_pattern, prev->sqli_mysql_comment_condition_pattern, conf, "sqli_mysql_comment_condition_pattern");
    merge_pattern(cf, conf->sqli_chained_injection_2_pattern, prev->sqli_chained_injection_2_pattern, conf, "sqli_chained_injection_2_pattern");
    merge_pattern(cf, conf->sqli_mysql_postgres_function_pattern, prev->sqli_mysql_postgres_function_pattern, conf, "sqli_mysql_postgres_function_pattern");
    merge_pattern(cf, conf->sqli_classic_injection_1_pattern, prev->sqli_classic_injection_1_pattern, conf, "sqli_classic_injection_1_pattern");
    merge_pattern(cf, conf->sqli_authentication_bypass_3_pattern, prev->sqli_authentication_bypass_3_pattern, conf, "sqli_authentication_bypass_3_pattern");
    merge_pattern(cf, conf->sqli_mysql_udf_injection_pattern, prev->sqli_mysql_udf_injection_pattern, conf, "sqli_mysql_udf_injection_pattern");
    merge_pattern(cf, conf->sqli_concatenated_injection_pattern, prev->sqli_concatenated_injection_pattern, conf, "sqli_concatenated_injection_pattern");
    merge_pattern(cf, conf->sqli_keyword_alter_union_pattern, prev->sqli_keyword_alter_union_pattern, conf, "sqli_keyword_alter_union_pattern");
    merge_pattern(cf, conf->sqli_classic_injection_2_pattern, prev->sqli_classic_injection_2_pattern, conf, "sqli_classic_injection_2_pattern");
    merge_pattern(cf, conf->sqli_attack_pattern, prev->sqli_attack_pattern, conf, "sqli_attack_pattern");
    merge_pattern(cf, conf->sqli_restricted_character_pattern, prev->sqli_restricted_character_pattern, conf, "sqli_restricted_character_pattern");
    merge_pattern(cf, conf->sqli_comment_sequence_pattern, prev->sqli_comment_sequence_pattern, conf, "sqli_comment_sequence_pattern");
    merge_pattern(cf, conf->sqli_hex_encoding_pattern, prev->sqli_hex_encoding_pattern, conf, "sqli_hex_encoding_pattern");
    merge_pattern(cf, conf->sqli_meta_character_pattern, prev->sqli_meta_character_pattern, conf, "sqli_meta_character_pattern");
    merge_pattern(cf, conf->sqli_mysql_inline_comment_pattern, prev->sqli_mysql_inline_comment_pattern, conf, "sqli_mysql_inline_comment_pattern");
    merge_pattern(cf, conf->sqli_bypass_ticks_pattern, prev->sqli_bypass_ticks_pattern, conf, "sqli_bypass_ticks_pattern");
    merge_pattern(cf, conf->path_traversal_evasion_header_pattern, prev->path_traversal_evasion_header_pattern, conf, "path_traversal_evasion_header_pattern");
    merge_pattern(cf, conf->path_traversal_evasion_body_pattern, prev->path_traversal_evasion_body_pattern, conf, "path_traversal_evasion_body_pattern");

    merge_pattern(cf, conf->sql_injection_common_testing_pattern, prev->sql_injection_common_testing_pattern, conf, "sql_injection_common_testing_pattern");
    merge_pattern(cf, conf->sql_injection_comment_sequence_pattern, prev->sql_injection_comment_sequence_pattern, conf, "sql_injection_comment_sequence_pattern");
    merge_pattern(cf, conf->sql_injection_attack_pattern, prev->sql_injection_attack_pattern, conf, "sql_injection_attack_pattern");
    merge_pattern(cf, conf->sql_authentication_bypass_pattern, prev->sql_authentication_bypass_pattern, conf, "sql_authentication_bypass_pattern");

    // Set default values if not set
    if (conf->skip_local == NGX_CONF_UNSET)
    {
        conf->skip_local = 0;
    }

    // Set default values if not set
    if (conf->enable_sql_injection == NGX_CONF_UNSET)
    {
        conf->enable_sql_injection = 0;
    }

    if (conf->enable_session_rules == NGX_CONF_UNSET)
    {
        conf->enable_session_rules = 0;
    }

    if (conf->enable_xss == NGX_CONF_UNSET)
    {
        conf->enable_xss = 0;
    }

    if (conf->enable_protocol_attack == NGX_CONF_UNSET)
    {
        conf->enable_protocol_attack = 0;
    }

    if (conf->enable_rce_php_node == NGX_CONF_UNSET)
    {
        conf->enable_rce_php_node = 0;
    }

    if (conf->enable_general_rules == NGX_CONF_UNSET)
    {
        conf->enable_general_rules = 0;
    }

    // Merge session-related settings
    if (conf->session_ttl == NGX_CONF_UNSET)
    {
        conf->session_ttl = (prev->session_ttl == NGX_CONF_UNSET) ? 30000 : prev->session_ttl;
    }

    if (conf->log_decisions == NGX_CONF_UNSET)
    {
        conf->log_decisions = (prev->log_decisions == NGX_CONF_UNSET) ? true : prev->log_decisions;
    }

    if (conf->max_requests_per_minute == NGX_CONF_UNSET)
    {
        conf->max_requests_per_minute = (prev->max_requests_per_minute == NGX_CONF_UNSET) ? 60 : prev->max_requests_per_minute;
    }

    if (conf->block_duration == NGX_CONF_UNSET)
    {
        conf->block_duration = (prev->block_duration == NGX_CONF_UNSET) ? 600 : prev->block_duration; // 10 minutes
    }

    return NGX_CONF_OK;
}

// Configuration function
char *ngx_http_waf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t *clcf = (ngx_http_core_loc_conf_t *)ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_waf_handler;
    return NGX_CONF_OK;
}

static ngx_int_t ngx_http_waf_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt *h;
    ngx_http_core_main_conf_t *cmcf;

    cmcf = (ngx_http_core_main_conf_t *)ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = (ngx_http_handler_pt *)ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL)
    {
        return NGX_ERROR;
    }

    *h = ngx_http_waf_handler;

    return NGX_OK;
}

// Module context
ngx_http_module_t ngx_http_waf_module_ctx = {
    NULL,                         // preconfiguration
    ngx_http_waf_init,            // postconfiguration
    NULL,                         // create main configuration
    NULL,                         // init main configuration
    NULL,                         // create server configuration
    NULL,                         // merge server configuration
    ngx_http_waf_create_loc_conf, // create location configuration
    ngx_http_waf_merge_loc_conf   // merge location configuration
};

// Module definition
ngx_module_t ngx_http_waf_module = {
    NGX_MODULE_V1,
    &ngx_http_waf_module_ctx, // module context
    ngx_http_waf_commands,    // module directives
    NGX_HTTP_MODULE,          // module type
    NULL,                     // init master
    NULL,                     // init module
    NULL,                     // init process
    NULL,                     // init thread
    NULL,                     // exit thread
    NULL,                     // exit process
    NULL,                     // exit master
    NGX_MODULE_V1_PADDING};
