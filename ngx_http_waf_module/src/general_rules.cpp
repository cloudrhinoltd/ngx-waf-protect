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

extern "C" {
#include <ngx_core.h>
#include <ngx_http.h>
}

#include "../include/waf_utils.h"
#include "../include/general_rules.h"

// Function to check invalid HTTP request line (RuleId: 920100)
ngx_int_t check_invalid_http_request_line(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_invalid_http_request_line");

    if (r->request_line.len == 0 || r->request_line.data == NULL) {
        ngx_waf_log_access(r, "Request line is empty or null");
        return NGX_DECLINED;
    }

    std::string request_line(reinterpret_cast<const char *>(r->request_line.data), r->request_line.len);
    std::regex regex_pattern;
    if (compile_and_log_regex(r, get_pattern_from_conf(r, "invalid_request_line_pattern"), "check_invalid_http_request_line", regex_pattern, std::regex_constants::icase)) {
        if (std::regex_search(request_line, regex_pattern)) {
            ngx_waf_log_access(r, "Regex search found a match");
            return log_and_reject(r, "Invalid HTTP Request Line", "920100");
        }
    }

    ngx_waf_log_access(r, "Exiting check_invalid_http_request_line with no attack detected");
    return NGX_DECLINED;
}

// Function to check multipart/form-data bypass (RuleId: 920120, 920121)
ngx_int_t check_multipart_form_data_bypass(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_multipart_form_data_bypass");

    if (r->headers_in.content_type == NULL) {
        ngx_waf_log_access(r, "Exiting check_multipart_form_data_bypass with no attack detected");
        return NGX_DECLINED;
    }

    std::string content_type(reinterpret_cast<const char *>(r->headers_in.content_type->value.data), r->headers_in.content_type->value.len);
    if (content_type.find("multipart/form-data") != std::string::npos) {
        std::regex regex_pattern;
        if (compile_and_log_regex(r, get_pattern_from_conf(r, "multipart_bypass_pattern"), "check_multipart_form_data_bypass", regex_pattern, std::regex_constants::icase)) {
            if (std::regex_search(content_type, regex_pattern)) {
                ngx_waf_log_access(r, "Exiting check_multipart_form_data_bypass with attack detected");
                return log_and_reject(r, "Attempted multipart/form-data bypass", "920120, 920121");
            }
        }
    }

    ngx_waf_log_access(r, "Exiting check_multipart_form_data_bypass with no attack detected");
    return NGX_DECLINED;
}

// Function to check Content-Length header is numeric (RuleId: 920160)
ngx_int_t check_content_length_numeric(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_content_length_numeric");

    if (r->headers_in.content_length == NULL) {
        ngx_waf_log_access(r, "Exiting check_content_length_numeric with no attack detected");
        return NGX_DECLINED;
    }

    std::string content_length(reinterpret_cast<const char *>(r->headers_in.content_length->value.data), r->headers_in.content_length->value.len);
    if (!std::all_of(content_length.begin(), content_length.end(), ::isdigit)) {
        ngx_waf_log_access(r, "Exiting check_content_length_numeric with attack detected");
        return log_and_reject(r, "Content-Length HTTP header isn't numeric", "920160");
    }

    ngx_waf_log_access(r, "Exiting check_content_length_numeric with no attack detected");
    return NGX_DECLINED;
}

// Function to check GET or HEAD request with body content (RuleId: 920170)
ngx_int_t check_get_head_with_body(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_get_head_with_body");

    if ((r->method == NGX_HTTP_GET || r->method == NGX_HTTP_HEAD) && r->headers_in.content_length_n > 0) {
        ngx_waf_log_access(r, "Exiting check_get_head_with_body with attack detected");
        return log_and_reject(r, "GET or HEAD Request with Body Content", "920170");
    }

    ngx_waf_log_access(r, "Exiting check_get_head_with_body with no attack detected");
    return NGX_DECLINED;
}

// Function to check GET or HEAD request with Transfer-Encoding (RuleId: 920171)
ngx_int_t check_get_head_with_transfer_encoding(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_get_head_with_transfer_encoding");

    if ((r->method == NGX_HTTP_GET || r->method == NGX_HTTP_HEAD) && r->headers_in.transfer_encoding) {
        ngx_waf_log_access(r, "Exiting check_get_head_with_transfer_encoding with attack detected");
        return log_and_reject(r, "GET or HEAD Request with Transfer-Encoding", "920171");
    }

    ngx_waf_log_access(r, "Exiting check_get_head_with_transfer_encoding with no attack detected");
    return NGX_DECLINED;
}

// Function to check POST request missing Content-Length Header (RuleId: 920180)
ngx_int_t check_post_request_missing_content_length(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_post_request_missing_content_length");

    if (r->method == NGX_HTTP_POST && r->headers_in.content_length == NULL) {
        ngx_waf_log_access(r, "Exiting check_post_request_missing_content_length with attack detected");
        return log_and_reject(r, "POST request missing Content-Length Header", "920180");
    }

    ngx_waf_log_access(r, "Exiting check_post_request_missing_content_length with no attack detected");
    return NGX_DECLINED;
}

// Function to check conflicting Content-Length and Transfer-Encoding headers (RuleId: 920181)
ngx_int_t check_content_length_and_transfer_encoding(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_content_length_and_transfer_encoding");

    if (r->headers_in.content_length && r->headers_in.transfer_encoding) {
        ngx_waf_log_access(r, "Exiting check_content_length_and_transfer_encoding with attack detected");
        return log_and_reject(r, "Content-Length and Transfer-Encoding headers present", "920181");
    }

    ngx_waf_log_access(r, "Exiting check_content_length_and_transfer_encoding with no attack detected");
    return NGX_DECLINED;
}

// Function to check invalid Range header (RuleId: 920190)
ngx_int_t check_invalid_range_header(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_invalid_range_header");

    if (r->headers_in.range == NULL) {
        ngx_waf_log_access(r, "Exiting check_invalid_range_header with no attack detected");
        return NGX_DECLINED;
    }

    std::string range(reinterpret_cast<const char *>(r->headers_in.range->value.data), r->headers_in.range->value.len);
    std::regex regex_pattern;
    if (compile_and_log_regex(r, get_pattern_from_conf(r, "invalid_range_pattern"), "check_invalid_range_header", regex_pattern, std::regex_constants::icase)) {
        if (std::regex_search(range, regex_pattern)) {
            ngx_waf_log_access(r, "Exiting check_invalid_range_header with attack detected");
            return log_and_reject(r, "Range: Invalid Last Byte Value", "920190");
        }
    }

    ngx_waf_log_access(r, "Exiting check_invalid_range_header with no attack detected");
    return NGX_DECLINED;
}

// Function to check too many Range fields (RuleId: 920200, 920201)
ngx_int_t check_too_many_range_fields(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_too_many_range_fields");

    if (r->headers_in.range == NULL) {
        ngx_waf_log_access(r, "Exiting check_too_many_range_fields with no attack detected");
        return NGX_DECLINED;
    }

    std::string range(reinterpret_cast<const char *>(r->headers_in.range->value.data), r->headers_in.range->value.len);
    int field_count = std::count(range.begin(), range.end(), ',') + 1;

    if (field_count >= 6) {
        ngx_waf_log_access(r, "Exiting check_too_many_range_fields with attack detected");
        return log_and_reject(r, "Range: Too many fields (6 or more)", "920200");
    }

    if (r->headers_in.content_type && std::string(reinterpret_cast<const char *>(r->headers_in.content_type->value.data), r->headers_in.content_type->value.len).find("application/pdf") != std::string::npos && field_count >= 35) {
        ngx_waf_log_access(r, "Exiting check_too_many_range_fields with attack detected for PDF request");
        return log_and_reject(r, "Range: Too many fields for pdf request (35 or more)", "920201");
    }

    ngx_waf_log_access(r, "Exiting check_too_many_range_fields with no attack detected");
    return NGX_DECLINED;
}

// Function to check URL encoding abuse (RuleId: 920220, 920240)
ngx_int_t check_url_encoding_abuse(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_url_encoding_abuse");

    std::string uri(reinterpret_cast<const char *>(r->uri.data), r->uri.len);
    std::regex regex_pattern;
    if (compile_and_log_regex(r, get_pattern_from_conf(r, "url_encoding_abuse_pattern"), "check_url_encoding_abuse", regex_pattern)) {
        if (std::regex_search(uri, regex_pattern)) {
            ngx_waf_log_access(r, "Exiting check_url_encoding_abuse with attack detected");
            return log_and_reject(r, "URL Encoding Abuse Attack Attempt", "920220, 920240");
        }
    }

    ngx_waf_log_access(r, "Exiting check_url_encoding_abuse with no attack detected");
    return NGX_DECLINED;
}

// Function to check multiple URL encoding (RuleId: 920230)
ngx_int_t check_multiple_url_encoding(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_multiple_url_encoding");

    std::string uri(reinterpret_cast<const char *>(r->uri.data), r->uri.len);
    std::regex regex_pattern;

    if (compile_and_log_regex(r, get_pattern_from_conf(r, "multiple_url_encoding_pattern"), "check_multiple_url_encoding", regex_pattern)) {
        if (std::regex_search(uri, regex_pattern)) {
            ngx_waf_log_access(r, "Exiting check_multiple_url_encoding with attack detected");
            return log_and_reject(r, "Multiple URL Encoding Detected", "920230");
        }
    }

    ngx_waf_log_access(r, "Exiting check_multiple_url_encoding with no attack detected");
    return NGX_DECLINED;
}

// Function to check for Unicode abuse (RuleId: 920260)
ngx_int_t check_unicode_abuse(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_unicode_abuse");

    std::string uri(reinterpret_cast<const char *>(r->uri.data), r->uri.len);
    std::regex regex_pattern;

    if (compile_and_log_regex(r, get_pattern_from_conf(r, "unicode_abuse_pattern"), "check_unicode_abuse", regex_pattern)) {
        if (std::regex_search(uri, regex_pattern)) {
            ngx_waf_log_access(r, "Exiting check_unicode_abuse with attack detected");
            return log_and_reject(r, "Unicode Full/Half Width Abuse Attack Attempt", "920260");
        }
    }

    ngx_waf_log_access(r, "Exiting check_unicode_abuse with no attack detected");
    return NGX_DECLINED;
}

// Function to check for null characters in request (RuleId: 920270)
ngx_int_t check_null_characters(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_null_characters");

    std::string request(reinterpret_cast<const char *>(r->request_line.data), r->request_line.len);

    if (request.find(' ') != std::string::npos) {
        ngx_waf_log_access(r, "Exiting check_null_characters with attack detected");
        return log_and_reject(r, "Invalid character in request (null character)", "920270");
    }

    ngx_waf_log_access(r, "Exiting check_null_characters with no attack detected");
    return NGX_DECLINED;
}

// Function to check for nonprintable characters in request (RuleId: 920271)
ngx_int_t check_nonprintable_characters(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_nonprintable_characters");

    std::string request(reinterpret_cast<const char *>(r->request_line.data), r->request_line.len);

    for (char c : request) {
        if (!isprint(c) && !isspace(c)) {
            ngx_waf_log_access(r, "Exiting check_nonprintable_characters with attack detected");
            return log_and_reject(r, "Invalid character in request (nonprintable characters)", "920271");
        }
    }

    ngx_waf_log_access(r, "Exiting check_nonprintable_characters with no attack detected");
    return NGX_DECLINED;
}

// Function to check for missing Host header (RuleId: 920280)
ngx_int_t check_missing_host_header(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_missing_host_header");

    if (r->headers_in.host == NULL) {
        ngx_waf_log_access(r, "Exiting check_missing_host_header with attack detected");
        return log_and_reject(r, "Request Missing a Host Header", "920280");
    }

    ngx_waf_log_access(r, "Exiting check_missing_host_header with no attack detected");
    return NGX_DECLINED;
}

// Function to check for empty Host header (RuleId: 920290)
ngx_int_t check_empty_host_header(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_empty_host_header");

    if (r->headers_in.host && r->headers_in.host->value.len == 0) {
        ngx_waf_log_access(r, "Exiting check_empty_host_header with attack detected");
        return log_and_reject(r, "Empty Host Header", "920290");
    }

    ngx_waf_log_access(r, "Exiting check_empty_host_header with no attack detected");
    return NGX_DECLINED;
}

// Function to check for empty Accept header (RuleId: 920310, 920311)
ngx_int_t check_empty_accept_header(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_empty_accept_header");

#ifdef NGX_HTTP_HEADERS
    if (r->headers_in.accept && r->headers_in.accept->value.len == 0) {
        ngx_waf_log_access(r, "Exiting check_empty_accept_header with attack detected");
        return log_and_reject(r, "Request Has an Empty Accept Header", "920310, 920311");
    }
#endif

    ngx_waf_log_access(r, "Exiting check_empty_accept_header with no attack detected");
    return NGX_DECLINED;
}

// Function to check for missing Accept header (RuleId: 920300)
ngx_int_t check_missing_accept_header(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_missing_accept_header");

#ifdef NGX_HTTP_HEADERS
    if (r->headers_in.accept == NULL) {
        ngx_waf_log_access(r, "Exiting check_missing_accept_header with attack detected");
        return log_and_reject(r, "Request Missing an Accept Header", "920300");
    }
#endif

    ngx_waf_log_access(r, "Exiting check_missing_accept_header with no attack detected");
    return NGX_DECLINED;
}

// Function to check for missing User-Agent header (RuleId: 920320)
ngx_int_t check_missing_user_agent_header(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_missing_user_agent_header");

    if (r->headers_in.user_agent == NULL) {
        ngx_waf_log_access(r, "Exiting check_missing_user_agent_header with attack detected");
        return log_and_reject(r, "Missing User Agent Header", "920320");
    }

    ngx_waf_log_access(r, "Exiting check_missing_user_agent_header with no attack detected");
    return NGX_DECLINED;
}

// Function to check for empty User-Agent header (RuleId: 920330)
ngx_int_t check_empty_user_agent_header(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_empty_user_agent_header");

    if (r->headers_in.user_agent && r->headers_in.user_agent->value.len == 0) {
        ngx_waf_log_access(r, "Exiting check_empty_user_agent_header with attack detected");
        return log_and_reject(r, "Empty User Agent Header", "920330");
    }

    ngx_waf_log_access(r, "Exiting check_empty_user_agent_header with no attack detected");
    return NGX_DECLINED;
}

// Function to check for request containing content but missing Content-Type header (RuleId: 920340, 920341)
ngx_int_t check_request_missing_content_type_header(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_request_missing_content_type_header");

    if (r->headers_in.content_length_n > 0 && r->headers_in.content_type == NULL) {
        ngx_waf_log_access(r, "Exiting check_request_missing_content_type_header with attack detected");
        return log_and_reject(r, "Request Containing Content, but Missing Content-Type header", "920340, 920341");
    }

    ngx_waf_log_access(r, "Exiting check_request_missing_content_type_header with no attack detected");
    return NGX_DECLINED;
}

// Function to check for invalid Content-Type header (RuleId: 920470)
ngx_int_t check_invalid_content_type_header(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_invalid_content_type_header");

    if (r->headers_in.content_type == NULL) {
        ngx_waf_log_access(r, "Content-Type header is missing. Exiting check_invalid_content_type_header with no attack detected");
        return NGX_DECLINED;
    }

    std::string content_type(reinterpret_cast<const char *>(r->headers_in.content_type->value.data), r->headers_in.content_type->value.len);
    std::regex regex_pattern;
    if (compile_and_log_regex(r, get_pattern_from_conf(r, "invalid_content_type_pattern"), "check_invalid_content_type_header", regex_pattern)) {
        if (std::regex_search(content_type, regex_pattern)) {
            ngx_waf_log_access(r, "Exiting check_invalid_content_type_header with attack detected");
            return log_and_reject(r, "Illegal Content-Type header", "920470");
        }
    }

    ngx_waf_log_access(r, "Exiting check_invalid_content_type_header with no attack detected");
    return NGX_DECLINED;
}

// Function to check for invalid charset in Content-Type header (RuleId: 920480)
ngx_int_t check_invalid_content_type_charset(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_invalid_content_type_charset");

    if (r->headers_in.content_type == NULL) {
        ngx_waf_log_access(r, "Exiting check_invalid_content_type_charset with no attack detected (no Content-Type header)");
        return NGX_DECLINED;
    }

    std::string content_type(reinterpret_cast<const char *>(r->headers_in.content_type->value.data), r->headers_in.content_type->value.len);
    std::regex charset_regex("charset=([^;]+)", std::regex::icase);
    std::smatch match;

    if (std::regex_search(content_type, match, charset_regex)) {
        std::string charset = match[1].str();
        ngx_waf_log_access(r, ("Detected charset: " + charset).c_str());

        std::regex regex_pattern;
        if (compile_and_log_regex(r, get_pattern_from_conf(r, "invalid_charset_pattern"), "check_invalid_content_type_charset", regex_pattern)) {
            if (std::regex_match(charset, regex_pattern)) {
                ngx_waf_log_access(r, "Exiting check_invalid_content_type_charset with attack detected");
                return log_and_reject(r, "Request content type charset isn't allowed by policy", "920480");
            }
        }
    } else {
        ngx_waf_log_access(r, "No charset found in Content-Type header");
    }

    ngx_waf_log_access(r, "Exiting check_invalid_content_type_charset with no attack detected");
    return NGX_DECLINED;
}

// Function to check for backup or working file access attempt (RuleId: 920500)
ngx_int_t check_backup_file_access(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_backup_file_access");

    std::string uri(reinterpret_cast<const char *>(r->uri.data), r->uri.len);
    std::regex regex_pattern;
    if (compile_and_log_regex(r, get_pattern_from_conf(r, "backup_file_pattern"), "check_backup_file_access", regex_pattern)) {
        if (std::regex_search(uri, regex_pattern)) {
            ngx_waf_log_access(r, "Exiting check_backup_file_access with attack detected");
            return log_and_reject(r, "Attempt to access a backup or working file", "920500");
        }
    }

    ngx_waf_log_access(r, "Exiting check_backup_file_access with no attack detected");
    return NGX_DECLINED;
}

// Function to check multiple/conflicting Connection headers (RuleId: 920210)
ngx_int_t check_multiple_conflicting_connection_headers(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_multiple_conflicting_connection_headers");

    ngx_list_part_t *part = &r->headers_in.headers.part;
    ngx_table_elt_t *header = (ngx_table_elt_t *)part->elts;

    int connection_header_count = 0;

    for (ngx_uint_t i = 0;; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            header = (ngx_table_elt_t *)part->elts;
            i = 0;
        }

        if (ngx_strcasecmp(header[i].key.data, (u_char *)"Connection") == 0) {
            connection_header_count++;
            if (connection_header_count > 1) {
                ngx_waf_log_access(r, "Exiting check_multiple_conflicting_connection_headers with attack detected");
                return log_and_reject(r, "Multiple/Conflicting Connection Header Data Found", "920210");
            }
        }
    }

    ngx_waf_log_access(r, "Exiting check_multiple_conflicting_connection_headers with no attack detected");
    return NGX_DECLINED;
}

// Entry point function
ngx_int_t generic_rules_entry_point(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered generic_rules_entry_point");

    if (check_invalid_http_request_line(r) != NGX_DECLINED) return NGX_HTTP_FORBIDDEN;
    if (check_multipart_form_data_bypass(r) != NGX_DECLINED) return NGX_HTTP_FORBIDDEN;
    if (check_content_length_numeric(r) != NGX_DECLINED) return NGX_HTTP_FORBIDDEN;
    if (check_get_head_with_body(r) != NGX_DECLINED) return NGX_HTTP_FORBIDDEN;
    if (check_get_head_with_transfer_encoding(r) != NGX_DECLINED) return NGX_HTTP_FORBIDDEN;
    if (check_post_request_missing_content_length(r) != NGX_DECLINED) return NGX_HTTP_FORBIDDEN;
    if (check_content_length_and_transfer_encoding(r) != NGX_DECLINED) return NGX_HTTP_FORBIDDEN;
    if (check_invalid_range_header(r) != NGX_DECLINED) return NGX_HTTP_FORBIDDEN;
    if (check_too_many_range_fields(r) != NGX_DECLINED) return NGX_HTTP_FORBIDDEN;
    if (check_multiple_conflicting_connection_headers(r) != NGX_DECLINED) return NGX_HTTP_FORBIDDEN;
    if (check_url_encoding_abuse(r) != NGX_DECLINED) return NGX_HTTP_FORBIDDEN;
    if (check_multiple_url_encoding(r) != NGX_DECLINED) return NGX_HTTP_FORBIDDEN;
    if (check_unicode_abuse(r) != NGX_DECLINED) return NGX_HTTP_FORBIDDEN;
    if (check_null_characters(r) != NGX_DECLINED) return NGX_HTTP_FORBIDDEN;
    if (check_nonprintable_characters(r) != NGX_DECLINED) return NGX_HTTP_FORBIDDEN;
    if (check_missing_host_header(r) != NGX_DECLINED) return NGX_HTTP_FORBIDDEN;
    if (check_empty_host_header(r) != NGX_DECLINED) return NGX_HTTP_FORBIDDEN;
    if (check_missing_accept_header(r) != NGX_DECLINED) return NGX_HTTP_FORBIDDEN;
    if (check_empty_accept_header(r) != NGX_DECLINED) return NGX_HTTP_FORBIDDEN;
    if (check_missing_user_agent_header(r) != NGX_DECLINED) return NGX_HTTP_FORBIDDEN;
    if (check_empty_user_agent_header(r) != NGX_DECLINED) return NGX_HTTP_FORBIDDEN;
    if (check_request_missing_content_type_header(r) != NGX_DECLINED) return NGX_HTTP_FORBIDDEN;
    if (check_invalid_content_type_header(r) != NGX_DECLINED) return NGX_HTTP_FORBIDDEN;
    if (check_invalid_content_type_charset(r) != NGX_DECLINED) return NGX_HTTP_FORBIDDEN;
    if (check_backup_file_access(r) != NGX_DECLINED) return NGX_HTTP_FORBIDDEN;

    ngx_waf_log_access(r, "Exiting generic_rules_entry_point with no attack detected");
    return NGX_DECLINED;
}
