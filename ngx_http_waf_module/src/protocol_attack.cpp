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

#include "../include/waf_utils.h"
#include <regex>

// Function to check for HTTP protocol anomalies
ngx_int_t is_protocol_anomaly(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered is_protocol_anomaly");

    std::string request(reinterpret_cast<const char *>(r->request_line.data), r->request_line.len);
    std::regex regex_pattern;
    
    if (compile_and_log_regex(r, get_pattern_from_conf(r, "protocol_anomaly_pattern"), "is_protocol_anomaly", regex_pattern, std::regex_constants::icase)) {
        if (std::regex_search(request, regex_pattern)) {
            ngx_waf_log_access(r, "Exiting is_protocol_anomaly with attack detected");
            return log_and_reject(r, "HTTP Protocol Anomaly", "000000");
        }
    }

    ngx_waf_log_access(r, "Exiting is_protocol_anomaly with no attack detected");
    return NGX_DECLINED;
}

// Function to check HTTP Request Smuggling Attack (RuleId: 921110)
ngx_int_t check_http_request_smuggling(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_http_request_smuggling");
    if (r->headers_in.transfer_encoding && r->headers_in.content_length) {
        ngx_waf_log_access(r, "Exiting check_http_request_smuggling with attack detected");
        return log_and_reject(r, "HTTP Request Smuggling Attack", "921110");
    }
    ngx_waf_log_access(r, "Exiting check_http_request_smuggling with no attack detected");
    return NGX_DECLINED;
}

// Function to check HTTP Response Splitting Attack (RuleId: 921120, 921130)
ngx_int_t check_http_response_splitting(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_http_response_splitting");

    std::string request(reinterpret_cast<const char *>(r->request_line.data), r->request_line.len);
    if (request.find("\r\n") != std::string::npos) {
        ngx_waf_log_access(r, "Exiting check_http_response_splitting with attack detected");
        return log_and_reject(r, "HTTP Response Splitting Attack", "921120, 921130");
    }

    ngx_waf_log_access(r, "Exiting check_http_response_splitting with no attack detected");
    return NGX_DECLINED;
}

// Updated function to check HTTP Header Injection Attack (RuleId: 921140, 921150, 921151, 921160)
ngx_int_t check_http_header_injection(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_http_header_injection");
    ngx_list_part_t *part = &r->headers_in.headers.part;
    ngx_table_elt_t *header = (ngx_table_elt_t *)part->elts;

    for (ngx_uint_t i = 0;; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            header = (ngx_table_elt_t *)part->elts;
            i = 0;
        }

        std::string header_value(reinterpret_cast<const char*>(header[i].value.data), header[i].value.len);

        // Decode percent-encoded characters in the header value
        std::string decoded_header_value = decode_percent_encoded(header_value);

        // Check for injected carriage return and newline characters
        if (decoded_header_value.find("\r") != std::string::npos || decoded_header_value.find("\n") != std::string::npos) {
            ngx_waf_log_access(r, "Exiting check_http_header_injection with attack detected");
            return log_and_reject(r, "HTTP Header Injection Attack", "921140, 921150, 921151, 921160");
        }
    }

    ngx_waf_log_access(r, "Exiting check_http_header_injection with no attack detected");
    return NGX_DECLINED;
}

// Function to check HTTP Splitting (CR/LF in request filename) (RuleId: 921190)
ngx_int_t check_http_splitting(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_http_splitting");

    // Decode the URI to catch any percent-encoded characters
    std::string uri = decode_percent_encoded(std::string(reinterpret_cast<const char *>(r->uri.data), r->uri.len));

    if (uri.find("\r") != std::string::npos || uri.find("\n") != std::string::npos) {
        ngx_waf_log_access(r, "Exiting check_http_splitting with attack detected");
        return log_and_reject(r, "HTTP Splitting (CR/LF in request filename detected)", "921190");
    }
    ngx_waf_log_access(r, "Exiting check_http_splitting with no attack detected");
    return NGX_DECLINED;
}

// Function to check LDAP Injection Attack (RuleId: 921200)
ngx_int_t check_ldap_injection_attack(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_ldap_injection_attack");

    std::string query(reinterpret_cast<const char *>(r->args.data), r->args.len);
    std::regex regex_pattern;
    
    if (compile_and_log_regex(r, get_pattern_from_conf(r, "ldap_injection_pattern"), "check_ldap_injection_attack", regex_pattern)) {
        if (std::regex_search(query, regex_pattern)) {
            ngx_waf_log_access(r, "Exiting check_ldap_injection_attack with attack detected");
            return log_and_reject(r, "LDAP Injection Attack", "921200");
        }
    }

    ngx_waf_log_access(r, "Exiting check_ldap_injection_attack with no attack detected");
    return NGX_DECLINED;
}

// Function to check Path Traversal Attack (/../) (RuleId: 930100, 930110)
ngx_int_t check_path_traversal_attack(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_path_traversal_attack");

    std::string uri(reinterpret_cast<const char *>(r->uri.data), r->uri.len);
    std::regex regex_pattern;
    
    if (compile_and_log_regex(r, get_pattern_from_conf(r, "path_traversal_pattern"), "check_path_traversal_attack", regex_pattern)) {
        if (std::regex_search(uri, regex_pattern)) {
            ngx_waf_log_access(r, "Exiting check_path_traversal_attack with attack detected");
            return log_and_reject(r, "Path Traversal Attack (/../)", "930100, 930110");
        }
    }

    ngx_waf_log_access(r, "Exiting check_path_traversal_attack with no attack detected");
    return NGX_DECLINED;
}

// Function to check OS File Access Attempt (RuleId: 930120)
ngx_int_t check_os_file_access_attempt(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_os_file_access_attempt");

    std::string uri(reinterpret_cast<const char *>(r->uri.data), r->uri.len);
    std::regex regex_pattern;
    
    if (compile_and_log_regex(r, get_pattern_from_conf(r, "os_file_access_pattern"), "check_os_file_access_attempt", regex_pattern)) {
        if (std::regex_search(uri, regex_pattern)) {
            ngx_waf_log_access(r, "Exiting check_os_file_access_attempt with attack detected");
            return log_and_reject(r, "OS File Access Attempt", "930120");
        }
    }

    ngx_waf_log_access(r, "Exiting check_os_file_access_attempt with no attack detected");
    return NGX_DECLINED;
}

// Function to check Restricted File Access Attempt (RuleId: 930130)
ngx_int_t check_restricted_file_access_attempt(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_restricted_file_access_attempt");

    std::string uri(reinterpret_cast<const char *>(r->uri.data), r->uri.len);
    std::regex regex_pattern;

    if (compile_and_log_regex(r, get_pattern_from_conf(r, "restricted_file_access_pattern"), "check_restricted_file_access_attempt", regex_pattern)) {
        if (std::regex_search(uri, regex_pattern)) {
            ngx_waf_log_access(r, "Exiting check_restricted_file_access_attempt with attack detected");
            return log_and_reject(r, "Restricted File Access Attempt", "930130");
        }
    }

    ngx_waf_log_access(r, "Exiting check_restricted_file_access_attempt with no attack detected");
    return NGX_DECLINED;
}

// Function to check Remote File Inclusion Attack (RuleId: 931100, 931110, 931120, 931130)
ngx_int_t check_remote_file_inclusion_attack(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_remote_file_inclusion_attack");

    std::string query(reinterpret_cast<const char *>(r->args.data), r->args.len);

    std::regex rfi_ip_regex, rfi_common_param_regex, rfi_trailing_question_mark_regex, rfi_off_domain_regex;

    if (compile_and_log_regex(r, get_pattern_from_conf(r, "rfi_ip_pattern"), "check_remote_file_inclusion_attack (IP)", rfi_ip_regex) &&
        compile_and_log_regex(r, get_pattern_from_conf(r, "rfi_common_param_pattern"), "check_remote_file_inclusion_attack (Common Param)", rfi_common_param_regex) &&
        compile_and_log_regex(r, get_pattern_from_conf(r, "rfi_trailing_question_mark_pattern"), "check_remote_file_inclusion_attack (Trailing Question Mark)", rfi_trailing_question_mark_regex) &&
        compile_and_log_regex(r, get_pattern_from_conf(r, "rfi_off_domain_pattern"), "check_remote_file_inclusion_attack (Off Domain)", rfi_off_domain_regex)) {

        if (std::regex_search(query, rfi_ip_regex)) {
            ngx_waf_log_access(r,"Exiting check_remote_file_inclusion_attack with attack detected: URL Parameter using IP address");
            return log_and_reject(r, "Possible Remote File Inclusion (RFI) Attack: URL Parameter using IP address", "931100");
        } else if (std::regex_search(query, rfi_common_param_regex)) {
            ngx_waf_log_access(r,"Exiting check_remote_file_inclusion_attack with attack detected: Common RFI Vulnerable Parameter Name used w/URL Payload");
            return log_and_reject(r, "Possible Remote File Inclusion (RFI) Attack: Common RFI Vulnerable Parameter Name used w/URL Payload", "931110");
        } else if (std::regex_search(query, rfi_trailing_question_mark_regex)) {
            ngx_waf_log_access(r,"Exiting check_remote_file_inclusion_attack with attack detected: URL Payload Used w/Trailing Question Mark Character (?)");
            return log_and_reject(r, "Possible Remote File Inclusion (RFI) Attack: URL Payload Used w/Trailing Question Mark Character (?)", "931120");
        } else if (std::regex_search(query, rfi_off_domain_regex)) {
            ngx_waf_log_access(r,"Exiting check_remote_file_inclusion_attack with attack detected: Off-Domain Reference/Link");
            return log_and_reject(r, "Possible Remote File Inclusion (RFI) Attack: Off-Domain Reference/Link", "931130");
        }
    }

    ngx_waf_log_access(r,"Exiting check_remote_file_inclusion_attack with no attack detected");
    return NGX_DECLINED;
}

// Entry point function
ngx_int_t protocol_attack_entry_point(ngx_http_request_t *r) {
    ngx_waf_log_access(r,"Entered protocol_attack_entry_point");
    
    if (is_protocol_anomaly(r) != NGX_DECLINED) return NGX_HTTP_FORBIDDEN;
    if (check_http_request_smuggling(r) != NGX_DECLINED) return NGX_HTTP_FORBIDDEN;
    if (check_http_response_splitting(r) != NGX_DECLINED) return NGX_HTTP_FORBIDDEN;
    if (check_http_header_injection(r) != NGX_DECLINED) return NGX_HTTP_FORBIDDEN;
    if (check_http_splitting(r) != NGX_DECLINED) return NGX_HTTP_FORBIDDEN;
    if (check_ldap_injection_attack(r) != NGX_DECLINED) return NGX_HTTP_FORBIDDEN;
    if (check_path_traversal_attack(r) != NGX_DECLINED) return NGX_HTTP_FORBIDDEN;
    if (check_os_file_access_attempt(r) != NGX_DECLINED) return NGX_HTTP_FORBIDDEN;
    if (check_restricted_file_access_attempt(r) != NGX_DECLINED) return NGX_HTTP_FORBIDDEN;
    if (check_remote_file_inclusion_attack(r) != NGX_DECLINED) return NGX_HTTP_FORBIDDEN;

    ngx_waf_log_access(r,"Exiting protocol_attack_entry_point with no attack detected");
    return NGX_DECLINED;
}
