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

// Function to check HTTP Request Smuggling Attack (RuleId: 921110)
bool check_http_request_smuggling(ngx_http_request_t *r) {
    ngx_waf_log_access(r,"Entered check_http_request_smuggling");
    if (r->headers_in.transfer_encoding && r->headers_in.content_length) {
        ngx_waf_log_access(r,"Exiting check_http_request_smuggling with attack detected");
        return log_and_reject(r, "HTTP Request Smuggling Attack", "921110");
    }
    ngx_waf_log_access(r,"Exiting check_http_request_smuggling with no attack detected");
    return false;
}

// Function to check HTTP Response Splitting Attack (RuleId: 921120, 921130)
bool check_http_response_splitting(ngx_http_request_t *r) {
    ngx_waf_log_access(r,"Entered check_http_response_splitting");
    std::string request(reinterpret_cast<const char*>(r->request_line.data), r->request_line.len);
    if (request.find("
") != std::string::npos) {
        ngx_waf_log_access(r,"Exiting check_http_response_splitting with attack detected");
        return log_and_reject(r, "HTTP Response Splitting Attack", "921120, 921130");
    }
    ngx_waf_log_access(r,"Exiting check_http_response_splitting with no attack detected");
    return false;
}

// Function to check HTTP Header Injection Attack (RuleId: 921140, 921150, 921151, 921160)
bool check_http_header_injection(ngx_http_request_t *r) {
    ngx_waf_log_access(r,"Entered check_http_header_injection");
    ngx_list_part_t *part = &r->headers_in.headers.part;
    ngx_table_elt_t *header = (ngx_table_elt_t *) part->elts;

    for (ngx_uint_t i = 0; ; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            header = (ngx_table_elt_t *) part->elts;
            i = 0;
        }

        std::string header_value(reinterpret_cast<const char*>(header[i].value.data), header[i].value.len);
        if (header_value.find("") != std::string::npos || header_value.find("
") != std::string::npos) {
            ngx_waf_log_access(r,"Exiting check_http_header_injection with attack detected");
            return log_and_reject(r, "HTTP Header Injection Attack", "921140, 921150, 921151, 921160");
        }
    }
    ngx_waf_log_access(r,"Exiting check_http_header_injection with no attack detected");
    return false;
}

// Function to check HTTP Splitting (CR/LF in request filename) (RuleId: 921190)
bool check_http_splitting(ngx_http_request_t *r) {
    ngx_waf_log_access(r,"Entered check_http_splitting");
    std::string uri(reinterpret_cast<const char*>(r->uri.data), r->uri.len);
    if (uri.find("") != std::string::npos || uri.find("
") != std::string::npos) {
        ngx_waf_log_access(r,"Exiting check_http_splitting with attack detected");
        return log_and_reject(r, "HTTP Splitting (CR/LF in request filename detected)", "921190");
    }
    ngx_waf_log_access(r,"Exiting check_http_splitting with no attack detected");
    return false;
}

// Function to check LDAP Injection Attack (RuleId: 921200)
bool check_ldap_injection_attack(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_ldap_injection_attack");

    // Extract the query string from the request
    std::string query(reinterpret_cast<const char*>(r->args.data), r->args.len);

    // Get the LDAP injection pattern from the configuration
    std::string ldap_pattern = get_pattern_from_conf(r, "ldap_injection_pattern");

    try {
        std::regex ldap_injection_pattern(ldap_pattern);

        // Log the pattern and query for debugging
        ngx_waf_log_access(r, ("LDAP Injection Pattern: " + ldap_pattern).c_str());
        ngx_waf_log_access(r, ("Query: " + query).c_str());

        // Perform regex search to check for LDAP injection
        if (std::regex_search(query, ldap_injection_pattern)) {
            ngx_waf_log_access(r, "Exiting check_ldap_injection_attack with attack detected");
            return log_and_reject(r, "LDAP Injection Attack", "921200");
        }
    } catch (const std::exception &e) {
        ngx_waf_log_access(r, ("Exception in LDAP injection check: " + std::string(e.what())).c_str());
    }

    ngx_waf_log_access(r, "Exiting check_ldap_injection_attack with no attack detected");
    return false;
}

// Function to check Path Traversal Attack (/../) (RuleId: 930100, 930110)
bool check_path_traversal_attack(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_path_traversal_attack");
    
    // Extract the URI from the request
    std::string uri(reinterpret_cast<const char*>(r->uri.data), r->uri.len);

    // Log the URI for debugging
    ngx_waf_log_access(r, ("URI: " + uri).c_str());

    // Skip check for empty URIs or root path
    if (uri.empty() || uri == "/") {
        ngx_waf_log_access(r, "Exiting check_path_traversal_attack with no attack detected due to empty or root URI");
        return false;
    }

    // Get the path traversal pattern from the configuration
    std::string path_traversal_pattern = get_pattern_from_conf(r, "path_traversal_pattern");

    // Log the pattern for debugging
    ngx_waf_log_access(r, ("Path Traversal Pattern: " + path_traversal_pattern).c_str());

    try {
        // Compile the regex pattern
        std::regex path_traversal_regex(path_traversal_pattern);

        // Perform regex search to check for path traversal
        if (std::regex_search(uri, path_traversal_regex)) {
            ngx_waf_log_access(r, "Exiting check_path_traversal_attack with attack detected");
            return log_and_reject(r, "Path Traversal Attack (/../)", "930100, 930110");
        }
    } catch (const std::exception &e) {
        ngx_waf_log_access(r, ("Exception in path traversal check: " + std::string(e.what())).c_str());
    }

    ngx_waf_log_access(r, "Exiting check_path_traversal_attack with no attack detected");
    return false;
}

// Function to check OS File Access Attempt (RuleId: 930120)
bool check_os_file_access_attempt(ngx_http_request_t *r) {
    ngx_waf_log_access(r,"Entered check_os_file_access_attempt");
    std::string uri(reinterpret_cast<const char*>(r->uri.data), r->uri.len);
    std::regex os_file_access_pattern(get_pattern_from_conf(r, "os_file_access_pattern"));
    if (std::regex_search(uri, os_file_access_pattern)) {
        ngx_waf_log_access(r,"Exiting check_os_file_access_attempt with attack detected");
        return log_and_reject(r, "OS File Access Attempt", "930120");
    }
    ngx_waf_log_access(r,"Exiting check_os_file_access_attempt with no attack detected");
    return false;
}

// Function to check Restricted File Access Attempt (RuleId: 930130)
bool check_restricted_file_access_attempt(ngx_http_request_t *r) {
    ngx_waf_log_access(r,"Entered check_restricted_file_access_attempt");
    std::string uri(reinterpret_cast<const char*>(r->uri.data), r->uri.len);

    std::string restricted_file_access_pattern = get_pattern_from_conf(r, "restricted_file_access_pattern");
    ngx_waf_log_access(r, ("Restricted File Access Pattern: " + restricted_file_access_pattern).c_str());

    std::regex restricted_file_access_regex(restricted_file_access_pattern);

    if (std::regex_search(uri, restricted_file_access_regex)) {
        ngx_waf_log_access(r,"Exiting check_restricted_file_access_attempt with attack detected");
        return log_and_reject(r, "Restricted File Access Attempt", "930130");
    }
    ngx_waf_log_access(r,"Exiting check_restricted_file_access_attempt with no attack detected");
    return false;
}

// Function to check Remote File Inclusion Attack (RuleId: 931100, 931110, 931120, 931130)
bool check_remote_file_inclusion_attack(ngx_http_request_t *r) {
    ngx_waf_log_access(r,"Entered check_remote_file_inclusion_attack");
    std::string query(reinterpret_cast<const char*>(r->args.data), r->args.len);

    std::string rfi_ip_pattern = get_pattern_from_conf(r, "rfi_ip_pattern");
    std::string rfi_common_param_pattern = get_pattern_from_conf(r, "rfi_common_param_pattern");
    std::string rfi_trailing_question_mark_pattern = get_pattern_from_conf(r, "rfi_trailing_question_mark_pattern");
    std::string rfi_off_domain_pattern = get_pattern_from_conf(r, "rfi_off_domain_pattern");

    ngx_waf_log_access(r, ("RFI IP Pattern: " + rfi_ip_pattern).c_str());
    ngx_waf_log_access(r, ("RFI Common Param Pattern: " + rfi_common_param_pattern).c_str());
    ngx_waf_log_access(r, ("RFI Trailing Question Mark Pattern: " + rfi_trailing_question_mark_pattern).c_str());
    ngx_waf_log_access(r, ("RFI Off Domain Pattern: " + rfi_off_domain_pattern).c_str());

    try {
        std::regex rfi_ip_regex(rfi_ip_pattern);
        std::regex rfi_common_param_regex(rfi_common_param_pattern);
        std::regex rfi_trailing_question_mark_regex(rfi_trailing_question_mark_pattern);
        std::regex rfi_off_domain_regex(rfi_off_domain_pattern);

        ngx_waf_log_access(r, "Regex compiled successfully");

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
    } catch (const std::regex_error &e) {
        ngx_waf_log_access(r, ("Regex error: " + std::string(e.what())).c_str());
        return false;
    } catch (const std::exception &e) {
        ngx_waf_log_access(r, ("Exception: " + std::string(e.what())).c_str());
        return false;
    }
    ngx_waf_log_access(r,"Exiting check_remote_file_inclusion_attack with no attack detected");
    return false;
}

// Entry point function
ngx_int_t protocol_attack_entry_point(ngx_http_request_t *r) {
    ngx_waf_log_access(r,"Entered protocol_attack_entry_point");
    if (check_http_request_smuggling(r)) return NGX_HTTP_FORBIDDEN;
    if (check_http_response_splitting(r)) return NGX_HTTP_FORBIDDEN;
    if (check_http_header_injection(r)) return NGX_HTTP_FORBIDDEN;
    if (check_http_splitting(r)) return NGX_HTTP_FORBIDDEN;
    if (check_ldap_injection_attack(r)) return NGX_HTTP_FORBIDDEN;
    if (check_path_traversal_attack(r)) return NGX_HTTP_FORBIDDEN;
    if (check_os_file_access_attempt(r)) return NGX_HTTP_FORBIDDEN;
    if (check_restricted_file_access_attempt(r)) return NGX_HTTP_FORBIDDEN;
    if (check_remote_file_inclusion_attack(r)) return NGX_HTTP_FORBIDDEN;
    ngx_waf_log_access(r,"Exiting protocol_attack_entry_point with no attack detected");
    return NGX_DECLINED;
}
