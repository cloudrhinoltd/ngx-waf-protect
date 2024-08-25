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

// Function to check Session Fixation Attack: Setting Cookie Values in HTML (RuleId: 943100)
bool check_session_fixation_cookie_values(ngx_http_request_t *r) {
    ngx_waf_log_access(r,"Entered check_session_fixation_cookie_values");

    std::string body(reinterpret_cast<const char*>(r->request_body->bufs->buf->pos), r->request_body->bufs->buf->last - r->request_body->bufs->buf->pos);
    std::regex regex_pattern;
    if (compile_and_log_regex(r, get_pattern_from_conf(r, "session_fixation_cookie_pattern"), "check_session_fixation_cookie_values", regex_pattern, std::regex_constants::icase)) {
        if (std::regex_search(body, regex_pattern)) {
            ngx_waf_log_access(r,"Exiting check_session_fixation_cookie_values with attack detected");
            return log_and_reject(r, "Possible Session Fixation Attack: Setting Cookie Values in HTML", "943100");
        }
    }
    ngx_waf_log_access(r,"Exiting check_session_fixation_cookie_values with no attack detected");
    return false;
}

// Function to check Session Fixation Attack: SessionID Parameter Name with Off-Domain Referrer (RuleId: 943110)
bool check_session_fixation_off_domain_referrer(ngx_http_request_t *r) {
    ngx_waf_log_access(r,"Entered check_session_fixation_off_domain_referrer");

    std::string referrer(reinterpret_cast<const char*>(r->headers_in.referer->value.data), r->headers_in.referer->value.len);
    std::string args(reinterpret_cast<const char*>(r->args.data), r->args.len);

    std::regex sessionid_regex;
    std::regex off_domain_regex;

    if (compile_and_log_regex(r, get_pattern_from_conf(r, "session_fixation_sessionid_pattern"), "check_session_fixation_off_domain_referrer (sessionid)", sessionid_regex, std::regex_constants::icase) &&
        compile_and_log_regex(r, get_pattern_from_conf(r, "session_fixation_off_domain_pattern"), "check_session_fixation_off_domain_referrer (off_domain)", off_domain_regex, std::regex_constants::icase)) {

        if (std::regex_search(args, sessionid_regex) && !referrer.empty() && !std::regex_search(referrer, off_domain_regex)) {
            ngx_waf_log_access(r,"Exiting check_session_fixation_off_domain_referrer with attack detected");
            return log_and_reject(r, "Possible Session Fixation Attack: SessionID Parameter Name with Off-Domain Referrer", "943110");
        }
    }
    ngx_waf_log_access(r,"Exiting check_session_fixation_off_domain_referrer with no attack detected");
    return false;
}

// Function to check Session Fixation Attack: SessionID Parameter Name with No Referrer (RuleId: 943120)
bool check_session_fixation_no_referrer(ngx_http_request_t *r) {
    ngx_waf_log_access(r,"Entered check_session_fixation_no_referrer");

    std::string args(reinterpret_cast<const char*>(r->args.data), r->args.len);

    std::regex sessionid_regex;
    if (compile_and_log_regex(r, get_pattern_from_conf(r, "session_fixation_sessionid_pattern"), "check_session_fixation_no_referrer (sessionid)", sessionid_regex, std::regex_constants::icase)) {
        if (std::regex_search(args, sessionid_regex) && r->headers_in.referer == NULL) {
            ngx_waf_log_access(r,"Exiting check_session_fixation_no_referrer with attack detected");
            return log_and_reject(r, "Possible Session Fixation Attack: SessionID Parameter Name with No Referrer", "943120");
        }
    }
    ngx_waf_log_access(r,"Exiting check_session_fixation_no_referrer with no attack detected");
    return false;
}

// Function to check Java Remote Command Execution (RuleId: 944100, 944110, 944120, 944130, 944200, 944210, 944240, 944250)
bool check_java_remote_command_execution(ngx_http_request_t *r) {
    ngx_waf_log_access(r,"Entered check_java_remote_command_execution");

    std::string body(reinterpret_cast<const char*>(r->request_body->bufs->buf->pos), r->request_body->bufs->buf->last - r->request_body->bufs->buf->pos);

    std::regex java_rce_pattern;
    if (compile_and_log_regex(r, get_pattern_from_conf(r, "java_rce_pattern"), "check_java_remote_command_execution", java_rce_pattern, std::regex_constants::icase)) {
        if (std::regex_search(body, java_rce_pattern)) {
            ngx_waf_log_access(r,"Exiting check_java_remote_command_execution with attack detected");
            return log_and_reject(r, "Possible Remote Command Execution: Java-related attack", "944100, 944110, 944120, 944130, 944200, 944210, 944240, 944250");
        }
    }
    ngx_waf_log_access(r,"Exiting check_java_remote_command_execution with no attack detected");
    return false;
}

// Function to check MS-ThreatIntel-WebShells (RuleId: 99005002, 99005003, 99005004, 99005005, 99005006)
bool check_web_shell_interaction(ngx_http_request_t *r) {
    ngx_waf_log_access(r,"Entered check_web_shell_interaction");

    if (r->method == NGX_HTTP_POST) {
        std::string body(reinterpret_cast<const char*>(r->request_body->bufs->buf->pos), r->request_body->bufs->buf->last - r->request_body->bufs->buf->pos);

        std::regex web_shell_pattern;
        if (compile_and_log_regex(r, get_pattern_from_conf(r, "web_shell_pattern"), "check_web_shell_interaction", web_shell_pattern, std::regex_constants::icase)) {
            if (std::regex_search(body, web_shell_pattern)) {
                ngx_waf_log_access(r,"Exiting check_web_shell_interaction with attack detected");
                return log_and_reject(r, "Possible Web Shell Interaction Attempt", "99005002, 99005003, 99005004, 99005005, 99005006");
            }
        }
    }
    ngx_waf_log_access(r,"Exiting check_web_shell_interaction with no attack detected");
    return false;
}

// Function to check Path Traversal Evasion in Headers (RuleId: 99030001)
bool check_path_traversal_evasion_headers(ngx_http_request_t *r) {
    ngx_waf_log_access(r,"Entered check_path_traversal_evasion_headers");

    ngx_list_part_t *part = &r->headers_in.headers.part;
    ngx_table_elt_t *header = (ngx_table_elt_t *) part->elts;

    std::regex path_traversal_evasion_pattern;
    if (compile_and_log_regex(r, get_pattern_from_conf(r, "path_traversal_evasion_header_pattern"), "check_path_traversal_evasion_headers", path_traversal_evasion_pattern, std::regex_constants::icase)) {
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
            if (std::regex_search(header_value, path_traversal_evasion_pattern)) {
                ngx_waf_log_access(r,"Exiting check_path_traversal_evasion_headers with attack detected");
                return log_and_reject(r, "Path Traversal Evasion in Headers (/.././../)", "99030001");
            }
        }
    }
    ngx_waf_log_access(r,"Exiting check_path_traversal_evasion_headers with no attack detected");
    return false;
}

// Function to check Path Traversal Evasion in Request Body (RuleId: 99030002)
bool check_path_traversal_evasion_body(ngx_http_request_t *r) {
    ngx_waf_log_access(r,"Entered check_path_traversal_evasion_body");

    std::string body(reinterpret_cast<const char*>(r->request_body->bufs->buf->pos), r->request_body->bufs->buf->last - r->request_body->bufs->buf->pos);

    std::regex path_traversal_evasion_pattern;
    if (compile_and_log_regex(r, get_pattern_from_conf(r, "path_traversal_evasion_body_pattern"), "check_path_traversal_evasion_body", path_traversal_evasion_pattern, std::regex_constants::icase)) {
        if (std::regex_search(body, path_traversal_evasion_pattern)) {
            ngx_waf_log_access(r,"Exiting check_path_traversal_evasion_body with attack detected");
            return log_and_reject(r, "Path Traversal Evasion in Request Body (/.././../)", "99030002");
        }
    }
    ngx_waf_log_access(r,"Exiting check_path_traversal_evasion_body with no attack detected");
    return false;
}

// Function to check SQL Injection (RuleId: 99031001, 99031002, 99031003, 99031004)
bool check_sql_injection(ngx_http_request_t *r) {
    ngx_waf_log_access(r,"Entered check_sql_injection");

    std::string args(reinterpret_cast<const char*>(r->args.data), r->args.len);
    std::string body(reinterpret_cast<const char*>(r->request_body->bufs->buf->pos), r->request_body->bufs->buf->last - r->request_body->bufs->buf->pos);

    std::regex sql_injection_common_testing_pattern;
    std::regex sql_injection_comment_sequence_pattern;
    std::regex sql_authentication_bypass_pattern;

    if (compile_and_log_regex(r, get_pattern_from_conf(r, "sql_injection_common_testing_pattern"), "check_sql_injection (injection)", sql_injection_common_testing_pattern, std::regex_constants::icase) &&
        compile_and_log_regex(r, get_pattern_from_conf(r, "sql_injection_comment_sequence_pattern"), "check_sql_injection (comment)", sql_injection_comment_sequence_pattern, std::regex_constants::icase) &&
        compile_and_log_regex(r, get_pattern_from_conf(r, "sql_authentication_bypass_pattern"), "check_sql_injection (auth_bypass)", sql_authentication_bypass_pattern, std::regex_constants::icase)) {

        if (std::regex_search(args, sql_injection_common_testing_pattern) || std::regex_search(body, sql_injection_common_testing_pattern)) {
            ngx_waf_log_access(r,"Exiting check_sql_injection with attack detected: SQL Injection Attack");
            return log_and_reject(r, "SQL Injection Attack: Common Injection Testing Detected", "99031001, 99031003");
        } else if (std::regex_search(args, sql_injection_comment_sequence_pattern) || std::regex_search(body, sql_injection_comment_sequence_pattern)) {
            ngx_waf_log_access(r,"Exiting check_sql_injection with attack detected: SQL Comment Sequence Detected");
            return log_and_reject(r, "SQL Comment Sequence Detected", "99031002");
        } else if (std::regex_search(args, sql_authentication_bypass_pattern) || std::regex_search(body, sql_authentication_bypass_pattern)) {
            ngx_waf_log_access(r,"Exiting check_sql_injection with attack detected: SQL Authentication Bypass Attempt");
            return log_and_reject(r, "Detects basic SQL authentication bypass attempts", "99031004");
        }
    }

    ngx_waf_log_access(r,"Exiting check_sql_injection with no attack detected");
    return false;
}

// Entry point function for the updated WAF ruleset
ngx_int_t session_java_ms_entry_point(ngx_http_request_t *r) {
    ngx_waf_log_access(r,"Entered new_waf_entry_point");

    // Session fixation checks
    if (check_session_fixation_cookie_values(r)) return NGX_HTTP_FORBIDDEN;
    if (check_session_fixation_off_domain_referrer(r)) return NGX_HTTP_FORBIDDEN;
    if (check_session_fixation_no_referrer(r)) return NGX_HTTP_FORBIDDEN;

    // Java attack checks
    if (check_java_remote_command_execution(r)) return NGX_HTTP_FORBIDDEN;

    // MS-ThreatIntel-WebShells checks
    if (check_web_shell_interaction(r)) return NGX_HTTP_FORBIDDEN;

    // MS-ThreatIntel-AppSec checks
    if (check_path_traversal_evasion_headers(r)) return NGX_HTTP_FORBIDDEN;
    if (check_path_traversal_evasion_body(r)) return NGX_HTTP_FORBIDDEN;

    // MS-ThreatIntel-SQLI checks
    if (check_sql_injection(r)) return NGX_HTTP_FORBIDDEN;

    ngx_waf_log_access(r,"Exiting new_waf_entry_point with no attack detected");
    return NGX_DECLINED;
}
