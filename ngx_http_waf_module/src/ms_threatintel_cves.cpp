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

// Function to check for Attempted F5 tmui (CVE-2020-5902) REST API exploitation with known credentials (RuleId: 99001001)
bool check_cve_2020_5902(ngx_http_request_t *r) {
    ngx_waf_log_access(r,"Entered check_cve_2020_5902");

    std::string body(reinterpret_cast<const char*>(r->request_body->bufs->buf->pos), r->request_body->bufs->buf->last - r->request_body->bufs->buf->pos);
    std::regex regex_pattern;
    if (compile_and_log_regex(r, get_pattern_from_conf(r, "cve_2020_5902_pattern"), "check_cve_2020_5902", regex_pattern, std::regex_constants::icase)) {
        if (std::regex_search(body, regex_pattern)) {
            ngx_waf_log_access(r,"Exiting check_cve_2020_5902 with attack detected");
            return log_and_reject(r, "Attempted F5 tmui (CVE-2020-5902) REST API exploitation with known credentials", "99001001");
        }
    }
    ngx_waf_log_access(r,"Exiting check_cve_2020_5902 with no attack detected");
    return false;
}

// Function to check for Attempted Citrix NSC_USER directory traversal CVE-2019-19781 (RuleId: 99001002)
bool check_cve_2019_19781(ngx_http_request_t *r) {
    ngx_waf_log_access(r,"Entered check_cve_2019_19781");

    std::string uri(reinterpret_cast<const char*>(r->uri.data), r->uri.len);
    std::regex regex_pattern;
    if (compile_and_log_regex(r, get_pattern_from_conf(r, "cve_2019_19781_pattern"), "check_cve_2019_19781", regex_pattern, std::regex_constants::icase)) {
        if (std::regex_search(uri, regex_pattern)) {
            ngx_waf_log_access(r,"Exiting check_cve_2019_19781 with attack detected");
            return log_and_reject(r, "Attempted Citrix NSC_USER directory traversal CVE-2019-19781", "99001002");
        }
    }
    ngx_waf_log_access(r,"Exiting check_cve_2019_19781 with no attack detected");
    return false;
}

// Function to check for Attempted Atlassian Confluence Widget Connector exploitation CVE-2019-3396 (RuleId: 99001003)
bool check_cve_2019_3396(ngx_http_request_t *r) {
    ngx_waf_log_access(r,"Entered check_cve_2019_3396");

    std::string body(reinterpret_cast<const char*>(r->request_body->bufs->buf->pos), r->request_body->bufs->buf->last - r->request_body->bufs->buf->pos);
    std::regex regex_pattern;
    if (compile_and_log_regex(r, get_pattern_from_conf(r, "cve_2019_3396_pattern"), "check_cve_2019_3396", regex_pattern, std::regex_constants::icase)) {
        if (std::regex_search(body, regex_pattern)) {
            ngx_waf_log_access(r,"Exiting check_cve_2019_3396 with attack detected");
            return log_and_reject(r, "Attempted Atlassian Confluence Widget Connector exploitation CVE-2019-3396", "99001003");
        }
    }
    ngx_waf_log_access(r,"Exiting check_cve_2019_3396 with no attack detected");
    return false;
}

// Repeat similar functions for the remaining CVEs...

// Entry point function for the MS-ThreatIntel-CVEs ruleset
ngx_int_t cve_threatintel_entry_point(ngx_http_request_t *r) {
    ngx_waf_log_access(r,"Entered cve_threatintel_entry_point");

    if (check_cve_2020_5902(r)) return NGX_HTTP_FORBIDDEN;
    if (check_cve_2019_19781(r)) return NGX_HTTP_FORBIDDEN;
    if (check_cve_2019_3396(r)) return NGX_HTTP_FORBIDDEN;
    // Add calls to other check functions here...

    ngx_waf_log_access(r,"Exiting cve_threatintel_entry_point with no attack detected");
    return NGX_DECLINED;
}
