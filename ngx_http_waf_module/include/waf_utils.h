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

#ifndef WAF_UTILS_H
#define WAF_UTILS_H

extern "C" {
    #include <ngx_core.h>
    #include <ngx_http.h>
}

#include <regex>
#include <string>

// Function declarations

std::string get_pattern_from_conf(ngx_http_request_t *r, const char *pattern_name);
bool log_and_reject(ngx_http_request_t *r, const char *message, const char *rule_id);
bool compile_and_log_regex(ngx_http_request_t *r, const std::string &pattern_str, const std::string &rule_name, std::regex &out_pattern, std::regex_constants::syntax_option_type flags = std::regex_constants::ECMAScript);

void ngx_waf_log_access(ngx_http_request_t *r, const std::string &message);
void ngx_waf_log_access(ngx_http_request_t *r, const char *message);
std::string decode_percent_encoded(const std::string &input);

#endif // WAF_UTILS_H
