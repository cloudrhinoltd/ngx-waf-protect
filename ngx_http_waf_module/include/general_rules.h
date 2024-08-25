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

#ifndef GENERIC_RULES_H
#define GENERIC_RULES_H

// The extern "C" block should only encapsulate C headers
#ifdef __cplusplus
extern "C" {
#endif

#include <ngx_core.h>
#include <ngx_http.h>

#ifdef __cplusplus
}
#endif

// C++ includes
#include <string>
#include <regex>
#include "../include/waf_utils.h" // Ensure this is included for utility functions like log_and_reject

// Function declarations
ngx_int_t check_invalid_http_request_line(ngx_http_request_t *r);
ngx_int_t check_multipart_form_data_bypass(ngx_http_request_t *r);
ngx_int_t check_content_length_numeric(ngx_http_request_t *r);
ngx_int_t check_get_head_with_body(ngx_http_request_t *r);
ngx_int_t check_get_head_with_transfer_encoding(ngx_http_request_t *r);
ngx_int_t check_post_request_missing_content_length(ngx_http_request_t *r);
ngx_int_t check_content_length_and_transfer_encoding(ngx_http_request_t *r);
ngx_int_t check_invalid_range_header(ngx_http_request_t *r);
ngx_int_t check_too_many_range_fields(ngx_http_request_t *r);
ngx_int_t check_multiple_conflicting_connection_headers(ngx_http_request_t *r);
ngx_int_t check_url_encoding_abuse(ngx_http_request_t *r);
ngx_int_t check_multiple_url_encoding(ngx_http_request_t *r);
ngx_int_t check_unicode_abuse(ngx_http_request_t *r);
ngx_int_t check_null_characters(ngx_http_request_t *r);
ngx_int_t check_nonprintable_characters(ngx_http_request_t *r);
ngx_int_t check_missing_host_header(ngx_http_request_t *r);
ngx_int_t check_empty_host_header(ngx_http_request_t *r);
ngx_int_t check_missing_accept_header(ngx_http_request_t *r);
ngx_int_t check_empty_accept_header(ngx_http_request_t *r);
ngx_int_t check_missing_user_agent_header(ngx_http_request_t *r);
ngx_int_t check_empty_user_agent_header(ngx_http_request_t *r);
ngx_int_t check_request_missing_content_type_header(ngx_http_request_t *r);
ngx_int_t check_invalid_content_type_header(ngx_http_request_t *r);
ngx_int_t check_invalid_content_type_charset(ngx_http_request_t *r);
ngx_int_t check_backup_file_access(ngx_http_request_t *r);

ngx_int_t generic_rules_entry_point(ngx_http_request_t *r);

#endif // GENERIC_RULES_H
