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

#ifndef NGX_HTTP_WAF_MODULE_H
#define NGX_HTTP_WAF_MODULE_H

extern "C"
{
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <maxminddb.h>
}

#include <iostream>
#include <regex>
#include <unordered_map>
#include <chrono>
#include <string>
#include <mutex>
#include <ctime>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <sstream>
#include <vector>
#include <atomic>

// Module config
typedef struct
{
    ngx_flag_t enable_sql_injection;
    ngx_flag_t enable_xss;
    ngx_flag_t enable_protocol_attack;
    ngx_flag_t enable_rce_php_node;
    ngx_flag_t enable_general_rules;
    ngx_flag_t enable_session_rules;

    ngx_str_t geoip_db_path;
    ngx_str_t sql_injection_pattern;
    ngx_str_t xss_pattern;
    ngx_str_t file_inclusion_pattern;
    ngx_str_t command_injection_pattern;
    ngx_str_t directory_traversal_pattern;
    ngx_str_t parameter_tampering_pattern;
    ngx_str_t protocol_anomaly_pattern;
    ngx_str_t malicious_user_agent_pattern;
    ngx_str_t url_encoding_abuse_pattern;
    ngx_str_t invalid_request_line_pattern;
    ngx_str_t multipart_bypass_pattern;
    ngx_str_t invalid_range_pattern;
    ngx_str_t multiple_url_encoding_pattern;
    ngx_str_t unicode_abuse_pattern;
    ngx_str_t invalid_content_type_pattern;
    ngx_str_t invalid_charset_pattern;
    ngx_str_t backup_file_pattern;

    // New patterns
    ngx_str_t ldap_injection_pattern;
    ngx_str_t path_traversal_pattern;
    ngx_str_t os_file_access_pattern;
    ngx_str_t restricted_file_access_pattern;
    ngx_str_t rfi_ip_pattern;
    ngx_str_t rfi_common_param_pattern;
    ngx_str_t rfi_trailing_question_mark_pattern;
    ngx_str_t rfi_off_domain_pattern;

    // New RCE, PHP, and Node.js patterns
    ngx_str_t rce_unix_command_injection_pattern;
    ngx_str_t rce_windows_command_injection_pattern;
    ngx_str_t rce_powershell_command_pattern;
    ngx_str_t rce_unix_shell_expression_pattern;
    ngx_str_t rce_windows_for_if_command_pattern;
    ngx_str_t rce_unix_shell_code_pattern;
    ngx_str_t rce_shellshock_pattern;
    ngx_str_t rce_restricted_file_upload_pattern;
    ngx_str_t php_opening_closing_tag_pattern;
    ngx_str_t php_script_file_upload_pattern;
    ngx_str_t php_config_directive_pattern;
    ngx_str_t php_variables_pattern;
    ngx_str_t php_io_stream_pattern;
    ngx_str_t php_high_risk_function_name_pattern;
    ngx_str_t php_medium_risk_function_name_pattern;
    ngx_str_t php_high_risk_function_call_pattern;
    ngx_str_t php_serialized_object_injection_pattern;
    ngx_str_t php_variable_function_call_pattern;
    ngx_str_t php_wrapper_scheme_pattern;
    ngx_str_t nodejs_injection_pattern;

    // New XSS patterns
    ngx_str_t xss_libinjection_pattern;
    ngx_str_t xss_libinjection_101_pattern;
    ngx_str_t xss_script_tag_vector_pattern;
    ngx_str_t xss_event_handler_vector_pattern;
    ngx_str_t xss_attribute_vector_pattern;
    ngx_str_t xss_js_uri_vector_pattern;
    ngx_str_t xss_disallowed_html_attributes_pattern;
    ngx_str_t xss_html_injection_pattern;
    ngx_str_t xss_attribute_injection_pattern;
    ngx_str_t xss_node_validator_blocklist_pattern;
    ngx_str_t xss_using_stylesheets_pattern;
    ngx_str_t xss_using_vml_frames_pattern;
    ngx_str_t xss_obfuscated_javascript_pattern;
    ngx_str_t xss_obfuscated_vbscript_pattern;
    ngx_str_t xss_using_embed_tag_pattern;
    ngx_str_t xss_using_import_attribute_pattern;
    ngx_str_t xss_ie_filters_pattern;
    ngx_str_t xss_using_meta_tag_pattern;
    ngx_str_t xss_using_link_href_pattern;
    ngx_str_t xss_using_base_tag_pattern;
    ngx_str_t xss_using_applet_tag_pattern;
    ngx_str_t xss_us_ascii_encoding_pattern;
    ngx_str_t xss_html_tag_handler_pattern;
    ngx_str_t xss_ie_filters_320_pattern;
    ngx_str_t xss_ie_filters_330_pattern;
    ngx_str_t xss_ie_filters_340_pattern;
    ngx_str_t xss_utf7_encoding_pattern;
    ngx_str_t xss_js_obfuscation_pattern;
    ngx_str_t xss_js_global_variable_pattern;
    ngx_str_t xss_angularjs_template_injection_pattern;

    // SQL Injection Patterns
    ngx_str_t sqli_benchmark_sleep_pattern;
    ngx_str_t sqli_libinjection_pattern;
    ngx_str_t sqli_common_injection_testing_pattern;
    ngx_str_t sqli_operator_pattern;
    ngx_str_t sqli_common_db_names_pattern;
    ngx_str_t sqli_blind_sqli_testing_pattern;
    ngx_str_t sqli_authentication_bypass_1_pattern;
    ngx_str_t sqli_mssql_code_execution_pattern;
    ngx_str_t sqli_mysql_comment_obfuscation_pattern;
    ngx_str_t sqli_chained_injection_1_pattern;
    ngx_str_t sqli_integer_overflow_pattern;
    ngx_str_t sqli_conditional_injection_pattern;
    ngx_str_t sqli_mysql_charset_switch_pattern;
    ngx_str_t sqli_match_against_pattern;
    ngx_str_t sqli_authentication_bypass_2_pattern;
    ngx_str_t sqli_basic_injection_pattern;
    ngx_str_t sqli_postgres_sleep_pattern;
    ngx_str_t sqli_mongodb_injection_pattern;
    ngx_str_t sqli_mysql_comment_condition_pattern;
    ngx_str_t sqli_chained_injection_2_pattern;
    ngx_str_t sqli_mysql_postgres_function_pattern;
    ngx_str_t sqli_classic_injection_1_pattern;
    ngx_str_t sqli_authentication_bypass_3_pattern;
    ngx_str_t sqli_mysql_udf_injection_pattern;
    ngx_str_t sqli_concatenated_injection_pattern;
    ngx_str_t sqli_keyword_alter_union_pattern;
    ngx_str_t sqli_classic_injection_2_pattern;
    ngx_str_t sqli_attack_pattern;
    ngx_str_t sqli_restricted_character_pattern;
    ngx_str_t sqli_comment_sequence_pattern;
    ngx_str_t sqli_hex_encoding_pattern;
    ngx_str_t sqli_meta_character_pattern;
    ngx_str_t sqli_bypass_ticks_pattern;
    ngx_str_t sqli_mysql_inline_comment_pattern;

    ngx_int_t session_ttl;
    ngx_flag_t log_decisions;
    ngx_int_t max_requests_per_minute;
    ngx_int_t block_duration;

    ngx_str_t rce_windows_powershell_pattern;
    ngx_str_t rce_windows_for_if_pattern;
    ngx_str_t restricted_file_upload_pattern;
    ngx_str_t rce_direct_unix_command_pattern;

    // New MS-ThreatIntel-AppSec patterns
    ngx_str_t path_traversal_evasion_header_pattern;
    ngx_str_t path_traversal_evasion_body_pattern;

    // New MS-ThreatIntel-SQLI patterns
    ngx_str_t sql_injection_common_testing_pattern;
    ngx_str_t sql_injection_comment_sequence_pattern;
    ngx_str_t sql_injection_attack_pattern;
    ngx_str_t sql_authentication_bypass_pattern;

} ngx_http_waf_loc_conf_t;

typedef struct
{
    ngx_flag_t processed;
    std::string request_id; // Store the request ID here
} ngx_http_waf_request_ctx_t;

extern unsigned char key[32];
extern unsigned char iv[16];
extern std::unordered_map<std::string, std::chrono::steady_clock::time_point> blocked_ips;
extern std::unordered_map<std::string, std::pair<int, std::chrono::steady_clock::time_point>> rate_limit_map;
extern std::mutex rate_limit_mutex;

void generate_key_and_iv();
std::string encrypt_session_value(const std::string &plaintext);
std::string decrypt_session_value(const std::string &ciphertext);
std::string generate_session_id(const std::string &client_ip, const std::string &user_agent, const std::string &uri, const std::string &geo_location, int ttl);
bool is_sql_injection(const std::string &input, const std::regex &pattern);
bool is_xss(const std::string &input, const std::regex &pattern);
bool is_file_inclusion(const std::string &input, const std::regex &pattern);
bool is_command_injection(const std::string &input, const std::regex &pattern);
bool is_directory_traversal(const std::string &input, const std::regex &pattern);
bool is_parameter_tampering(const std::string &input, const std::regex &pattern);
bool is_protocol_anomaly(const std::string &input, const std::regex &pattern);
bool is_malicious_user_agent(const std::string &input, const std::regex &pattern);
bool is_brute_force(ngx_http_request_t *r, const std::string &ip);
bool is_session_valid(ngx_http_request_t *r, std::string &session_id, int ttl);
bool set_session_cookie(ngx_http_request_t *r, const std::string &session_id);
std::string get_pattern_from_conf(ngx_http_request_t *r, const char *pattern_name);
std::string get_geo_location(const std::string &ip, const char *db_path, ngx_http_request_t *r);
std::string create_session_value(const std::string &ip, const std::string &user_agent, const std::string &uri, const std::string &db_path, ngx_http_request_t *r);
bool check_or_create_session(ngx_http_request_t *r, std::string &session_value, const std::string &db_path);
void block_ip(const std::string &ip);
bool is_blocked_ip(ngx_http_request_t *r, const std::string &ip);
ngx_int_t ngx_http_waf_handler(ngx_http_request_t *r);
void ngx_waf_log_access(ngx_http_request_t *r, const char *message);
void *ngx_http_waf_create_loc_conf(ngx_conf_t *cf);
char *ngx_http_waf_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
char *ngx_http_waf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

// Module directives
extern ngx_command_t ngx_http_waf_commands[];

// Module context
extern ngx_http_module_t ngx_http_waf_module_ctx;

// Module definition
extern ngx_module_t ngx_http_waf_module;

ngx_command_t ngx_http_waf_commands[] = {
    {ngx_string("clrh_waf_handler"),
     NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS,
     ngx_http_waf,
     NGX_HTTP_LOC_CONF_OFFSET,
     0,
     NULL},
    {ngx_string("geoip_db_path"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, geoip_db_path),
     NULL},
    // Add the new directives here
    {ngx_string("ldap_injection_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, ldap_injection_pattern),
     NULL},
    {ngx_string("path_traversal_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, path_traversal_pattern),
     NULL},
    {ngx_string("os_file_access_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, os_file_access_pattern),
     NULL},
    {ngx_string("restricted_file_access_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, restricted_file_access_pattern),
     NULL},
    {ngx_string("rfi_ip_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, rfi_ip_pattern),
     NULL},
    {ngx_string("rfi_common_param_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, rfi_common_param_pattern),
     NULL},
    {ngx_string("rfi_trailing_question_mark_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, rfi_trailing_question_mark_pattern),
     NULL},
    {ngx_string("rfi_off_domain_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, rfi_off_domain_pattern),
     NULL},
    {ngx_string("rce_unix_command_injection_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, rce_unix_command_injection_pattern),
     NULL},
    {ngx_string("rce_windows_command_injection_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, rce_windows_command_injection_pattern),
     NULL},
    {ngx_string("rce_windows_powershell_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, rce_windows_powershell_pattern),
     NULL},
    {ngx_string("rce_unix_shell_expression_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, rce_unix_shell_expression_pattern),
     NULL},
    {ngx_string("rce_windows_for_if_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, rce_windows_for_if_pattern),
     NULL},
    {ngx_string("rce_unix_shell_code_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, rce_unix_shell_code_pattern),
     NULL},
    {ngx_string("rce_shellshock_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, rce_shellshock_pattern),
     NULL},
    {ngx_string("restricted_file_upload_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, restricted_file_upload_pattern),
     NULL},
    {ngx_string("php_opening_closing_tag_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, php_opening_closing_tag_pattern),
     NULL},
    {ngx_string("php_script_file_upload_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, php_script_file_upload_pattern),
     NULL},
    {ngx_string("php_config_directive_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, php_config_directive_pattern),
     NULL},
    {ngx_string("php_variables_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, php_variables_pattern),
     NULL},
    {ngx_string("php_io_stream_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, php_io_stream_pattern),
     NULL},
    {ngx_string("php_high_risk_function_name_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, php_high_risk_function_name_pattern),
     NULL},
    {ngx_string("php_medium_risk_function_name_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, php_medium_risk_function_name_pattern),
     NULL},
    {ngx_string("php_high_risk_function_call_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, php_high_risk_function_call_pattern),
     NULL},
    {ngx_string("php_serialized_object_injection_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, php_serialized_object_injection_pattern),
     NULL},
    {ngx_string("php_variable_function_call_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, php_variable_function_call_pattern),
     NULL},
    {ngx_string("php_wrapper_scheme_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, php_wrapper_scheme_pattern),
     NULL},
    {ngx_string("nodejs_injection_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, nodejs_injection_pattern),
     NULL},

    // XSS directives
    {ngx_string("xss_libinjection_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, xss_libinjection_pattern),
     NULL},
    {ngx_string("xss_libinjection_101_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, xss_libinjection_101_pattern),
     NULL},
    {ngx_string("xss_script_tag_vector_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, xss_script_tag_vector_pattern),
     NULL},
    {ngx_string("xss_event_handler_vector_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, xss_event_handler_vector_pattern),
     NULL},
    {ngx_string("xss_attribute_vector_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, xss_attribute_vector_pattern),
     NULL},
    {ngx_string("xss_js_uri_vector_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, xss_js_uri_vector_pattern),
     NULL},
    {ngx_string("xss_disallowed_html_attributes_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, xss_disallowed_html_attributes_pattern),
     NULL},
    {ngx_string("xss_html_injection_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, xss_html_injection_pattern),
     NULL},
    {ngx_string("xss_attribute_injection_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, xss_attribute_injection_pattern),
     NULL},
    {ngx_string("xss_node_validator_blocklist_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, xss_node_validator_blocklist_pattern),
     NULL},
    {ngx_string("xss_using_stylesheets_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, xss_using_stylesheets_pattern),
     NULL},
    {ngx_string("xss_using_vml_frames_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, xss_using_vml_frames_pattern),
     NULL},
    {ngx_string("xss_obfuscated_javascript_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, xss_obfuscated_javascript_pattern),
     NULL},
    {ngx_string("xss_obfuscated_vbscript_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, xss_obfuscated_vbscript_pattern),
     NULL},
    {ngx_string("xss_using_embed_tag_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, xss_using_embed_tag_pattern),
     NULL},
    {ngx_string("xss_using_import_attribute_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, xss_using_import_attribute_pattern),
     NULL},
    {ngx_string("xss_ie_filters_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, xss_ie_filters_pattern),
     NULL},
    {ngx_string("xss_using_meta_tag_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, xss_using_meta_tag_pattern),
     NULL},
    {ngx_string("xss_using_link_href_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, xss_using_link_href_pattern),
     NULL},
    {ngx_string("xss_using_base_tag_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, xss_using_base_tag_pattern),
     NULL},
    {ngx_string("xss_using_applet_tag_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, xss_using_applet_tag_pattern),
     NULL},
    {ngx_string("xss_us_ascii_encoding_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, xss_us_ascii_encoding_pattern),
     NULL},
    {ngx_string("xss_html_tag_handler_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, xss_html_tag_handler_pattern),
     NULL},
    {ngx_string("xss_ie_filters_320_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, xss_ie_filters_320_pattern),
     NULL},
    {ngx_string("xss_ie_filters_330_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, xss_ie_filters_330_pattern),
     NULL},
    {ngx_string("xss_ie_filters_340_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, xss_ie_filters_340_pattern),
     NULL},
    {ngx_string("xss_utf7_encoding_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, xss_utf7_encoding_pattern),
     NULL},
    {ngx_string("xss_js_obfuscation_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, xss_js_obfuscation_pattern),
     NULL},
    {ngx_string("xss_js_global_variable_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, xss_js_global_variable_pattern),
     NULL},
    {ngx_string("xss_angularjs_template_injection_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, xss_angularjs_template_injection_pattern),
     NULL},
    // Existing directives
    {ngx_string("sql_injection_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, sql_injection_pattern),
     NULL},
    {ngx_string("xss_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, xss_pattern),
     NULL},
    {ngx_string("file_inclusion_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, file_inclusion_pattern),
     NULL},
    {ngx_string("command_injection_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, command_injection_pattern),
     NULL},
    {ngx_string("directory_traversal_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, directory_traversal_pattern),
     NULL},
    {ngx_string("parameter_tampering_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, parameter_tampering_pattern),
     NULL},
    {ngx_string("protocol_anomaly_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, protocol_anomaly_pattern),
     NULL},
    {ngx_string("malicious_user_agent_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, malicious_user_agent_pattern),
     NULL},
    {ngx_string("url_encoding_abuse_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, url_encoding_abuse_pattern),
     NULL},
    {ngx_string("invalid_request_line_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, invalid_request_line_pattern),
     NULL},
    {ngx_string("multipart_bypass_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, multipart_bypass_pattern),
     NULL},
    {ngx_string("invalid_range_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, invalid_range_pattern),
     NULL},
    {ngx_string("multiple_url_encoding_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, multiple_url_encoding_pattern),
     NULL},
    {ngx_string("unicode_abuse_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, unicode_abuse_pattern),
     NULL},
    {ngx_string("invalid_content_type_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, invalid_content_type_pattern),
     NULL},
    {ngx_string("invalid_charset_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, invalid_charset_pattern),
     NULL},
    {ngx_string("backup_file_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, backup_file_pattern),
     NULL},
    {ngx_string("session_ttl"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_num_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, session_ttl),
     NULL},
    {ngx_string("log_decisions"),
     NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
     ngx_conf_set_flag_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, log_decisions),
     NULL},
    {ngx_string("max_requests_per_minute"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_num_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, max_requests_per_minute),
     NULL},
    {ngx_string("block_duration"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_num_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, block_duration),
     NULL},
    // Add the new SQL injection pattern directives here
    {ngx_string("sqli_libinjection_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, sqli_libinjection_pattern),
     NULL},
    {ngx_string("sqli_common_injection_testing_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, sqli_common_injection_testing_pattern),
     NULL},
    {ngx_string("sqli_operator_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, sqli_operator_pattern),
     NULL},
    {ngx_string("sqli_common_db_names_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, sqli_common_db_names_pattern),
     NULL},
    {ngx_string("sqli_blind_sqli_testing_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, sqli_blind_sqli_testing_pattern),
     NULL},
    {ngx_string("sqli_authentication_bypass_1_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, sqli_authentication_bypass_1_pattern),
     NULL},
    {ngx_string("sqli_mssql_code_execution_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, sqli_mssql_code_execution_pattern),
     NULL},
    {ngx_string("sqli_mysql_comment_obfuscation_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, sqli_mysql_comment_obfuscation_pattern),
     NULL},
    {ngx_string("sqli_chained_injection_1_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, sqli_chained_injection_1_pattern),
     NULL},
    {ngx_string("sqli_integer_overflow_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, sqli_integer_overflow_pattern),
     NULL},
    {ngx_string("sqli_conditional_injection_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, sqli_conditional_injection_pattern),
     NULL},
    {ngx_string("sqli_mysql_charset_switch_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, sqli_mysql_charset_switch_pattern),
     NULL},
    {ngx_string("sqli_match_against_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, sqli_match_against_pattern),
     NULL},
    {ngx_string("sqli_authentication_bypass_2_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, sqli_authentication_bypass_2_pattern),
     NULL},
    {ngx_string("sqli_basic_injection_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, sqli_basic_injection_pattern),
     NULL},
    {ngx_string("sqli_postgres_sleep_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, sqli_postgres_sleep_pattern),
     NULL},
    {ngx_string("sqli_mongodb_injection_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, sqli_mongodb_injection_pattern),
     NULL},
    {ngx_string("sqli_mysql_comment_condition_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, sqli_mysql_comment_condition_pattern),
     NULL},
    {ngx_string("sqli_chained_injection_2_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, sqli_chained_injection_2_pattern),
     NULL},
    {ngx_string("sqli_mysql_postgres_function_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, sqli_mysql_postgres_function_pattern),
     NULL},
    {ngx_string("sqli_classic_injection_1_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, sqli_classic_injection_1_pattern),
     NULL},
    {ngx_string("sqli_authentication_bypass_3_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, sqli_authentication_bypass_3_pattern),
     NULL},
    {ngx_string("sqli_mysql_udf_injection_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, sqli_mysql_udf_injection_pattern),
     NULL},
    {ngx_string("sqli_concatenated_injection_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, sqli_concatenated_injection_pattern),
     NULL},
    {ngx_string("sqli_keyword_alter_union_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, sqli_keyword_alter_union_pattern),
     NULL},
    {ngx_string("sqli_classic_injection_2_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, sqli_classic_injection_2_pattern),
     NULL},
    {ngx_string("sqli_attack_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, sqli_attack_pattern),
     NULL},
    {ngx_string("sqli_restricted_character_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, sqli_restricted_character_pattern),
     NULL},
    {ngx_string("sqli_comment_sequence_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, sqli_comment_sequence_pattern),
     NULL},
    {ngx_string("sqli_hex_encoding_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, sqli_hex_encoding_pattern),
     NULL},
    {ngx_string("sqli_meta_character_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, sqli_meta_character_pattern),
     NULL},
    {ngx_string("sqli_bypass_ticks_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, sqli_bypass_ticks_pattern),
     NULL},
    {ngx_string("sqli_benchmark_sleep_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, sqli_benchmark_sleep_pattern),
     NULL},
    {ngx_string("sqli_mysql_inline_comment_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, sqli_mysql_inline_comment_pattern),
     NULL},
    {ngx_string("rce_direct_unix_command_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, rce_direct_unix_command_pattern),
     NULL},
    {ngx_string("enable_sql_injection"),
     NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
     ngx_conf_set_flag_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, enable_sql_injection),
     NULL},
    {ngx_string("enable_xss"),
     NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
     ngx_conf_set_flag_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, enable_xss),
     NULL},
    {ngx_string("enable_protocol_attack"),
     NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
     ngx_conf_set_flag_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, enable_protocol_attack),
     NULL},
    {ngx_string("enable_rce_php_node"),
     NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
     ngx_conf_set_flag_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, enable_rce_php_node),
     NULL},
    {ngx_string("enable_general_rules"),
     NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
     ngx_conf_set_flag_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, enable_general_rules),
     NULL},
    {ngx_string("enable_session_rules"),
     NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
     ngx_conf_set_flag_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, enable_session_rules),
     NULL},
    {ngx_string("path_traversal_evasion_header_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, path_traversal_evasion_header_pattern),
     NULL},

    {ngx_string("path_traversal_evasion_body_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, path_traversal_evasion_body_pattern),
     NULL},

    {ngx_string("sql_injection_common_testing_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, sql_injection_common_testing_pattern),
     NULL},

    {ngx_string("sql_injection_comment_sequence_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, sql_injection_comment_sequence_pattern),
     NULL},

    {ngx_string("sql_injection_attack_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, sql_injection_attack_pattern),
     NULL},

    {ngx_string("sql_authentication_bypass_pattern"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_waf_loc_conf_t, sql_authentication_bypass_pattern),
     NULL},

    ngx_null_command};

#endif // NGX_HTTP_WAF_MODULE_H
