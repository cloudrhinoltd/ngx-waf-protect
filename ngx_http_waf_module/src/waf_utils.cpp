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

extern "C"
{
#include <ngx_core.h>
#include <ngx_http.h>
}

#include <unordered_map>
#include <string>
#include <regex>
#include "../include/ngx_http_waf_module.h"

// Forward declaration
std::string get_pattern_from_conf_loc(ngx_http_waf_loc_conf_t *wlcf, const char *pattern_name, bool first);

// Function to retrieve patterns from the configuration based on ngx_http_waf_loc_conf_t
std::string get_pattern_from_conf_loc(ngx_http_waf_loc_conf_t *wlcf, const char *pattern_name, bool first = true)
{
    std::unordered_map<std::string, std::pair<ngx_str_t, std::string>> pattern_map = {
        {"xss_pattern", {wlcf->xss_pattern, "(<script.*?>.*?</script.*?>|onload=.*?|javascript:|alert\()"}},
        {"file_inclusion_pattern", {wlcf->file_inclusion_pattern, "(http://|https://|ftp://|../../|/etc/passwd|C:\\windows)"}},
        {"command_injection_pattern", {wlcf->command_injection_pattern, "(;|&&|\||wget|curl|system|exec|sh|bash)"}},
        {"directory_traversal_pattern", {wlcf->directory_traversal_pattern, "(../|..\\|/etc/passwd|/etc/shadow)"}},
        {"parameter_tampering_pattern", {wlcf->parameter_tampering_pattern, "(unusual|suspicious|manipulated)"}},
        {"protocol_anomaly_pattern", {wlcf->protocol_anomaly_pattern, "(invalid|unusual|oversized|abnormal)"}},
        {"malicious_user_agent_pattern", {wlcf->malicious_user_agent_pattern, "(badbot|evilbot|scrapy|crawler|scanner)"}},
        {"url_encoding_abuse_pattern", {wlcf->url_encoding_abuse_pattern, ".*%[0-9a-fA-F]{2}.*"}},
        {"invalid_request_line_pattern", {wlcf->invalid_request_line_pattern, ".*\r\n.*"}},
        {"multipart_bypass_pattern", {wlcf->multipart_bypass_pattern, ".*multipart.*"}},
        {"invalid_range_pattern", {wlcf->invalid_range_pattern, ".*bytes=0-.*"}},
        {"multiple_url_encoding_pattern", {wlcf->multiple_url_encoding_pattern, ".*(%25.*%25).*"}},
        {"unicode_abuse_pattern", {wlcf->unicode_abuse_pattern, ".*[uU][0-9a-fA-F]{4}.*"}},
        {"invalid_content_type_pattern", {wlcf->invalid_content_type_pattern, "^(?!application/json$|text/html$|application/xml$|application/x-www-form-urlencoded$|multipart/form-data$|text/plain$).*$"}},
        {"invalid_charset_pattern", {wlcf->invalid_charset_pattern, "charset\s*=\s*(?!utf-8|iso-8859-1|us-ascii|windows-1252|shift_jis|euc-jp|gb2312|big5|iso-8859-2|iso-8859-15)([^;]+)"}},
        {"backup_file_pattern", {wlcf->backup_file_pattern, ".*\.bak.*"}},
        {"ldap_injection_pattern", {wlcf->ldap_injection_pattern, "(&&|\|\||\(\)|\*|\))"}},
        {"path_traversal_pattern", {wlcf->path_traversal_pattern, "(/\.\./)"}},
        {"os_file_access_pattern", {wlcf->os_file_access_pattern, "(/etc/passwd|/etc/shadow|/etc/group)"}},
        {"restricted_file_access_pattern", {wlcf->restricted_file_access_pattern, "(\.htaccess|\.htpasswd|\.git|\.svn|/WEB-INF/)"}},
        {"rfi_ip_pattern", {wlcf->rfi_ip_pattern, "((http|https|ftp|ftps)://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"}},
        {"rfi_common_param_pattern", {wlcf->rfi_common_param_pattern, "(\burl\b|\bfile\b|\bpath\b|\bpage\b=)"}},
        {"rfi_trailing_question_mark_pattern", {wlcf->rfi_trailing_question_mark_pattern, "(\?.*$)"}},
        {"rfi_off_domain_pattern", {wlcf->rfi_off_domain_pattern, "((http|https|ftp|ftps)://)"}},

        // RCE Patterns
        {"rce_unix_command_injection_pattern", {wlcf->rce_unix_command_injection_pattern, "(\b(cat|ls|ps|netstat|whoami|id)\b|;|&&|\|)"}},
        {"rce_windows_command_injection_pattern", {wlcf->rce_windows_command_injection_pattern, "(\b(cmd|powershell|net user|net localgroup)\b|;|&&|\|)"}},
        {"rce_windows_powershell_pattern", {wlcf->rce_windows_powershell_pattern, "(\bpowershell\b)"}},
        {"rce_unix_shell_expression_pattern", {wlcf->rce_unix_shell_expression_pattern, "($\(.+\)|`.+`)"}},
        {"rce_windows_for_if_pattern", {wlcf->rce_windows_for_if_pattern, "(\bfor\b|\bif\b)"}},
        {"rce_direct_unix_command_pattern", {wlcf->rce_direct_unix_command_pattern, "(\bexec\b|\bsystem\b)"}},
        {"rce_unix_shell_code_pattern", {wlcf->rce_unix_shell_code_pattern, "(\b/bin/sh\b|\b/bin/bash\b)"}},
        {"rce_shellshock_pattern", {wlcf->rce_shellshock_pattern, "(\(\)\s*\{)"}},
        {"restricted_file_upload_pattern", {wlcf->restricted_file_upload_pattern, "(\.php|\.asp|\.jsp)"}},

        // PHP Injection Patterns
        {"php_opening_closing_tag_pattern", {wlcf->php_opening_closing_tag_pattern, "(<\?(php)?|\?>)"}},
        {"php_script_file_upload_pattern", {wlcf->php_script_file_upload_pattern, "(\.(php|phtml|phar)$)"}},
        {"php_config_directive_pattern", {wlcf->php_config_directive_pattern, "(\b(ini_set|ini_get|dl|disable_functions|disable_classes)\b)"}},
        {"php_variables_pattern", {wlcf->php_variables_pattern, "($_(GET|POST|COOKIE|REQUEST|FILES|ENV|SERVER|SESSION|GLOBALS)\b)"}},
        {"php_io_stream_pattern", {wlcf->php_io_stream_pattern, "(php://input|data://text/plain|php://filter)"}},
        {"php_high_risk_function_name_pattern", {wlcf->php_high_risk_function_name_pattern, "(\b(exec|shell_exec|system|passthru|popen|proc_open)\b)"}},
        {"php_medium_risk_function_name_pattern", {wlcf->php_medium_risk_function_name_pattern, "(\b(eval|assert|preg_replace|create_function|include|require)\b)"}},
        {"php_high_risk_function_call_pattern", {wlcf->php_high_risk_function_call_pattern, "(\b(call_user_func|call_user_func_array)\b)"}},
        {"php_serialized_object_injection_pattern", {wlcf->php_serialized_object_injection_pattern, "(O:\d+:\"[^\"]+\":\d+:\{[^\}]+\})"}},
        {"php_variable_function_call_pattern", {wlcf->php_variable_function_call_pattern, "(${.*?}\(.*?\))"}},
        {"php_wrapper_scheme_pattern", {wlcf->php_wrapper_scheme_pattern, "(data://text/plain;base64,)"}},

        // Node.js Injection Pattern
        {"nodejs_injection_pattern", {wlcf->nodejs_injection_pattern, "(require\(|child_process|fs\.|eval\()"}},

        // XSS Patterns
        {"xss_libinjection_pattern", {wlcf->xss_libinjection_pattern, "pattern_for_libinjection"}},
        {"xss_libinjection_101_pattern", {wlcf->xss_libinjection_101_pattern, "pattern_for_libinjection_101"}},
        {"xss_script_tag_vector_pattern", {wlcf->xss_script_tag_vector_pattern, "<script.*?>"}},
        {"xss_event_handler_vector_pattern", {wlcf->xss_event_handler_vector_pattern, "on(load|error|click|mouseover)="}},
        {"xss_attribute_vector_pattern", {wlcf->xss_attribute_vector_pattern, "style=.*expression"}},
        {"xss_js_uri_vector_pattern", {wlcf->xss_js_uri_vector_pattern, "javascript:"}},
        {"xss_disallowed_html_attributes_pattern", {wlcf->xss_disallowed_html_attributes_pattern, "srcdoc|srcset|formaction"}},
        {"xss_html_injection_pattern", {wlcf->xss_html_injection_pattern, "<.*?>"}},
        {"xss_attribute_injection_pattern", {wlcf->xss_attribute_injection_pattern, "=[\"'].*?[\"']"}},
        {"xss_node_validator_blocklist_pattern", {wlcf->xss_node_validator_blocklist_pattern, "alert|eval|execScript"}},
        {"xss_using_stylesheets_pattern", {wlcf->xss_using_stylesheets_pattern, "<style>.*</style>"}},
        {"xss_using_vml_frames_pattern", {wlcf->xss_using_vml_frames_pattern, "<xml>.*</xml>"}},
        {"xss_obfuscated_javascript_pattern", {wlcf->xss_obfuscated_javascript_pattern, "btoa|atob|fromCharCode"}},
        {"xss_obfuscated_vbscript_pattern", {wlcf->xss_obfuscated_vbscript_pattern, "vbscript:"}},
        {"xss_using_embed_tag_pattern", {wlcf->xss_using_embed_tag_pattern, "<embed.*?>"}},
        {"xss_using_import_attribute_pattern", {wlcf->xss_using_import_attribute_pattern, "import=.*"}},
        {"xss_ie_filters_pattern", {wlcf->xss_ie_filters_pattern, "expression|eval"}},
        {"xss_using_meta_tag_pattern", {wlcf->xss_using_meta_tag_pattern, "<meta.*?>"}},
        {"xss_using_link_href_pattern", {wlcf->xss_using_link_href_pattern, "<link.*?href="}},
        {"xss_using_base_tag_pattern", {wlcf->xss_using_base_tag_pattern, "<base.*?>"}},
        {"xss_using_applet_tag_pattern", {wlcf->xss_using_applet_tag_pattern, "<applet.*?>"}},
        {"xss_us_ascii_encoding_pattern", {wlcf->xss_us_ascii_encoding_pattern, "%u[0-9a-fA-F]{4}"}},
        {"xss_html_tag_handler_pattern", {wlcf->xss_html_tag_handler_pattern, "<.*?>"}},
        {"xss_ie_filters_320_pattern", {wlcf->xss_ie_filters_320_pattern, "src=.*?"}},
        {"xss_ie_filters_330_pattern", {wlcf->xss_ie_filters_330_pattern, "on.*?="}},
        {"xss_ie_filters_340_pattern", {wlcf->xss_ie_filters_340_pattern, "style=.*?"}},
        {"xss_utf7_encoding_pattern", {wlcf->xss_utf7_encoding_pattern, "\+ADw-"}},
        {"xss_js_obfuscation_pattern", {wlcf->xss_js_obfuscation_pattern, "fromCharCode|eval"}},
        {"xss_js_global_variable_pattern", {wlcf->xss_js_global_variable_pattern, "window\."}},
        {"xss_angularjs_template_injection_pattern", {wlcf->xss_angularjs_template_injection_pattern, "\{\{.*?\}\}"}},

        // SQL Injection Patterns
        {"sqli_mysql_comment_obfuscation_pattern", {wlcf->sqli_mysql_comment_obfuscation_pattern, "\/\*!.*?\*\/.*?(union|select|insert|update|delete|drop|alter|create|replace)"}},
        {"sqli_benchmark_sleep_pattern", {wlcf->sqli_benchmark_sleep_pattern, "(sleep\(\d+\)|benchmark\(\d+,)"}},
        {"sqli_operator_pattern", {wlcf->sqli_operator_pattern, "(=|<|>|!|\|\||&&|<>|>=|<=|!=|LIKE|BETWEEN|IS NULL|IS NOT NULL)"}},
        {"sql_injection_pattern", {wlcf->sql_injection_pattern, "(union.*select|select.*from|drop.*table|insert.*into|or.*=.*|--|;|exec|union|select|concat|information_schema)"}},
        {"sqli_libinjection_pattern", {wlcf->sqli_libinjection_pattern, "pattern_for_libinjection"}},
        {"sqli_common_injection_testing_pattern", {wlcf->sqli_common_injection_testing_pattern, "select.*from.*where"}},
        {"sqli_common_db_names_pattern", {wlcf->sqli_common_db_names_pattern, "(information_schema|mysql|pg_catalog)"}},
        {"sqli_blind_sqli_testing_pattern", {wlcf->sqli_blind_sqli_testing_pattern, "(sleep|benchmark)"}},
        {"sqli_authentication_bypass_1_pattern", {wlcf->sqli_authentication_bypass_1_pattern, "(or.*=.*|--|;|union.*select)"}},
        {"sqli_mssql_code_execution_pattern", {wlcf->sqli_mssql_code_execution_pattern, "exec.*xp_"}},
        {"sqli_chained_injection_1_pattern", {wlcf->sqli_chained_injection_1_pattern, "and.*select"}},
        {"sqli_integer_overflow_pattern", {wlcf->sqli_integer_overflow_pattern, "(\d{10,}|\d+\.\d+e\d+|0x[0-9a-fA-F]+)"}},
        {"sqli_conditional_injection_pattern", {wlcf->sqli_conditional_injection_pattern, "(case when|if\())"}},
        {"sqli_mysql_charset_switch_pattern", {wlcf->sqli_mysql_charset_switch_pattern, "charset=utf8"}},
        {"sqli_match_against_pattern", {wlcf->sqli_match_against_pattern, "match.*against"}},
        {"sqli_authentication_bypass_2_pattern", {wlcf->sqli_authentication_bypass_2_pattern, "admin'--"}},
        {"sqli_basic_injection_pattern", {wlcf->sqli_basic_injection_pattern, "(union.*select|select.*from|insert.*into|delete.*from|update.*set)"}},
        {"sqli_postgres_sleep_pattern", {wlcf->sqli_postgres_sleep_pattern, "pg_sleep"}},
        {"sqli_mongodb_injection_pattern", {wlcf->sqli_mongodb_injection_pattern, "db\.getCollection"}},
        {"sqli_mysql_comment_condition_pattern", {wlcf->sqli_mysql_comment_condition_pattern, "(--|\#|/\*|/\*/|;|')"}},
        {"sqli_chained_injection_2_pattern", {wlcf->sqli_chained_injection_2_pattern, "select.*and.*select"}},
        {"sqli_mysql_postgres_function_pattern", {wlcf->sqli_mysql_postgres_function_pattern, "(\(.*select.*\))"}},
        {"sqli_classic_injection_1_pattern", {wlcf->sqli_classic_injection_1_pattern, "or.*=.*"}},
        {"sqli_authentication_bypass_3_pattern", {wlcf->sqli_authentication_bypass_3_pattern, "or.*=.*--"}},
        {"sqli_mysql_udf_injection_pattern", {wlcf->sqli_mysql_udf_injection_pattern, "udf_"}},
        {"sqli_concatenated_injection_pattern", {wlcf->sqli_concatenated_injection_pattern, "concat.*select"}},
        {"sqli_keyword_alter_union_pattern", {wlcf->sqli_keyword_alter_union_pattern, "(alter|union)"}},
        {"sqli_classic_injection_2_pattern", {wlcf->sqli_classic_injection_2_pattern, "(select|insert|update|delete|drop|exec)"}},
        {"sqli_attack_pattern", {wlcf->sqli_attack_pattern, "(select|union|insert|drop|update|delete|exec)"}},
        {"sqli_restricted_character_pattern", {wlcf->sqli_restricted_character_pattern, "[;\"']"}},
        {"sqli_comment_sequence_pattern", {wlcf->sqli_comment_sequence_pattern, "--"}},
        {"sqli_hex_encoding_pattern", {wlcf->sqli_hex_encoding_pattern, "0x[0-9a-fA-F]+"}},
        {"sqli_meta_character_pattern", {wlcf->sqli_meta_character_pattern, "\W"}},
        {"sqli_mysql_inline_comment_pattern", {wlcf->sqli_mysql_inline_comment_pattern, "--.*$"}},
        {"sqli_bypass_ticks_pattern", {wlcf->sqli_bypass_ticks_pattern, "`|'"}},

        // MS-ThreatIntel-AppSec patterns
        {"path_traversal_evasion_header_pattern", {wlcf->path_traversal_evasion_header_pattern, "(/\.\././\.\./)"}},
        {"path_traversal_evasion_body_pattern", {wlcf->path_traversal_evasion_body_pattern, "(/\.\././\.\./)"}},

        // MS-ThreatIntel-SQLI patterns
        {"sql_injection_common_testing_pattern", {wlcf->sql_injection_common_testing_pattern, "(union.*select|select.*from|drop.*table|insert.*into|or.*=.*|--|;|exec|union|select|concat|information_schema)"}},
        {"sql_injection_comment_sequence_pattern", {wlcf->sql_injection_comment_sequence_pattern, "(--|/\*|\*/|#)"}},
        {"sql_injection_attack_pattern", {wlcf->sql_injection_attack_pattern, "(union.*select|select.*from|drop.*table|insert.*into|or.*=.*|--|;|exec|union|select|concat|information_schema)"}},
        {"sql_authentication_bypass_pattern", {wlcf->sql_authentication_bypass_pattern, "(admin'--|or.*=.*|--|;|union.*select)"}}};

    auto it = pattern_map.find(pattern_name);
    if (it != pattern_map.end())
    {
        if (it->second.first.data != nullptr)
        {
            std::string custom_pattern((char *)it->second.first.data, it->second.first.len);
            if (!custom_pattern.empty())
            {
                return custom_pattern;
            }
        }
        std::string pattern = it->second.second;
        return pattern;
    }

    return "";
}

std::string get_pattern_from_conf(ngx_http_request_t *r, const char *pattern_name)
{
    ngx_http_waf_loc_conf_t *wlcf;
    wlcf = (ngx_http_waf_loc_conf_t *)ngx_http_get_module_loc_conf(r, ngx_http_waf_module);

    std::string pattern = get_pattern_from_conf_loc(wlcf, pattern_name);
    if (pattern.empty())
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Pattern %s not found or empty in configuration", pattern_name);
    }
    return pattern;
}

// Function to log and reject a request with a custom message in the response
bool log_and_reject(ngx_http_request_t *r, const char *message, const char *rule_id)
{
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "WAF - RuleId %s: %s", rule_id, message);

    // Set the status code to 403 Forbidden
    r->headers_out.status = NGX_HTTP_FORBIDDEN;

    // Prepare the response body with the message
    std::string response_body = "403 Forbidden
";
    response_body += "WAF - RuleId: ";
    response_body += rule_id;
    response_body += "
";
    response_body += message;
    response_body += "
";

    // Set the content length
    r->headers_out.content_length_n = response_body.size();

    // Allocate a buffer for the response body
    ngx_buf_t *b = ngx_create_temp_buf(r->pool, response_body.size());
    if (b == NULL)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    // Copy the response body into the buffer
    ngx_memcpy(b->pos, response_body.c_str(), response_body.size());
    b->last = b->pos + response_body.size();

    // Set the buffer flags
    b->last_buf = 1;

    // Create a chain link for the buffer
    ngx_chain_t out;
    out.buf = b;
    out.next = NULL;

    // Set the content type of the response
    r->headers_out.content_type.len = sizeof("text/plain") - 1;
    r->headers_out.content_type.data = (u_char *)"text/plain";

    // Send the headers
    ngx_http_send_header(r);

    // Send the body
    return ngx_http_output_filter(r, &out);
}

// Overloaded function to handle std::string
void ngx_waf_log_access(ngx_http_request_t *r, const std::string &message)
{
    // Convert std::string to const char* and call the other version
    ngx_waf_log_access(r, message.c_str());
}

void ngx_waf_log_access(ngx_http_request_t *r, const char *message)
{
    ngx_http_waf_request_ctx_t *ctx = (ngx_http_waf_request_ctx_t *)ngx_http_get_module_ctx(r, ngx_http_waf_module);
    std::string log_message;

    if (ctx && !ctx->request_id.empty())
    {
        log_message = "[Request ID: " + ctx->request_id + "] " + message;
    }
    else
    {
        log_message = message;
    }

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "%s", log_message.c_str());
}

// Function to compile and log regex with custom flags
bool compile_and_log_regex(ngx_http_request_t *r, const std::string &pattern_str, const std::string &rule_name, std::regex &out_pattern, std::regex_constants::syntax_option_type flags)
{
    ngx_waf_log_access(r, ("Compiling regex for " + rule_name + ": " + pattern_str).c_str());
    try
    {
        // Compile the regex pattern with the provided flags
        out_pattern = std::regex(pattern_str, flags);
        ngx_waf_log_access(r, ("Regex compiled successfully for " + rule_name).c_str());
        return true;
    }
    catch (const std::regex_error &e)
    {
        ngx_waf_log_access(r, ("Regex error in " + rule_name + ": " + std::string(e.what())).c_str());
        return false;
    }
}
