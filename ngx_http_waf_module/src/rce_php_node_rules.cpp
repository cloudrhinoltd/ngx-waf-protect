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

// Function definitions for each RCE, PHP, and Node.js attack
// Function to check Remote Command Execution: Unix Command Injection (RuleId: 932100)
bool check_rce_unix_command_injection(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_rce_unix_command_injection");
    std::string query(reinterpret_cast<const char*>(r->args.data), r->args.len);

    std::string rce_pattern = get_pattern_from_conf(r, "rce_unix_command_injection_pattern");
    ngx_waf_log_access(r, ("RCE Unix Command Injection Pattern: " + rce_pattern).c_str());

    try {
        std::regex rce_regex(rce_pattern);
        ngx_waf_log_access(r, "Regex compiled successfully");

        if (std::regex_search(query, rce_regex)) {
            ngx_waf_log_access(r, "Exiting check_rce_unix_command_injection with attack detected");
            return log_and_reject(r, "Possible Remote Command Execution: Unix Command Injection", "932100");
        }
    } catch (const std::regex_error &e) {
        ngx_waf_log_access(r, ("Regex error: " + std::string(e.what())).c_str());
    } catch (const std::exception &e) {
        ngx_waf_log_access(r, ("Exception: " + std::string(e.what())).c_str());
    }

    ngx_waf_log_access(r, "Exiting check_rce_unix_command_injection with no attack detected");
    return false;
}

// Function to check Remote Command Execution: Windows Command Injection (RuleId: 932110)
bool check_rce_windows_command_injection(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_rce_windows_command_injection");
    std::string query(reinterpret_cast<const char*>(r->args.data), r->args.len);

    std::string rce_pattern = get_pattern_from_conf(r, "rce_windows_command_injection_pattern");
    ngx_waf_log_access(r, ("RCE Windows Command Injection Pattern: " + rce_pattern).c_str());

    try {
        std::regex rce_regex(rce_pattern);
        ngx_waf_log_access(r, "Regex compiled successfully");

        if (std::regex_search(query, rce_regex)) {
            ngx_waf_log_access(r, "Exiting check_rce_windows_command_injection with attack detected");
            return log_and_reject(r, "Possible Remote Command Execution: Windows Command Injection", "932110");
        }
    } catch (const std::regex_error &e) {
        ngx_waf_log_access(r, ("Regex error: " + std::string(e.what())).c_str());
    } catch (const std::exception &e) {
        ngx_waf_log_access(r, ("Exception: " + std::string(e.what())).c_str());
    }

    ngx_waf_log_access(r, "Exiting check_rce_windows_command_injection with no attack detected");
    return false;
}

// Function to check Remote Command Execution: Windows PowerShell Command Found (RuleId: 932120)
bool check_rce_windows_powershell(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_rce_windows_powershell");
    std::string query(reinterpret_cast<const char*>(r->args.data), r->args.len);

    std::string rce_pattern = get_pattern_from_conf(r, "rce_windows_powershell_pattern");
    ngx_waf_log_access(r, ("RCE Windows PowerShell Pattern: " + rce_pattern).c_str());

    try {
        std::regex rce_regex(rce_pattern);
        ngx_waf_log_access(r, "Regex compiled successfully");

        if (std::regex_search(query, rce_regex)) {
            ngx_waf_log_access(r, "Exiting check_rce_windows_powershell with attack detected");
            return log_and_reject(r, "Possible Remote Command Execution: Windows PowerShell Command Found", "932120");
        }
    } catch (const std::regex_error &e) {
        ngx_waf_log_access(r, ("Regex error: " + std::string(e.what())).c_str());
    } catch (const std::exception &e) {
        ngx_waf_log_access(r, ("Exception: " + std::string(e.what())).c_str());
    }

    ngx_waf_log_access(r, "Exiting check_rce_windows_powershell with no attack detected");
    return false;
}

// Function to check Remote Command Execution: Unix Shell Expression or Confluence Vulnerability (CVE-2022-26134) Found (RuleId: 932130)
bool check_rce_unix_shell_expression(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_rce_unix_shell_expression");
    std::string query(reinterpret_cast<const char*>(r->args.data), r->args.len);

    std::string rce_pattern = get_pattern_from_conf(r, "rce_unix_shell_expression_pattern");
    ngx_waf_log_access(r, ("RCE Unix Shell Expression Pattern: " + rce_pattern).c_str());

    try {
        std::regex rce_regex(rce_pattern);
        ngx_waf_log_access(r, "Regex compiled successfully");

        if (std::regex_search(query, rce_regex)) {
            ngx_waf_log_access(r, "Exiting check_rce_unix_shell_expression with attack detected");
            return log_and_reject(r, "Possible Remote Command Execution: Unix Shell Expression or Confluence Vulnerability (CVE-2022-26134) Found", "932130");
        }
    } catch (const std::regex_error &e) {
        ngx_waf_log_access(r, ("Regex error: " + std::string(e.what())).c_str());
    } catch (const std::exception &e) {
        ngx_waf_log_access(r, ("Exception: " + std::string(e.what())).c_str());
    }

    ngx_waf_log_access(r, "Exiting check_rce_unix_shell_expression with no attack detected");
    return false;
}

// Function to check Remote Command Execution: Windows FOR/IF Command Found (RuleId: 932140)
bool check_rce_windows_for_if(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_rce_windows_for_if");
    std::string query(reinterpret_cast<const char*>(r->args.data), r->args.len);

    std::string rce_pattern = get_pattern_from_conf(r, "rce_windows_for_if_pattern");
    ngx_waf_log_access(r, ("RCE Windows FOR/IF Command Pattern: " + rce_pattern).c_str());

    try {
        std::regex rce_regex(rce_pattern);
        ngx_waf_log_access(r, "Regex compiled successfully");

        if (std::regex_search(query, rce_regex)) {
            ngx_waf_log_access(r, "Exiting check_rce_windows_for_if with attack detected");
            return log_and_reject(r, "Possible Remote Command Execution: Windows FOR/IF Command Found", "932140");
        }
    } catch (const std::regex_error &e) {
        ngx_waf_log_access(r, ("Regex error: " + std::string(e.what())).c_str());
    } catch (const std::exception &e) {
        ngx_waf_log_access(r, ("Exception: " + std::string(e.what())).c_str());
    }

    ngx_waf_log_access(r, "Exiting check_rce_windows_for_if with no attack detected");
    return false;
}

// Function to check Remote Command Execution: Direct Unix Command Execution (RuleId: 932150)
bool check_rce_direct_unix_command(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_rce_direct_unix_command");
    std::string query(reinterpret_cast<const char*>(r->args.data), r->args.len);

    std::string rce_pattern = get_pattern_from_conf(r, "rce_direct_unix_command_pattern");
    ngx_waf_log_access(r, ("RCE Direct Unix Command Execution Pattern: " + rce_pattern).c_str());

    try {
        std::regex rce_regex(rce_pattern);
        ngx_waf_log_access(r, "Regex compiled successfully");

        if (std::regex_search(query, rce_regex)) {
            ngx_waf_log_access(r, "Exiting check_rce_direct_unix_command with attack detected");
            return log_and_reject(r, "Possible Remote Command Execution: Direct Unix Command Execution", "932150");
        }
    } catch (const std::regex_error &e) {
        ngx_waf_log_access(r, ("Regex error: " + std::string(e.what())).c_str());
    } catch (const std::exception &e) {
        ngx_waf_log_access(r, ("Exception: " + std::string(e.what())).c_str());
    }

    ngx_waf_log_access(r, "Exiting check_rce_direct_unix_command with no attack detected");
    return false;
}

// Function to check Remote Command Execution: Unix Shell Code Found (RuleId: 932160)
bool check_rce_unix_shell_code(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_rce_unix_shell_code");
    std::string query(reinterpret_cast<const char*>(r->args.data), r->args.len);

    std::string rce_pattern = get_pattern_from_conf(r, "rce_unix_shell_code_pattern");
    ngx_waf_log_access(r, ("RCE Unix Shell Code Pattern: " + rce_pattern).c_str());

    try {
        std::regex rce_regex(rce_pattern);
        ngx_waf_log_access(r, "Regex compiled successfully");

        if (std::regex_search(query, rce_regex)) {
            ngx_waf_log_access(r, "Exiting check_rce_unix_shell_code with attack detected");
            return log_and_reject(r, "Possible Remote Command Execution: Unix Shell Code Found", "932160");
        }
    } catch (const std::regex_error &e) {
        ngx_waf_log_access(r, ("Regex error: " + std::string(e.what())).c_str());
    } catch (const std::exception &e) {
        ngx_waf_log_access(r, ("Exception: " + std::string(e.what())).c_str());
    }

    ngx_waf_log_access(r, "Exiting check_rce_unix_shell_code with no attack detected");
    return false;
}

// Function to check Remote Command Execution: Shellshock (CVE-2014-6271) (RuleId: 932170, 932171)
bool check_rce_shellshock(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_rce_shellshock");
    std::string query(reinterpret_cast<const char*>(r->args.data), r->args.len);

    std::string rce_pattern = get_pattern_from_conf(r, "rce_shellshock_pattern");
    ngx_waf_log_access(r, ("RCE Shellshock Pattern: " + rce_pattern).c_str());

    try {
        std::regex rce_regex(rce_pattern);
        ngx_waf_log_access(r, "Regex compiled successfully");

        if (std::regex_search(query, rce_regex)) {
            ngx_waf_log_access(r, "Exiting check_rce_shellshock with attack detected");
            return log_and_reject(r, "Possible Remote Command Execution: Shellshock (CVE-2014-6271)", "932170");
        }
    } catch (const std::regex_error &e) {
        ngx_waf_log_access(r, ("Regex error: " + std::string(e.what())).c_str());
    } catch (const std::exception &e) {
        ngx_waf_log_access(r, ("Exception: " + std::string(e.what())).c_str());
    }

    ngx_waf_log_access(r, "Exiting check_rce_shellshock with no attack detected");
    return false;
}

// Function to check Restricted File Upload Attempt (RuleId: 932180)
bool check_restricted_file_upload(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_restricted_file_upload");
    std::string query(reinterpret_cast<const char*>(r->args.data), r->args.len);

    std::string rce_pattern = get_pattern_from_conf(r, "restricted_file_upload_pattern");
    ngx_waf_log_access(r, ("Restricted File Upload Pattern: " + rce_pattern).c_str());

    try {
        std::regex rce_regex(rce_pattern);
        ngx_waf_log_access(r, "Regex compiled successfully");

        if (std::regex_search(query, rce_regex)) {
            ngx_waf_log_access(r, "Exiting check_restricted_file_upload with attack detected");
            return log_and_reject(r, "Restricted File Upload Attempt", "932180");
        }
    } catch (const std::regex_error &e) {
        ngx_waf_log_access(r, ("Regex error: " + std::string(e.what())).c_str());
    } catch (const std::exception &e) {
        ngx_waf_log_access(r, ("Exception: " + std::string(e.what())).c_str());
    }

    ngx_waf_log_access(r, "Exiting check_restricted_file_upload with no attack detected");
    return false;
}

// Function to check PHP Injection Attack: Opening/Closing Tag Found (RuleId: 933100)
bool check_php_opening_closing_tag(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_php_opening_closing_tag");
    std::string query(reinterpret_cast<const char*>(r->args.data), r->args.len);

    std::string php_pattern = get_pattern_from_conf(r, "php_opening_closing_tag_pattern");
    ngx_waf_log_access(r, ("PHP Injection Opening/Closing Tag Pattern: " + php_pattern).c_str());

    try {
        std::regex php_regex(php_pattern);
        ngx_waf_log_access(r, "Regex compiled successfully");

        if (std::regex_search(query, php_regex)) {
            ngx_waf_log_access(r, "Exiting check_php_opening_closing_tag with attack detected");
            return log_and_reject(r, "PHP Injection Attack: Opening/Closing Tag Found", "933100");
        }
    } catch (const std::regex_error &e) {
        ngx_waf_log_access(r, ("Regex error: " + std::string(e.what())).c_str());
    } catch (const std::exception &e) {
        ngx_waf_log_access(r, ("Exception: " + std::string(e.what())).c_str());
    }

    ngx_waf_log_access(r, "Exiting check_php_opening_closing_tag with no attack detected");
    return false;
}

// Function to check PHP Injection Attack: PHP Script File Upload Found (RuleId: 933110)
bool check_php_script_file_upload(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_php_script_file_upload");
    std::string query(reinterpret_cast<const char*>(r->args.data), r->args.len);

    std::string php_pattern = get_pattern_from_conf(r, "php_script_file_upload_pattern");
    ngx_waf_log_access(r, ("PHP Script File Upload Pattern: " + php_pattern).c_str());

    try {
        std::regex php_regex(php_pattern);
        ngx_waf_log_access(r, "Regex compiled successfully");

        if (std::regex_search(query, php_regex)) {
            ngx_waf_log_access(r, "Exiting check_php_script_file_upload with attack detected");
            return log_and_reject(r, "PHP Injection Attack: PHP Script File Upload Found", "933110");
        }
    } catch (const std::regex_error &e) {
        ngx_waf_log_access(r, ("Regex error: " + std::string(e.what())).c_str());
    } catch (const std::exception &e) {
        ngx_waf_log_access(r, ("Exception: " + std::string(e.what())).c_str());
    }

    ngx_waf_log_access(r, "Exiting check_php_script_file_upload with no attack detected");
    return false;
}

// Function to check PHP Injection Attack: Configuration Directive Found (RuleId: 933120)
bool check_php_config_directive(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_php_config_directive");
    std::string query(reinterpret_cast<const char*>(r->args.data), r->args.len);

    std::string php_pattern = get_pattern_from_conf(r, "php_config_directive_pattern");
    ngx_waf_log_access(r, ("PHP Injection Configuration Directive Pattern: " + php_pattern).c_str());

    try {
        std::regex php_regex(php_pattern);
        ngx_waf_log_access(r, "Regex compiled successfully");

        if (std::regex_search(query, php_regex)) {
            ngx_waf_log_access(r, "Exiting check_php_config_directive with attack detected");
            return log_and_reject(r, "PHP Injection Attack: Configuration Directive Found", "933120");
        }
    } catch (const std::regex_error &e) {
        ngx_waf_log_access(r, ("Regex error: " + std::string(e.what())).c_str());
    } catch (const std::exception &e) {
        ngx_waf_log_access(r, ("Exception: " + std::string(e.what())).c_str());
    }

    ngx_waf_log_access(r, "Exiting check_php_config_directive with no attack detected");
    return false;
}

// Function to check PHP Injection Attack: Variables Found (RuleId: 933130)
bool check_php_variables(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_php_variables");
    std::string query(reinterpret_cast<const char*>(r->args.data), r->args.len);

    std::string php_pattern = get_pattern_from_conf(r, "php_variables_pattern");
    ngx_waf_log_access(r, ("PHP Injection Variables Pattern: " + php_pattern).c_str());

    try {
        std::regex php_regex(php_pattern);
        ngx_waf_log_access(r, "Regex compiled successfully");

        if (std::regex_search(query, php_regex)) {
            ngx_waf_log_access(r, "Exiting check_php_variables with attack detected");
            return log_and_reject(r, "PHP Injection Attack: Variables Found", "933130");
        }
    } catch (const std::regex_error &e) {
        ngx_waf_log_access(r, ("Regex error: " + std::string(e.what())).c_str());
    } catch (const std::exception &e) {
        ngx_waf_log_access(r, ("Exception: " + std::string(e.what())).c_str());
    }

    ngx_waf_log_access(r, "Exiting check_php_variables with no attack detected");
    return false;
}

// Function to check PHP Injection Attack: I/O Stream Found (RuleId: 933140)
bool check_php_io_stream(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_php_io_stream");
    std::string query(reinterpret_cast<const char*>(r->args.data), r->args.len);

    std::string php_pattern = get_pattern_from_conf(r, "php_io_stream_pattern");
    ngx_waf_log_access(r, ("PHP Injection I/O Stream Pattern: " + php_pattern).c_str());

    try {
        std::regex php_regex(php_pattern);
        ngx_waf_log_access(r, "Regex compiled successfully");

        if (std::regex_search(query, php_regex)) {
            ngx_waf_log_access(r, "Exiting check_php_io_stream with attack detected");
            return log_and_reject(r, "PHP Injection Attack: I/O Stream Found", "933140");
        }
    } catch (const std::regex_error &e) {
        ngx_waf_log_access(r, ("Regex error: " + std::string(e.what())).c_str());
    } catch (const std::exception &e) {
        ngx_waf_log_access(r, ("Exception: " + std::string(e.what())).c_str());
    }

    ngx_waf_log_access(r, "Exiting check_php_io_stream with no attack detected");
    return false;
}

// Function to check PHP Injection Attack: High-Risk PHP Function Name Found (RuleId: 933150)
bool check_php_high_risk_function_name(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_php_high_risk_function_name");
    std::string query(reinterpret_cast<const char*>(r->args.data), r->args.len);

    std::string php_pattern = get_pattern_from_conf(r, "php_high_risk_function_name_pattern");
    ngx_waf_log_access(r, ("PHP High-Risk Function Name Pattern: " + php_pattern).c_str());

    try {
        std::regex php_regex(php_pattern);
        ngx_waf_log_access(r, "Regex compiled successfully");

        if (std::regex_search(query, php_regex)) {
            ngx_waf_log_access(r, "Exiting check_php_high_risk_function_name with attack detected");
            return log_and_reject(r, "PHP Injection Attack: High-Risk PHP Function Name Found", "933150");
        }
    } catch (const std::regex_error &e) {
        ngx_waf_log_access(r, ("Regex error: " + std::string(e.what())).c_str());
    } catch (const std::exception &e) {
        ngx_waf_log_access(r, ("Exception: " + std::string(e.what())).c_str());
    }

    ngx_waf_log_access(r, "Exiting check_php_high_risk_function_name with no attack detected");
    return false;
}

// Function to check PHP Injection Attack: Medium-Risk PHP Function Name Found (RuleId: 933151)
bool check_php_medium_risk_function_name(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_php_medium_risk_function_name");
    std::string query(reinterpret_cast<const char*>(r->args.data), r->args.len);

    std::string php_pattern = get_pattern_from_conf(r, "php_medium_risk_function_name_pattern");
    ngx_waf_log_access(r, ("PHP Medium-Risk Function Name Pattern: " + php_pattern).c_str());

    try {
        std::regex php_regex(php_pattern);
        ngx_waf_log_access(r, "Regex compiled successfully");

        if (std::regex_search(query, php_regex)) {
            ngx_waf_log_access(r, "Exiting check_php_medium_risk_function_name with attack detected");
            return log_and_reject(r, "PHP Injection Attack: Medium-Risk PHP Function Name Found", "933151");
        }
    } catch (const std::regex_error &e) {
        ngx_waf_log_access(r, ("Regex error: " + std::string(e.what())).c_str());
    } catch (const std::exception &e) {
        ngx_waf_log_access(r, ("Exception: " + std::string(e.what())).c_str());
    }

    ngx_waf_log_access(r, "Exiting check_php_medium_risk_function_name with no attack detected");
    return false;
}

// Function to check PHP Injection Attack: High-Risk PHP Function Call Found (RuleId: 933160)
bool check_php_high_risk_function_call(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_php_high_risk_function_call");
    std::string query(reinterpret_cast<const char*>(r->args.data), r->args.len);

    std::string php_pattern = get_pattern_from_conf(r, "php_high_risk_function_call_pattern");
    ngx_waf_log_access(r, ("PHP High-Risk Function Call Pattern: " + php_pattern).c_str());

    try {
        std::regex php_regex(php_pattern);
        ngx_waf_log_access(r, "Regex compiled successfully");

        if (std::regex_search(query, php_regex)) {
            ngx_waf_log_access(r, "Exiting check_php_high_risk_function_call with attack detected");
            return log_and_reject(r, "PHP Injection Attack: High-Risk PHP Function Call Found", "933160");
        }
    } catch (const std::regex_error &e) {
        ngx_waf_log_access(r, ("Regex error: " + std::string(e.what())).c_str());
    } catch (const std::exception &e) {
        ngx_waf_log_access(r, ("Exception: " + std::string(e.what())).c_str());
    }

    ngx_waf_log_access(r, "Exiting check_php_high_risk_function_call with no attack detected");
    return false;
}

// Function to check PHP Injection Attack: Serialized Object Injection (RuleId: 933170)
bool check_php_serialized_object_injection(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_php_serialized_object_injection");
    std::string query(reinterpret_cast<const char*>(r->args.data), r->args.len);

    std::string php_pattern = get_pattern_from_conf(r, "php_serialized_object_injection_pattern");
    ngx_waf_log_access(r, ("PHP Serialized Object Injection Pattern: " + php_pattern).c_str());

    try {
        std::regex php_regex(php_pattern);
        ngx_waf_log_access(r, "Regex compiled successfully");

        if (std::regex_search(query, php_regex)) {
            ngx_waf_log_access(r, "Exiting check_php_serialized_object_injection with attack detected");
            return log_and_reject(r, "PHP Injection Attack: Serialized Object Injection", "933170");
        }
    } catch (const std::regex_error &e) {
        ngx_waf_log_access(r, ("Regex error: " + std::string(e.what())).c_str());
    } catch (const std::exception &e) {
        ngx_waf_log_access(r, ("Exception: " + std::string(e.what())).c_str());
    }

    ngx_waf_log_access(r, "Exiting check_php_serialized_object_injection with no attack detected");
    return false;
}

// Function to check PHP Injection Attack: Variable Function Call Found (RuleId: 933180, 933210)
bool check_php_variable_function_call(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_php_variable_function_call");
    std::string query(reinterpret_cast<const char*>(r->args.data), r->args.len);

    std::string php_pattern = get_pattern_from_conf(r, "php_variable_function_call_pattern");
    ngx_waf_log_access(r, ("PHP Variable Function Call Pattern: " + php_pattern).c_str());

    try {
        std::regex php_regex(php_pattern);
        ngx_waf_log_access(r, "Regex compiled successfully");

        if (std::regex_search(query, php_regex)) {
            ngx_waf_log_access(r, "Exiting check_php_variable_function_call with attack detected");
            return log_and_reject(r, "PHP Injection Attack: Variable Function Call Found", "933180");
        }
    } catch (const std::regex_error &e) {
        ngx_waf_log_access(r, ("Regex error: " + std::string(e.what())).c_str());
    } catch (const std::exception &e) {
        ngx_waf_log_access(r, ("Exception: " + std::string(e.what())).c_str());
    }

    ngx_waf_log_access(r, "Exiting check_php_variable_function_call with no attack detected");
    return false;
}

// Function to check PHP Injection Attack: Wrapper scheme detected (RuleId: 933200)
bool check_php_wrapper_scheme(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_php_wrapper_scheme");
    std::string query(reinterpret_cast<const char*>(r->args.data), r->args.len);

    std::string php_pattern = get_pattern_from_conf(r, "php_wrapper_scheme_pattern");
    ngx_waf_log_access(r, ("PHP Wrapper Scheme Pattern: " + php_pattern).c_str());

    try {
        std::regex php_regex(php_pattern);
        ngx_waf_log_access(r, "Regex compiled successfully");

        if (std::regex_search(query, php_regex)) {
            ngx_waf_log_access(r, "Exiting check_php_wrapper_scheme with attack detected");
            return log_and_reject(r, "PHP Injection Attack: Wrapper scheme detected", "933200");
        }
    } catch (const std::regex_error &e) {
        ngx_waf_log_access(r, ("Regex error: " + std::string(e.what())).c_str());
    } catch (const std::exception &e) {
        ngx_waf_log_access(r, ("Exception: " + std::string(e.what())).c_str());
    }

    ngx_waf_log_access(r, "Exiting check_php_wrapper_scheme with no attack detected");
    return false;
}

// Function to check Node.js Injection Attack (RuleId: 934100)
bool check_nodejs_injection(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_nodejs_injection");
    std::string query(reinterpret_cast<const char*>(r->args.data), r->args.len);

    std::string nodejs_pattern = get_pattern_from_conf(r, "nodejs_injection_pattern");
    ngx_waf_log_access(r, ("Node.js Injection Pattern: " + nodejs_pattern).c_str());

    try {
        std::regex nodejs_regex(nodejs_pattern);
        ngx_waf_log_access(r, "Regex compiled successfully");

        if (std::regex_search(query, nodejs_regex)) {
            ngx_waf_log_access(r, "Exiting check_nodejs_injection with attack detected");
            return log_and_reject(r, "Node.js Injection Attack", "934100");
        }
    } catch (const std::regex_error &e) {
        ngx_waf_log_access(r, ("Regex error: " + std::string(e.what())).c_str());
    } catch (const std::exception &e) {
        ngx_waf_log_access(r, ("Exception: " + std::string(e.what())).c_str());
    }

    ngx_waf_log_access(r, "Exiting check_nodejs_injection with no attack detected");
    return false;
}

// Entry point function
ngx_int_t rce_php_node_rules_entry_point(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered protocol_attack_entry_point");
        
    // Check RCE attacks
    if (check_rce_unix_command_injection(r)) return NGX_HTTP_FORBIDDEN;
    if (check_rce_windows_command_injection(r)) return NGX_HTTP_FORBIDDEN;
    if (check_rce_windows_powershell(r)) return NGX_HTTP_FORBIDDEN;
    if (check_rce_unix_shell_expression(r)) return NGX_HTTP_FORBIDDEN;
    if (check_rce_windows_for_if(r)) return NGX_HTTP_FORBIDDEN;
    if (check_rce_direct_unix_command(r)) return NGX_HTTP_FORBIDDEN;
    if (check_rce_unix_shell_code(r)) return NGX_HTTP_FORBIDDEN;
    if (check_rce_shellshock(r)) return NGX_HTTP_FORBIDDEN;
    if (check_restricted_file_upload(r)) return NGX_HTTP_FORBIDDEN;
    
    // Check PHP injection attacks
    if (check_php_opening_closing_tag(r)) return NGX_HTTP_FORBIDDEN;
    if (check_php_script_file_upload(r)) return NGX_HTTP_FORBIDDEN;
    if (check_php_config_directive(r)) return NGX_HTTP_FORBIDDEN;
    if (check_php_variables(r)) return NGX_HTTP_FORBIDDEN;
    if (check_php_io_stream(r)) return NGX_HTTP_FORBIDDEN;
    if (check_php_high_risk_function_name(r)) return NGX_HTTP_FORBIDDEN;
    if (check_php_medium_risk_function_name(r)) return NGX_HTTP_FORBIDDEN;
    if (check_php_high_risk_function_call(r)) return NGX_HTTP_FORBIDDEN;
    if (check_php_serialized_object_injection(r)) return NGX_HTTP_FORBIDDEN;
    if (check_php_variable_function_call(r)) return NGX_HTTP_FORBIDDEN;
    if (check_php_wrapper_scheme(r)) return NGX_HTTP_FORBIDDEN;
    
    // Check Node.js injection attack
    if (check_nodejs_injection(r)) return NGX_HTTP_FORBIDDEN;
    
    ngx_waf_log_access(r, "Exiting protocol_attack_entry_point with no attack detected");
    return NGX_DECLINED;
}
