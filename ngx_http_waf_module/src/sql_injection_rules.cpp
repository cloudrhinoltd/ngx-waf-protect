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

// Function to check SQL Injection Attack Detected via libinjection (RuleId: 942100)
bool check_sqli_libinjection(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_sqli_libinjection");
    std::string query(reinterpret_cast<const char*>(r->args.data), r->args.len);

    std::string sqli_pattern = get_pattern_from_conf(r, "sqli_libinjection_pattern");
    ngx_waf_log_access(r, ("SQL Injection Libinjection Pattern: " + sqli_pattern).c_str());

    try {
        std::regex sqli_regex(sqli_pattern);
        ngx_waf_log_access(r, "Regex compiled successfully");

        if (std::regex_search(query, sqli_regex)) {
            ngx_waf_log_access(r, "Exiting check_sqli_libinjection with attack detected");
            return log_and_reject(r, "SQL Injection Attack Detected via libinjection", "942100");
        }
    } catch (const std::regex_error &e) {
        ngx_waf_log_access(r, ("Regex error: " + std::string(e.what())).c_str());
    } catch (const std::exception &e) {
        ngx_waf_log_access(r, ("Exception: " + std::string(e.what())).c_str());
    }

    ngx_waf_log_access(r, "Exiting check_sqli_libinjection with no attack detected");
    return false;
}

// Function to check SQL Injection Attack: Common Injection Testing Detected (RuleId: 942110)
bool check_sqli_common_testing(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_sqli_common_testing");
    std::string query(reinterpret_cast<const char*>(r->args.data), r->args.len);

    std::string sqli_pattern = get_pattern_from_conf(r, "sql_injection_pattern");
    ngx_waf_log_access(r, ("SQL Injection Common Testing Pattern: " + sqli_pattern).c_str());

    try {
        std::regex sqli_regex(sqli_pattern);
        ngx_waf_log_access(r, "Regex compiled successfully");

        if (std::regex_search(query, sqli_regex)) {
            ngx_waf_log_access(r, "Exiting check_sqli_common_testing with attack detected");
            return log_and_reject(r, "SQL Injection Attack: Common Injection Testing Detected", "942110");
        }
    } catch (const std::regex_error &e) {
        ngx_waf_log_access(r, ("Regex error: " + std::string(e.what())).c_str());
    } catch (const std::exception &e) {
        ngx_waf_log_access(r, ("Exception: " + std::string(e.what())).c_str());
    }

    ngx_waf_log_access(r, "Exiting check_sqli_common_testing with no attack detected");
    return false;
}

// Function to check SQL Injection Attack: SQL Operator Detected (RuleId: 942120)
bool check_sqli_operator(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_sqli_sql_operator");
    std::string query(reinterpret_cast<const char*>(r->args.data), r->args.len);

    std::string sqli_pattern = get_pattern_from_conf(r, "sqli_operator_pattern");
    ngx_waf_log_access(r, ("SQL Injection SQL Operator Pattern: " + sqli_pattern).c_str());

    try {
        std::regex sqli_regex(sqli_pattern);
        ngx_waf_log_access(r, "Regex compiled successfully");

        if (std::regex_search(query, sqli_regex)) {
            ngx_waf_log_access(r, "Exiting sqli_operator_pattern with attack detected");
            return log_and_reject(r, "SQL Injection Attack: SQL Operator Detected", "942120");
        }
    } catch (const std::regex_error &e) {
        ngx_waf_log_access(r, ("Regex error: " + std::string(e.what())).c_str());
    } catch (const std::exception &e) {
        ngx_waf_log_access(r, ("Exception: " + std::string(e.what())).c_str());
    }

    ngx_waf_log_access(r, "Exiting check_sqli_sql_operator with no attack detected");
    return false;
}

// Function to check SQL Injection Attack: Common DB Names Detected (RuleId: 942140)
bool check_sqli_common_db_names(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_sqli_common_db_names");
    std::string query(reinterpret_cast<const char*>(r->args.data), r->args.len);

    std::string sqli_pattern = get_pattern_from_conf(r, "sqli_common_db_names_pattern");
    ngx_waf_log_access(r, ("SQL Injection Common DB Names Pattern: " + sqli_pattern).c_str());

    try {
        std::regex sqli_regex(sqli_pattern);
        ngx_waf_log_access(r, "Regex compiled successfully");

        if (std::regex_search(query, sqli_regex)) {
            ngx_waf_log_access(r, "Exiting check_sqli_common_db_names with attack detected");
            return log_and_reject(r, "SQL Injection Attack: Common DB Names Detected", "942140");
        }
    } catch (const std::regex_error &e) {
        ngx_waf_log_access(r, ("Regex error: " + std::string(e.what())).c_str());
    } catch (const std::exception &e) {
        ngx_waf_log_access(r, ("Exception: " + std::string(e.what())).c_str());
    }

    ngx_waf_log_access(r, "Exiting check_sqli_common_db_names with no attack detected");
    return false;
}

// Function to check SQL Injection Attack (RuleId: 942150,942380,942390,942400,942410)
bool check_sqli_attack(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_sqli_attack");
    std::string query(reinterpret_cast<const char*>(r->args.data), r->args.len);

    std::string sqli_pattern = get_pattern_from_conf(r, "sqli_attack_pattern");
    ngx_waf_log_access(r, ("SQL Injection Attack Pattern: " + sqli_pattern).c_str());

    try {
        std::regex sqli_regex(sqli_pattern);
        ngx_waf_log_access(r, "Regex compiled successfully");

        if (std::regex_search(query, sqli_regex)) {
            ngx_waf_log_access(r, "Exiting check_sqli_attack with attack detected");
            return log_and_reject(r, "SQL Injection Attack", "942150");
        }
    } catch (const std::regex_error &e) {
        ngx_waf_log_access(r, ("Regex error: " + std::string(e.what())).c_str());
    } catch (const std::exception &e) {
        ngx_waf_log_access(r, ("Exception: " + std::string(e.what())).c_str());
    }

    ngx_waf_log_access(r, "Exiting check_sqli_attack with no attack detected");
    return false;
}

// Function to check Detects blind SQLI tests using sleep() or benchmark() (RuleId: 942160)
bool check_sqli_blind_tests(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_sqli_blind_tests");
    std::string query(reinterpret_cast<const char*>(r->args.data), r->args.len);

    std::string sqli_pattern = get_pattern_from_conf(r, "sqli_blind_sqli_testing_pattern");
    ngx_waf_log_access(r, ("SQL Injection Blind Tests Pattern: " + sqli_pattern).c_str());

    try {
        std::regex sqli_regex(sqli_pattern);
        ngx_waf_log_access(r, "Regex compiled successfully");

        if (std::regex_search(query, sqli_regex)) {
            ngx_waf_log_access(r, "Exiting check_sqli_blind_tests with attack detected");
            return log_and_reject(r, "Detects blind SQLI tests using sleep() or benchmark()", "942160");
        }
    } catch (const std::regex_error &e) {
        ngx_waf_log_access(r, ("Regex error: " + std::string(e.what())).c_str());
    } catch (const std::exception &e) {
        ngx_waf_log_access(r, ("Exception: " + std::string(e.what())).c_str());
    }

    ngx_waf_log_access(r, "Exiting check_sqli_blind_tests with no attack detected");
    return false;
}

// Function to check Detects SQL benchmark and sleep injection attempts including conditional queries (RuleId: 942170)
bool check_sqli_benchmark_sleep(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_sqli_benchmark_sleep");
    std::string query(reinterpret_cast<const char*>(r->args.data), r->args.len);

    std::string sqli_pattern = get_pattern_from_conf(r, "sqli_benchmark_sleep_pattern");
    ngx_waf_log_access(r, ("SQL Injection Benchmark Sleep Pattern: " + sqli_pattern).c_str());

    try {
        std::regex sqli_regex(sqli_pattern);
        ngx_waf_log_access(r, "Regex compiled successfully");

        if (std::regex_search(query, sqli_regex)) {
            ngx_waf_log_access(r, "Exiting check_sqli_benchmark_sleep with attack detected");
            return log_and_reject(r, "Detects SQL benchmark and sleep injection attempts including conditional queries", "942170");
        }
    } catch (const std::regex_error &e) {
        ngx_waf_log_access(r, ("Regex error: " + std::string(e.what())).c_str());
    } catch (const std::exception &e) {
        ngx_waf_log_access(r, ("Exception: " + std::string(e.what())).c_str());
    }

    ngx_waf_log_access(r, "Exiting check_sqli_benchmark_sleep with no attack detected");
    return false;
}

// Function to check Detects basic SQL authentication bypass attempts 1/3 (RuleId: 942180)
bool check_sqli_auth_bypass_1(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_sqli_auth_bypass_1");
    std::string query(reinterpret_cast<const char*>(r->args.data), r->args.len);

    std::string sqli_pattern = get_pattern_from_conf(r, "sqli_authentication_bypass_1_pattern");
    ngx_waf_log_access(r, ("SQL Injection Auth Bypass 1 Pattern: " + sqli_pattern).c_str());

    try {
        std::regex sqli_regex(sqli_pattern);
        ngx_waf_log_access(r, "Regex compiled successfully");

        if (std::regex_search(query, sqli_regex)) {
            ngx_waf_log_access(r, "Exiting check_sqli_auth_bypass_1 with attack detected");
            return log_and_reject(r, "Detects basic SQL authentication bypass attempts 1/3", "942180");
        }
    } catch (const std::regex_error &e) {
        ngx_waf_log_access(r, ("Regex error: " + std::string(e.what())).c_str());
    } catch (const std::exception &e) {
        ngx_waf_log_access(r, ("Exception: " + std::string(e.what())).c_str());
    }

    ngx_waf_log_access(r, "Exiting check_sqli_auth_bypass_1 with no attack detected");
    return false;
}

// Function to check Detects MSSQL code execution and information gathering attempts (RuleId: 942190)
bool check_sqli_mssql_code_exec(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_sqli_mssql_code_exec");
    std::string query(reinterpret_cast<const char*>(r->args.data), r->args.len);

    std::string sqli_pattern = get_pattern_from_conf(r, "sqli_mssql_code_execution_pattern");
    ngx_waf_log_access(r, ("SQL Injection MSSQL Code Execution Pattern: " + sqli_pattern).c_str());

    try {
        std::regex sqli_regex(sqli_pattern);
        ngx_waf_log_access(r, "Regex compiled successfully");

        if (std::regex_search(query, sqli_regex)) {
            ngx_waf_log_access(r, "Exiting check_sqli_mssql_code_exec with attack detected");
            return log_and_reject(r, "Detects MSSQL code execution and information gathering attempts", "942190");
        }
    } catch (const std::regex_error &e) {
        ngx_waf_log_access(r, ("Regex error: " + std::string(e.what())).c_str());
    } catch (const std::exception &e) {
        ngx_waf_log_access(r, ("Exception: " + std::string(e.what())).c_str());
    }

    ngx_waf_log_access(r, "Exiting check_sqli_mssql_code_exec with no attack detected");
    return false;
}

// Function to check Detects MySQL comment-/space-obfuscated injections and backtick termination (RuleId: 942200)
bool check_sqli_mysql_comment_obfuscated(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_sqli_mysql_comment_obfuscated");
    std::string query(reinterpret_cast<const char*>(r->args.data), r->args.len);

    std::string sqli_pattern = get_pattern_from_conf(r, "sqli_mysql_inline_comment_pattern");
    ngx_waf_log_access(r, ("SQL Injection MySQL Comment Obfuscated Pattern: " + sqli_pattern).c_str());

    try {
        std::regex sqli_regex(sqli_pattern);
        ngx_waf_log_access(r, "Regex compiled successfully");

        if (std::regex_search(query, sqli_regex)) {
            ngx_waf_log_access(r, "Exiting check_sqli_mysql_comment_obfuscated with attack detected");
            return log_and_reject(r, "Detects MySQL comment-/space-obfuscated injections and backtick termination", "942200");
        }
    } catch (const std::regex_error &e) {
        ngx_waf_log_access(r, ("Regex error: " + std::string(e.what())).c_str());
    } catch (const std::exception &e) {
        ngx_waf_log_access(r, ("Exception: " + std::string(e.what())).c_str());
    }

    ngx_waf_log_access(r, "Exiting check_sqli_mysql_comment_obfuscated with no attack detected");
    return false;
}

// Function to check Detects chained SQL injection attempts 1/2 (RuleId: 942210)
bool check_sqli_chained_1(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_sqli_chained_1");
    std::string query(reinterpret_cast<const char*>(r->args.data), r->args.len);

    std::string sqli_pattern = get_pattern_from_conf(r, "sqli_chained_injection_1_pattern");
    ngx_waf_log_access(r, ("SQL Injection Chained 1 Pattern: " + sqli_pattern).c_str());

    try {
        std::regex sqli_regex(sqli_pattern);
        ngx_waf_log_access(r, "Regex compiled successfully");

        if (std::regex_search(query, sqli_regex)) {
            ngx_waf_log_access(r, "Exiting check_sqli_chained_1 with attack detected");
            return log_and_reject(r, "Detects chained SQL injection attempts 1/2", "942210");
        }
    } catch (const std::regex_error &e) {
        ngx_waf_log_access(r, ("Regex error: " + std::string(e.what())).c_str());
    } catch (const std::exception &e) {
        ngx_waf_log_access(r, ("Exception: " + std::string(e.what())).c_str());
    }

    ngx_waf_log_access(r, "Exiting check_sqli_chained_1 with no attack detected");
    return false;
}

// Function to check Detects conditional SQL injection attempts (RuleId: 942230)
bool check_sqli_conditional_attempts(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_sqli_conditional_attempts");
    std::string query(reinterpret_cast<const char*>(r->args.data), r->args.len);

    std::string sqli_pattern = get_pattern_from_conf(r, "sqli_conditional_injection_pattern");
    ngx_waf_log_access(r, ("SQL Injection Conditional Attempts Pattern: " + sqli_pattern).c_str());

    try {
        std::regex sqli_regex(sqli_pattern);
        ngx_waf_log_access(r, "Regex compiled successfully");

        if (std::regex_search(query, sqli_regex)) {
            ngx_waf_log_access(r, "Exiting check_sqli_conditional_attempts with attack detected");
            return log_and_reject(r, "Detects conditional SQL injection attempts", "942230");
        }
    } catch (const std::regex_error &e) {
        ngx_waf_log_access(r, ("Regex error: " + std::string(e.what())).c_str());
    } catch (const std::exception &e) {
        ngx_waf_log_access(r, ("Exception: " + std::string(e.what())).c_str());
    }

    ngx_waf_log_access(r, "Exiting check_sqli_conditional_attempts with no attack detected");
    return false;
}

// Function to check Detects MySQL charset switch and MSSQL DoS attempts (RuleId: 942240)
bool check_sqli_charset_switch_dos(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_sqli_charset_switch_dos");
    std::string query(reinterpret_cast<const char*>(r->args.data), r->args.len);

    std::string sqli_pattern = get_pattern_from_conf(r, "sqli_mysql_charset_switch_pattern");
    ngx_waf_log_access(r, ("SQL Injection Charset Switch DoS Pattern: " + sqli_pattern).c_str());

    try {
        std::regex sqli_regex(sqli_pattern);
        ngx_waf_log_access(r, "Regex compiled successfully");

        if (std::regex_search(query, sqli_regex)) {
            ngx_waf_log_access(r, "Exiting check_sqli_charset_switch_dos with attack detected");
            return log_and_reject(r, "Detects MySQL charset switch and MSSQL DoS attempts", "942240");
        }
    } catch (const std::regex_error &e) {
        ngx_waf_log_access(r, ("Regex error: " + std::string(e.what())).c_str());
    } catch (const std::exception &e) {
        ngx_waf_log_access(r, ("Exception: " + std::string(e.what())).c_str());
    }

    ngx_waf_log_access(r, "Exiting check_sqli_charset_switch_dos with no attack detected");
    return false;
}

// Function to check Detects MATCH AGAINST, MERGE and EXECUTE IMMEDIATE injections (RuleId: 942250)
bool check_sqli_match_against_merge_execute(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_sqli_match_against_merge_execute");
    std::string query(reinterpret_cast<const char*>(r->args.data), r->args.len);

    std::string sqli_pattern = get_pattern_from_conf(r, "sqli_match_against_pattern");
    ngx_waf_log_access(r, ("SQL Injection Match Against Merge Execute Pattern: " + sqli_pattern).c_str());

    try {
        std::regex sqli_regex(sqli_pattern);
        ngx_waf_log_access(r, "Regex compiled successfully");

        if (std::regex_search(query, sqli_regex)) {
            ngx_waf_log_access(r, "Exiting check_sqli_match_against_merge_execute with attack detected");
            return log_and_reject(r, "Detects MATCH AGAINST, MERGE and EXECUTE IMMEDIATE injections", "942250");
        }
    } catch (const std::regex_error &e) {
        ngx_waf_log_access(r, ("Regex error: " + std::string(e.what())).c_str());
    } catch (const std::exception &e) {
        ngx_waf_log_access(r, ("Exception: " + std::string(e.what())).c_str());
    }

    ngx_waf_log_access(r, "Exiting check_sqli_match_against_merge_execute with no attack detected");
    return false;
}

// Function to check Detects basic SQL authentication bypass attempts 2/3 (RuleId: 942260)
bool check_sqli_auth_bypass_2(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_sqli_auth_bypass_2");
    std::string query(reinterpret_cast<const char*>(r->args.data), r->args.len);

    std::string sqli_pattern = get_pattern_from_conf(r, "sqli_authentication_bypass_2_pattern");
    ngx_waf_log_access(r, ("SQL Injection Auth Bypass 2 Pattern: " + sqli_pattern).c_str());

    try {
        std::regex sqli_regex(sqli_pattern);
        ngx_waf_log_access(r, "Regex compiled successfully");

        if (std::regex_search(query, sqli_regex)) {
            ngx_waf_log_access(r, "Exiting check_sqli_auth_bypass_2 with attack detected");
            return log_and_reject(r, "Detects basic SQL authentication bypass attempts 2/3", "942260");
        }
    } catch (const std::regex_error &e) {
        ngx_waf_log_access(r, ("Regex error: " + std::string(e.what())).c_str());
    } catch (const std::exception &e) {
        ngx_waf_log_access(r, ("Exception: " + std::string(e.what())).c_str());
    }

    ngx_waf_log_access(r, "Exiting check_sqli_auth_bypass_2 with no attack detected");
    return false;
}

// Function to check Looking for basic SQL injection. Common attack string for MySQL, Oracle, and others (RuleId: 942270)
bool check_sqli_common_attack_string(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_sqli_common_attack_string");
    std::string query(reinterpret_cast<const char*>(r->args.data), r->args.len);

    std::string sqli_pattern = get_pattern_from_conf(r, "sqli_basic_injection_pattern");
    ngx_waf_log_access(r, ("SQL Injection Common Attack String Pattern: " + sqli_pattern).c_str());

    try {
        std::regex sqli_regex(sqli_pattern);
        ngx_waf_log_access(r, "Regex compiled successfully");

        if (std::regex_search(query, sqli_regex)) {
            ngx_waf_log_access(r, "Exiting check_sqli_common_attack_string with attack detected");
            return log_and_reject(r, "Looking for basic SQL injection. Common attack string for MySQL, Oracle, and others", "942270");
        }
    } catch (const std::regex_error &e) {
        ngx_waf_log_access(r, ("Regex error: " + std::string(e.what())).c_str());
    } catch (const std::exception &e) {
        ngx_waf_log_access(r, ("Exception: " + std::string(e.what())).c_str());
    }

    ngx_waf_log_access(r, "Exiting check_sqli_common_attack_string with no attack detected");
    return false;
}

// Function to check Detects Postgres pg_sleep injection, wait for delay attacks, and database shutdown attempts (RuleId: 942280)
bool check_sqli_pg_sleep(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_sqli_pg_sleep");
    std::string query(reinterpret_cast<const char*>(r->args.data), r->args.len);

    std::string sqli_pattern = get_pattern_from_conf(r, "sqli_postgres_sleep_pattern");
    ngx_waf_log_access(r, ("SQL Injection PG Sleep Pattern: " + sqli_pattern).c_str());

    try {
        std::regex sqli_regex(sqli_pattern);
        ngx_waf_log_access(r, "Regex compiled successfully");

        if (std::regex_search(query, sqli_regex)) {
            ngx_waf_log_access(r, "Exiting check_sqli_pg_sleep with attack detected");
            return log_and_reject(r, "Detects Postgres pg_sleep injection, wait for delay attacks, and database shutdown attempts", "942280");
        }
    } catch (const std::regex_error &e) {
        ngx_waf_log_access(r, ("Regex error: " + std::string(e.what())).c_str());
    } catch (const std::exception &e) {
        ngx_waf_log_access(r, ("Exception: " + std::string(e.what())).c_str());
    }

    ngx_waf_log_access(r, "Exiting check_sqli_pg_sleep with no attack detected");
    return false;
}

// Function to check Finds basic MongoDB SQL injection attempts (RuleId: 942290)
bool check_sqli_mongodb_injection(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_sqli_mongodb_injection");
    std::string query(reinterpret_cast<const char*>(r->args.data), r->args.len);

    std::string sqli_pattern = get_pattern_from_conf(r, "sqli_mongodb_injection_pattern");
    ngx_waf_log_access(r, ("SQL Injection MongoDB Injection Pattern: " + sqli_pattern).c_str());

    try {
        std::regex sqli_regex(sqli_pattern);
        ngx_waf_log_access(r, "Regex compiled successfully");

        if (std::regex_search(query, sqli_regex)) {
            ngx_waf_log_access(r, "Exiting check_sqli_mongodb_injection with attack detected");
            return log_and_reject(r, "Finds basic MongoDB SQL injection attempts", "942290");
        }
    } catch (const std::regex_error &e) {
        ngx_waf_log_access(r, ("Regex error: " + std::string(e.what())).c_str());
    } catch (const std::exception &e) {
        ngx_waf_log_access(r, ("Exception: " + std::string(e.what())).c_str());
    }

    ngx_waf_log_access(r, "Exiting check_sqli_mongodb_injection with no attack detected");
    return false;
}

// Function to check Detects MySQL comments, conditions, and ch(a)r injections (RuleId: 942300)
bool check_sqli_mysql_comments_conditions(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_sqli_mysql_comments_conditions");
    std::string query(reinterpret_cast<const char*>(r->args.data), r->args.len);

    std::string sqli_pattern = get_pattern_from_conf(r, "sqli_mysql_comment_condition_pattern");
    ngx_waf_log_access(r, ("SQL Injection MySQL Comments Conditions Pattern: " + sqli_pattern).c_str());

    try {
        std::regex sqli_regex(sqli_pattern);
        ngx_waf_log_access(r, "Regex compiled successfully");

        if (std::regex_search(query, sqli_regex)) {
            ngx_waf_log_access(r, "Exiting check_sqli_mysql_comments_conditions with attack detected");
            return log_and_reject(r, "Detects MySQL comments, conditions, and ch(a)r injections", "942300");
        }
    } catch (const std::regex_error &e) {
        ngx_waf_log_access(r, ("Regex error: " + std::string(e.what())).c_str());
    } catch (const std::exception &e) {
        ngx_waf_log_access(r, ("Exception: " + std::string(e.what())).c_str());
    }

    ngx_waf_log_access(r, "Exiting check_sqli_mysql_comments_conditions with no attack detected");
    return false;
}

// Function to check Detects chained SQL injection attempts 2/2 (RuleId: 942310)
bool check_sqli_chained_2(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_sqli_chained_2");
    std::string query(reinterpret_cast<const char*>(r->args.data), r->args.len);

    std::string sqli_pattern = get_pattern_from_conf(r, "sqli_chained_injection_2_pattern");
    ngx_waf_log_access(r, ("SQL Injection Chained 2 Pattern: " + sqli_pattern).c_str());

    try {
        std::regex sqli_regex(sqli_pattern);
        ngx_waf_log_access(r, "Regex compiled successfully");

        if (std::regex_search(query, sqli_regex)) {
            ngx_waf_log_access(r, "Exiting check_sqli_chained_2 with attack detected");
            return log_and_reject(r, "Detects chained SQL injection attempts 2/2", "942310");
        }
    } catch (const std::regex_error &e) {
        ngx_waf_log_access(r, ("Regex error: " + std::string(e.what())).c_str());
    } catch (const std::exception &e) {
        ngx_waf_log_access(r, ("Exception: " + std::string(e.what())).c_str());
    }

    ngx_waf_log_access(r, "Exiting check_sqli_chained_2 with no attack detected");
    return false;
}

// Function to check Detects MySQL and PostgreSQL stored procedure/function injections (RuleId: 942320)
bool check_sqli_stored_procedure_injections(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_sqli_stored_procedure_injections");
    std::string query(reinterpret_cast<const char*>(r->args.data), r->args.len);

    std::string sqli_pattern = get_pattern_from_conf(r, "sqli_mysql_postgres_function_pattern");
    ngx_waf_log_access(r, ("SQL Injection Stored Procedure Injections Pattern: " + sqli_pattern).c_str());

    try {
        std::regex sqli_regex(sqli_pattern);
        ngx_waf_log_access(r, "Regex compiled successfully");

        if (std::regex_search(query, sqli_regex)) {
            ngx_waf_log_access(r, "Exiting check_sqli_stored_procedure_injections with attack detected");
            return log_and_reject(r, "Detects MySQL and PostgreSQL stored procedure/function injections", "942320");
        }
    } catch (const std::regex_error &e) {
        ngx_waf_log_access(r, ("Regex error: " + std::string(e.what())).c_str());
    } catch (const std::exception &e) {
        ngx_waf_log_access(r, ("Exception: " + std::string(e.what())).c_str());
    }

    ngx_waf_log_access(r, "Exiting check_sqli_stored_procedure_injections with no attack detected");
    return false;
}

// Function to check Detects classic SQL injection probings 1/2 (RuleId: 942330)
bool check_sqli_classic_probings_1(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_sqli_classic_probings_1");
    std::string query(reinterpret_cast<const char*>(r->args.data), r->args.len);

    std::string sqli_pattern = get_pattern_from_conf(r, "sqli_classic_injection_1_pattern");
    ngx_waf_log_access(r, ("SQL Injection Classic Probings 1 Pattern: " + sqli_pattern).c_str());

    try {
        std::regex sqli_regex(sqli_pattern);
        ngx_waf_log_access(r, "Regex compiled successfully");

        if (std::regex_search(query, sqli_regex)) {
            ngx_waf_log_access(r, "Exiting check_sqli_classic_probings_1 with attack detected");
            return log_and_reject(r, "Detects classic SQL injection probings 1/2", "942330");
        }
    } catch (const std::regex_error &e) {
        ngx_waf_log_access(r, ("Regex error: " + std::string(e.what())).c_str());
    } catch (const std::exception &e) {
        ngx_waf_log_access(r, ("Exception: " + std::string(e.what())).c_str());
    }

    ngx_waf_log_access(r, "Exiting check_sqli_classic_probings_1 with no attack detected");
    return false;
}

// Function to check Detects basic SQL authentication bypass attempts 3/3 (RuleId: 942340)
bool check_sqli_auth_bypass_3(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_sqli_auth_bypass_3");
    std::string query(reinterpret_cast<const char*>(r->args.data), r->args.len);

    std::string sqli_pattern = get_pattern_from_conf(r, "sqli_authentication_bypass_3_pattern");
    ngx_waf_log_access(r, ("SQL Injection Auth Bypass 3 Pattern: " + sqli_pattern).c_str());

    try {
        std::regex sqli_regex(sqli_pattern);
        ngx_waf_log_access(r, "Regex compiled successfully");

        if (std::regex_search(query, sqli_regex)) {
            ngx_waf_log_access(r, "Exiting check_sqli_auth_bypass_3 with attack detected");
            return log_and_reject(r, "Detects basic SQL authentication bypass attempts 3/3", "942340");
        }
    } catch (const std::regex_error &e) {
        ngx_waf_log_access(r, ("Regex error: " + std::string(e.what())).c_str());
    } catch (const std::exception &e) {
        ngx_waf_log_access(r, ("Exception: " + std::string(e.what())).c_str());
    }

    ngx_waf_log_access(r, "Exiting check_sqli_auth_bypass_3 with no attack detected");
    return false;
}

// Function to check Detects MySQL UDF injection and other data/structure manipulation attempts (RuleId: 942350)
bool check_sqli_udf_injection(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_sqli_udf_injection");
    std::string query(reinterpret_cast<const char*>(r->args.data), r->args.len);

    std::string sqli_pattern = get_pattern_from_conf(r, "sqli_mysql_udf_injection_pattern");
    ngx_waf_log_access(r, ("SQL Injection UDF Injection Pattern: " + sqli_pattern).c_str());

    try {
        std::regex sqli_regex(sqli_pattern);
        ngx_waf_log_access(r, "Regex compiled successfully");

        if (std::regex_search(query, sqli_regex)) {
            ngx_waf_log_access(r, "Exiting check_sqli_udf_injection with attack detected");
            return log_and_reject(r, "Detects MySQL UDF injection and other data/structure manipulation attempts", "942350");
        }
    } catch (const std::regex_error &e) {
        ngx_waf_log_access(r, ("Regex error: " + std::string(e.what())).c_str());
    } catch (const std::exception &e) {
        ngx_waf_log_access(r, ("Exception: " + std::string(e.what())).c_str());
    }

    ngx_waf_log_access(r, "Exiting check_sqli_udf_injection with no attack detected");
    return false;
}

// Function to check Detects concatenated basic SQL injection and SQLLFI attempts (RuleId: 942360)
bool check_sqli_concatenated_injection(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_sqli_concatenated_injection");
    std::string query(reinterpret_cast<const char*>(r->args.data), r->args.len);

    std::string sqli_pattern = get_pattern_from_conf(r, "sqli_concatenated_injection_pattern");
    ngx_waf_log_access(r, ("SQL Injection Concatenated Injection Pattern: " + sqli_pattern).c_str());

    try {
        std::regex sqli_regex(sqli_pattern);
        ngx_waf_log_access(r, "Regex compiled successfully");

        if (std::regex_search(query, sqli_regex)) {
            ngx_waf_log_access(r, "Exiting check_sqli_concatenated_injection with attack detected");
            return log_and_reject(r, "Detects concatenated basic SQL injection and SQLLFI attempts", "942360");
        }
    } catch (const std::regex_error &e) {
        ngx_waf_log_access(r, ("Regex error: " + std::string(e.what())).c_str());
    } catch (const std::exception &e) {
        ngx_waf_log_access(r, ("Exception: " + std::string(e.what())).c_str());
    }

    ngx_waf_log_access(r, "Exiting check_sqli_concatenated_injection with no attack detected");
    return false;
}

// Function to check Detects basic SQL injection based on keyword alter or union (RuleId: 942361)
bool check_sqli_keyword_alter_union(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_sqli_keyword_alter_union");
    std::string query(reinterpret_cast<const char*>(r->args.data), r->args.len);

    std::string sqli_pattern = get_pattern_from_conf(r, "sqli_keyword_alter_union_pattern");
    ngx_waf_log_access(r, ("SQL Injection Keyword Alter Union Pattern: " + sqli_pattern).c_str());

    try {
        std::regex sqli_regex(sqli_pattern);
        ngx_waf_log_access(r, "Regex compiled successfully");

        if (std::regex_search(query, sqli_regex)) {
            ngx_waf_log_access(r, "Exiting check_sqli_keyword_alter_union with attack detected");
            return log_and_reject(r, "Detects basic SQL injection based on keyword alter or union", "942361");
        }
    } catch (const std::regex_error &e) {
        ngx_waf_log_access(r, ("Regex error: " + std::string(e.what())).c_str());
    } catch (const std::exception &e) {
        ngx_waf_log_access(r, ("Exception: " + std::string(e.what())).c_str());
    }

    ngx_waf_log_access(r, "Exiting check_sqli_keyword_alter_union with no attack detected");
    return false;
}

// Function to check Detects classic SQL injection probings 2/2 (RuleId: 942370)
bool check_sqli_classic_probings_2(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_sqli_classic_probings_2");
    std::string query(reinterpret_cast<const char*>(r->args.data), r->args.len);

    std::string sqli_pattern = get_pattern_from_conf(r, "sqli_classic_injection_2_pattern");
    ngx_waf_log_access(r, ("SQL Injection Classic Probings 2 Pattern: " + sqli_pattern).c_str());

    try {
        std::regex sqli_regex(sqli_pattern);
        ngx_waf_log_access(r, "Regex compiled successfully");

        if (std::regex_search(query, sqli_regex)) {
            ngx_waf_log_access(r, "Exiting check_sqli_classic_probings_2 with attack detected");
            return log_and_reject(r, "Detects classic SQL injection probings 2/2", "942370");
        }
    } catch (const std::regex_error &e) {
        ngx_waf_log_access(r, ("Regex error: " + std::string(e.what())).c_str());
    } catch (const std::exception &e) {
        ngx_waf_log_access(r, ("Exception: " + std::string(e.what())).c_str());
    }

    ngx_waf_log_access(r, "Exiting check_sqli_classic_probings_2 with no attack detected");
    return false;
}

// Function to check Restricted SQL Character Anomaly Detection (args): # of special characters exceeded (12) (RuleId: 942430)
bool check_sqli_restricted_characters(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_sqli_restricted_characters");
    std::string query(reinterpret_cast<const char*>(r->args.data), r->args.len);

    std::string sqli_pattern = get_pattern_from_conf(r, "sqli_restricted_character_pattern");
    ngx_waf_log_access(r, ("SQL Injection Restricted Characters Pattern: " + sqli_pattern).c_str());

    try {
        std::regex sqli_regex(sqli_pattern);
        ngx_waf_log_access(r, "Regex compiled successfully");

        if (std::regex_search(query, sqli_regex)) {
            ngx_waf_log_access(r, "Exiting check_sqli_restricted_characters with attack detected");
            return log_and_reject(r, "Restricted SQL Character Anomaly Detection (args): # of special characters exceeded (12)", "942430");
        }
    } catch (const std::regex_error &e) {
        ngx_waf_log_access(r, ("Regex error: " + std::string(e.what())).c_str());
    } catch (const std::exception &e) {
        ngx_waf_log_access(r, ("Exception: " + std::string(e.what())).c_str());
    }

    ngx_waf_log_access(r, "Exiting check_sqli_restricted_characters with no attack detected");
    return false;
}

// Function to check SQL Comment Sequence Detected (RuleId: 942440)
bool check_sqli_comment_sequence(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_sqli_comment_sequence");
    std::string query(reinterpret_cast<const char*>(r->args.data), r->args.len);

    std::string sqli_pattern = get_pattern_from_conf(r, "sqli_comment_sequence_pattern");
    ngx_waf_log_access(r, ("SQL Injection Comment Sequence Pattern: " + sqli_pattern).c_str());

    try {
        std::regex sqli_regex(sqli_pattern);
        ngx_waf_log_access(r, "Regex compiled successfully");

        if (std::regex_search(query, sqli_regex)) {
            ngx_waf_log_access(r, "Exiting check_sqli_comment_sequence with attack detected");
            return log_and_reject(r, "SQL Comment Sequence Detected", "942440");
        }
    } catch (const std::regex_error &e) {
        ngx_waf_log_access(r, ("Regex error: " + std::string(e.what())).c_str());
    } catch (const std::exception &e) {
        ngx_waf_log_access(r, ("Exception: " + std::string(e.what())).c_str());
    }

    ngx_waf_log_access(r, "Exiting check_sqli_comment_sequence with no attack detected");
    return false;
}

// Function to check SQL Hex Encoding Identified (RuleId: 942450)
bool check_sqli_hex_encoding(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_sqli_hex_encoding");
    std::string query(reinterpret_cast<const char*>(r->args.data), r->args.len);

    std::string sqli_pattern = get_pattern_from_conf(r, "sqli_hex_encoding_pattern");
    ngx_waf_log_access(r, ("SQL Injection Hex Encoding Pattern: " + sqli_pattern).c_str());

    try {
        std::regex sqli_regex(sqli_pattern);
        ngx_waf_log_access(r, "Regex compiled successfully");

        if (std::regex_search(query, sqli_regex)) {
            ngx_waf_log_access(r, "Exiting check_sqli_hex_encoding with attack detected");
            return log_and_reject(r, "SQL Hex Encoding Identified", "942450");
        }
    } catch (const std::regex_error &e) {
        ngx_waf_log_access(r, ("Regex error: " + std::string(e.what())).c_str());
    } catch (const std::exception &e) {
        ngx_waf_log_access(r, ("Exception: " + std::string(e.what())).c_str());
    }

    ngx_waf_log_access(r, "Exiting check_sqli_hex_encoding with no attack detected");
    return false;
}

// Function to check Meta-Character Anomaly Detection Alert - Repetitive Non-Word Characters (RuleId: 942460)
bool check_sqli_meta_character_anomaly(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_sqli_meta_character_anomaly");
    std::string query(reinterpret_cast<const char*>(r->args.data), r->args.len);

    std::string sqli_pattern = get_pattern_from_conf(r, "sqli_meta_character_pattern");
    ngx_waf_log_access(r, ("SQL Injection Meta-Character Anomaly Pattern: " + sqli_pattern).c_str());

    try {
        std::regex sqli_regex(sqli_pattern);
        ngx_waf_log_access(r, "Regex compiled successfully");

        if (std::regex_search(query, sqli_regex)) {
            ngx_waf_log_access(r, "Exiting check_sqli_meta_character_anomaly with attack detected");
            return log_and_reject(r, "Meta-Character Anomaly Detection Alert - Repetitive Non-Word Characters", "942460");
        }
    } catch (const std::regex_error &e) {
        ngx_waf_log_access(r, ("Regex error: " + std::string(e.what())).c_str());
    } catch (const std::exception &e) {
        ngx_waf_log_access(r, ("Exception: " + std::string(e.what())).c_str());
    }

    ngx_waf_log_access(r, "Exiting check_sqli_meta_character_anomaly with no attack detected");
    return false;
}

// Function to check MySQL in-line comment detected (RuleId: 942500)
bool check_sqli_mysql_inline_comment(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_sqli_mysql_inline_comment");
    std::string query(reinterpret_cast<const char*>(r->args.data), r->args.len);

    std::string sqli_pattern = get_pattern_from_conf(r, "sqli_mysql_comment_obfuscation_pattern");
    ngx_waf_log_access(r, ("SQL Injection MySQL Inline Comment Pattern: " + sqli_pattern).c_str());

    try {
        std::regex sqli_regex(sqli_pattern);
        ngx_waf_log_access(r, "Regex compiled successfully");

        if (std::regex_search(query, sqli_regex)) {
            ngx_waf_log_access(r, "Exiting check_sqli_mysql_inline_comment with attack detected");
            return log_and_reject(r, "MySQL in-line comment detected", "942500");
        }
    } catch (const std::regex_error &e) {
        ngx_waf_log_access(r, ("Regex error: " + std::string(e.what())).c_str());
    } catch (const std::exception &e) {
        ngx_waf_log_access(r, ("Exception: " + std::string(e.what())).c_str());
    }

    ngx_waf_log_access(r, "Exiting check_sqli_mysql_inline_comment with no attack detected");
    return false;
}

// Function to check SQLi bypass attempt by ticks or backticks detected (RuleId: 942510)
bool check_sqli_ticks_backticks(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_sqli_ticks_backticks");
    std::string query(reinterpret_cast<const char*>(r->args.data), r->args.len);

    std::string sqli_pattern = get_pattern_from_conf(r, "sqli_bypass_ticks_pattern");
    ngx_waf_log_access(r, ("SQL Injection Ticks Backticks Pattern: " + sqli_pattern).c_str());

    try {
        std::regex sqli_regex(sqli_pattern);
        ngx_waf_log_access(r, "Regex compiled successfully");

        if (std::regex_search(query, sqli_regex)) {
            ngx_waf_log_access(r, "Exiting check_sqli_ticks_backticks with attack detected");
            return log_and_reject(r, "SQLi bypass attempt by ticks or backticks detected", "942510");
        }
    } catch (const std::regex_error &e) {
        ngx_waf_log_access(r, ("Regex error: " + std::string(e.what())).c_str());
    } catch (const std::exception &e) {
        ngx_waf_log_access(r, ("Exception: " + std::string(e.what())).c_str());
    }

    ngx_waf_log_access(r, "Exiting check_sqli_ticks_backticks with no attack detected");
    return false;
}

// Function to handle SQLI rules entry point
ngx_int_t sqli_rules_entry_point(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered sqli_rules_entry_point");

    if (check_sqli_libinjection(r)) return NGX_HTTP_FORBIDDEN;
    if (check_sqli_common_testing(r)) return NGX_HTTP_FORBIDDEN;
    if (check_sqli_operator(r)) return NGX_HTTP_FORBIDDEN;
    if (check_sqli_common_db_names(r)) return NGX_HTTP_FORBIDDEN;
    if (check_sqli_attack(r)) return NGX_HTTP_FORBIDDEN;
    if (check_sqli_blind_tests(r)) return NGX_HTTP_FORBIDDEN;
    if (check_sqli_benchmark_sleep(r)) return NGX_HTTP_FORBIDDEN;
    if (check_sqli_auth_bypass_1(r)) return NGX_HTTP_FORBIDDEN;
    if (check_sqli_mssql_code_exec(r)) return NGX_HTTP_FORBIDDEN;
    if (check_sqli_mysql_comment_obfuscated(r)) return NGX_HTTP_FORBIDDEN;
    if (check_sqli_chained_1(r)) return NGX_HTTP_FORBIDDEN;
    if (check_sqli_conditional_attempts(r)) return NGX_HTTP_FORBIDDEN;
    if (check_sqli_charset_switch_dos(r)) return NGX_HTTP_FORBIDDEN;
    if (check_sqli_match_against_merge_execute(r)) return NGX_HTTP_FORBIDDEN;
    if (check_sqli_auth_bypass_2(r)) return NGX_HTTP_FORBIDDEN;
    if (check_sqli_common_attack_string(r)) return NGX_HTTP_FORBIDDEN;
    if (check_sqli_pg_sleep(r)) return NGX_HTTP_FORBIDDEN;
    if (check_sqli_mongodb_injection(r)) return NGX_HTTP_FORBIDDEN;
    if (check_sqli_mysql_comments_conditions(r)) return NGX_HTTP_FORBIDDEN;
    if (check_sqli_chained_2(r)) return NGX_HTTP_FORBIDDEN;
    if (check_sqli_stored_procedure_injections(r)) return NGX_HTTP_FORBIDDEN;
    if (check_sqli_classic_probings_1(r)) return NGX_HTTP_FORBIDDEN;
    if (check_sqli_auth_bypass_3(r)) return NGX_HTTP_FORBIDDEN;
    if (check_sqli_udf_injection(r)) return NGX_HTTP_FORBIDDEN;
    if (check_sqli_concatenated_injection(r)) return NGX_HTTP_FORBIDDEN;
    if (check_sqli_keyword_alter_union(r)) return NGX_HTTP_FORBIDDEN;
    if (check_sqli_classic_probings_2(r)) return NGX_HTTP_FORBIDDEN;
    if (check_sqli_restricted_characters(r)) return NGX_HTTP_FORBIDDEN;
    if (check_sqli_comment_sequence(r)) return NGX_HTTP_FORBIDDEN;
    if (check_sqli_meta_character_anomaly(r)) return NGX_HTTP_FORBIDDEN;
    if (check_sqli_mysql_inline_comment(r)) return NGX_HTTP_FORBIDDEN;
    if (check_sqli_ticks_backticks(r)) return NGX_HTTP_FORBIDDEN;

    ngx_waf_log_access(r, "Exiting sqli_rules_entry_point with no attack detected");
    return NGX_DECLINED;
}
