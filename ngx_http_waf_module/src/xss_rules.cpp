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

// Function to check XSS Attack Detected via libinjection (RuleId: 941100)
bool check_xss_libinjection(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_xss_libinjection");
    std::string query(reinterpret_cast<const char*>(r->args.data), r->args.len);

    std::string xss_pattern = get_pattern_from_conf(r, "xss_libinjection_pattern");
    ngx_waf_log_access(r, ("XSS libinjection Pattern: " + xss_pattern).c_str());

    try {
        std::regex xss_regex(xss_pattern);
        ngx_waf_log_access(r, "Regex compiled successfully");

        if (std::regex_search(query, xss_regex)) {
            ngx_waf_log_access(r, "Exiting check_xss_libinjection with attack detected");
            return log_and_reject(r, "XSS Attack Detected via libinjection", "941100");
        }
    } catch (const std::regex_error &e) {
        ngx_waf_log_access(r, ("Regex error: " + std::string(e.what())).c_str());
    } catch (const std::exception &e) {
        ngx_waf_log_access(r, ("Exception: " + std::string(e.what())).c_str());
    }

    ngx_waf_log_access(r, "Exiting check_xss_libinjection with no attack detected");
    return false;
}

// Function to check XSS Attack Detected via libinjection (RuleId: 941101)
bool check_xss_libinjection_101(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_xss_libinjection_101");
    std::string query(reinterpret_cast<const char*>(r->args.data), r->args.len);

    std::string xss_pattern = get_pattern_from_conf(r, "xss_libinjection_101_pattern");
    ngx_waf_log_access(r, ("XSS libinjection 101 Pattern: " + xss_pattern).c_str());

    try {
        std::regex xss_regex(xss_pattern);
        ngx_waf_log_access(r, "Regex compiled successfully");

        if (std::regex_search(query, xss_regex)) {
            ngx_waf_log_access(r, "Exiting check_xss_libinjection_101 with attack detected");
            return log_and_reject(r, "XSS Attack Detected via libinjection", "941101");
        }
    } catch (const std::regex_error &e) {
        ngx_waf_log_access(r, ("Regex error: " + std::string(e.what())).c_str());
    } catch (const std::exception &e) {
        ngx_waf_log_access(r, ("Exception: " + std::string(e.what())).c_str());
    }

    ngx_waf_log_access(r, "Exiting check_xss_libinjection_101 with no attack detected");
    return false;
}

// Function to check XSS Filter - Category 1: Script Tag Vector (RuleId: 941110)
bool check_xss_script_tag_vector(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_xss_script_tag_vector");
    std::string query(reinterpret_cast<const char*>(r->args.data), r->args.len);

    std::string xss_pattern = get_pattern_from_conf(r, "xss_script_tag_vector_pattern");
    ngx_waf_log_access(r, ("XSS Script Tag Vector Pattern: " + xss_pattern).c_str());

    try {
        std::regex xss_regex(xss_pattern);
        ngx_waf_log_access(r, "Regex compiled successfully");

        if (std::regex_search(query, xss_regex)) {
            ngx_waf_log_access(r, "Exiting check_xss_script_tag_vector with attack detected");
            return log_and_reject(r, "XSS Filter - Category 1: Script Tag Vector", "941110");
        }
    } catch (const std::regex_error &e) {
        ngx_waf_log_access(r, ("Regex error: " + std::string(e.what())).c_str());
    } catch (const std::exception &e) {
        ngx_waf_log_access(r, ("Exception: " + std::string(e.what())).c_str());
    }

    ngx_waf_log_access(r, "Exiting check_xss_script_tag_vector with no attack detected");
    return false;
}

// Function to check XSS Filter - Category 2: Event Handler Vector (RuleId: 941120)
bool check_xss_event_handler_vector(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_xss_event_handler_vector");
    std::string query(reinterpret_cast<const char*>(r->args.data), r->args.len);

    std::string xss_pattern = get_pattern_from_conf(r, "xss_event_handler_vector_pattern");
    ngx_waf_log_access(r, ("XSS Event Handler Vector Pattern: " + xss_pattern).c_str());

    try {
        std::regex xss_regex(xss_pattern);
        ngx_waf_log_access(r, "Regex compiled successfully");

        if (std::regex_search(query, xss_regex)) {
            ngx_waf_log_access(r, "Exiting check_xss_event_handler_vector with attack detected");
            return log_and_reject(r, "XSS Filter - Category 2: Event Handler Vector", "941120");
        }
    } catch (const std::regex_error &e) {
        ngx_waf_log_access(r, ("Regex error: " + std::string(e.what())).c_str());
    } catch (const std::exception &e) {
        ngx_waf_log_access(r, ("Exception: " + std::string(e.what())).c_str());
    }

    ngx_waf_log_access(r, "Exiting check_xss_event_handler_vector with no attack detected");
    return false;
}

// Function to check XSS Filter - Category 3: Attribute Vector (RuleId: 941130)
bool check_xss_attribute_vector(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_xss_attribute_vector");
    std::string query(reinterpret_cast<const char*>(r->args.data), r->args.len);

    std::string xss_pattern = get_pattern_from_conf(r, "xss_attribute_vector_pattern");
    ngx_waf_log_access(r, ("XSS Attribute Vector Pattern: " + xss_pattern).c_str());

    try {
        std::regex xss_regex(xss_pattern);
        ngx_waf_log_access(r, "Regex compiled successfully");

        if (std::regex_search(query, xss_regex)) {
            ngx_waf_log_access(r, "Exiting check_xss_attribute_vector with attack detected");
            return log_and_reject(r, "XSS Filter - Category 3: Attribute Vector", "941130");
        }
    } catch (const std::regex_error &e) {
        ngx_waf_log_access(r, ("Regex error: " + std::string(e.what())).c_str());
    } catch (const std::exception &e) {
        ngx_waf_log_access(r, ("Exception: " + std::string(e.what())).c_str());
    }

    ngx_waf_log_access(r, "Exiting check_xss_attribute_vector with no attack detected");
    return false;
}

// Function to check XSS Filter - Category 4: JavaScript URI Vector (RuleId: 941140)
bool check_xss_js_uri_vector(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_xss_js_uri_vector");
    std::string query(reinterpret_cast<const char*>(r->args.data), r->args.len);

    std::string xss_pattern = get_pattern_from_conf(r, "xss_js_uri_vector_pattern");
    ngx_waf_log_access(r, ("XSS JS URI Vector Pattern: " + xss_pattern).c_str());

    try {
        std::regex xss_regex(xss_pattern);
        ngx_waf_log_access(r, "Regex compiled successfully");

        if (std::regex_search(query, xss_regex)) {
            ngx_waf_log_access(r, "Exiting check_xss_js_uri_vector with attack detected");
            return log_and_reject(r, "XSS Filter - Category 4: JavaScript URI Vector", "941140");
        }
    } catch (const std::regex_error &e) {
        ngx_waf_log_access(r, ("Regex error: " + std::string(e.what())).c_str());
    } catch (const std::exception &e) {
        ngx_waf_log_access(r, ("Exception: " + std::string(e.what())).c_str());
    }

    ngx_waf_log_access(r, "Exiting check_xss_js_uri_vector with no attack detected");
    return false;
}

// Function to check XSS Filter - Category 5: Disallowed HTML Attributes (RuleId: 941150)
bool check_xss_disallowed_html_attributes(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_xss_disallowed_html_attributes");
    std::string query(reinterpret_cast<const char*>(r->args.data), r->args.len);

    std::string xss_pattern = get_pattern_from_conf(r, "xss_disallowed_html_attributes_pattern");
    ngx_waf_log_access(r, ("XSS Disallowed HTML Attributes Pattern: " + xss_pattern).c_str());

    try {
        std::regex xss_regex(xss_pattern);
        ngx_waf_log_access(r, "Regex compiled successfully");

        if (std::regex_search(query, xss_regex)) {
            ngx_waf_log_access(r, "Exiting check_xss_disallowed_html_attributes with attack detected");
            return log_and_reject(r, "XSS Filter - Category 5: Disallowed HTML Attributes", "941150");
        }
    } catch (const std::regex_error &e) {
        ngx_waf_log_access(r, ("Regex error: " + std::string(e.what())).c_str());
    } catch (const std::exception &e) {
        ngx_waf_log_access(r, ("Exception: " + std::string(e.what())).c_str());
    }

    ngx_waf_log_access(r, "Exiting check_xss_disallowed_html_attributes with no attack detected");
    return false;
}

// Function to check NoScript XSS InjectionChecker: HTML Injection (RuleId: 941160)
bool check_xss_html_injection(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_xss_html_injection");
    std::string query(reinterpret_cast<const char*>(r->args.data), r->args.len);

    std::string xss_pattern = get_pattern_from_conf(r, "xss_html_injection_pattern");
    ngx_waf_log_access(r, ("XSS HTML Injection Pattern: " + xss_pattern).c_str());

    try {
        std::regex xss_regex(xss_pattern);
        ngx_waf_log_access(r, "Regex compiled successfully");

        if (std::regex_search(query, xss_regex)) {
            ngx_waf_log_access(r, "Exiting check_xss_html_injection with attack detected");
            return log_and_reject(r, "NoScript XSS InjectionChecker: HTML Injection", "941160");
        }
    } catch (const std::regex_error &e) {
        ngx_waf_log_access(r, ("Regex error: " + std::string(e.what())).c_str());
    } catch (const std::exception &e) {
        ngx_waf_log_access(r, ("Exception: " + std::string(e.what())).c_str());
    }

    ngx_waf_log_access(r, "Exiting check_xss_html_injection with no attack detected");
    return false;
}

// Function to check NoScript XSS InjectionChecker: Attribute Injection (RuleId: 941170)
bool check_xss_attribute_injection(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_xss_attribute_injection");
    std::string query(reinterpret_cast<const char*>(r->args.data), r->args.len);

    std::string xss_pattern = get_pattern_from_conf(r, "xss_attribute_injection_pattern");
    ngx_waf_log_access(r, ("XSS Attribute Injection Pattern: " + xss_pattern).c_str());

    try {
        std::regex xss_regex(xss_pattern);
        ngx_waf_log_access(r, "Regex compiled successfully");

        if (std::regex_search(query, xss_regex)) {
            ngx_waf_log_access(r, "Exiting check_xss_attribute_injection with attack detected");
            return log_and_reject(r, "NoScript XSS InjectionChecker: Attribute Injection", "941170");
        }
    } catch (const std::regex_error &e) {
        ngx_waf_log_access(r, ("Regex error: " + std::string(e.what())).c_str());
    } catch (const std::exception &e) {
        ngx_waf_log_access(r, ("Exception: " + std::string(e.what())).c_str());
    }

    ngx_waf_log_access(r, "Exiting check_xss_attribute_injection with no attack detected");
    return false;
}

// Function to check Node-Validator Blocklist Keywords (RuleId: 941180)
bool check_xss_node_validator_blocklist(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_xss_node_validator_blocklist");
    std::string query(reinterpret_cast<const char*>(r->args.data), r->args.len);

    std::string xss_pattern = get_pattern_from_conf(r, "xss_node_validator_blocklist_pattern");
    ngx_waf_log_access(r, ("XSS Node Validator Blocklist Pattern: " + xss_pattern).c_str());

    try {
        std::regex xss_regex(xss_pattern);
        ngx_waf_log_access(r, "Regex compiled successfully");

        if (std::regex_search(query, xss_regex)) {
            ngx_waf_log_access(r, "Exiting check_xss_node_validator_blocklist with attack detected");
            return log_and_reject(r, "Node-Validator Blocklist Keywords", "941180");
        }
    } catch (const std::regex_error &e) {
        ngx_waf_log_access(r, ("Regex error: " + std::string(e.what())).c_str());
    } catch (const std::exception &e) {
        ngx_waf_log_access(r, ("Exception: " + std::string(e.what())).c_str());
    }

    ngx_waf_log_access(r, "Exiting check_xss_node_validator_blocklist with no attack detected");
    return false;
}

// Function to check XSS using style sheets (RuleId: 941190)
bool check_xss_using_stylesheets(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_xss_using_stylesheets");
    std::string query(reinterpret_cast<const char*>(r->args.data), r->args.len);

    std::string xss_pattern = get_pattern_from_conf(r, "xss_using_stylesheets_pattern");
    ngx_waf_log_access(r, ("XSS using stylesheets Pattern: " + xss_pattern).c_str());

    try {
        std::regex xss_regex(xss_pattern);
        ngx_waf_log_access(r, "Regex compiled successfully");

        if (std::regex_search(query, xss_regex)) {
            ngx_waf_log_access(r, "Exiting check_xss_using_stylesheets with attack detected");
            return log_and_reject(r, "XSS using style sheets", "941190");
        }
    } catch (const std::regex_error &e) {
        ngx_waf_log_access(r, ("Regex error: " + std::string(e.what())).c_str());
    } catch (const std::exception &e) {
        ngx_waf_log_access(r, ("Exception: " + std::string(e.what())).c_str());
    }

    ngx_waf_log_access(r, "Exiting check_xss_using_stylesheets with no attack detected");
    return false;
}

// Function to check XSS using VML frames (RuleId: 941200)
bool check_xss_using_vml_frames(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_xss_using_vml_frames");
    std::string query(reinterpret_cast<const char*>(r->args.data), r->args.len);

    std::string xss_pattern = get_pattern_from_conf(r, "xss_using_vml_frames_pattern");
    ngx_waf_log_access(r, ("XSS using VML frames Pattern: " + xss_pattern).c_str());

    try {
        std::regex xss_regex(xss_pattern);
        ngx_waf_log_access(r, "Regex compiled successfully");

        if (std::regex_search(query, xss_regex)) {
            ngx_waf_log_access(r, "Exiting check_xss_using_vml_frames with attack detected");
            return log_and_reject(r, "XSS using VML frames", "941200");
        }
    } catch (const std::regex_error &e) {
        ngx_waf_log_access(r, ("Regex error: " + std::string(e.what())).c_str());
    } catch (const std::exception &e) {
        ngx_waf_log_access(r, ("Exception: " + std::string(e.what())).c_str());
    }

    ngx_waf_log_access(r, "Exiting check_xss_using_vml_frames with no attack detected");
    return false;
}

// Function to check XSS using obfuscated JavaScript (RuleId: 941210)
bool check_xss_obfuscated_javascript(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_xss_obfuscated_javascript");
    std::string query(reinterpret_cast<const char*>(r->args.data), r->args.len);

    std::string xss_pattern = get_pattern_from_conf(r, "xss_obfuscated_javascript_pattern");
    ngx_waf_log_access(r, ("XSS Obfuscated JavaScript Pattern: " + xss_pattern).c_str());

    try {
        std::regex xss_regex(xss_pattern);
        ngx_waf_log_access(r, "Regex compiled successfully");

        if (std::regex_search(query, xss_regex)) {
            ngx_waf_log_access(r, "Exiting check_xss_obfuscated_javascript with attack detected");
            return log_and_reject(r, "XSS using obfuscated JavaScript", "941210");
        }
    } catch (const std::regex_error &e) {
        ngx_waf_log_access(r, ("Regex error: " + std::string(e.what())).c_str());
    } catch (const std::exception &e) {
        ngx_waf_log_access(r, ("Exception: " + std::string(e.what())).c_str());
    }

    ngx_waf_log_access(r, "Exiting check_xss_obfuscated_javascript with no attack detected");
    return false;
}

// Function to check XSS using obfuscated VB Script (RuleId: 941220)
bool check_xss_obfuscated_vbscript(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_xss_obfuscated_vbscript");
    std::string query(reinterpret_cast<const char*>(r->args.data), r->args.len);

    std::string xss_pattern = get_pattern_from_conf(r, "xss_obfuscated_vbscript_pattern");
    ngx_waf_log_access(r, ("XSS Obfuscated VB Script Pattern: " + xss_pattern).c_str());

    try {
        std::regex xss_regex(xss_pattern);
        ngx_waf_log_access(r, "Regex compiled successfully");

        if (std::regex_search(query, xss_regex)) {
            ngx_waf_log_access(r, "Exiting check_xss_obfuscated_vbscript with attack detected");
            return log_and_reject(r, "XSS using obfuscated VB Script", "941220");
        }
    } catch (const std::regex_error &e) {
        ngx_waf_log_access(r, ("Regex error: " + std::string(e.what())).c_str());
    } catch (const std::exception &e) {
        ngx_waf_log_access(r, ("Exception: " + std::string(e.what())).c_str());
    }

    ngx_waf_log_access(r, "Exiting check_xss_obfuscated_vbscript with no attack detected");
    return false;
}

// Function to check XSS using embed tag (RuleId: 941230)
bool check_xss_using_embed_tag(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_xss_using_embed_tag");
    std::string query(reinterpret_cast<const char*>(r->args.data), r->args.len);

    std::string xss_pattern = get_pattern_from_conf(r, "xss_using_embed_tag_pattern");
    ngx_waf_log_access(r, ("XSS using embed tag Pattern: " + xss_pattern).c_str());

    try {
        std::regex xss_regex(xss_pattern);
        ngx_waf_log_access(r, "Regex compiled successfully");

        if (std::regex_search(query, xss_regex)) {
            ngx_waf_log_access(r, "Exiting check_xss_using_embed_tag with attack detected");
            return log_and_reject(r, "XSS using embed tag", "941230");
        }
    } catch (const std::regex_error &e) {
        ngx_waf_log_access(r, ("Regex error: " + std::string(e.what())).c_str());
    } catch (const std::exception &e) {
        ngx_waf_log_access(r, ("Exception: " + std::string(e.what())).c_str());
    }

    ngx_waf_log_access(r, "Exiting check_xss_using_embed_tag with no attack detected");
    return false;
}

// Function to check XSS using import or implementation attribute (RuleId: 941240)
bool check_xss_using_import_attribute(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_xss_using_import_attribute");
    std::string query(reinterpret_cast<const char*>(r->args.data), r->args.len);

    std::string xss_pattern = get_pattern_from_conf(r, "xss_using_import_attribute_pattern");
    ngx_waf_log_access(r, ("XSS using import attribute Pattern: " + xss_pattern).c_str());

    try {
        std::regex xss_regex(xss_pattern);
        ngx_waf_log_access(r, "Regex compiled successfully");

        if (std::regex_search(query, xss_regex)) {
            ngx_waf_log_access(r, "Exiting check_xss_using_import_attribute with attack detected");
            return log_and_reject(r, "XSS using import or implementation attribute", "941240");
        }
    } catch (const std::regex_error &e) {
        ngx_waf_log_access(r, ("Regex error: " + std::string(e.what())).c_str());
    } catch (const std::exception &e) {
        ngx_waf_log_access(r, ("Exception: " + std::string(e.what())).c_str());
    }

    ngx_waf_log_access(r, "Exiting check_xss_using_import_attribute with no attack detected");
    return false;
}

// Function to check IE XSS Filters - Attack Detected (RuleId: 941250)
bool check_xss_ie_filters(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_xss_ie_filters");
    std::string query(reinterpret_cast<const char*>(r->args.data), r->args.len);

    std::string xss_pattern = get_pattern_from_conf(r, "xss_ie_filters_pattern");
    ngx_waf_log_access(r, ("XSS IE Filters Pattern: " + xss_pattern).c_str());

    try {
        std::regex xss_regex(xss_pattern);
        ngx_waf_log_access(r, "Regex compiled successfully");

        if (std::regex_search(query, xss_regex)) {
            ngx_waf_log_access(r, "Exiting check_xss_ie_filters with attack detected");
            return log_and_reject(r, "IE XSS Filters - Attack Detected", "941250");
        }
    } catch (const std::regex_error &e) {
        ngx_waf_log_access(r, ("Regex error: " + std::string(e.what())).c_str());
    } catch (const std::exception &e) {
        ngx_waf_log_access(r, ("Exception: " + std::string(e.what())).c_str());
    }

    ngx_waf_log_access(r, "Exiting check_xss_ie_filters with no attack detected");
    return false;
}

// Function to check XSS using meta tag (RuleId: 941260)
bool check_xss_using_meta_tag(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_xss_using_meta_tag");
    std::string query(reinterpret_cast<const char*>(r->args.data), r->args.len);

    std::string xss_pattern = get_pattern_from_conf(r, "xss_using_meta_tag_pattern");
    ngx_waf_log_access(r, ("XSS using meta tag Pattern: " + xss_pattern).c_str());

    try {
        std::regex xss_regex(xss_pattern);
        ngx_waf_log_access(r, "Regex compiled successfully");

        if (std::regex_search(query, xss_regex)) {
            ngx_waf_log_access(r, "Exiting check_xss_using_meta_tag with attack detected");
            return log_and_reject(r, "XSS using meta tag", "941260");
        }
    } catch (const std::regex_error &e) {
        ngx_waf_log_access(r, ("Regex error: " + std::string(e.what())).c_str());
    } catch (const std::exception &e) {
        ngx_waf_log_access(r, ("Exception: " + std::string(e.what())).c_str());
    }

    ngx_waf_log_access(r, "Exiting check_xss_using_meta_tag with no attack detected");
    return false;
}

// Function to check XSS using link href (RuleId: 941270)
bool check_xss_using_link_href(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_xss_using_link_href");
    std::string query(reinterpret_cast<const char*>(r->args.data), r->args.len);

    std::string xss_pattern = get_pattern_from_conf(r, "xss_using_link_href_pattern");
    ngx_waf_log_access(r, ("XSS using link href Pattern: " + xss_pattern).c_str());

    try {
        std::regex xss_regex(xss_pattern);
        ngx_waf_log_access(r, "Regex compiled successfully");

        if (std::regex_search(query, xss_regex)) {
            ngx_waf_log_access(r, "Exiting check_xss_using_link_href with attack detected");
            return log_and_reject(r, "XSS using link href", "941270");
        }
    } catch (const std::regex_error &e) {
        ngx_waf_log_access(r, ("Regex error: " + std::string(e.what())).c_str());
    } catch (const std::exception &e) {
        ngx_waf_log_access(r, ("Exception: " + std::string(e.what())).c_str());
    }

    ngx_waf_log_access(r, "Exiting check_xss_using_link_href with no attack detected");
    return false;
}

// Function to check XSS using base tag (RuleId: 941280)
bool check_xss_using_base_tag(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_xss_using_base_tag");
    std::string query(reinterpret_cast<const char*>(r->args.data), r->args.len);

    std::string xss_pattern = get_pattern_from_conf(r, "xss_using_base_tag_pattern");
    ngx_waf_log_access(r, ("XSS using base tag Pattern: " + xss_pattern).c_str());

    try {
        std::regex xss_regex(xss_pattern);
        ngx_waf_log_access(r, "Regex compiled successfully");

        if (std::regex_search(query, xss_regex)) {
            ngx_waf_log_access(r, "Exiting check_xss_using_base_tag with attack detected");
            return log_and_reject(r, "XSS using base tag", "941280");
        }
    } catch (const std::regex_error &e) {
        ngx_waf_log_access(r, ("Regex error: " + std::string(e.what())).c_str());
    } catch (const std::exception &e) {
        ngx_waf_log_access(r, ("Exception: " + std::string(e.what())).c_str());
    }

    ngx_waf_log_access(r, "Exiting check_xss_using_base_tag with no attack detected");
    return false;
}

// Function to check XSS using applet tag (RuleId: 941290)
bool check_xss_using_applet_tag(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_xss_using_applet_tag");
    std::string query(reinterpret_cast<const char*>(r->args.data), r->args.len);

    std::string xss_pattern = get_pattern_from_conf(r, "xss_using_applet_tag_pattern");
    ngx_waf_log_access(r, ("XSS using applet tag Pattern: " + xss_pattern).c_str());

    try {
        std::regex xss_regex(xss_pattern);
        ngx_waf_log_access(r, "Regex compiled successfully");

        if (std::regex_search(query, xss_regex)) {
            ngx_waf_log_access(r, "Exiting check_xss_using_applet_tag with attack detected");
            return log_and_reject(r, "XSS using applet tag", "941290");
        }
    } catch (const std::regex_error &e) {
        ngx_waf_log_access(r, ("Regex error: " + std::string(e.what())).c_str());
    } catch (const std::exception &e) {
        ngx_waf_log_access(r, ("Exception: " + std::string(e.what())).c_str());
    }

    ngx_waf_log_access(r, "Exiting check_xss_using_applet_tag with no attack detected");
    return false;
}

// Function to check US-ASCII Malformed Encoding XSS Filter - Attack Detected (RuleId: 941300)
bool check_xss_us_ascii_encoding(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_xss_us_ascii_encoding");
    std::string query(reinterpret_cast<const char*>(r->args.data), r->args.len);

    std::string xss_pattern = get_pattern_from_conf(r, "xss_us_ascii_encoding_pattern");
    ngx_waf_log_access(r, ("US-ASCII Malformed Encoding XSS Pattern: " + xss_pattern).c_str());

    try {
        std::regex xss_regex(xss_pattern);
        ngx_waf_log_access(r, "Regex compiled successfully");

        if (std::regex_search(query, xss_regex)) {
            ngx_waf_log_access(r, "Exiting check_xss_us_ascii_encoding with attack detected");
            return log_and_reject(r, "US-ASCII Malformed Encoding XSS Filter - Attack Detected", "941300");
        }
    } catch (const std::regex_error &e) {
        ngx_waf_log_access(r, ("Regex error: " + std::string(e.what())).c_str());
    } catch (const std::exception &e) {
        ngx_waf_log_access(r, ("Exception: " + std::string(e.what())).c_str());
    }

    ngx_waf_log_access(r, "Exiting check_xss_us_ascii_encoding with no attack detected");
    return false;
}

// Function to check Possible XSS Attack Detected - HTML Tag Handler (RuleId: 941310)
bool check_xss_html_tag_handler(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_xss_html_tag_handler");
    std::string query(reinterpret_cast<const char*>(r->args.data), r->args.len);

    std::string xss_pattern = get_pattern_from_conf(r, "xss_html_tag_handler_pattern");
    ngx_waf_log_access(r, ("XSS HTML Tag Handler Pattern: " + xss_pattern).c_str());

    try {
        std::regex xss_regex(xss_pattern);
        ngx_waf_log_access(r, "Regex compiled successfully");

        if (std::regex_search(query, xss_regex)) {
            ngx_waf_log_access(r, "Exiting check_xss_html_tag_handler with attack detected");
            return log_and_reject(r, "Possible XSS Attack Detected - HTML Tag Handler", "941310");
        }
    } catch (const std::regex_error &e) {
        ngx_waf_log_access(r, ("Regex error: " + std::string(e.what())).c_str());
    } catch (const std::exception &e) {
        ngx_waf_log_access(r, ("Exception: " + std::string(e.what())).c_str());
    }

    ngx_waf_log_access(r, "Exiting check_xss_html_tag_handler with no attack detected");
    return false;
}

// Function to check IE XSS Filters - Attack Detected (RuleId: 941320)
bool check_xss_ie_filters_320(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_xss_ie_filters_320");
    std::string query(reinterpret_cast<const char*>(r->args.data), r->args.len);

    std::string xss_pattern = get_pattern_from_conf(r, "xss_ie_filters_320_pattern");
    ngx_waf_log_access(r, ("XSS IE Filters 320 Pattern: " + xss_pattern).c_str());

    try {
        std::regex xss_regex(xss_pattern);
        ngx_waf_log_access(r, "Regex compiled successfully");

        if (std::regex_search(query, xss_regex)) {
            ngx_waf_log_access(r, "Exiting check_xss_ie_filters_320 with attack detected");
            return log_and_reject(r, "IE XSS Filters - Attack Detected", "941320");
        }
    } catch (const std::regex_error &e) {
        ngx_waf_log_access(r, ("Regex error: " + std::string(e.what())).c_str());
    } catch (const std::exception &e) {
        ngx_waf_log_access(r, ("Exception: " + std::string(e.what())).c_str());
    }

    ngx_waf_log_access(r, "Exiting check_xss_ie_filters_320 with no attack detected");
    return false;
}

// Function to check IE XSS Filters - Attack Detected (RuleId: 941330)
bool check_xss_ie_filters_330(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_xss_ie_filters_330");
    std::string query(reinterpret_cast<const char*>(r->args.data), r->args.len);

    std::string xss_pattern = get_pattern_from_conf(r, "xss_ie_filters_330_pattern");
    ngx_waf_log_access(r, ("XSS IE Filters 330 Pattern: " + xss_pattern).c_str());

    try {
        std::regex xss_regex(xss_pattern);
        ngx_waf_log_access(r, "Regex compiled successfully");

        if (std::regex_search(query, xss_regex)) {
            ngx_waf_log_access(r, "Exiting check_xss_ie_filters_330 with attack detected");
            return log_and_reject(r, "IE XSS Filters - Attack Detected", "941330");
        }
    } catch (const std::regex_error &e) {
        ngx_waf_log_access(r, ("Regex error: " + std::string(e.what())).c_str());
    } catch (const std::exception &e) {
        ngx_waf_log_access(r, ("Exception: " + std::string(e.what())).c_str());
    }

    ngx_waf_log_access(r, "Exiting check_xss_ie_filters_330 with no attack detected");
    return false;
}

// Function to check IE XSS Filters - Attack Detected (RuleId: 941340)
bool check_xss_ie_filters_340(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_xss_ie_filters_340");
    std::string query(reinterpret_cast<const char*>(r->args.data), r->args.len);

    std::string xss_pattern = get_pattern_from_conf(r, "xss_ie_filters_340_pattern");
    ngx_waf_log_access(r, ("XSS IE Filters 340 Pattern: " + xss_pattern).c_str());

    try {
        std::regex xss_regex(xss_pattern);
        ngx_waf_log_access(r, "Regex compiled successfully");

        if (std::regex_search(query, xss_regex)) {
            ngx_waf_log_access(r, "Exiting check_xss_ie_filters_340 with attack detected");
            return log_and_reject(r, "IE XSS Filters - Attack Detected", "941340");
        }
    } catch (const std::regex_error &e) {
        ngx_waf_log_access(r, ("Regex error: " + std::string(e.what())).c_str());
    } catch (const std::exception &e) {
        ngx_waf_log_access(r, ("Exception: " + std::string(e.what())).c_str());
    }

    ngx_waf_log_access(r, "Exiting check_xss_ie_filters_340 with no attack detected");
    return false;
}

// Function to check UTF-7 Encoding IE XSS - Attack Detected (RuleId: 941350)
bool check_xss_utf7_encoding(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_xss_utf7_encoding");
    std::string query(reinterpret_cast<const char*>(r->args.data), r->args.len);

    std::string xss_pattern = get_pattern_from_conf(r, "xss_utf7_encoding_pattern");
    ngx_waf_log_access(r, ("UTF-7 Encoding IE XSS Pattern: " + xss_pattern).c_str());

    try {
        std::regex xss_regex(xss_pattern);
        ngx_waf_log_access(r, "Regex compiled successfully");

        if (std::regex_search(query, xss_regex)) {
            ngx_waf_log_access(r, "Exiting check_xss_utf7_encoding with attack detected");
            return log_and_reject(r, "UTF-7 Encoding IE XSS - Attack Detected", "941350");
        }
    } catch (const std::regex_error &e) {
        ngx_waf_log_access(r, ("Regex error: " + std::string(e.what())).c_str());
    } catch (const std::exception &e) {
        ngx_waf_log_access(r, ("Exception: " + std::string(e.what())).c_str());
    }

    ngx_waf_log_access(r, "Exiting check_xss_utf7_encoding with no attack detected");
    return false;
}

// Function to check JavaScript obfuscation detected (RuleId: 941360)
bool check_xss_js_obfuscation(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_xss_js_obfuscation");
    std::string query(reinterpret_cast<const char*>(r->args.data), r->args.len);

    std::string xss_pattern = get_pattern_from_conf(r, "xss_js_obfuscation_pattern");
    ngx_waf_log_access(r, ("JavaScript Obfuscation Pattern: " + xss_pattern).c_str());

    try {
        std::regex xss_regex(xss_pattern);
        ngx_waf_log_access(r, "Regex compiled successfully");

        if (std::regex_search(query, xss_regex)) {
            ngx_waf_log_access(r, "Exiting check_xss_js_obfuscation with attack detected");
            return log_and_reject(r, "JavaScript obfuscation detected", "941360");
        }
    } catch (const std::regex_error &e) {
        ngx_waf_log_access(r, ("Regex error: " + std::string(e.what())).c_str());
    } catch (const std::exception &e) {
        ngx_waf_log_access(r, ("Exception: " + std::string(e.what())).c_str());
    }

    ngx_waf_log_access(r, "Exiting check_xss_js_obfuscation with no attack detected");
    return false;
}

// Function to check JavaScript global variable found (RuleId: 941370)
bool check_xss_js_global_variable(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_xss_js_global_variable");
    std::string query(reinterpret_cast<const char*>(r->args.data), r->args.len);

    std::string xss_pattern = get_pattern_from_conf(r, "xss_js_global_variable_pattern");
    ngx_waf_log_access(r, ("JavaScript Global Variable Pattern: " + xss_pattern).c_str());

    try {
        std::regex xss_regex(xss_pattern);
        ngx_waf_log_access(r, "Regex compiled successfully");

        if (std::regex_search(query, xss_regex)) {
            ngx_waf_log_access(r, "Exiting check_xss_js_global_variable with attack detected");
            return log_and_reject(r, "JavaScript global variable found", "941370");
        }
    } catch (const std::regex_error &e) {
        ngx_waf_log_access(r, ("Regex error: " + std::string(e.what())).c_str());
    } catch (const std::exception &e) {
        ngx_waf_log_access(r, ("Exception: " + std::string(e.what())).c_str());
    }

    ngx_waf_log_access(r, "Exiting check_xss_js_global_variable with no attack detected");
    return false;
}

// Function to check AngularJS client side template injection detected (RuleId: 941380)
bool check_xss_angularjs_template_injection(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered check_xss_angularjs_template_injection");
    std::string query(reinterpret_cast<const char*>(r->args.data), r->args.len);

    std::string xss_pattern = get_pattern_from_conf(r, "xss_angularjs_template_injection_pattern");
    ngx_waf_log_access(r, ("AngularJS Client Side Template Injection Pattern: " + xss_pattern).c_str());

    try {
        std::regex xss_regex(xss_pattern);
        ngx_waf_log_access(r, "Regex compiled successfully");

        if (std::regex_search(query, xss_regex)) {
            ngx_waf_log_access(r, "Exiting check_xss_angularjs_template_injection with attack detected");
            return log_and_reject(r, "AngularJS client side template injection detected", "941380");
        }
    } catch (const std::regex_error &e) {
        ngx_waf_log_access(r, ("Regex error: " + std::string(e.what())).c_str());
    } catch (const std::exception &e) {
        ngx_waf_log_access(r, ("Exception: " + std::string(e.what())).c_str());
    }

    ngx_waf_log_access(r, "Exiting check_xss_angularjs_template_injection with no attack detected");
    return false;
}

// Main entry point for XSS rules
ngx_int_t xss_rules_entry_point(ngx_http_request_t *r) {
    ngx_waf_log_access(r, "Entered xss_rules_entry_point");

    if (check_xss_libinjection(r)) return NGX_HTTP_FORBIDDEN;
    if (check_xss_libinjection_101(r)) return NGX_HTTP_FORBIDDEN;
    if (check_xss_script_tag_vector(r)) return NGX_HTTP_FORBIDDEN;
    if (check_xss_event_handler_vector(r)) return NGX_HTTP_FORBIDDEN;
    if (check_xss_attribute_vector(r)) return NGX_HTTP_FORBIDDEN;
    if (check_xss_js_uri_vector(r)) return NGX_HTTP_FORBIDDEN;
    if (check_xss_disallowed_html_attributes(r)) return NGX_HTTP_FORBIDDEN;
    if (check_xss_html_injection(r)) return NGX_HTTP_FORBIDDEN;
    if (check_xss_attribute_injection(r)) return NGX_HTTP_FORBIDDEN;
    if (check_xss_node_validator_blocklist(r)) return NGX_HTTP_FORBIDDEN;
    if (check_xss_using_stylesheets(r)) return NGX_HTTP_FORBIDDEN;
    if (check_xss_using_vml_frames(r)) return NGX_HTTP_FORBIDDEN;
    if (check_xss_obfuscated_javascript(r)) return NGX_HTTP_FORBIDDEN;
    if (check_xss_obfuscated_vbscript(r)) return NGX_HTTP_FORBIDDEN;
    if (check_xss_using_embed_tag(r)) return NGX_HTTP_FORBIDDEN;
    if (check_xss_using_import_attribute(r)) return NGX_HTTP_FORBIDDEN;
    if (check_xss_ie_filters(r)) return NGX_HTTP_FORBIDDEN;
    if (check_xss_using_meta_tag(r)) return NGX_HTTP_FORBIDDEN;
    if (check_xss_using_link_href(r)) return NGX_HTTP_FORBIDDEN;
    if (check_xss_using_base_tag(r)) return NGX_HTTP_FORBIDDEN;
    if (check_xss_using_applet_tag(r)) return NGX_HTTP_FORBIDDEN;
    if (check_xss_us_ascii_encoding(r)) return NGX_HTTP_FORBIDDEN;
    if (check_xss_html_tag_handler(r)) return NGX_HTTP_FORBIDDEN;
    if (check_xss_ie_filters_320(r)) return NGX_HTTP_FORBIDDEN;
    if (check_xss_ie_filters_330(r)) return NGX_HTTP_FORBIDDEN;
    if (check_xss_ie_filters_340(r)) return NGX_HTTP_FORBIDDEN;
    if (check_xss_utf7_encoding(r)) return NGX_HTTP_FORBIDDEN;
    if (check_xss_js_obfuscation(r)) return NGX_HTTP_FORBIDDEN;
    if (check_xss_js_global_variable(r)) return NGX_HTTP_FORBIDDEN;
    if (check_xss_angularjs_template_injection(r)) return NGX_HTTP_FORBIDDEN;

    ngx_waf_log_access(r, "Exiting xss_rules_entry_point with no attack detected");
    return NGX_DECLINED;
}
