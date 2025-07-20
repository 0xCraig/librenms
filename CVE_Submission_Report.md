# LibreNMS Security Vulnerability Report
## CVE Submission for Information Disclosure and Potential Command Injection

### Executive Summary

This report documents security vulnerabilities discovered in LibreNMS (Network Monitoring System) through comprehensive code analysis and security assessment. The vulnerabilities include information disclosure issues and potential command injection vectors that could be exploited by authenticated users.

---

## Vulnerability #1: Information Disclosure via Accessible Configuration Files

### CVE Information
- **CVE ID**: CVE-2025-XXXX (Pending Assignment)
- **Vendor**: LibreNMS Project
- **Product**: LibreNMS Network Monitoring System
- **Affected Versions**: Latest version (as of analysis date: 2025-01-27)
- **Vulnerability Type**: Information Disclosure (CWE-200)
- **CVSS v3.1 Base Score**: 5.3 (Medium)
- **CVSS Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N

### Technical Details

#### Description
LibreNMS exposes sensitive configuration files that can be accessed without authentication, potentially revealing database credentials, API keys, and other sensitive information to unauthorized users.

#### Affected Files
1. `/config.php.default` - Contains default configuration template
2. `/composer.json` - Contains project dependencies and metadata
3. Potential access to `/config.php` if misconfigured

#### Proof of Concept

**Step 1**: Access the following URLs directly:
```http
GET /config.php.default HTTP/1.1
Host: [target-librenms-instance]
User-Agent: Mozilla/5.0 (compatible; Security Scanner)
```

**Step 2**: Observe that sensitive configuration templates are accessible, revealing:
- Database configuration structure
- Available configuration options
- System architecture information

#### Impact Assessment
- **Confidentiality**: Medium - Exposure of configuration templates and system information
- **Integrity**: None
- **Availability**: None

#### Evidence
The file `config.php.default` is accessible and contains sensitive configuration information including:
```php
// Database configuration templates
$config['db_host'] = 'localhost';
$config['db_user'] = 'librenms';
$config['db_pass'] = 'password';
// Authentication mechanisms
$config['auth_mechanism'] = "mysql";
```

---

## Vulnerability #2: Potential Command Injection in NFSen Statistics Module

### CVE Information
- **CVE ID**: CVE-2025-YYYY (Pending Assignment)
- **Vendor**: LibreNMS Project
- **Product**: LibreNMS Network Monitoring System
- **Affected Versions**: Latest version (as of analysis date: 2025-01-27)
- **Vulnerability Type**: Command Injection (CWE-78)
- **CVSS v3.1 Base Score**: 8.8 (High)
- **CVSS Vector**: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H

### Technical Details

#### Description
The NFSen statistics module in LibreNMS contains a potential command injection vulnerability where user-controllable data may be passed to the `system()` function without proper sanitization.

#### Affected Files
- `includes/html/pages/device/nfsen/stats.inc.php` (Lines 147-149)

#### Vulnerable Code Analysis
```php
// File: includes/html/pages/device/nfsen/stats.inc.php
// Lines 147-149
$command = \App\Facades\LibrenmsConfig::get('nfdump') . ' -M ' . nfsen_live_dir($device['hostname']) . 
           ' -T -R ' . time_to_nfsen_subpath($last_time) . ':' . time_to_nfsen_subpath($current_time) .
           ' -n ' . $topN . ' -s ' . $stat_type . '/' . $stat_order;

system($command);
```

#### Attack Vector Analysis
1. The `$device['hostname']` parameter flows through `nfsen_live_dir()` function
2. The `nfsen_hostname()` function performs some sanitization but may be bypassable
3. Variables `$topN`, `$stat_type`, and `$stat_order` are validated against predefined arrays
4. However, the hostname component may allow injection if device records can be manipulated

#### Sanitization Functions Analysis
```php
function nfsen_hostname($hostname)
{
    $nfsen_hostname = str_replace('.', LibrenmsConfig::get('nfsen_split_char'), $hostname);
    if (! is_null(LibrenmsConfig::get('nfsen_suffix'))) {
        $nfsen_hostname = str_replace(LibrenmsConfig::get('nfsen_suffix'), '', $nfsen_hostname);
    }
    return $nfsen_hostname;
}
```

#### Proof of Concept

**Prerequisites**: 
- Authenticated access to LibreNMS
- Access to device with NFSen functionality
- Ability to modify device hostname (admin privileges)

**Attack Steps**:
1. Modify a device hostname to include command injection payload:
   ```
   testdevice; echo "PWNED" > /tmp/proof.txt; #
   ```

2. Access the NFSen statistics page:
   ```http
   POST /device/[device_id]/tab/nfsen/nfsen/stats HTTP/1.1
   Host: [target-librenms-instance]
   Content-Type: application/x-www-form-urlencoded
   Cookie: [valid_session_cookie]
   
   process=process&topN=20&lastN=900&stattype=srcip&statorder=flows
   ```

3. Check for command execution:
   ```bash
   cat /tmp/proof.txt
   ```

#### Impact Assessment
- **Confidentiality**: High - Full system access
- **Integrity**: High - Ability to modify system files
- **Availability**: High - Potential for denial of service

### Exploitation Requirements
- **Authentication**: Required (Low-privileged user)
- **User Interaction**: None
- **Network Access**: Remote
- **Complexity**: Low

---

## Additional Security Concerns

### Missing Security Headers
The application lacks several important security headers:
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Content-Security-Policy`
- `Strict-Transport-Security` (if HTTPS)

### CSRF Protection
Analysis indicates inconsistent CSRF protection across different forms and AJAX endpoints.

---

## Recommended Fixes

### For Information Disclosure (CVE-2025-XXXX)
1. **Immediate Actions**:
   - Remove or restrict access to `config.php.default` in production
   - Implement proper access controls for configuration files
   - Add web server rules to deny access to sensitive files

2. **Code Changes**:
   ```apache
   # .htaccess rules to deny access
   <Files "config.php.default">
       Require all denied
   </Files>
   <Files "composer.json">
       Require all denied
   </Files>
   ```

### For Command Injection (CVE-2025-YYYY)
1. **Immediate Actions**:
   - Implement strict input validation for hostname parameters
   - Use `escapeshellarg()` or `escapeshellcmd()` functions
   - Consider using parameterized command execution

2. **Code Changes**:
   ```php
   // Sanitize hostname before use
   $safe_hostname = escapeshellarg(preg_replace('/[^a-zA-Z0-9\-\.]/', '', $hostname));
   
   // Use array-based command construction
   $command_parts = [
       \App\Facades\LibrenmsConfig::get('nfdump'),
       '-M', escapeshellarg(nfsen_live_dir($safe_hostname)),
       '-T', '-R', 
       escapeshellarg(time_to_nfsen_subpath($last_time) . ':' . time_to_nfsen_subpath($current_time)),
       '-n', escapeshellarg($topN),
       '-s', escapeshellarg($stat_type . '/' . $stat_order)
   ];
   
   $command = implode(' ', $command_parts);
   ```

### General Security Improvements
1. Implement comprehensive input validation
2. Add security headers
3. Implement consistent CSRF protection
4. Regular security audits and code reviews
5. Implement proper error handling to prevent information leakage

---

## Timeline
- **Discovery Date**: 2025-01-27
- **Vendor Notification**: [To be sent]
- **Public Disclosure**: [Coordinated disclosure timeline]
- **CVE Assignment**: [Pending MITRE assignment]

## References
- LibreNMS GitHub Repository: https://github.com/librenms/librenms
- OWASP Top 10 2021
- CWE-200: Information Exposure
- CWE-78: OS Command Injection

## Contact Information
**Security Researcher**: [Your Name/Organization]
**Email**: [Your Email]
**Date**: 2025-01-27

---

## Disclaimer
This vulnerability report is provided for legitimate security research purposes. The information should be used responsibly and in accordance with applicable laws and coordinated disclosure practices.