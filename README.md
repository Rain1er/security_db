# security_db

记录一些学习资源，早日成为一名优秀的安全研究员：）

## 0. 开发技能

> vibeCoding感觉有点扯……自己要少用ai编程



### 恶意软件开发

当下主要使用c/cpp、后面为了提高静态规避效率，可以去用下nim。



### bp插件开发

主要使用Kotlin语言和montoya-api，涉及到Gui的，使用swing就可以了，反正不需要写很好看的前端，能用就行。

要想好看还是用electron吧。



### Golang囊地鼠（我的主力语言）

https://github.com/inancgumus/learngo

https://github.com/YYRise/black-hat-go-zh

https://github.com/blackhat-go/bhg

https://github.com/LearnGolang/HackGolang 

https://github.com/Firebasky/Go 

https://github.com/leveryd/go-sec-code

 https://github.com/fengziHK/bypass_go 

https://github.com/TideSec/GoBypassAV 

https://github.com/binganao/golang-shellcode-bypassav 

https://github.com/aqiao-jashell/go-bypass

### 游戏安全 & 外挂开发

易语言: )  感觉也挺好玩的， 写外挂必备技能，开发gui效率高。

### MCP & A2A 开发

利用ai做一些有意思的事情。



## 1. 业务侧安全

语言层面相关漏洞感觉有时并不重要，我有点讨厌反序列化。PHP还简单点，Java天天这链子那链子的……有啥意思。

业务安全才是我主要的研究方向。

### 1.1 Java & .net 业务层

基础知识

https://www.javasec.org/

https://github.com/HackJava/HackJava

https://github.com/guardrailsio/awesome-java-security



漏洞环境

https://github.com/whgojp/JavaSecLab

https://github.com/j3ers3/Hello-Java-Sec

https://github.com/WebGoat/WebGoat

https://github.com/lemono0/FastJsonParty

https://github.com/OWASP/crAPI

https://github.com/JoyChou93/java-sec-code



代码审计插件 SAST

https://github.com/SpringKill-team/CodeAuditAssistant?tab=readme-ov-file

https://github.com/KimJun1010/inspector?tab=readme-ov-file

https://github.com/novysodope/javaeasyscan

https://github.com/momosecurity/momo-code-sec-inspector-java



代码审计tips

https://www.cnblogs.com/macter/p/16181588.html

### 1.2 Java & .Net 安全研究

 **.net安全矩阵知识星球**

https://github.com/Ivan1ee/NET-Deserialize?tab=readme-ov-file

https://github.com/Y4er/dotnet-deserialization

https://github.com/dotnet/docs

https://github.com/guardrailsio/awesome-dotnet-security

https://github.com/dotnet/runtime/security/advisories

https://security-code-scan.github.io/

https://cheatsheetseries.owasp.org/cheatsheets/DotNet_Security_Cheat_Sheet.html

https://learn.microsoft.com/en-us/dotnet/standard/security/secure-coding-guidelines

https://github.com/paulveillard/cybersecurity-dotnet-security

https://github.com/security-code-scan/security-code-scan

https://github.com/pumasecurity/puma-scan

https://github.com/Microsoft/DevSkim

https://github.com/nccgroup/VulnerableDotNetHTTPRemoting

https://hub.docker.com/r/santosomar/vuln_app

https://learn.microsoft.com/zh-cn/dotnet/devops/dotnet-secure-github-action

https://github.com/ffffffff0x/1earn/blob/master/1earn/Security/RedTeam/%E8%AF%AD%E8%A8%80%E5%AE%89%E5%85%A8/dotnet%E5%AE%89%E5%85%A8.md

.net安全研究员

https://speakerdeck.com/pwntester/

### 1.3 Python & Php & Go

这里主要是研究一些语言层面的漏洞了。没有主攻业务的Java、.Net范围广，所以分开来看。

python

https://github.com/guardrailsio/awesome-python-security

php

https://github.com/guardrailsio/awesome-php-security

Go

https://github.com/HackGolang/HackGolang

https://github.com/google/security-research-pocs

https://github.com/guardrailsio/awesome-golang-security

https://github.com/OWASP/Go-SCP

https://github.com/praetorian-inc/gokart

https://github.com/advisories?query=type%3Areviewed+ecosystem%3Ago

https://github.com/securego/gosec

https://go.dev/wiki/ResearchPapers



## 2. 前端 & NodeJs & Electron

客户端漏洞挖掘我认为还是很有前景的，研究的人不多，后面仔细研究下xss2RCE。**有大用处：）**

https://www.electronjs.org/docs/latest/tutorial/security

https://github.com/Just-Hack-For-Fun/Electron-Security



## 3. 移动端

语言主要是`kotlin`，`Objective-C`，`swift`等。涉及的方向有api安全，逆向工程等



## 4. 攻防对抗

这里主要是记录一些实战相关的知识，学习一些blueTeam的知识。弄一些蜜罐来玩一下。

Java的一些东西

* RCE相关

https://github.com/Whoopsunix/JavaRce

* Utf OverLoad Encoding 对抗waf

https://github.com/byname66/SerializeJava	

* 内存马

https://github.com/Getshell/Mshell	

https://github.com/veo/wsMemShell 

https://github.com/pen4uin/java-memshell-generator

https://github.com/ReaJason/MemShellParty

https://github.com/W01fh4cker/LearnJavaMemshellFromZero

https://github.com/jweny/MemShellDemo

## 5. 逆向工程 & IOT

目标是掌握windows、Linux、android、ios、Macos全平台逆向技能。

2025-5-25 在做crackeMe160，能熟练看汇编才是真本事……少用F5。

固件相关知识、fuzz、蓝牙、车联网……

* 静态反编译

https://hex-rays.com/ida-pro  

https://www.hopperapp.com/  

https://github.com/NationalSecurityAgency/ghidra  

https://github.com/rizinorg/cutter  



## 6. 区块链

还是很想学一学区块链的，背后的原理，安全漏洞审计，各种钓鱼玩法，自动交易机器人等。

https://github.com/AmazingAng/WTF-Solidity  



## 7. 学术研究 & 安全 & 程序分析

主要是论文相关了，学习一下最新的研究成果。

https://www.bilibili.com/video/BV1sJ4m1e7bM/?spm_id_from=333.1387.collection.video_card.click&vd_source=d68dbbcf753f7781e9d8e5ba552b80cb

https://www.bilibili.com/video/BV1b7411K7P4/?vd_source=c9811ab2e22550bf4c939a898a1313cf



