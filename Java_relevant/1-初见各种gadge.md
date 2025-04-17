# Java安全研究之各种gadget

## 1. Commons-Collections链

> Apache Commons Collections 是一个广泛使用的 Java 库，提供了丰富的集合框架扩展和实用工具。然而，它也因其在 Java 反序列化攻击中的广泛应用而受到关注。Commons Collections 库中的某些类可以被恶意利用，导致任意代码执行。

* 环境准备
  * OpenJDK https://hg.openjdk.org/jdk8u/jdk8u/jdk/rev/af660750b2f4
  * JDK8u65

首先解压 `/Library/Java/JavaVirtualMachines/jdk1.8.0_65.jdk/Contents/Home`下面的`src.zip` 

之后下载openjdk并解压，将`src\share\classes\sun`目录复制到上面解压出的`src`目录内 

最后在SDKs中添加sourcepath就好了.

<img src="https://cdn.jsdelivr.net/gh/Rain1er/images@main/img/image-20250417212749018.png" alt="image-20250417212749018" style="zoom:50%;" />

<img src="https://cdn.jsdelivr.net/gh/Rain1er/images@main/img/image-20250417212830432.png" alt="image-20250417212830432" style="zoom:50%;" />

能在`rt.jar`中的`sun.reflect.`目录下看到Java源代码就代表成功了，这样做的目的是获取源码级别的调试.

![image-20250417213042227](https://cdn.jsdelivr.net/gh/Rain1er/images@main/img/image-20250417213042227.png)

 反射与类加载：

- **反射（Reflection）**：是 Java 提供的一种机制，允许程序在运行时检查和操作类的结构（如类名、方法、字段等）。
- **类加载（Class Loading）**：是 JVM 在**运行时**将类的字节码加载到内存，生成 `Class` 对象的过程。

他们的关系：

- 反射的前提是**类已经被加载进 JVM**，即已经有了对应的 `Class` 对象。
- 反射本身不会自动**动态加载类**，但它可以触发类的加载（比如通过 `Class.forName("xxx")`）。

这里暂时弄不清楚也没关系，代码量上去了会理解的。

### 1.1 CC1

pom.xml中添加存在漏洞的`Commons Collections`

```xml
<dependencies>
    <dependency>
        <groupId>commons-collections</groupId>
        <artifactId>commons-collections</artifactId>
        <version>3.2.1</version>
    </dependency>
</dependencies>
```

CC1 有两条，大同小异。



### 1.2 CC6

> 为啥需要CC6？Apache Commons Collections 1  LazyMap 这条利用链是受JDK和cc版本的限制的， 在 java 8u71后这条链子挂了。
>
> 主要的原因是 `sun.reflect.annotation.AnnotationInvocationHandler#readObject`的逻辑发生变化，导致整个在`AnnotationInvocationHandler`做为入口类的链都不能用了。

Java 反序列化当中，CC6 链被称为是最好用的 CC 链，它可以不受 JDK、CC的版本约束进行反序列化攻击。

### 1.3 CC3

> 前面的CC1与CC6链都是通过 Runtime.exec() 进行命令执行的。Runtime关键字位于黑名单的时候就不能使用了。 CC3链的好处是通过动态加载类的机制实现恶意类代码执行。

测试环境同CC1



### 1.4 CC4

> 因为 Commons Collections 4 除 4.0 之外的其他版本，去掉了 InvokerTransformer对 Serializable的继承，导致无法序列化。
>
> 但同时 CommonsCollections 4的版本中 `TransformingComparator` 继承了 Serializable接口，而CommonsCollections 3里是没有的，根据这个差异构造一条新的攻击路径。

测试环境

JDK：jdk8u65

CC：Commons-Collections 4.0

```xml
<dependencies>
  <dependency>
      <groupId>org.apache.commons</groupId>
      <artifactId>commons-collections4</artifactId>
      <version>4.0</version>
  </dependency>
</dependencies>
```



### 1.5 CC5

> CC5链和CC1差不多，只不过调用LazyMap.get()是通过 TiedMapEntry.toString()触发的

JDK：jdk8u65

CC：Commons-Collections 3.2.1

### 1.6 CC2

> 在 commons-collections 4 中有两条链子可以用，分别是cc2 和 cc4  在Commons Collections 4.0中InvokerTransformer这个类继承Serializable（之后移除继承），所以是可序列化的，相比 commons collections 3 而且还多了`TransformingComparator`这个类。



### 1.7 CC7

> CC7利用的是hashtable#readObject作为反序列化入口。AbstractMap的equals来触发的LazyMap的get方法



## 2. commons-beanutils

```xml
<dependencies>
    <dependency>
        <groupId>commons-beanutils</groupId>
        <artifactId>commons-beanutils</artifactId>
        <version>1.8.3</version>
    </dependency>

    <dependency>
        <groupId>commons-collections</groupId>
        <artifactId>commons-collections</artifactId>
        <version>3.2.1</version>
    </dependency>
  
    <dependency>
        <groupId>commons-logging</groupId>
        <artifactId>commons-logging</artifactId>
        <version>1.2</version>
    </dependency>
</dependencies>
```



### 2.1 CB1

> Apache Commons 工具集下除了`collections`以外还有`BeanUtils`，它主要用于操控`JavaBean`。
>
> 以 Utils 结尾，指示这是一个工具类/集.



### 2.2 CB2

> 无cc利用链



## 3. ysoserial工具

> 为了简化这些链子的使用，ysoserial应运而生。







## 4. 二进制序列化数据

`ser.bin` 顺便学习下序列化后的二进制内容吧。

```
hexdump -C ser.bin
```

