# Java安全研究之各种gadget

## 1. CC链

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

### 1.2 CC6

> 为啥需要CC6？Apache Commons Collections 1  LazyMap 这条利用链是受JDK和cc版本的限制的， 在 java 8u71后这条链子挂了。
>
> 主要的原因是 `sun.reflect.annotation.AnnotationInvocationHandler#readObject`的逻辑发生变化，导致整个在`AnnotationInvocationHandler`做为入口类的链都不能用了。

Java 反序列化当中，CC6 链被称为是最好用的 CC 链，它可以不受 JDK、CC的版本约束进行反序列化攻击。