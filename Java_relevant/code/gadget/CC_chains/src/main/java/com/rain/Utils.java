package com.rain;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

public class Utils {
    public static void serialize(Object obj) throws Exception {
        ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("ser.bin"));
        oos.writeObject(obj);
    }

    public static void  deserialize() throws Exception {
        ObjectInputStream ois = new ObjectInputStream(new FileInputStream("ser.bin"));
        ois.readObject();
    }
}
