using System;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using System.Runtime.Serialization;


namespace NetSerializer
{
    internal class Tools
    {

        // 序列化
        public static void BinaryFormatterSerialize(string file, object o)
        {

            BinaryFormatter binaryFormatter = new BinaryFormatter();    // 使用BinaryFormatter以二进制形式序列化
            FileStream fileStream = new FileStream(file, FileMode.Create, FileAccess.Write, FileShare.None);
            binaryFormatter.Serialize(fileStream, o);
            fileStream.Close();
            Console.WriteLine($"serialize object {o} to file {file}.");
        }

        //反序列化
        public static object BinaryFormatterDeserialFromFile(string file)
        {
            IFormatter formatter = new BinaryFormatter();
            Stream stream = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.Read);
            object o = formatter.Deserialize(stream);
            stream.Close();
            return o;
        }
    }
}
