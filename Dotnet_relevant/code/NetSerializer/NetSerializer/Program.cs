using System;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using System.Runtime.Serialization;


namespace NetSerializer
{
    class Program
    {
        static void Main()
        {

            ////STEP 1 反序列化基础
            //Demo1 demo1 = new Demo1
            //{
            //    n1 = 1,
            //    n2 = 2,
            //    str = "raindrop"
            //};

            //// 序列化
            //Tools.BinaryFormatterSerialize("1.bin", demo1);

            //// 反序列化
            //Demo1 deserializedDemo1 = (Demo1)Tools.BinaryFormatterDeserialFromFile("1.bin");

            //Console.WriteLine($"Demo1.n1:{deserializedDemo1.n1}");
            //Console.WriteLine($"Demo1.n2:{deserializedDemo1.n2}");
            //Console.WriteLine($"Demo1.str:{deserializedDemo1.str}");



            // STEP 2 反序列化生命周期
            Demo2 demo2 = new Demo2 { str = "hello" };

            using (MemoryStream memoryStream = new MemoryStream())
            {
                // 构建formatter序列化器
                BinaryFormatter binaryFormatter = new BinaryFormatter();

                // 设置序列化代理选择器
                SurrogateSelector ss = new SurrogateSelector();
                ss.AddSurrogate(typeof(Demo2), binaryFormatter.Context, new MySerializationSurrogate());

                // 赋值给formatter 这里是否设置代理选择器决定了序列化的生命周期
                binaryFormatter.SurrogateSelector = ss;

                // 序列化
                binaryFormatter.Serialize(memoryStream, demo2);
                memoryStream.Position = 0;  // 重置stream，用于把指针指向开头用于后续反序列化

                // 反序列化
                Demo2 deserializedDemo2 = (Demo2)binaryFormatter.Deserialize(memoryStream);

                //Console.WriteLine(deserializedDemo2.str);    // hello
            }
        }

    }
}
