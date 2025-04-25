using System;
using System.Runtime.Serialization;
using System.Security.Permissions;


namespace NetSerializer
{
    [Serializable]
    internal class Demo2 : ISerializable    //  实现ISerializable接口 （可选）
    //internal class Demo2
    {
        public string str { get; set; }
        public Demo2() { }

        [SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.SerializationFormatter)]
        public virtual void GetObjectData(SerializationInfo info, StreamingContext context)
        {
            Console.WriteLine("---Demo2的GetObjectData序列化函数被调用---");
            info.AddValue("str", str, typeof(string));
        }

        // 实现了ISerializable接口的类，必须包含有序列化构造函数，否则会出错
        // 这里就相当于代理类的反序列化函数SetObjectData
        protected Demo2(SerializationInfo info, StreamingContext context)
        {
            Console.WriteLine("---Demo2的反序列化构造函数被调用---");
            str = info.GetString("str");
        }

        // 4个回调事件，在PHP中称为魔术方法

        [OnSerializing] // 序列化之前调用
        private void OnSerializing_(StreamingContext sc)
        {
            Console.WriteLine("序列化之前调用 OnSerializing");
        }
        [OnSerialized]  // 序列化之后调用
        private void OnSerialized_(StreamingContext sc)
        {
            Console.WriteLine("序列化之后调用 OnSerialized");
        }


        [OnDeserializing]   // 反序列化之前
        private void OnDeserializing_(StreamingContext sc)
        {
            Console.WriteLine("反序列化之前调用 OnDeserializing");

        }
        [OnDeserialized]    // 反序列化之后
        private void OnDeserialized_(StreamingContext sc)
        {
            Console.WriteLine("反序列化之后调用 OnDeserialized");
        }



    }

    // 代理类
    class MySerializationSurrogate : ISerializationSurrogate
    {
        public void GetObjectData(object obj, SerializationInfo info, StreamingContext context)
        {
            Console.WriteLine("---代理类的GetObjectData序列化函数被调用---");
            info.AddValue("str", ((Demo2)obj).str);
        }

        public object SetObjectData(object obj, SerializationInfo info, StreamingContext context, ISurrogateSelector selector)
        {
            Console.WriteLine("---代理类的SetObjectData反序列化函数被调用---");
            Demo2 m = new Demo2();
            m.str = (string)info.GetValue("str", typeof(string));
            return m;
        }
    }
}
