using System;

namespace NetSerializer
{
    [Serializable]  // 标识这个类可以序列化
    public class Demo1
    {
        public int n1;
        [NonSerialized] public int n2;  // 禁止序列化这个属性
        public String str;

    }
}
