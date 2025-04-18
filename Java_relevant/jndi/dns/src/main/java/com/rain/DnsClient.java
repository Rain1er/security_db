package com.rain;
import javax.naming.InitialContext;
import javax.naming.NamingException;

public class DnsClient {
    public static void main(String[] args) throws NamingException {
        InitialContext initialContext = new InitialContext();
        initialContext.lookup("dns://c17208f0.log.cdncache.rr.nu.");    // 关闭clash的tun模式
    }
}
