package com.rain;

import javax.naming.InitialContext;
import javax.naming.NamingException;

public class LDAPClient {

    public static void main(String[] args) throws NamingException {
        InitialContext initialContext = new InitialContext();
        initialContext.lookup("ldap://127.0.0.1:1389/Exp");
    }

}