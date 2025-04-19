package me.rain.bug.spring.redis.session.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.session.data.redis.config.annotation.web.http.EnableRedisHttpSession;


@Configuration
@EnableRedisHttpSession(redisNamespace = "rain-session", maxInactiveIntervalInSeconds = 2 * 60 * 60)
public class SpringHttpSessionConfig {


}
