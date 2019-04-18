package com.mykbox.config.resource;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;

@Configuration
@EnableWebSecurity
@EnableResourceServer
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ResourceConfigurer extends ResourceServerConfigurerAdapter {

    private static final String SECURED_PATTERN = "/api/**";

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http.httpBasic().disable();
        http.requestMatchers()
                .antMatchers(SECURED_PATTERN).and().authorizeRequests().anyRequest().authenticated();
    }
}