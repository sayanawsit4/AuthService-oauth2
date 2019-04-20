package com.mykbox.config;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.jdbc.DataSourceBuilder;
import org.springframework.boot.autoconfigure.security.oauth2.client.EnableOAuth2Sso;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JdbcTokenStore;
import com.mykbox.config.*;
import javax.sql.DataSource;

/**
 *  REST API Resource Server.
 */
@Configuration
@EnableWebSecurity
@EnableResourceServer
@EnableGlobalMethodSecurity(prePostEnabled = true) // Allow method annotations like @PreAuthorize
public class ResourceConfigurer extends ResourceServerConfigurerAdapter {

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http.httpBasic().disable();
        http.authorizeRequests().anyRequest().authenticated();
    }

    @Bean
    //@ConditionalOnProperty(name = "token-type",havingValue = "token")
    @ConfigurationProperties(prefix="spring.datasource")
    public DataSource ouathDataSource(){
        return DataSourceBuilder.create().build();
    }

    @Bean
    //@ConditionalOnProperty(name = "token-type",havingValue = "token")
    public TokenStore tokenStore() {
        System.out.println("inside tokenstore");
      //  return new CustomJdbcTokenStore(oauthDataSource());
         return new JdbcTokenStore(ouathDataSource());
         //return new JwtTokenStore(accessTokenConverter());
    }

    @Override
        public void configure (ResourceServerSecurityConfigurer resources)throws Exception {
        //TokenStore tokenStore=new JdbcTokenStore(ouathDataSource());
       if(true)
        resources.resourceId("product_api").tokenStore(tokenStore());

       // resources.resourceId("product_api").;
     }

}
