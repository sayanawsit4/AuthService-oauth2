package com.mykbox.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.jdbc.DataSourceBuilder;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestOperations;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsResourceDetails;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JdbcTokenStore;

import javax.sql.DataSource;
import java.util.Arrays;

/**
 *  REST API Resource Server.
 */
@Configuration
@EnableWebSecurity
@EnableResourceServer
@EnableGlobalMethodSecurity(prePostEnabled = true) // Allow method annotations like @PreAuthorize
public class ResourceConfigurer extends ResourceServerConfigurerAdapter {

    private static final String SECURED_PATTERN = "/secured/**";


    @Autowired
    private TokenStore tokenStore;

    @Autowired
    private DataSource oauthDataSource;

 /*   @Bean
    @Primary
    //@ConditionalOnProperty(name = "token-type",havingValue = "token")
    @ConfigurationProperties(prefix="spring.datasource")
    public DataSource ouathDataSource(){
        return DataSourceBuilder.create().build();
    }

    @Bean
    @Primary
    //@ConditionalOnProperty(name = "token-type",havingValue = "token")
    public TokenStore tokenStore() {
        System.out.println("inside tokenstore");
        return new JdbcTokenStore(ouathDataSource());
        //return new JwtTokenStore(accessTokenConverter());
    }
*/

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http.httpBasic().disable();
        http.requestMatchers()
                .antMatchers(SECURED_PATTERN).and().authorizeRequests().anyRequest().authenticated();
    }

   /* @Override
    public void configure (ResourceServerSecurityConfigurer resources)throws Exception {
         if(true)
            resources.resourceId("").tokenStore(tokenStore());
      }*/

}