package com.mykbox.config;

import java.security.KeyPair;

import com.mykbox.security.UserDetailsServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.Resource;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;

@Configuration
@EnableAuthorizationServer
@Order(6)
public class AuthServerConfigurer
    extends
        AuthorizationServerConfigurerAdapter {

    @Autowired
    private CustomAccessTokenConverter customAccessTokenConverter;


    @Value("${jwt.certificate.store.file}")
    private Resource keystore;

    @Value("${jwt.certificate.store.password}")
    private String keystorePassword;

    @Value("${jwt.certificate.key.alias}")
    private String keyAlias;

    @Value("${jwt.certificate.key.password}")
    private String keyPassword;

    @Bean
    public UserDetailsService userDetailsService() {
        return new UserDetailsServiceImpl();
    }

    @Override
    public void configure(
        ClientDetailsServiceConfigurer clients)
        throws Exception {
        clients
            .inMemory()
            .withClient("authserver")
            .secret("passwordforauthserver")
            .redirectUris("http://localhost:8080/login/oauth2/code/authserver")
            .authorizedGrantTypes("authorization_code",
             "refresh_token", "implicit","password","client_credentials")
            .scopes("myscope")
            .autoApprove(true)
            .accessTokenValiditySeconds(30000)
            .refreshTokenValiditySeconds(1800)

        .and()
                .withClient("vibe")
                .secret("passwordforvibeserver")
                .redirectUris("http://localhost:8081/login/oauth2/code/vibe")
                .authorizedGrantTypes("authorization_code","refresh_token", "implicit","password","client_credentials")
                .scopes("myscope")
                .autoApprove(true)
                .accessTokenValiditySeconds(30)
                .refreshTokenValiditySeconds(1800);
    }

    @Override
    public void configure(
        AuthorizationServerEndpointsConfigurer endpoints)
        throws Exception {
        endpoints
            .accessTokenConverter(accessTokenConverter())
            .userDetailsService(userDetailsService());
    }

 /*   @Bean
    public JwtAccessTokenConverter jwtAccessTokenConverter() {
        KeyStoreKeyFactory keyStoreKeyFactory = new KeyStoreKeyFactory(
            keystore, keystorePassword.toCharArray());
        KeyPair keyPair = keyStoreKeyFactory.getKeyPair(
            keyAlias, keyPassword.toCharArray());
        JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
        converter.setKeyPair(keyPair);
        return converter;
    }*/

    @Bean
    public JwtAccessTokenConverter accessTokenConverter() {
        KeyStoreKeyFactory keyStoreKeyFactory = new KeyStoreKeyFactory(
                keystore, keystorePassword.toCharArray());
        KeyPair keyPair = keyStoreKeyFactory.getKeyPair(
                keyAlias, keyPassword.toCharArray());
        CustomTokenConverter tokenConverter = new CustomTokenConverter();
        tokenConverter.setAccessTokenConverter(customAccessTokenConverter);
         tokenConverter.setKeyPair(keyPair);
        return tokenConverter;
    }
}