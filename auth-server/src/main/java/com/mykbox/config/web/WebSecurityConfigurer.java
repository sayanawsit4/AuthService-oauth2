package com.mykbox.config.web;

import com.mykbox.config.auth.CustomJdbcTokenStore;
import org.springframework.boot.autoconfigure.jdbc.DataSourceBuilder;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import com.mykbox.config.user.UserDetailsServiceImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JdbcTokenStore;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.sql.DataSource;


@Configuration
@EnableWebSecurity
public class WebSecurityConfigurer
    extends
        WebSecurityConfigurerAdapter {



    /*@Bean
    public PasswordEncoder passwordEncoder() {
        return new ShaPasswordEncoder(256);
    }*/

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(HttpSecurity http)
        throws Exception {
//        http
//            .authorizeRequests()
//            .antMatchers("/login**").permitAll()
//            .anyRequest().authenticated()
//            .and().csrf()
//            .and().formLogin().loginPage("/login");

        http    .authorizeRequests()
                .antMatchers("/login","/logout.do").permitAll()
                .antMatchers("/**").authenticated()
                .antMatchers("/authserver/**").authenticated()
                .and()
                .formLogin()
                .loginPage("/login")
                .and()
                .logout()
                .logoutRequestMatcher(new AntPathRequestMatcher("/logout.do"))
                .and()
                .userDetailsService(userDetailsService());
    }


    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/getAccessTokenByEmail","/tokens","/webjars/**","/resources/**","/getjwttoken/**","/authenticateSSO/**");
    }


    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        return new UserDetailsServiceImpl();
    }

    @Override
    protected void configure(
        AuthenticationManagerBuilder auth) throws Exception {
//        auth
//            .inMemoryAuthentication()
//            .withUser("user").password("user")
//            .roles("USER")
//            .and()
//            .withUser("admin").password("admin")
//            .roles("USER", "ADMIN");
        auth.userDetailsService(userDetailsService())
                .passwordEncoder(passwordEncoder());
    }

    @Bean

    @ConfigurationProperties(prefix = "spring.datasource")
    public DataSource oauthDataSource() {
        return DataSourceBuilder.create().build();
    }


    @Bean
    public TokenStore tokenStore() {
        System.out.println("inside tokenstore");
        return new CustomJdbcTokenStore(oauthDataSource());
        //return new JdbcTokenStore(oauthDataSource());
        //return new JwtTokenStore(accessTokenConverter());
    }




//    @Override
//    @Bean(name = "userDetailsService")
//    public UserDetailsService userDetailsServiceBean()
//            throws Exception {
//        return super.userDetailsServiceBean();
//    }

}