package com.mykbox.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.encoding.PasswordEncoder;
import org.springframework.security.authentication.encoding.ShaPasswordEncoder;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import com.mykbox.security.UserDetailsServiceImpl;


@Configuration
@EnableWebSecurity
public class WebSecurityConfigurer
    extends
        WebSecurityConfigurerAdapter {



    @Bean
    public PasswordEncoder passwordEncoder() {
        return new ShaPasswordEncoder(256);
    }

    @Override
    protected void configure(HttpSecurity http)
        throws Exception {
        http
            .authorizeRequests()
            .antMatchers("/login**").permitAll()
            .anyRequest().authenticated()
            .and().csrf()
            .and().formLogin().loginPage("/login");
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/gettoken");
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


//    @Override
//    @Bean(name = "userDetailsService")
//    public UserDetailsService userDetailsServiceBean()
//            throws Exception {
//        return super.userDetailsServiceBean();
//    }

}