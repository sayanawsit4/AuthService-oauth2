package com.mykbox;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.*;
import org.springframework.session.jdbc.config.annotation.web.http.EnableJdbcHttpSession;

@SpringBootApplication
@EnableJdbcHttpSession
public class AuthServer {

    public static void main(String[] args) {
        SpringApplication.run(AuthServer.class, args);
    }
}
