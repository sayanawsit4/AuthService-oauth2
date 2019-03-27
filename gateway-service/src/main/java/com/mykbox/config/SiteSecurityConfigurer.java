package com.mykbox.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.cloud.security.oauth2.gateway.TokenRelayGatewayFilterFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;



@Configuration
@EnableWebFluxSecurity
@PropertySource("classpath:application-oauth2.properties")
public class SiteSecurityConfigurer {


    @Bean
    public SecurityWebFilterChain configure(ServerHttpSecurity http) throws Exception {
        return http.authorizeExchange()
                .pathMatchers("/about").permitAll()
                .anyExchange().authenticated()
                .and().oauth2Login()
                .and().build();
    }

//    @Bean
//    public RouteLocator routeLocator2(RouteLocatorBuilder builder) {
//        return builder.routes()
//                .route(r ->
//                        r.path("/person/**")
//                                .filters(f -> f.filter(filterFactory.apply()))
////                                .filters(
////                                        f -> f.stripPrefix(1)
////                                )
//                                .uri("http://localhost:9000/person")
//                )
//                .build();
//    }

 }
