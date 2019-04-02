package com.mykbox.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import static org.springframework.security.oauth2.client.web.reactive.function.client.ServerOAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient;

@RestController
public class GatewayServiceController {

    @Autowired
    WebClient webClient;

    @GetMapping("/auth-code")
    Mono<String> useOauthWithAuthCode(@RegisteredOAuth2AuthorizedClient("authserver") OAuth2AuthorizedClient client) {
        Mono<String> retrievedResource = webClient.get()
                .uri("http://localhost:9000/user")
                .attributes(oauth2AuthorizedClient(client))
                .retrieve()
                .bodyToMono(String.class);
        return retrievedResource.map(string -> "We retrieved the following resource using Oauth: " + string);
    }



    @GetMapping("/")
    public Mono<String> index(@AuthenticationPrincipal Mono<OAuth2User> oauth2User, @RegisteredOAuth2AuthorizedClient("authserver") OAuth2AuthorizedClient client) {

        oauth2User.map(OAuth2User::getAttributes).subscribe(System.out::println);

        Mono<String> retrievedResource = webClient.get()
                .uri("http://localhost:9000/person")
                .attributes(oauth2AuthorizedClient(client))
                .retrieve()
                .bodyToMono(String.class);

        return retrievedResource.map( string -> string);
    }

    @GetMapping("/about")
    public String getAboutPage() {
        return "WebFlux OAuth example";
    }

}