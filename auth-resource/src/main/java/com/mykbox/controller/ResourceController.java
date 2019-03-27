package com.mykbox.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.oauth2.client.DefaultOAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsResourceDetails;
import org.springframework.security.oauth2.client.token.grant.password.ResourceOwnerPasswordResourceDetails;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.security.oauth2.provider.token.TokenStore;

import javax.servlet.http.HttpServletRequest;
import java.security.Principal;
import java.util.Arrays;
import java.util.Map;

/**
 * Because this application is also a User Info Resource Server, we expose info about the logged in user at:
 *
 *     http://localhost:9090/auth/user
 */
@RestController
public class ResourceController {
    @Autowired
    private TokenStore tokenStore;

    @Autowired
    private OAuth2ProtectedResourceDetails resource;

    @Autowired
    private OAuth2RestTemplate tokenRelayTemplate;

    @RequestMapping("/user")
    public Principal user(Principal user,OAuth2Authentication auth) {
        final OAuth2AuthenticationDetails details = (OAuth2AuthenticationDetails) auth.getDetails();
        final OAuth2AccessToken accessToken = tokenStore.readAccessToken(details.getTokenValue());
        System.out.println(accessToken.getValue());
        Jwt jwtToken = JwtHelper.decode(accessToken.getValue());
        System.out.println(accessToken.getAdditionalInformation().get("test"));
        System.out.println(jwtToken.getClaims());
        System.out.println(details.getDecodedDetails());
        return user;
    }



//    private HttpEntity<?> getRequest(HttpServletRequest request) {
//        HttpHeaders headers = new HttpHeaders();
//        headers.set("Authorization", "Bearer " + getRequestToken(request));
//        return new HttpEntity<>(null, headers);
//    }

    @GetMapping("/test")
    @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_USER')")
    public String  testinfo(Principal user,OAuth2Authentication auth) {

        OAuth2AuthenticationDetails details = (OAuth2AuthenticationDetails) auth.getDetails();
        OAuth2AccessToken accessToken = tokenStore.readAccessToken(details.getTokenValue());
        OAuth2ClientContext context = new DefaultOAuth2ClientContext(new DefaultOAuth2AccessToken(details.getTokenValue()));
        OAuth2RestTemplate tokenRelayTemplate=new OAuth2RestTemplate(resource, context);
        //ResponseEntity<String> response =
        ResponseEntity<String> response = tokenRelayTemplate.getForEntity("http://localhost:9001/person", String.class);
        //ResponseEntity<String> response = restTemplate.getForEntity("http://localhost:9001/person", String.class);
        return "Success! (" + response.getBody() + ")";
        //return restOperations.getForObject("http://localhost:9001/person", String.class);
        // return "Success! (" + response.getBody() + ")";
        //return new Person("sayan", "bangalore", "India", 32, "Male");
    }

//    public OAuth2RestTemplate tokenRelayTemplate(Principal principal, OAuth2Authentication auth) {
//        OAuth2AuthenticationDetails details = (OAuth2AuthenticationDetails) auth.getDetails();
//        OAuth2AccessToken accessToken = tokenStore.readAccessToken(details.getTokenValue());
//        OAuth2ClientContext context = new DefaultOAuth2ClientContext(new DefaultOAuth2AccessToken(details.getTokenValue()));
//        return new OAuth2RestTemplate(resource, context);
//    }

//    @Autowired
//    private OAuth2ProtectedResourceDetails resource;
//
//    private OAuth2RestTemplate tokenRelayTemplate(Principal principal) {
//        OAuth2Authentication authentication = (OAuth2Authentication) principal;
//        OAuth2AuthenticationDetails details = (OAuth2AuthenticationDetails) authentication.getDetails();
//        details.getTokenValue();
//        OAuth2ClientContext context = new DefaultOAuth2ClientContext(new DefaultOAuth2AccessToken(details.getTokenValue()));
//        return new OAuth2RestTemplate(resource, context);
//    }

}
