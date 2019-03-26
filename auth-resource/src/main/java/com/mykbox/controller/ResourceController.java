package com.mykbox.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.security.oauth2.provider.token.TokenStore;
import java.security.Principal;
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

}
