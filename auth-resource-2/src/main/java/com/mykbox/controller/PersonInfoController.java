package com.mykbox.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import com.mykbox.model.Person;

import java.security.Principal;

@RestController
public class PersonInfoController {

   // private TokenStore tokenStore;

    @GetMapping("/person")
    @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_USER')")
    public @ResponseBody Person personInfo(Principal user, OAuth2Authentication auth) {

        // details = (OAuth2AuthenticationDetails) auth.getDetails();
        //OAuth2AccessToken accessToken = tokenStore.readAccessToken(details.getTokenValue());

        //ystem.out.println("sdfsdfsfddsfsdf"+details.getTokenValue());

        return new Person("sayan", "bangalore123", "India", 32, "Male");
    }   
}
