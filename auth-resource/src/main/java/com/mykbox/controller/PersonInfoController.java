package com.mykbox.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.oauth2.client.DefaultOAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestOperations;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import com.mykbox.model.Person;
import org.springframework.web.client.RestOperations;

import java.security.Principal;

@RestController
public class PersonInfoController {

    @Autowired
    private OAuth2RestOperations restTemplate;

    @Autowired
    private RestOperations restOperations;

    @Autowired
    private TokenStore tokenStore;

    @Autowired
    private OAuth2ProtectedResourceDetails resource;

    @GetMapping("/person")
    @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_USER')")
    public String  personInfo(Principal user, OAuth2Authentication auth) {

        OAuth2AuthenticationDetails details = (OAuth2AuthenticationDetails) auth.getDetails();
        OAuth2AccessToken accessToken = tokenStore.readAccessToken(details.getTokenValue());
        OAuth2ClientContext context = new DefaultOAuth2ClientContext(new DefaultOAuth2AccessToken(details.getTokenValue()));
        OAuth2RestTemplate tokenRelayTemplate=new OAuth2RestTemplate(resource, context);
        //ResponseEntity<String> response =
        ResponseEntity<String> response = tokenRelayTemplate.getForEntity("http://localhost:9001/person", String.class);

        //ResponseEntity<String> response =
        //ResponseEntity<String> response = restTemplate.getForEntity("http://localhost:9001/person", String.class);
        return "Success! (" + response.getBody() + ")";
        //return restOperations.getForObject("http://localhost:9001/person", String.class);
       // return "Success! (" + response.getBody() + ")";
        //return new Person("sayan", "bangalore", "India", 32, "Male");
    }

//    @GetMapping("/personremote")
//     public String  personremote() {
//        String personResourceUrl = "http://localhost:9001/person";
//        System.out.println(restOperations.getForObject(personResourceUrl, String.class));
//        return "sdfsfd";
//     }



//    @RequestMapping("/relay")
//    public String relay() {
//        ResponseEntity<String> response =
//                restTemplate.getForEntity("http://localhost:9001/person", String.class);
//        return "Success! (" + response.getBody() + ")";
//    }
}
