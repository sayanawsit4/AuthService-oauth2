package com.mykbox.config;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

public class CustomTokenConverter extends JwtAccessTokenConverter {

    @Override
    public OAuth2AccessToken enhance(OAuth2AccessToken accessToken,
                                     OAuth2Authentication authentication) {
        //if(authentication.getOAuth2Request().getGrantType().equalsIgnoreCase("password")) {
           //UserDetails user = (UserDetails)  SecurityContextHolder.getContext().getAuthentication().getPrincipal().;

          // System.out.println(user.getUsername());

        //Authentication auth = SecurityContextHolder.getContext().getAuthentication();
       // User u =(User) auth.getPrincipal();

       // Authentication auth = SecurityContextHolder.getContext().getAuthentication();
       // MediUser currentUser = (MediUser)auth.getPrincipal();
       // System.out.println("user is"+currentUser.getUsername());
       // System.out.println("Email is"+currentUser.getEmail());

        //MediUser currentUser = (MediUser)authentication.getPrincipal();
        //System.out.println("Email is"+currentUser.getEmail());

           final Map<String, Object> additionalInfo = new HashMap<String, Object>();
            additionalInfo.put("test1", "test1");
            ((DefaultOAuth2AccessToken) accessToken).setAdditionalInformation(additionalInfo);
     //   }
        accessToken = super.enhance(accessToken, authentication);
        ((DefaultOAuth2AccessToken) accessToken).setAdditionalInformation(new HashMap<>());
         authentication = super.extractAuthentication(additionalInfo);
        //((DefaultOAuth2AccessToken) accessToken).setScope(new HashSet<String>(Arrays.asList("read")));
         authentication.setDetails(additionalInfo);

        return accessToken;
    }

}
