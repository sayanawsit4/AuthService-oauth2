package com.mykbox.controller;

import com.mykbox.config.MediUser;
import io.swagger.annotations.Api;
import org.apache.catalina.Store;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerEndpointsConfiguration;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.*;

@RestController
@Api(value="Authentication API", description="Authenticate user using authorization token.")
public class ResourceController {

    @Autowired
    private AuthorizationServerEndpointsConfiguration configuration;

    // TODO: 2/28/2019 :protect this endpoint with xauth headers as per AuthService 1.0 implementation
    @RequestMapping("/gettoken")
    public @ResponseBody
    String gettoken() {

        Map<String, String> requestParameters = new HashMap<String, String>();
        boolean approved = true;
        Set<String> responseTypes = new HashSet<String>();
        responseTypes.add("code");
        List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
        authorities.add(new SimpleGrantedAuthority("ROLE_" + "USER"));
        OAuth2Request oauth2Request = new OAuth2Request(requestParameters, "authserver", authorities, approved, new HashSet<String>(Arrays.asList("myscope")), null, null, responseTypes, null);
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken("piomin", "N/A", authorities);
        OAuth2Authentication auth = new OAuth2Authentication(oauth2Request, authenticationToken);
        AuthorizationServerTokenServices tokenService = configuration.getEndpointsConfigurer().getTokenServices();
        OAuth2AccessToken token = tokenService.createAccessToken(auth);
        System.out.println(token.getValue());
        return token.getValue();

    }

    @RequestMapping("/principalcheck")
    public String getStores(Principal principal){
        MediUser activeUser = (MediUser) ((Authentication) principal).getPrincipal();
        System.out.println(activeUser.getEmail());
        return activeUser.getEmail();

    }

    @RequestMapping("/secured/userdetails")
    @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_USER')")
    public String userdetails(Principal user, OAuth2Authentication auth){
        OAuth2AuthenticationDetails details = (OAuth2AuthenticationDetails) auth.getDetails();
         return user.getName();

    }

}