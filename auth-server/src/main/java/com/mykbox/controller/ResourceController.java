package com.mykbox.controller;

import com.mykbox.config.MediUser;
import com.mykbox.domain.User;
import com.mykbox.repository.UserRepository;
import io.swagger.annotations.Api;
import org.apache.catalina.Store;
import org.omg.Messaging.SYNC_WITH_TRANSPORT;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerEndpointsConfiguration;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.security.oauth2.provider.client.JdbcClientDetailsService;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.security.oauth2.provider.token.ConsumerTokenServices;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JdbcTokenStore;
import org.springframework.web.bind.annotation.*;

import javax.annotation.Resource;
import java.security.Principal;
import java.util.*;

@RestController
@Api(value="Authentication API", description="Authenticate user using authorization token.")
public class ResourceController {

    @Autowired
    private AuthorizationServerEndpointsConfiguration configuration;

    @Autowired
    private UserRepository userRepository;

    @Resource(name="tokenStore")
    TokenStore tokenStore;





    // TODO: 2/28/2019 :protect this endpoint with xauth headers as per AuthService 1.0 implementation
    @RequestMapping("/gettoken")
    public @ResponseBody
    String gettoken() {

        System.out.println("get token123");
        Map<String, String> requestParameters = new HashMap<String, String>();
        boolean approved = true;
        Set<String> responseTypes = new HashSet<String>();
        responseTypes.add("code");
        List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
        authorities.add(new SimpleGrantedAuthority("ROLE_" + "USER"));
        OAuth2Request oauth2Request = new OAuth2Request(requestParameters, "authserver", authorities, approved, new HashSet<String>(Arrays.asList("testy")), null, null, responseTypes, null);
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken("piomin", "N/A", authorities);
        OAuth2Authentication auth = new OAuth2Authentication(oauth2Request, authenticationToken);

        DefaultTokenServices tokenServices = new DefaultTokenServices();
        tokenServices.setTokenStore(configuration.getEndpointsConfigurer().getTokenStore());
        tokenServices.setSupportRefreshToken(true);
        tokenServices.setClientDetailsService(configuration.getEndpointsConfigurer().getClientDetailsService());
        tokenServices.setTokenEnhancer(configuration.getEndpointsConfigurer().getTokenEnhancer());
        tokenServices.setAccessTokenValiditySeconds(217200);

       // ConsumerTokenServices tokenServices2 =configuration.getEndpointsConfigurer().getConsumerTokenServices();

       // AuthorizationServerTokenServices tokenService = (DefaultTokenServices)tokenServices2; //new DefaultTokenServices();
        // configuration.getEndpointsConfigurer().getTokenServices();

       // ClientDetailsService clientDetailsService = configuration.getEndpointsConfigurer().getClientDetailsService();
       // ClientDetails clientDetails = clientDetailsService.loadClientByClientId("authserver");
        //clientDetails.



        //AuthorizationServerTokenServices tokenService = configuration.getEndpointsConfigurer().getTokenServices();
         OAuth2AccessToken token = tokenServices.createAccessToken(auth);

        System.out.println(token.getExpiration());
        System.out.println(token.getValue());
        return token.getValue();

    }

    @RequestMapping("/gettokenExtended")
    public @ResponseBody
    String gettokenExtended() {

        Map<String, String> requestParameters = new HashMap<String, String>();
        boolean approved = true;
        Set<String> responseTypes = new HashSet<String>();
        responseTypes.add("code");
        List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
        authorities.add(new SimpleGrantedAuthority("ROLE_" + "USER"));
        OAuth2Request oauth2Request = new OAuth2Request(requestParameters, "authserver", authorities, approved, new HashSet<String>(Arrays.asList("testy")), null, null, responseTypes, null);
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken("piomin", "N/A", authorities);
        OAuth2Authentication auth = new OAuth2Authentication(oauth2Request, authenticationToken);
        AuthorizationServerTokenServices tokenService = configuration.getEndpointsConfigurer().getTokenServices();
        OAuth2AccessToken token = tokenService.createAccessToken(auth);
        System.out.println(token.getValue());
         return token.getValue();

    }

    @RequestMapping(method = RequestMethod.GET, value = "/tokens")
    @ResponseBody
    public List<String> getTokens() {
        List<String> tokenValues = new ArrayList<String>();
        Collection<OAuth2AccessToken> tokens = tokenStore.findTokensByClientId("authserver");

        System.out.println("inside method");

        if (tokens!=null){
            for (OAuth2AccessToken token:tokens){
                System.out.println(token.getValue());
               token.getScope().forEach(s -> System.out.println(s.toString()));
                 if(token.getScope().contains("testy") && token.getScope().size()==1)
                 tokenValues.add(token.getValue());
            }
        }
        return tokenValues;
    }

//    @RequestMapping(method = RequestMethod.POST, value = "/tokens/revoke/")
//    @ResponseBody
//    public String revokeToken() {
//        tokenServices.revokeToken(tokenId);
//        return tokenId;
//    }

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

    @RequestMapping("/secured/findall")
    @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_USER')")
    public List findAll(){
        String result = "";
        for(User cust : userRepository.findAll()){
            result += cust.toString() + "<br>";
        }
      return userRepository.findAll();
    }

    @RequestMapping("/secured/user")
    public Principal user(Principal user,OAuth2Authentication auth) {
        return user;
    }

}