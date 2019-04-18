package com.mykbox.controller;

import com.mykbox.config.user.ExtendedUser;
import com.mykbox.domain.User;
import com.mykbox.dto.updatePasswordRequest;
import com.mykbox.dto.userResponse;
import com.mykbox.repository.UserRepository;
import io.swagger.annotations.Api;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.jwt.crypto.sign.RsaVerifier;
import org.springframework.security.jwt.crypto.sign.SignatureVerifier;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerEndpointsConfiguration;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;
import org.springframework.web.bind.annotation.*;

import javax.annotation.Resource;
import java.security.KeyPair;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;

@RestController
@Api(value = "Authentication API", description = "Authenticate user using authorization token.")
public class ResourceController {

    @Autowired
    private AuthorizationServerEndpointsConfiguration configuration;

    @Autowired
    private UserRepository userRepository;


    @Autowired
    private UserDetailsService userDetailsService;
//
//    @Autowired
//    private TokenStore tokenStore;

    @Resource(name = "tokenStore")
    TokenStore tokenStore;

    @Value("${jwt.certificate.store.file}")
    private org.springframework.core.io.Resource keystore;

    @Value("${jwt.certificate.store.password}")
    private String keystorePassword;

    @Value("${jwt.certificate.key.alias}")
    private String keyAlias;

    @Value("${jwt.certificate.key.password}")
    private String keyPassword;

    @Value("${token.validity}")
    private Integer validity;

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



        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(userDetailsService.loadUserByUsername("piotr.minkowski@gmail.com"), "N/A", authorities);

        OAuth2Authentication auth = new OAuth2Authentication(oauth2Request, authenticationToken);
        //authenticationToken.setDetails( userDetailsService.loadUserByUsername("piomin"));
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

    @RequestMapping("/getjwttoken")
    public @ResponseBody
    String tokenverify(){
       // Jwt jwt = JwtHelper.decode("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX25hbWUiOiJwaW9taW4iLCJzY29wZSI6WyJ0ZXN0eSJdLCJleHAiOjE1NTUyNDUwMDIsInRlc3QxIjoidGVzdDIiLCJhdXRob3JpdGllcyI6WyJST0xFX1VTRVIiXSwianRpIjoiN2IzZjAwMTktM2M0My00YzJiLWEyNDctODUxZGE4ZDVmY2QzIiwiY2xpZW50X2lkIjoiYXV0aHNlcnZlciJ9.T_4kflIshWp9csj3x69mZeDjljfs6UsWXaVgsgwxh-lL6CQIsJfj08gq8GJPbRrPpMCuHDgo382DZccSFog48aWRF0-sQN1Aa6yp0LapLFa_tLoGLXRdNLbOTQGwtHa0ZGFHmbxPkAkEuA1ldfzdE0poEzblLwAi1Olmswc2ltnVnkXauF-mDFLIgQvGR9gugyLvXDqAmB2p4eKYcXCJPV08hTM7zqj4NP4d8VU_7YLq-G8BpXQSaYQwSYvwPwusr2Ubjw4RXMndPl0s-647Ixpe6rM4qcPp-9CdkdqvDnfJyGobSnxqWRjRtglrrYe6sTJfcMeRvfgiiDVyBJR4tw");
        KeyStoreKeyFactory keyStoreKeyFactory = new KeyStoreKeyFactory(
                keystore, keystorePassword.toCharArray());
        KeyPair keyPair = keyStoreKeyFactory.getKeyPair(
                keyAlias, keyPassword.toCharArray());
        PrivateKey privateKey = keyPair.getPrivate();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
         //Signer signer = new RsaSigner((RSAPrivateKey) privateKey);
        SignatureVerifier verifier = new RsaVerifier(publicKey);
        String content="";
        try {
            Jwt jwt= JwtHelper.decodeAndVerify("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX25hbWUiOiJwaW9taW4iLCJzY29wZSI6WyJ0ZXN0eSJdLCJleHAiOjE1NTUyNDUwMDIsInRlc3QxIjoidGVzdDIiLCJhdXRob3JpdGllcyI6WyJST0xFX1VTRVIiXSwianRpIjoiN2IzZjAwMTktM2M0My00YzJiLWEyNDctODUxZGE4ZDVmY2QzIiwiY2xpZW50X2lkIjoiYXV0aHNlcnZlciJ9.T_4kflIshWp9csj3x69mZeDjljfs6UsWXaVgsgwxh-lL6CQIsJfj08gq8GJPbRrPpMCuHDgo382DZccSFog48aWRF0-sQN1Aa6yp0LapLFa_tLoGLXRdNLbOTQGwtHa0ZGFHmbxPkAkEuA1ldfzdE0poEzblLwAi1Olmswc2ltnVnkXauF-mDFLIgQvGR9gugyLvXDqAmB2p4eKYcXCJPV08hTM7zqj4NP4d8VU_7YLq-G8BpXQSaYQwSYvwPwusr2Ubjw4RXMndPl0s-647Ixpe6rM4qcPp-9CdkdqvDnfJyGobSnxqWRjRtglrrYe6sTJfcMeRvfgiiDVyBJR4tw", verifier);
            content = jwt.getClaims();
         }
        catch (Exception e) {
            throw new IllegalArgumentException("Cannot decode access token from JSON", e);
        }


        return content.toString();

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

        if (tokens != null) {
            for (OAuth2AccessToken token : tokens) {
                System.out.println(token.getValue());
                token.getScope().forEach(s -> System.out.println(s.toString()));
                if (token.getScope().contains("testy") && token.getScope().size() == 1)
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
    public String getStores(Principal principal) {
        ExtendedUser activeUser = (ExtendedUser) ((Authentication) principal).getPrincipal();
        System.out.println(activeUser.getEmail());
        return activeUser.getEmail();

    }

    @RequestMapping("/secured/userdetails")
    @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_USER')")
    public String userdetails(Principal user, OAuth2Authentication auth) {
        OAuth2AuthenticationDetails details = (OAuth2AuthenticationDetails) auth.getDetails();
        return user.getName();

    }

    @RequestMapping("/secured/findall")
    @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_USER')")
    public List findAll() {
        return userRepository.findAll();
    }

    @RequestMapping("/secured/save")
    @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_USER')")
    public String process(@RequestBody User user) {
        Optional<User> temp = Optional.ofNullable(userRepository.findByEmail(user.getEmail()));
        if (temp.isPresent()) {
            user.setUserId(temp.get().getUserId());
            userRepository.save(user);
        } else {
            userRepository.save(user);
        }
        return "done";
    }
    
    // TODO: 4/18/2019 legacy
    @RequestMapping("/api/createUser")
    @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_USER')")
    public String createUser(@RequestBody User user) {
        Optional<User> temp = Optional.ofNullable(userRepository.findByEmail(user.getEmail()));
        if (temp.isPresent()) {
            return "user already exists";
        } else {
            userRepository.save(user);
            return "created successfully";
        }
    }

    // TODO: 4/18/2019 legacy
    @RequestMapping("/api/updateUser")
    @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_USER')")
    public String updateUser(@RequestBody User user) {
        Optional<User> temp = Optional.ofNullable(userRepository.findByEmail(user.getEmail()));
        if (temp.isPresent()) {
            user.setUserId(temp.get().getUserId());
            userRepository.save(user);
            return "user updated successfully";
        } else {
            return "user not present";
        }
    }

    // TODO: 4/18/2019 legacy
    @RequestMapping("/api/updatePassword")
    @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_USER')")
    public String updateUser(@RequestBody updatePasswordRequest updatePasswordRequest) {
        User user = null;
        Optional<User> temp = Optional.ofNullable(userRepository.findByEmail(updatePasswordRequest.getEmail()));
        if (temp.isPresent()) {
            user = temp.get();
            user.setUserId(temp.get().getUserId());
            user.setPassword(new BCryptPasswordEncoder().encode(updatePasswordRequest.getNewPassword()));
            userRepository.save(user);
            return "password updated successfully";
        } else {
            return "user not present";
        }
    }



    @RequestMapping("/api/user")
    public userResponse user(Principal user, OAuth2Authentication auth) {
        ExtendedUser extendedUser = (ExtendedUser)auth.getPrincipal();
        userResponse userResponse = new userResponse();
        userResponse.setUserId(extendedUser.getUserid());
        userResponse.setUsername(extendedUser.getEmail());
        userResponse.setEmail(extendedUser.getEmail());
        userResponse.setFirst_name(extendedUser.getfirstName());
        userResponse.setLast_name(extendedUser.getlastName());
        return userResponse;
    }

}