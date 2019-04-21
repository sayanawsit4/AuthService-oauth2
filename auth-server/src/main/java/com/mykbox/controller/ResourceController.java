package com.mykbox.controller;

import com.mykbox.config.constants.Config;
import com.mykbox.config.constants.Dto;
import com.mykbox.config.constants.Roles;
import com.mykbox.config.user.ExtendedUser;
import com.mykbox.domain.OperationalAudit;
import com.mykbox.domain.User;
import com.mykbox.dto.authenticateUser;
import com.mykbox.dto.updatePasswordRequest;
import com.mykbox.dto.userResponse;
import com.mykbox.repository.OpsAuditRepository;
import com.mykbox.repository.UserRepository;
import com.mykbox.service.UserService;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
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
import org.springframework.security.oauth2.provider.token.ConsumerTokenServices;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;
import org.springframework.web.bind.annotation.*;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletResponse;
import java.security.KeyPair;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;
import java.util.stream.Collectors;

import static com.mykbox.config.constants.Roles.ROLE_ADMIN;
import static com.mykbox.config.constants.Roles.ROLE_USER;

@RestController
@Api(value = "Authentication API", description = "Authenticate user using authorization token.")

public class ResourceController {

    @Autowired
    private AuthorizationServerEndpointsConfiguration configuration;

    @Autowired
    private UserRepository userRepository;

    @Resource(name = "tokenServices")
    ConsumerTokenServices contokenServices;

    @Autowired
    OpsAuditRepository opsAuditRepository;


    @Autowired
    UserService userService;

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
    @RequestMapping("/getAccessTokenByEmail")
    public @ResponseBody
    String gettoken(
            @RequestParam(value = "expiry_extension", required = false) Optional<Integer> expiryExtension,
            @RequestParam(value = "email") String email
    ) {

        Integer extendedValidity = 0;
        String Scope = "ad-hoc";


        if (expiryExtension.isPresent()) {

            System.out.println("expiryExtension --->" + expiryExtension.get());

            if (expiryExtension.get().equals(0)) {
                Scope = "one-time";
                extendedValidity = 0;
            } else {
                //  Scope ="ad-hoc";
                extendedValidity = validity + expiryExtension.get();
            }
        } else
            extendedValidity = validity;

        //   System.out.println("Scope-------->"+Scope);
        System.out.println("get token123-------->" + extendedValidity);
        Map<String, String> requestParameters = new HashMap<String, String>();
        boolean approved = true;
        Set<String> responseTypes = new HashSet<String>();
        responseTypes.add("code");

       /* List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
        authorities.add(new SimpleGrantedAuthority("ROLE_" + "ADMIN"));*/

        //load user details
        ExtendedUser ext = (ExtendedUser) userDetailsService.loadUserByUsername(email);
        OAuth2Request oauth2Request = new OAuth2Request(requestParameters, "authserver", ext.getAuthorities(), approved, new HashSet<String>(Arrays.asList(Scope)), null, null, responseTypes, null);
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(ext, "N/A", ext.getAuthorities());
        OAuth2Authentication auth = new OAuth2Authentication(oauth2Request, authenticationToken);
        DefaultTokenServices tokenServices = new DefaultTokenServices();
        tokenServices.setTokenStore(configuration.getEndpointsConfigurer().getTokenStore());
        tokenServices.setSupportRefreshToken(true);
        tokenServices.setClientDetailsService(configuration.getEndpointsConfigurer().getClientDetailsService());
        tokenServices.setTokenEnhancer(configuration.getEndpointsConfigurer().getTokenEnhancer());
        tokenServices.setAccessTokenValiditySeconds(extendedValidity);
        // tokenServices.setAccessTokenValiditySeconds(configuration.getEndpointsConfigurer().getTokenServices().);
        OAuth2AccessToken token = tokenServices.createAccessToken(auth);
        System.out.println(token.getExpiration());
        System.out.println(token.getValue());
        return token.getValue();
    }

    @RequestMapping("/getjwttoken")
    public @ResponseBody
    String tokenverify() {
        // Jwt jwt = JwtHelper.decode("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX25hbWUiOiJwaW9taW4iLCJzY29wZSI6WyJ0ZXN0eSJdLCJleHAiOjE1NTUyNDUwMDIsInRlc3QxIjoidGVzdDIiLCJhdXRob3JpdGllcyI6WyJST0xFX1VTRVIiXSwianRpIjoiN2IzZjAwMTktM2M0My00YzJiLWEyNDctODUxZGE4ZDVmY2QzIiwiY2xpZW50X2lkIjoiYXV0aHNlcnZlciJ9.T_4kflIshWp9csj3x69mZeDjljfs6UsWXaVgsgwxh-lL6CQIsJfj08gq8GJPbRrPpMCuHDgo382DZccSFog48aWRF0-sQN1Aa6yp0LapLFa_tLoGLXRdNLbOTQGwtHa0ZGFHmbxPkAkEuA1ldfzdE0poEzblLwAi1Olmswc2ltnVnkXauF-mDFLIgQvGR9gugyLvXDqAmB2p4eKYcXCJPV08hTM7zqj4NP4d8VU_7YLq-G8BpXQSaYQwSYvwPwusr2Ubjw4RXMndPl0s-647Ixpe6rM4qcPp-9CdkdqvDnfJyGobSnxqWRjRtglrrYe6sTJfcMeRvfgiiDVyBJR4tw");
        KeyStoreKeyFactory keyStoreKeyFactory = new KeyStoreKeyFactory(
                keystore, keystorePassword.toCharArray());
        KeyPair keyPair = keyStoreKeyFactory.getKeyPair(
                keyAlias, keyPassword.toCharArray());
        PrivateKey privateKey = keyPair.getPrivate();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        //Signer signer = new RsaSigner((RSAPrivateKey) privateKey);
        SignatureVerifier verifier = new RsaVerifier(publicKey);
        String content = "";
        try {
            Jwt jwt = JwtHelper.decodeAndVerify("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX25hbWUiOiJwaW9taW4iLCJzY29wZSI6WyJ0ZXN0eSJdLCJleHAiOjE1NTUyNDUwMDIsInRlc3QxIjoidGVzdDIiLCJhdXRob3JpdGllcyI6WyJST0xFX1VTRVIiXSwianRpIjoiN2IzZjAwMTktM2M0My00YzJiLWEyNDctODUxZGE4ZDVmY2QzIiwiY2xpZW50X2lkIjoiYXV0aHNlcnZlciJ9.T_4kflIshWp9csj3x69mZeDjljfs6UsWXaVgsgwxh-lL6CQIsJfj08gq8GJPbRrPpMCuHDgo382DZccSFog48aWRF0-sQN1Aa6yp0LapLFa_tLoGLXRdNLbOTQGwtHa0ZGFHmbxPkAkEuA1ldfzdE0poEzblLwAi1Olmswc2ltnVnkXauF-mDFLIgQvGR9gugyLvXDqAmB2p4eKYcXCJPV08hTM7zqj4NP4d8VU_7YLq-G8BpXQSaYQwSYvwPwusr2Ubjw4RXMndPl0s-647Ixpe6rM4qcPp-9CdkdqvDnfJyGobSnxqWRjRtglrrYe6sTJfcMeRvfgiiDVyBJR4tw", verifier);
            content = jwt.getClaims();
        } catch (Exception e) {
            throw new IllegalArgumentException("Cannot decode access token from JSON", e);
        }


        return content.toString();

    }


    @RequestMapping("/gettokenExtended")
    public @ResponseBody
    String gettokenExtended(
            @RequestParam(value = "expiry_extension", required = false) Optional<String> expiryExtension
    ) {

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

    @RequestMapping(method = RequestMethod.POST, value = "/authenticateSSO")
    public @ResponseBody
    String authenticateSSO(@RequestBody authenticateUser authenticateUser, HttpServletResponse response) {

        // return  "invalid credentials";
        System.out.println(authenticateUser.getEmail());


        Map<String, String> requestParameters = new HashMap<String, String>();
        ExtendedUser temp = (ExtendedUser) userDetailsService.loadUserByUsername(authenticateUser.getEmail());
        PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

/*        System.out.println(authenticateUser.getPassword());
         System.out.println(new BCryptPasswordEncoder().encode(authenticateUser.getPassword()));
        System.out.println(temp.getPassword());
         System.out.println(BCrypt.checkpw(authenticateUser.getPassword(),temp.getPassword()));*/


        if (BCrypt.checkpw(authenticateUser.getPassword(), temp.getPassword())) {
            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(temp, authenticateUser.getPassword(), temp.getAuthorities());
            Set<String> responseTypes = new HashSet<String>();
            responseTypes.add("code");
            OAuth2Request oauth2Request = new OAuth2Request(requestParameters, "authserver", temp.getAuthorities(), true, new HashSet<String>(Arrays.asList("ad-hoc")), null, null, responseTypes, null);
            OAuth2Authentication auth = new OAuth2Authentication(oauth2Request, authenticationToken);
            DefaultTokenServices tokenServices = new DefaultTokenServices();
            tokenServices.setTokenStore(configuration.getEndpointsConfigurer().getTokenStore());
            tokenServices.setSupportRefreshToken(true);
            tokenServices.setClientDetailsService(configuration.getEndpointsConfigurer().getClientDetailsService());
            tokenServices.setTokenEnhancer(configuration.getEndpointsConfigurer().getTokenEnhancer());
            tokenServices.setAccessTokenValiditySeconds(validity);
            // tokenServices.setAccessTokenValiditySeconds(configuration.getEndpointsConfigurer().getTokenServices().);
            OAuth2AccessToken token = tokenServices.createAccessToken(auth);
            System.out.println(token.getExpiration());
            System.out.println(token.getValue());
            response.addHeader("token", token.getValue());
            return authenticateUser.getEmail();// "token created";
        } else
            return "invalid credentials";
    }


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

    @ApiOperation(value = "Update password", response = String.class)
    @RequestMapping(value = "/api/updatePassword", method = RequestMethod.POST)
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = Dto.UPDATE_SUCESSFULLY, response = String.class),
            @ApiResponse(code = 401, message = Dto.UPDATE_UNAUTHORIZED),
            @ApiResponse(code = 403, message = "Forbidden"),
            @ApiResponse(code = 404, message = Dto.UPDATE_USER_NOT_FOUND),
            @ApiResponse(code = 500, message = "Failure")})
    @PreAuthorize("hasAnyRole('"+ROLE_ADMIN+"', '"+ROLE_USER+"')")
    public ResponseEntity updateUser(@RequestBody updatePasswordRequest updatePasswordRequest,
                                     @SessionAttribute(Config.OPS_TRACE_ID) String trackId,
                                     OAuth2Authentication auth) {
    Map<String,String> responseobj =userService.updatePassword(updatePasswordRequest,(ExtendedUser) auth.getPrincipal(),trackId);
    return new ResponseEntity<>(responseobj.get("message"),HttpStatus.valueOf(responseobj.get("status")));

        //return new ResponseEntity(responseobj.get("message"),;

 /*       User user = null;
        Optional<User> temp = Optional.ofNullable(userRepository.findByEmail(updatePasswordRequest.getEmail()));
        if (temp.isPresent()) {
             ExtendedUser extendedUser = (ExtendedUser) auth.getPrincipal();
             List roles = extendedUser.getAuthorities().stream().map(s -> s.getAuthority()).collect(Collectors.toList());

            if (roles.contains(ROLE_ADMIN) || temp.get().getEmail().equals(extendedUser.getEmail())) {
                user = temp.get();
                user.setUserId(temp.get().getUserId());
                user.setPassword(new BCryptPasswordEncoder().encode(updatePasswordRequest.getNewPassword()));
                userRepository.save(user);

                OperationalAudit u = opsAuditRepository.findOne(UUID.fromString(trackId));
                u.setUserId(temp.get().getUserId());
                return new ResponseEntity<>(Dto.UPDATE_SUCESSFULLY, HttpStatus.OK);
            } else {
                return new ResponseEntity<>(Dto.UPDATE_UNAUTHORIZED, HttpStatus.UNAUTHORIZED);
            }
        } else {
             return new ResponseEntity<>(Dto.UPDATE_USER_NOT_FOUND,HttpStatus.NOT_FOUND);
        }
*/


    }


    @RequestMapping("/api/user")
    @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_USER')")
    public userResponse user(Principal user, OAuth2Authentication auth) {

        // auth.getOAuth2Request().
        // OAuth2Authentication.
        final OAuth2AuthenticationDetails details = (OAuth2AuthenticationDetails) auth.getDetails();
        final OAuth2AccessToken accessToken = tokenStore.readAccessToken(details.getTokenValue());

        // ConsumerTokenServices tokenServices = new tokenServices() ;

        if (accessToken.getScope().contains("one-time") && accessToken.getScope().size() == 1)
            contokenServices.revokeToken(details.getTokenValue());//tokenServices.

        //DefaultTokenServices tokenServices = new DefaultTokenServices();
        //  tokenServices.setTokenStore(configuration.getEndpointsConfigurer().getTokenStore());

        //  if (accessToken.getScope().contains("one-time") && accessToken.getScope().size() == 1)
        //tokenServices.revokeToken(tokenId);


        ExtendedUser extendedUser = (ExtendedUser) auth.getPrincipal();


        userResponse userResponse = new userResponse();
        userResponse.setUserId(extendedUser.getUserid());
        userResponse.setUsername(extendedUser.getEmail());
        userResponse.setEmail(extendedUser.getEmail());
        userResponse.setFirst_name(extendedUser.getfirstName());
        userResponse.setLast_name(extendedUser.getlastName());
        return userResponse;
    }

}