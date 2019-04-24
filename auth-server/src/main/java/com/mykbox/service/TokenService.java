package com.mykbox.service;

import com.mykbox.config.constants.Token;
import com.mykbox.config.user.ExtendedUser;
import com.mykbox.domain.OperationalAudit;
import com.mykbox.domain.User;
import com.mykbox.repository.OpsAuditRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.jwt.crypto.sign.RsaVerifier;
import org.springframework.security.jwt.crypto.sign.SignatureVerifier;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerEndpointsConfiguration;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.security.oauth2.provider.client.JdbcClientDetailsService;
import org.springframework.security.oauth2.provider.token.ConsumerTokenServices;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;

@Service
public class TokenService {

    @Value("${jwt.certificate.store.file}")
    private org.springframework.core.io.Resource keystore;

    @Value("${jwt.certificate.store.password}")
    private String keystorePassword;

    @Value("${jwt.certificate.key.alias}")
    private String keyAlias;

    @Value("${jwt.certificate.key.password}")
    private String keyPassword;

    @Resource(name = "tokenServices")
    ConsumerTokenServices contokenServices;

    @Resource(name = "tokenStore")
    TokenStore tokenStore;

    @Autowired
    OpsAuditRepository opsAuditRepository;

    @Autowired
    private JdbcClientDetailsService clientsDetailsService;

    @Autowired
    private AuthorizationServerEndpointsConfiguration configuration;

    public void  revokeToken(OAuth2AccessToken accessToken,OAuth2AuthenticationDetails details ) {
        if (accessToken.getScope().contains(Token.ONE_TIME) && accessToken.getScope().size() == 1)
            contokenServices.revokeToken(details.getTokenValue());
    }


    public Boolean checkClientId(String ClientId) {
        Boolean checkClint;
        try {
            checkClint = Optional.ofNullable(clientsDetailsService.loadClientByClientId(ClientId)).isPresent();
        } catch (Exception e) {
            checkClint = false;
        }
        return checkClint;
    }



    public void UpdateOperationalAudit(String trackId,
                                       String response,
                                       ExtendedUser extendedUser,
                                       String scope)
    {
        OperationalAudit u = opsAuditRepository.findOne(UUID.fromString(trackId));
        u.setUserId(extendedUser.getUserid());
        u.setScope(scope);
        u.setResponse(response);
    }



    public OAuth2AccessToken createToken(Integer extendedValidity,
                                         ExtendedUser ext,
                                         String scope,
                                         String clientId) throws AuthenticationException
    {
        String response;
        Map<String, String> requestParameters = new HashMap<String, String>();
        boolean approved = true;
        Set<String> responseTypes = new HashSet<String>();
        responseTypes.add("code");
        OAuth2Request oauth2Request = new OAuth2Request(requestParameters, clientId, ext.getAuthorities(), approved, new HashSet<String>(Arrays.asList(scope)), null, null, responseTypes, null);
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(ext, "N/A", ext.getAuthorities());
        OAuth2Authentication auth = new OAuth2Authentication(oauth2Request, authenticationToken);
        DefaultTokenServices tokenServices = new DefaultTokenServices();
        tokenServices.setTokenStore(configuration.getEndpointsConfigurer().getTokenStore());
        tokenServices.setSupportRefreshToken(true);
        tokenServices.setClientDetailsService(configuration.getEndpointsConfigurer().getClientDetailsService());
        tokenServices.setTokenEnhancer(configuration.getEndpointsConfigurer().getTokenEnhancer());
        tokenServices.setAccessTokenValiditySeconds(extendedValidity);
        tokenServices.createAccessToken(auth);
        return tokenServices.createAccessToken(auth);
    }


    public List<String> searchTokenByScope(Optional<String> scope, String clientId) {
        List<String> tokenValues = new ArrayList<String>();
        Collection<OAuth2AccessToken> tokens = tokenStore.findTokensByClientId(clientId);
        if (tokens != null) {
            for (OAuth2AccessToken token : tokens) {
                if (scope.isPresent() && token.getScope().contains(scope.get()) && token.getScope().size() == 1)
                    tokenValues.add(token.getValue());
                }
        }
        return tokenValues;
    }


    Boolean verifyJWTToken(String token){
        KeyStoreKeyFactory keyStoreKeyFactory = new KeyStoreKeyFactory(
                keystore, keystorePassword.toCharArray());
        KeyPair keyPair = keyStoreKeyFactory.getKeyPair(
                keyAlias, keyPassword.toCharArray());
        PrivateKey privateKey = keyPair.getPrivate();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        //Signer signer = new RsaSigner((RSAPrivateKey) privateKey);
        SignatureVerifier verifier = new RsaVerifier(publicKey);
        Optional<Jwt> jwt;
        try {
             jwt = Optional.ofNullable(JwtHelper.decodeAndVerify(token,verifier));
         } catch (Exception e) {
            //throw new IllegalArgumentException("Cannot decode access token from JSON", e);
            return false;
        }
        return  jwt.isPresent();
    }

}