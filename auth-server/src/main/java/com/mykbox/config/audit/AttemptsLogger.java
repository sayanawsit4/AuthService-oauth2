package com.mykbox.config.audit;

import com.mykbox.domain.AccessAudit;
import com.mykbox.repository.AuditRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.actuate.audit.AuditEvent;
import org.springframework.boot.actuate.audit.listener.AuditApplicationEvent;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Component
public class AttemptsLogger {


    @Resource(name = "tokenStore")
    TokenStore tokenStore;

    @Autowired
    AuditRepository auditRepository;

    @EventListener
    public void auditEventHappened(AuditApplicationEvent auditApplicationEvent) {
        AuditEvent auditEvent = auditApplicationEvent.getAuditEvent();
        System.out.println("Principal " + auditEvent.getPrincipal() + " - " + auditEvent.getType() + auditEvent.getData().get("details"));

        if (auditEvent.getData().get("details") instanceof WebAuthenticationDetails) {
            WebAuthenticationDetails details = (WebAuthenticationDetails) auditEvent.getData().get("details");
            System.out.println("Principal " + auditEvent.getPrincipal());
            System.out.println("Authentication " + auditEvent.getType());
            System.out.println("Remote IP address: " + details.getRemoteAddress());
            System.out.println("Session Id: " + details.getSessionId());
            System.out.println("Request URL: " + auditEvent.getData().get("requestUrl"));
        }

        if (auditEvent.getData().get("details") instanceof PreAuthenticatedAuthenticationToken) {
            PreAuthenticatedAuthenticationToken details = (PreAuthenticatedAuthenticationToken) auditEvent.getData().get("details");
            RequestAttributes requestAttributes = RequestContextHolder.getRequestAttributes();
            HttpServletRequest request = ((ServletRequestAttributes) requestAttributes).getRequest();
            System.out.println("Principal " + auditEvent.getPrincipal());
            System.out.println("Authentication " + auditEvent.getType());
            System.out.println("Remote IP: " + request.getRemoteAddr());
            System.out.println("Url: " + request.getRequestURL());
            System.out.println("Authtype: " + request.getAuthType());

            AccessAudit accessAudit = new AccessAudit();
            accessAudit.setEmail(auditEvent.getPrincipal());
            auditRepository.save(accessAudit);

        }

        if (auditEvent.getData().get("details") instanceof UsernamePasswordAuthenticationToken) {
            UsernamePasswordAuthenticationToken details = (UsernamePasswordAuthenticationToken) auditEvent.getData().get("details");
            RequestAttributes requestAttributes = RequestContextHolder.getRequestAttributes();
            HttpServletRequest request = ((ServletRequestAttributes) requestAttributes).getRequest();
            System.out.println("Principal " + auditEvent.getPrincipal());
            System.out.println("Authentication " + details.isAuthenticated());
            System.out.println("Remote IP: " + request.getRemoteAddr());
            System.out.println("Url: " + request.getRequestURL());
            System.out.println("Authtype: " + request.getAuthType());

        }

        if (auditEvent.getData().get("details") instanceof OAuth2Authentication) {
            OAuth2Authentication details = (OAuth2Authentication) auditEvent.getData().get("details");
            RequestAttributes requestAttributes = RequestContextHolder.getRequestAttributes();
            HttpServletRequest request = ((ServletRequestAttributes) requestAttributes).getRequest();
            System.out.println("Principal " + auditEvent.getPrincipal());
            System.out.println("Authentication " + auditEvent.getType());
            System.out.println("Remote IP: " + request.getRemoteAddr());
            System.out.println("Url: " + request.getRequestURL());
            System.out.println("authorities: " + details.getOAuth2Request().getAuthorities().toString());
            System.out.println("Grantype: " + details.getOAuth2Request().getGrantType());
            System.out.println("Scope: " + details.getOAuth2Request().getScope());
            System.out.println("Scope: " + details.getUserAuthentication().getDetails());
            //System.out.println("Client id: " + details.getOAuth2Request().getClientId());

            List<String> tokenValues = new ArrayList<String>();
            Collection<OAuth2AccessToken> tokens = tokenStore.findTokensByClientId(details.getOAuth2Request().getClientId());
            if (details.getDetails() instanceof OAuth2AuthenticationDetails) {
                OAuth2AuthenticationDetails oauthsDetails = (OAuth2AuthenticationDetails) details.getDetails();
                String token = oauthsDetails.getTokenValue();
                tokens.stream().filter(s -> s.getValue().equals(oauthsDetails.getTokenValue()))
                               .forEach(t -> System.out.println(t.getValue()));
             }
        }
    }
}