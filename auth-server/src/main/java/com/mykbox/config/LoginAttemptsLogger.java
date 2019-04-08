package com.mykbox.config;

import org.springframework.boot.actuate.audit.AuditEvent;
import org.springframework.boot.actuate.audit.listener.AuditApplicationEvent;
import org.springframework.context.event.EventListener;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Component;

@Component
public class LoginAttemptsLogger {

    @EventListener
    public void auditEventHappened(AuditApplicationEvent auditApplicationEvent) {

        AuditEvent auditEvent = auditApplicationEvent.getAuditEvent();
        System.out.println("Principal " + auditEvent.getPrincipal()+ " - " + auditEvent.getType()+auditEvent.getData().get("details"));

        if (auditEvent.getData().get("details") instanceof WebAuthenticationDetails) {
            WebAuthenticationDetails details = (WebAuthenticationDetails) auditEvent.getData().get("details");
            System.out.println("Principal " + auditEvent.getPrincipal());
            System.out.println("Authentication " + auditEvent.getType());
            System.out.println("Remote IP address: "+ details.getRemoteAddress());
            System.out.println("Session Id: " + details.getSessionId());
            System.out.println("Request URL: "+ auditEvent.getData().get("requestUrl"));
        }

        if (auditEvent.getData().get("details") instanceof OAuth2AuthenticationDetails){
            OAuth2AuthenticationDetails details= (OAuth2AuthenticationDetails) auditEvent.getData().get("details");
            System.out.println("Principal " + auditEvent.getPrincipal());
            System.out.println("Authentication " + auditEvent.getType());
            System.out.println("Remote IP address: "+ details.getRemoteAddress());
            System.out.println("Session Id: " + details.getSessionId());
            System.out.println("Token type: " + details.getTokenType());
            System.out.println("Request URL: "+ auditEvent.getData().get("requestUrl"));
         }
    }
}



