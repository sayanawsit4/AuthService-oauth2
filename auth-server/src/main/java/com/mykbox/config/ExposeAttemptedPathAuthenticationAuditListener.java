package com.mykbox.config;

import org.springframework.boot.actuate.audit.AuditEvent;
import org.springframework.boot.actuate.security.AbstractAuthenticationAuditListener;
import org.springframework.security.authentication.event.AbstractAuthenticationEvent;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

@Component
public class ExposeAttemptedPathAuthenticationAuditListener extends AbstractAuthenticationAuditListener {

    public static final String AUTHENTICATION_FAILURE = "AUTHENTICATION_FAILURE";

    @Override
    public void onApplicationEvent(AbstractAuthenticationEvent event) {
         if (event instanceof AbstractAuthenticationEvent) {
            onAuthenticationFailureEvent((AbstractAuthenticationFailureEvent) event);
        }
    }

    private void onAuthenticationFailureEvent(AbstractAuthenticationFailureEvent event) {
        System.out.println(event.toString());
        Map<String, Object> data = new HashMap<>();
        data.put("type", event.getAuthentication().getClass().getName());
        data.put("message", event.getException().getMessage());
        publish(new AuditEvent(event.getAuthentication().getName(), AUTHENTICATION_FAILURE, data));
    }
}