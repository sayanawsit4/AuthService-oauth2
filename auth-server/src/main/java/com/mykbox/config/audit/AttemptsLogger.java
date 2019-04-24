package com.mykbox.config.audit;

import com.mykbox.config.auth.CustomJdbcTokenStore;
import com.mykbox.config.constants.Config;
import com.mykbox.config.user.ExtendedUser;
import com.mykbox.domain.AccessAudit;
import com.mykbox.domain.OperationalAudit;
import com.mykbox.domain.User;
import com.mykbox.repository.AuditRepository;
import com.mykbox.repository.OpsAuditRepository;
import com.mykbox.repository.TokenRepository;
import com.mykbox.repository.UserRepository;
import org.apache.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.actuate.audit.AuditEvent;
import org.springframework.boot.actuate.audit.listener.AuditApplicationEvent;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import java.util.Date;

@Component
public class AttemptsLogger {

    @Autowired
    AuditRepository auditRepository;

    @Autowired
    TokenRepository tokenRepository;

    @Resource(name = "tokenStore")
    CustomJdbcTokenStore customJdbcTokenStore;

    @Autowired
    UserRepository userRepository;

    @Autowired
    OpsAuditRepository opsAuditRepository;

    //private static final Logger LOGGER = Logger.getLogger(AttemptsLogger.class);
    private static final org.slf4j.Logger LOGGER  = org.slf4j.LoggerFactory.getLogger(AttemptsLogger.class);


    @EventListener
    public void auditEventHappened(AuditApplicationEvent auditApplicationEvent) {
        AuditEvent auditEvent = auditApplicationEvent.getAuditEvent();
        LOGGER.info("Principal " + auditEvent.getPrincipal() + " - " + auditEvent.getType() + auditEvent.getData().get("details"));
        
        if (auditEvent.getData().get("details") instanceof WebAuthenticationDetails) {
            WebAuthenticationDetails details = (WebAuthenticationDetails) auditEvent.getData().get("details");

            LOGGER.info("Principal " + auditEvent.getPrincipal());
            LOGGER.info("Authentication " + auditEvent.getType());
            LOGGER.info("Remote IP address: " + details.getRemoteAddress());
            LOGGER.info("Session Id: " + details.getSessionId());
            LOGGER.info("Request URL: " + auditEvent.getData().get("requestUrl"));
        }

        if (auditEvent.getData().get("details") instanceof PreAuthenticatedAuthenticationToken) {
            PreAuthenticatedAuthenticationToken details = (PreAuthenticatedAuthenticationToken) auditEvent.getData().get("details");
            RequestAttributes requestAttributes = RequestContextHolder.getRequestAttributes();
            HttpServletRequest request = ((ServletRequestAttributes) requestAttributes).getRequest();

            LOGGER.info("Principal " + auditEvent.getPrincipal());
            LOGGER.info("Authentication " + auditEvent.getType());
            LOGGER.info("Remote IP: " + request.getRemoteAddr());
            LOGGER.info("Url: " + request.getRequestURL());
            LOGGER.info("Authtype: " + request.getAuthType());

            AccessAudit accessAudit = new AccessAudit();
            accessAudit.setEmail(auditEvent.getPrincipal());
            auditRepository.save(accessAudit);

        }

        if (auditEvent.getData().get("details") instanceof UsernamePasswordAuthenticationToken) {
            UsernamePasswordAuthenticationToken details = (UsernamePasswordAuthenticationToken) auditEvent.getData().get("details");
            RequestAttributes requestAttributes = RequestContextHolder.getRequestAttributes();
            HttpServletRequest request = ((ServletRequestAttributes) requestAttributes).getRequest();

            LOGGER.info("Principal " + auditEvent.getPrincipal());
            LOGGER.info("Authentication " + details.isAuthenticated());
            LOGGER.info("Remote IP: " + request.getRemoteAddr());
            LOGGER.info("Url: " + request.getRequestURL());
            LOGGER.info("Authtype: " + request.getAuthType());

        }

        if (auditEvent.getData().get("details") instanceof OAuth2Authentication) {
            OAuth2Authentication details = (OAuth2Authentication) auditEvent.getData().get("details");
            RequestAttributes requestAttributes = RequestContextHolder.getRequestAttributes();
            HttpServletRequest request = ((ServletRequestAttributes) requestAttributes).getRequest();

            LOGGER.info("Principal " + auditEvent.getPrincipal());
            LOGGER.info("Authentication " + auditEvent.getType());
            LOGGER.info("Remote IP: " + request.getRemoteAddr());
            LOGGER.info("Url: " + request.getRequestURL());
            LOGGER.info("authorities: " + details.getOAuth2Request().getAuthorities().toString());
            LOGGER.info("Grantype: " + details.getOAuth2Request().getGrantType());
            LOGGER.info("Scope: " + details.getOAuth2Request().getScope());
            LOGGER.info("Scope: " + details.getUserAuthentication().getDetails());
            LOGGER.info("user agent" + request.getHeader("User-Agent"));

            OAuth2AuthenticationDetails oauthsDetails = (OAuth2AuthenticationDetails) details.getDetails();
            ExtendedUser extendedUser = (ExtendedUser) details.getPrincipal();

            LOGGER.info(extendedUser.getUserid().toString());
            String tokentemp = customJdbcTokenStore.extractTokenKey(oauthsDetails.getTokenValue());
            LOGGER.info("token key is---------->" + customJdbcTokenStore.extractTokenKey(oauthsDetails.getTokenValue()));
            LOGGER.info("find by username-------->" + tokenRepository.findUsernameByToken(tokentemp));

            User user =  userRepository.findByEmail
                               (tokenRepository.findUsernameByToken
                               (customJdbcTokenStore.extractTokenKey(oauthsDetails.getTokenValue())));

            OperationalAudit operationalAudit = new OperationalAudit();
            operationalAudit.setOpsPerformedBy(extendedUser.getUserid());
            operationalAudit.setTokenId(customJdbcTokenStore.extractTokenKey(oauthsDetails.getTokenValue()));
            operationalAudit.setUserId(user.getUserId());
            operationalAudit.setClientId(details.getOAuth2Request().getClientId());
            operationalAudit.setCreatedTime(new Date());
            operationalAudit.setRemoteIP(request.getRemoteAddr());
            operationalAudit.setUrl(request.getRequestURL().toString());
            operationalAudit.setStatus(auditEvent.getType());
            operationalAudit.setUserAgent(request.getHeader("User-Agent"));
            opsAuditRepository.save(operationalAudit);

            request.getSession().setAttribute(Config.OPS_TRACE_ID, operationalAudit.getOpsAuditNo());
        }
    }

}