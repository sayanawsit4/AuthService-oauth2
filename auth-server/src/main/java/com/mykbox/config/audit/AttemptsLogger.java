package com.mykbox.config.audit;

import com.mykbox.config.auth.CustomJdbcTokenStore;
import com.mykbox.config.user.ExtendedUser;
import com.mykbox.domain.AccessAudit;
import com.mykbox.domain.OperationalAudit;
import com.mykbox.domain.User;
import com.mykbox.repository.AuditRepository;
import com.mykbox.repository.OpsAuditRepository;
import com.mykbox.repository.TokenRepository;
import com.mykbox.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.actuate.audit.AuditEvent;
import org.springframework.boot.actuate.audit.listener.AuditApplicationEvent;
import org.springframework.boot.actuate.trace.Trace;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
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
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

@Component
public class AttemptsLogger {


    @Resource(name = "tokenStore")
    TokenStore tokenStore;

    @Autowired
    AuditRepository auditRepository;

    @Autowired
    TokenRepository tokenRepository;

    @Autowired
    CustomJdbcTokenStore customJdbcTokenStore;

    @Autowired
    UserRepository userRepository;

    @Autowired
    OpsAuditRepository opsAuditRepository;

    @Autowired
    LoggingTraceRepository  loggingTraceRepository;


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
            System.out.println("user agent"+ request.getHeader("User-Agent"));

            //System.out.println("Client id: " + details.getOAuth2Request().getClientId());
/*String body="";
            try {
                body=   getBody(request);
            } catch (IOException e) {
                e.printStackTrace();
            }*/

           // System.out.println("body"+ body);

            System.out.println( "trace-id"+request.getHeader("trace-id"));

            OAuth2AuthenticationDetails oauthsDetails = (OAuth2AuthenticationDetails) details.getDetails();
            String token = oauthsDetails.getTokenValue();

            ExtendedUser extendedUser = (ExtendedUser) details.getPrincipal();

            System.out.println(extendedUser.getUserid());

            User user = (User) userRepository.findByEmail(tokenRepository.findUsernameByToken(customJdbcTokenStore.extractTokenKey(oauthsDetails.getTokenValue())));

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
          //  operationalAudit.setUserAgent(request.);
            opsAuditRepository.save(operationalAudit);

            request.getSession().setAttribute("trace-id",operationalAudit.getOpsAuditNo());

           // List<Trace> test=  loggingTraceRepository.findAll();
            //System.out.println(test.get(0).getInfo());
            // System.out.println(tokenRepository.findUsernameByToken(customJdbcTokenStore.extractTokenKey(oauthsDetails.getTokenValue())));

            // System.out.println(user.getUserId());
            //  operationalAudit.

            //details.getOAuth2Request().

            //System.out.println("token_id...."+customJdbcTokenStore.extractTokenKey(oauthsDetails.getTokenValue()));

            //   System.out.println("token_id...."+tokenRepository.findbytokenvalue(oauthsDetails.getTokenValue().getBytes()));

            // operationalAudit.set

         /*   List<String> tokenValues = new ArrayList<String>();
            Collection<OAuth2AccessToken> tokens = tokenStore.findTokensByClientId(details.getOAuth2Request().getClientId());
            if (details.getDetails() instanceof OAuth2AuthenticationDetails) {
                OAuth2AuthenticationDetails oauthsDetails = (OAuth2AuthenticationDetails) details.getDetails();
                String token = oauthsDetails.getTokenValue();
                tokens.stream().filter(s -> s.getValue().equals(oauthsDetails.getTokenValue()))
                               .forEach(t -> System.out.println(t.getValue()));
             }*/
        }
    }

    public static String getBody(HttpServletRequest request) throws IOException {

        String body = null;
        StringBuilder stringBuilder = new StringBuilder();
        BufferedReader bufferedReader = null;

        try {
            InputStream inputStream = request.getInputStream();
            if (inputStream != null) {
                bufferedReader = new BufferedReader(new InputStreamReader(inputStream));
                char[] charBuffer = new char[128];
                int bytesRead = -1;
                while ((bytesRead = bufferedReader.read(charBuffer)) > 0) {
                    stringBuilder.append(charBuffer, 0, bytesRead);
                }
            } else {
                stringBuilder.append("");
            }
        } catch (IOException ex) {
            throw ex;
        } finally {
            if (bufferedReader != null) {
                try {
                    bufferedReader.close();
                } catch (IOException ex) {
                    throw ex;
                }
            }
        }

        body = stringBuilder.toString();
        return body;
    }


}