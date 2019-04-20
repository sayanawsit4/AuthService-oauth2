package com.mykbox.config.Filters;

import com.mykbox.config.audit.LoggingTraceRepository;
import com.mykbox.config.auth.CustomJdbcTokenStore;
import com.mykbox.config.user.ExtendedUser;
import com.mykbox.domain.OperationalAudit;
import com.mykbox.domain.User;
import com.mykbox.repository.AuditRepository;
import com.mykbox.repository.OpsAuditRepository;
import com.mykbox.repository.TokenRepository;
import com.mykbox.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.actuate.audit.AuditEvent;
import org.springframework.boot.actuate.audit.listener.AuditApplicationEvent;
import org.springframework.context.event.EventListener;
import org.springframework.core.annotation.Order;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.annotation.Resource;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import java.util.UUID;

@Order(1)
@Component
public class FirstFilter extends OncePerRequestFilter {


    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest,
                                    HttpServletResponse httpServletResponse,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        //UUID uuid = UUID.randomUUID();
         httpServletResponse.addHeader("trace-id", "dd");
        filterChain.doFilter(httpServletRequest, httpServletResponse);
    }


}
