package com.example.servlet.filter;

import com.atlassian.crowd.embedded.api.CrowdService;
import com.atlassian.crowd.embedded.api.User;
import com.atlassian.jira.component.ComponentAccessor;
import com.atlassian.jira.security.login.JiraSeraphAuthenticator;
import org.keycloak.adapters.servlet.KeycloakOIDCFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.security.Principal;
import java.util.Enumeration;


public class OidcFilter extends KeycloakOIDCFilter {
    private static final Logger log = LoggerFactory.getLogger(OidcFilter.class);

    public void init(FilterConfig filterConfig) throws ServletException {

        super.init(filterConfig);
    }

    public void destroy() {

        super.destroy();
        log.warn("Destroyed " + this.getClass());
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        //do some custom handling here
        HttpServletRequest httpServletRequest = (HttpServletRequest) request;
        String authHeader = httpServletRequest.getHeader("Authorization");
        HttpSession session = httpServletRequest.getSession();
        CrowdService service = ComponentAccessor.getCrowdService();
        User user = service.getUser("admin");
        log.warn("Found user " + user.toString());


        if (session != null) {
            log.warn("User already has a session");
            //TODO enumeration display kann später weg
            Enumeration enumeration = session.getAttributeNames();
            Principal principal = (Principal) session.getAttribute("seraph_defaultauthenticator_user");
            if (principal != null) {
                log.warn("found this noob " + principal.getName());
            }
            // TODO key sollte eigentlich allgemein sein, damit nicht iwas an dem scheitert
            //  -> problem bei dependency, die scheint iwie verkettet zu sein und deswegen will
            //  das Plugin dann nicht laufen
            while (enumeration.hasMoreElements()) {
                log.warn(enumeration.nextElement().toString());
            }
            //Prüfen darauf, dass sich der User nicht angemeldet hat und nicht darauf, dass er sich abgemeldet hat
            if (session.getAttribute(JiraSeraphAuthenticator.LOGGED_IN_KEY) == null) {
                log.warn("user is not logged in");
                super.doFilter(request, response, chain);
            } else {
                log.warn("proceeding with filterchain as user is already authenticated");
                chain.doFilter(request, response);
            }
            //continue the request

        } else {
            log.warn("No Session found, searching for authorization in headerfields");
            if (authHeader != null && authHeader.contains("Basic")) {
                log.warn("I dont wanna handle basic auth");
                chain.doFilter(request, response);
            } else {
                log.warn("Authorization header thats interesting for Keycloak");

                super.doFilter(request, response, chain);

            }

        }
    }
}