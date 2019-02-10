package com.example.servlet.filter;
/*
 * Adapted from https://github.com/keycloak/keycloak/blob/master/adapters/oidc/servlet-filter/src/main/java/org/keycloak/adapters/servlet/KeycloakOIDCFilter.java
 * I changed the logger and added further debugging messages relevant to me
 * I also edited the standard location of the keycloak file
 * Furthermore i added functionality to also add a jira login to the httpsession
 * I needed to copy some methods over in a one-to-one session since they were private in the superclass
 * Below you will find the original copyright statement
 */

/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


import com.atlassian.crowd.embedded.api.CrowdService;
import com.atlassian.crowd.embedded.api.User;
import com.atlassian.jira.component.ComponentAccessor;
import com.atlassian.jira.security.login.JiraSeraphAuthenticator;
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.adapters.*;
import org.keycloak.adapters.servlet.FilterRequestAuthenticator;
import org.keycloak.adapters.servlet.KeycloakOIDCFilter;
import org.keycloak.adapters.servlet.OIDCFilterSessionStore;
import org.keycloak.adapters.servlet.OIDCServletHttpFacade;
import org.keycloak.adapters.spi.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.io.InputStream;
import java.security.Principal;
import java.util.Enumeration;
import java.util.List;
import java.util.regex.Pattern;


public class AdaptedKeycloakOIDCFilter extends KeycloakOIDCFilter {

    private final Logger log = LoggerFactory.getLogger(this.getClass());

    public static final String CONFIG_PATH_PARAM = "../../../../";

    protected AdapterDeploymentContext deploymentContext;

    protected SessionIdMapper idMapper = new InMemorySessionIdMapper();

    protected NodesRegistrationManagement nodesRegistrationManagement;

    protected Pattern skipPattern;

    private final KeycloakConfigResolver definedconfigResolver;

    /**
     * Constructor that can be used to define a {@code KeycloakConfigResolver} that will be used at initialization to
     * provide the {@code KeycloakDeployment}.
     *
     * @param definedconfigResolver the resolver
     */
    public AdaptedKeycloakOIDCFilter(KeycloakConfigResolver definedconfigResolver) {

        this.definedconfigResolver = definedconfigResolver;
    }

    public AdaptedKeycloakOIDCFilter() {

        this(null);
    }

    @Override
    public void init(final FilterConfig filterConfig) throws ServletException {

        String skipPatternDefinition = filterConfig.getInitParameter(SKIP_PATTERN_PARAM);
        if (skipPatternDefinition != null) {
            skipPattern = Pattern.compile(skipPatternDefinition, Pattern.DOTALL);
        }

        String path = "/keycloak.json";
        String pathParam = filterConfig.getInitParameter(CONFIG_PATH_PARAM);
        if (pathParam != null) path = pathParam;
        log.warn("searching for config at path " + path);
        InputStream is = filterConfig.getServletContext().getResourceAsStream(path);


        KeycloakDeployment kd = this.createKeycloakDeploymentFrom(is);

        deploymentContext = new AdapterDeploymentContext(kd);
        log.info("Keycloak is using a per-deployment configuration.");


        filterConfig.getServletContext().setAttribute(AdapterDeploymentContext.class.getName(), deploymentContext);
        nodesRegistrationManagement = new NodesRegistrationManagement();
    }

    private KeycloakDeployment createKeycloakDeploymentFrom(InputStream is) {

        if (is == null) {
            log.error("No adapter configuration. Keycloak is unconfigured and will deny all requests.");
            return new KeycloakDeployment();
        }
        return KeycloakDeploymentBuilder.build(is);
    }


    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {

        log.info("Keycloak OIDC Filter");
        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;

        if (shouldSkip(request)) {
            chain.doFilter(req, res);
            return;
        }
        HttpSession session = request.getSession();
        log.warn("User already has a session");
        Enumeration enumeration = session.getAttributeNames();

        Principal principal = (Principal) session.getAttribute(JiraSeraphAuthenticator.LOGGED_IN_KEY);

        if (principal != null) {
            log.warn("found jira user " + principal.getName()+" so we continue the filter chain");
            return;
        }
        while (enumeration.hasMoreElements()) {
            log.warn(enumeration.nextElement().toString());
        }
        log.warn("end of enumeration");
        //Prüfen darauf, dass sich der User nicht angemeldet hat und nicht darauf, dass er sich abgemeldet hat
        if (session.getAttribute(JiraSeraphAuthenticator.LOGGED_IN_KEY) == null) {
            log.warn("user is not logged in");
            RefreshableKeycloakSecurityContext account = (RefreshableKeycloakSecurityContext) session.getAttribute(
                    KeycloakSecurityContext.class.getName());

            if (account != null) {
                log.warn("Found a valid KC user, attempting login");
                User user = getCrowdService().getUser(account.getToken().getPreferredUsername());
                if (user == null) {
                    log.warn("User is in keycloak, but isnt added to jira");
                } else {
                    Object object = session.getAttribute(JiraSeraphAuthenticator.LOGGED_OUT_KEY);
                    if (object != null) {
                        log.warn("removing session attribute " + JiraSeraphAuthenticator.LOGGED_OUT_KEY);
                        session.removeAttribute(JiraSeraphAuthenticator.LOGGED_OUT_KEY);
                    }
                    session.setAttribute(JiraSeraphAuthenticator.LOGGED_IN_KEY, user);
                    log.warn("Set the session attribute " + JiraSeraphAuthenticator.LOGGED_IN_KEY + " for user " + user.getDisplayName());
                }
            }
        }

        OIDCServletHttpFacade facade = new OIDCServletHttpFacade(request, response);
        KeycloakDeployment deployment = deploymentContext.resolveDeployment(facade);
        if (deployment == null || !deployment.isConfigured()) {
            response.sendError(403);
            log.error("deployment not configured");
            return;
        }

        PreAuthActionsHandler preActions = new PreAuthActionsHandler(new UserSessionManagement() {
            @Override
            public void logoutAll() {

                if (idMapper != null) {
                    idMapper.clear();
                }
            }

            @Override
            public void logoutHttpSessions(List<String> ids) {

                log.info("**************** logoutHttpSessions");
                //System.err.println("**************** logoutHttpSessions");
                for (String id : ids) {
                    log.debug("removed idMapper: " + id);
                    idMapper.removeSession(id);
                }

            }
        }, deploymentContext, facade);

        if (preActions.handleRequest()) {
            //System.err.println("**************** preActions.handleRequest happened!");
            return;
        }


        nodesRegistrationManagement.tryRegister(deployment);
        OIDCFilterSessionStore tokenStore = new OIDCFilterSessionStore(request, facade, 100000, deployment, idMapper);
        tokenStore.checkCurrentToken();


        FilterRequestAuthenticator authenticator = new FilterRequestAuthenticator(deployment, tokenStore, facade, request, 8443);
        AuthOutcome outcome = authenticator.authenticate();
        if (outcome == AuthOutcome.AUTHENTICATED) {
            log.info("AUTHENTICATED");
            if (facade.isEnded()) {
                return;
            }
            AuthenticatedActionsHandler actions = new AuthenticatedActionsHandler(deployment, facade);
            if (actions.handledRequest()) {
                return;
            } else {
                HttpServletRequestWrapper wrapper = tokenStore.buildWrapper();
                chain.doFilter(wrapper, res);
                return;
            }
        }
        AuthChallenge challenge = authenticator.getChallenge();
        if (challenge != null) {
            log.info("challenge");
            challenge.challenge(facade);
            return;
        }
        response.sendError(403);

    }

    /**
     * Decides whether this {@link Filter} should skip the given {@link HttpServletRequest} based on the configured {@link KeycloakOIDCFilter#skipPattern}.
     * Patterns are matched against the {@link HttpServletRequest#getRequestURI() requestURI} of a request without the context-path.
     * A request for {@code /myapp/index.html} would be tested with {@code /index.html} against the skip pattern.
     * Skipped requests will not be processed further by {@link KeycloakOIDCFilter} and immediately delegated to the {@link FilterChain}.
     *
     * @param request the request to check
     * @return {@code true} if the request should not be handled,
     * {@code false} otherwise.
     */
    private boolean shouldSkip(HttpServletRequest request) {

        if (skipPattern == null) {
            log.info("Didnt skip the request");
            return false;
        }

        String requestPath = request.getRequestURI().substring(request.getContextPath().length());
        log.warn("Evaluating the request with path " + requestPath);
        return skipPattern.matcher(requestPath).matches();
    }


    private CrowdService getCrowdService() {

        return ComponentAccessor.getCrowdService();
    }
}