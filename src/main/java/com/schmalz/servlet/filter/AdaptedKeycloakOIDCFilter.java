package com.schmalz.servlet.filter;
/*
 * Adapted from https://github.com/keycloak/keycloak/blob/master/adapters/oidc/servlet-filter/src/main/java/org/keycloak/adapters/servlet/KeycloakOIDCFilter.java
 * I changed the logger and added further debugging messages relevant to me
 * Furthermore I added functionality to add a Jira user to the httpSession if he already authenticated to Keycloak
 * I needed to copy some methods over in a one-to-one manner since they were private in the superclass
 * Below you will find the original copyright statement
 * Many thanks to the awesome Red Hat developers writing Keycloak, the servlet adapter and putting it all under Apache 2.0!
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
import com.atlassian.jira.security.login.JiraSeraphAuthenticator;
import com.atlassian.plugin.spring.scanner.annotation.component.Scanned;
import com.atlassian.plugin.spring.scanner.annotation.imports.ComponentImport;
import com.atlassian.sal.api.pluginsettings.PluginSettings;
import com.atlassian.sal.api.pluginsettings.PluginSettingsFactory;
import com.schmalz.servlet.KeycloakConfigServlet;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.adapters.*;
import org.keycloak.adapters.servlet.KeycloakOIDCFilter;
import org.keycloak.adapters.spi.KeycloakAccount;
import org.keycloak.representations.adapters.config.AdapterConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import javax.ws.rs.core.UriBuilder;
import java.io.IOException;
import java.io.InputStream;
import java.security.Principal;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

@Scanned
public class AdaptedKeycloakOIDCFilter extends KeycloakOIDCFilter {
    public static final String SETTINGS_KEY = AdaptedKeycloakOIDCFilter.class.getName() + "-keycloakJiraPlugin-SettingsKey";
    private final Logger log = LoggerFactory.getLogger(this.getClass());
    private String authServer;
    private String realm;
    private String resource;
    private boolean disabled = false;
    private boolean debugeMode = false;

    @ComponentImport
    private final CrowdService crowdService;

    @ComponentImport
    private final PluginSettingsFactory pluginSettingsFactory;

    private FilterConfig filterConfiguration;

    /**
     * Constructor that can be used to define a {@code KeycloakConfigResolver} that will be used at initialization to
     * provide the {@code KeycloakDeployment}.
     *
     * @param definedconfigResolver the resolver
     */

    private AdaptedKeycloakOIDCFilter(KeycloakConfigResolver definedconfigResolver,
                                      PluginSettingsFactory factory, CrowdService crowdService) {

        super(definedconfigResolver);
        pluginSettingsFactory = factory;
        this.crowdService = crowdService;
    }

    public AdaptedKeycloakOIDCFilter(PluginSettingsFactory factory, CrowdService crowdService) {

        this(null, factory, crowdService);
    }


    @Override
    public void init(final FilterConfig filterConfig) throws ServletException {

        super.init(filterConfig);
        String pathParam = filterConfig.getInitParameter(CONFIG_PATH_PARAM);
        String path = pathParam == null ? "/keycloak.json" : pathParam;
        log.info("searching for config at path " + path);

        String debugParam = filterConfig.getInitParameter("plugin.debug");
        debugeMode = Boolean.parseBoolean(debugParam);

        //saving filterconfig so i can easily access the json-file later
        filterConfiguration = filterConfig;
        InputStream is = filterConfig.getServletContext().getResourceAsStream(path);
        if (is != null) {
            KeycloakDeployment deployment = KeycloakDeploymentBuilder.build(is);
            /*
            plugin settings can only store: String, List<String>, Map<String,String>; thread below describes other possibilities
            */
            //https://community.atlassian.com/t5/Answers-Developer-Questions/PluginSettings-vs-Active-Objects/qaq-p/485817
            realm = deployment.getRealm();
            authServer = deployment.getAuthServerBaseUrl();
            this.deploymentContext = new AdapterDeploymentContext(deployment);

            PluginSettings settings = pluginSettingsFactory.createGlobalSettings();
            Map<String, String> possiblyDifferentSettings = (Map<String, String>) settings.get(SETTINGS_KEY);
            if (possiblyDifferentSettings != null) {

                handleUpdate(possiblyDifferentSettings);

            } else {
                HashMap<String, String> toStore = new HashMap<>();
                toStore.put(KeycloakConfigServlet.REALM_KEY, realm);
                toStore.put(KeycloakConfigServlet.AUTH_SERVER_BASEURL_KEY, authServer);
                toStore.put(KeycloakConfigServlet.RESOURCE_KEY, deployment.getResourceName());
                toStore.put(KeycloakConfigServlet.PUBLIC_CLIENT_KEY, Boolean.toString(deployment.isPublicClient()));
                settings.put(SETTINGS_KEY, toStore);


            }

        } else {
            log.error("could not find configuration file, this plugin will disable itself");
            disabled = true;
        }
    }

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {

        HttpServletRequest request = (HttpServletRequest) req;
        PluginSettings settings = pluginSettingsFactory.createGlobalSettings();
        if (Boolean.parseBoolean((String) settings.get(KeycloakConfigServlet.UPDATED_SETTINGS_KEY))) {
            handleUpdate(settings);
        }

        if (shouldSkip(request) || disabled) {
            chain.doFilter(req, res);
            return;
        }

        HttpSession session = request.getSession();
        if (debugeMode) {
            logSessionAttributes(session);
            log.warn(session.getId());
        }

        RefreshableKeycloakSecurityContext account = (RefreshableKeycloakSecurityContext) session.getAttribute(
                KeycloakSecurityContext.class.getName());

        //logged_out_key is set by jira when logging out. handleLogout propagates the logout to keycloak
        if (request.getServletPath().contains("Logout") || session.getAttribute(JiraSeraphAuthenticator.LOGGED_OUT_KEY) != null) {
            if (handleLogout(account, session)) {
                log.debug("logout successful");

            } else {
                log.debug("logout failed");
            }
            chain.doFilter(req, res);
            return;
        }
        Principal principal = (Principal) session.getAttribute(JiraSeraphAuthenticator.LOGGED_IN_KEY);


        if (principal != null) {

            log.debug("found jira user " + principal.getName() + ", resuming filter chain");
            chain.doFilter(req, res);
            return;
        }

        // Check for missing authentication is unnecessary, we only end up here,
        // if the logged_in_key is missing


        if (account != null) {
            log.debug("user is authenticated by keycloak, attempting login");
            if (handleLogin(account.getToken().getPreferredUsername(), session)) {
                log.debug("login successful");

            } else {
                log.debug("login failed");
            }
            chain.doFilter(req, res);
            return;
        }
        /* if  the request could not be handled at this point, we delegate to the superclass to let the user log in*/
        super.doFilter(req, res, chain);
    }

    /**
     * @param account the Keycloak account to log out
     * @param session the session from which the user needs to be logged out
     * @return TRUE if the logout was successfully propagated to the AuthServer, FALSE otherwise
     */
    private boolean handleLogout(KeycloakSecurityContext account, HttpSession session) {

        if (debugeMode) {
            logSessionAttributes(session);
        }
        // https://docs.atlassian.com/software/jira/docs/api/7.2.2/com/atlassian/jira/web/action/user/Logout.html
        /* null checks are not necessary, but provide for better logging */
        if (session.getAttribute(KeycloakSecurityContext.class.getName()) != null) {
            log.debug("removed security context");
            session.removeAttribute(KeycloakSecurityContext.class.getName());
        }
        if (session.getAttribute(KeycloakAccount.class.getName()) != null) {
            session.removeAttribute(KeycloakAccount.class.getName());
            log.debug("removed account");
        }
        if (account != null) {
            log.info("attempting to logout user " + account.getIdToken().getPreferredUsername());
            HttpGet httpGet = new HttpGet();
            httpGet.setURI(UriBuilder.fromUri(authServer + "/realms/" + realm + "/protocol" +
                    "/openid-connect/logout?id_token_hint=" + account.getIdTokenString()).build());
            log.debug("trying get with " + httpGet.getURI());

            try (CloseableHttpClient client = HttpClientBuilder.create().build()) {

                HttpResponse httpResponse = client.execute(httpGet);
                log.debug(httpResponse.getStatusLine().toString());
                return true;
            } catch (Exception ex) {
                log.warn("Caught exception " + ex);
            }
        }
        return false;
    }

    /**
     * @param userName the name of the user which should be logged in to Jira
     * @param session  the session the user currently has
     * @return (@ code true) if the login was successful, (@code false) otherwise
     */
    private boolean handleLogin(String userName, HttpSession session) {

        log.info("Found a valid KC user, attempting login to jira");
        User user = crowdService.getUser(userName);

        if (user == null) {
            log.debug("Authentication unsuccessful, user does not exist in Jira");
            return false;
        } else {
            Object object = session.getAttribute(JiraSeraphAuthenticator.LOGGED_OUT_KEY);
            if (object != null) {
                log.info("removed logged out key");
                session.removeAttribute(JiraSeraphAuthenticator.LOGGED_OUT_KEY);
            }
            session.setAttribute(JiraSeraphAuthenticator.LOGGED_IN_KEY, user);
            log.debug("Successfully authenticated user " + user.getDisplayName() + " to Jira");

            return true;
        }
    }

    /**
     * @param request the request to check
     * @return (@ code true) if the filter should handle the request, (@code false) otherwise
     */
    private boolean shouldSkip(HttpServletRequest request) {
        /*custom part */
        String path = request.getServletPath();
        if (/*path.endsWith("login.jsp") ||*/ (request.getQueryString() != null && request.getQueryString().contains("noSSO"))) {
            log.info("keycloak is ignoring this certain page to allow external users to log in");
            return true;
        }
        if (path.contains("/rest")) {
            log.debug("skipping request " + path);
            return true;
        }
        /* end of custom part*/
        return false;
    }

    /**
     * A method purely used for debugging which logs all the attributes the given session has
     *
     * @param session the HttpSession whose attributes should be logged
     */
    private synchronized void logSessionAttributes(HttpSession session) {

        Enumeration<String> enumeration = session.getAttributeNames();
        log.warn("start of enum");
        while (enumeration.hasMoreElements())
            log.warn(enumeration.nextElement());
        log.warn("end of enum");
    }

    private void handleUpdate(PluginSettings settings) {

        handleUpdate((Map<String, String>) settings.get(SETTINGS_KEY));

        settings.remove(KeycloakConfigServlet.UPDATED_SETTINGS_KEY);
    }

    private void handleUpdate(Map<String, String> config) {

        try (InputStream is = filterConfiguration.getServletContext().getResourceAsStream("/keycloak.json")) {
            realm = config.get(KeycloakConfigServlet.REALM_KEY) != null ? config.get(KeycloakConfigServlet.REALM_KEY) : realm;
            authServer = config.get(KeycloakConfigServlet.AUTH_SERVER_BASEURL_KEY) != null ? config.get(KeycloakConfigServlet.AUTH_SERVER_BASEURL_KEY) : authServer;
            resource = config.get(KeycloakConfigServlet.RESOURCE_KEY) != null ? config.get(KeycloakConfigServlet.RESOURCE_KEY) : resource;
            AdapterConfig adapterConfig = KeycloakDeploymentBuilder.loadAdapterConfig(is);
            String pC = config.get(KeycloakConfigServlet.PUBLIC_CLIENT_KEY);
            Boolean publicClient = pC == null ? adapterConfig.isPublicClient() : Boolean.valueOf(pC);
            String secret = config.get(KeycloakConfigServlet.SECRET_KEY);
            Map<String, Object> credentials = adapterConfig.getCredentials();
            credentials.put("secret", secret);


            /*order is important here */
            adapterConfig.setRealm(realm);
            adapterConfig.setAuthServerUrl(authServer);
            adapterConfig.setResource(resource);
            log.warn("set everything that worked");

            adapterConfig.setPublicClient(publicClient);
            adapterConfig.setCredentials(credentials);
            KeycloakDeployment ment = KeycloakDeploymentBuilder.build(adapterConfig);

            deploymentContext = new AdapterDeploymentContext(ment);
        } catch (Exception e) {
            log.warn(e.getMessage());
        }


    }

}