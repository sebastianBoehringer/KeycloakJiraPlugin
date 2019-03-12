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
import org.apache.commons.lang.StringUtils;
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
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.ws.rs.core.UriBuilder;
import java.io.IOException;
import java.io.InputStream;
import java.security.Principal;
import java.util.Enumeration;
import java.util.Map;

@Scanned
public class AdaptedKeycloakOIDCFilter extends KeycloakOIDCFilter {
    public static final String SETTINGS_KEY = AdaptedKeycloakOIDCFilter.class.getName() + "-keycloakJiraPlugin-SettingsKey";
    private final Logger log = LoggerFactory.getLogger(this.getClass());
    private String authServer;
    private String realm;
    private String resource;
    private boolean disabled = false;
    private boolean debugMode = false;
    private boolean initialConfigurationNeeded = false;

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
        debugMode = Boolean.parseBoolean(debugParam);

        //saving filterconfig so i can easily access the json-file later
        filterConfiguration = filterConfig;
        InputStream is = filterConfig.getServletContext().getResourceAsStream(path);
        InputStream is2 = filterConfig.getServletContext().getResourceAsStream(path);
        if (is != null) {
            disabled = false;
            AdapterConfig deployment = KeycloakDeploymentBuilder.loadAdapterConfig(is);
            KeycloakDeployment ment = KeycloakDeploymentBuilder.build(is2);
            /*
            plugin settings can only store: String, List<String>, Map<String,String>; thread below describes other possibilities
            */
            //https://community.atlassian.com/t5/Answers-Developer-Questions/PluginSettings-vs-Active-Objects/qaq-p/485817
            realm = deployment.getRealm();
            authServer = deployment.getAuthServerUrl();
            deploymentContext = new AdapterDeploymentContext(ment);
            PluginSettings settings = pluginSettingsFactory.createSettingsForKey(SETTINGS_KEY);
            Object test = settings.get(KeycloakConfigServlet.REALM);
            this.deploymentContext = new AdapterDeploymentContext(ment);
            /*
             * method takes too long if a call to either (@code handleUpdate) or (@initConfig) is made
             * So we just set flags to indicate that those methods should be called when processing a request
             */
            if (test != null) {
                //method only changes the deploymentcontext so it does not need to know about the persisted settings
                settings.put(KeycloakConfigServlet.UPDATED_SETTINGS_KEY, "true");

            } else {
                /*
                fresh instance of JIRA or first time using the plugin, so the basic settings will be imported from the
                json file
                */
                initialConfigurationNeeded = true;

            }

        } else {
            log.error("could not find configuration file, this plugin will disable itself");
        }
    }

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {

        if (initialConfigurationNeeded) {
            PluginSettings settings = pluginSettingsFactory.createSettingsForKey(SETTINGS_KEY);
            try (InputStream is = filterConfiguration.getServletContext().getResourceAsStream("/keycloak.json")) {
                initFromConfig(KeycloakDeploymentBuilder.loadAdapterConfig(is), settings);
                initialConfigurationNeeded = false;
                log.warn("Initial configuration done");
                log.warn("removed stuff from settings");
                HttpServletResponse response = (HttpServletResponse) res;
                response.sendRedirect(((HttpServletRequest) req).getRequestURI());
                return;
            } catch (Exception e) {
                log.warn("Initial configuration failed");
            }
        }
        HttpServletRequest request = (HttpServletRequest) req;
        PluginSettings settings = pluginSettingsFactory.createSettingsForKey(SETTINGS_KEY);
        if (Boolean.parseBoolean((String) settings.get(KeycloakConfigServlet.UPDATED_SETTINGS_KEY))) {
            handleUpdate(settings);
        }

        if (shouldSkip(request) || disabled) {
            chain.doFilter(req, res);
            return;
        }

        HttpSession session = request.getSession();
        if (debugMode) {
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

        if (debugMode) {
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

    private void handleUpdate(PluginSettings config) {


        config.remove(KeycloakConfigServlet.UPDATED_SETTINGS_KEY);


        try (InputStream is = filterConfiguration.getServletContext().getResourceAsStream("/keycloak.json")) {
            realm = config.get(KeycloakConfigServlet.REALM) != null ? (String) config.get(KeycloakConfigServlet.REALM) : realm;
            authServer = config.get(KeycloakConfigServlet.AUTH_SERVER_URL) != null ? (String) config.get(KeycloakConfigServlet.AUTH_SERVER_URL) : authServer;
            resource = config.get(KeycloakConfigServlet.RESOURCE) != null ? (String) config.get(KeycloakConfigServlet.RESOURCE) : resource;

            AdapterConfig adapterConfig = KeycloakDeploymentBuilder.loadAdapterConfig(is);

            String secret = (String) config.get(KeycloakConfigServlet.SECRET);
            Map<String, Object> credentials = adapterConfig.getCredentials();
            credentials.put("secret", secret);

            String realmPublicKey = (String) config.get(KeycloakConfigServlet.REALM_PUBLIC_KEY);

            String ssl = (String) config.get(KeycloakConfigServlet.SSL_REQUIRED);

            int confidentialPort;
            try {
                confidentialPort = Integer.parseInt((String) config.get(KeycloakConfigServlet.CONFIDENTIAL_PORT));
            } catch (NumberFormatException e) {
                confidentialPort = 8443;
            }

            //defaults to false
            boolean enableCors = Boolean.valueOf((String) config.get(KeycloakConfigServlet.ENABLE_CORS));

            int poolSize;
            try {
                poolSize = Integer.parseInt((String) config.get(KeycloakConfigServlet.CONNECTION_POOL_SIZE));
            } catch (NumberFormatException e) {
                //default value from Keycloak documentation
                poolSize = 20;
            }

            String proxy = config.get(KeycloakConfigServlet.PROXY_URL) != null ?
                    (String) config.get(KeycloakConfigServlet.PROXY_URL) : adapterConfig.getProxyUrl();

            String truststore = config.get(KeycloakConfigServlet.TRUSTSTORE) != null ?
                    (String) config.get(KeycloakConfigServlet.TRUSTSTORE) : adapterConfig.getTruststore();

            String truststorePassword = config.get(KeycloakConfigServlet.TRUSTSTORE_PASSWORD) != null ?
                    (String) config.get(KeycloakConfigServlet.TRUSTSTORE_PASSWORD) : adapterConfig.getTruststorePassword();

            String clientKeystore = (String) config.get(KeycloakConfigServlet.CLIENT_KEYSTORE);

            int registerNodePeriod;
            try {
                registerNodePeriod = Integer.parseInt((String) config.get(KeycloakConfigServlet.REGISTER_NODE_PERIOD));
            } catch (NumberFormatException e) {
                registerNodePeriod = 60;
            }

            String tokenStore = config.get(KeycloakConfigServlet.TOKEN_STORE) != null ?
                    (String) config.get(KeycloakConfigServlet.TOKEN_STORE) : "Session";

            String principalAttribute = config.get(KeycloakConfigServlet.PRINCIPAL_ATTRIBUTE) != null ?
                    (String) config.get(KeycloakConfigServlet.PRINCIPAL_ATTRIBUTE) : "sub";

            int minTimeToLive;
            try {
                minTimeToLive = Integer.parseInt((String) config.get(KeycloakConfigServlet.TOKEN_MINIMUM_TIME_TO_LIVE));
            } catch (NumberFormatException e) {
                minTimeToLive = 0;
            }

            int timeBetweenJWKS;
            try {
                timeBetweenJWKS = Integer.parseInt((String) config.get(KeycloakConfigServlet.MIN_TIME_BETWEEN_JWKS_REQUEST));
            } catch (NumberFormatException e) {
                timeBetweenJWKS = 10;
            }

            int keyCacheTTL;
            try {
                keyCacheTTL = Integer.parseInt((String) config.get(KeycloakConfigServlet.PUBLIC_KEY_CACHE_TTL));
            } catch (NumberFormatException e) {
                keyCacheTTL = 86400;
            }


            /*order is important here */
            adapterConfig.setRealm(realm);
            adapterConfig.setResource(resource);
            if (!StringUtils.isEmpty(realmPublicKey))
                adapterConfig.setRealmKey(realmPublicKey);
            adapterConfig.setAuthServerUrl(authServer);
            adapterConfig.setSslRequired(ssl);
            adapterConfig.setUseResourceRoleMappings(Boolean.valueOf((String) config.get(KeycloakConfigServlet.USE_RESOURCE_ROLE_MAPPINGS)));
            adapterConfig.setConfidentialPort(confidentialPort);
            adapterConfig.setPublicClient(Boolean.valueOf((String) config.get(KeycloakConfigServlet.PUBLIC_CLIENT)));

            adapterConfig.setCors(enableCors);
            if (enableCors) {
                int corsMaxAge;
                try {
                    corsMaxAge = Integer.parseInt((String) config.get(KeycloakConfigServlet.CORS_MAX_AGE));
                } catch (NumberFormatException e) {
                    corsMaxAge = 20;
                }
                String allowedMethods = config.get(KeycloakConfigServlet.CORS_ALLOWED_METHODS) != null ?
                        (String) config.get(KeycloakConfigServlet.CORS_ALLOWED_METHODS) : adapterConfig.getCorsAllowedMethods();
                String allowedHeaders = config.get(KeycloakConfigServlet.CORS_ALLOWED_HEADERS) != null ?
                        (String) config.get(KeycloakConfigServlet.CORS_ALLOWED_HEADERS) : adapterConfig.getCorsAllowedHeaders();
                String exposedHeaders = config.get((KeycloakConfigServlet.CORS_EXPOSED_HEADERS)) != null ?
                        (String) config.get(KeycloakConfigServlet.CORS_EXPOSED_HEADERS) : adapterConfig.getCorsExposedHeaders();

                adapterConfig.setCorsMaxAge(corsMaxAge);
                adapterConfig.setCorsAllowedMethods(allowedMethods);
                adapterConfig.setCorsAllowedHeaders(allowedHeaders);
                adapterConfig.setCorsExposedHeaders(exposedHeaders);
            }

            adapterConfig.setBearerOnly(Boolean.valueOf((String) config.get(KeycloakConfigServlet.BEARER_ONLY)));
            adapterConfig.setAutodetectBearerOnly(Boolean.valueOf((String) config.get(KeycloakConfigServlet.AUTODETECT_BEARER_ONLY)));
            adapterConfig.setEnableBasicAuth(Boolean.valueOf((String) config.get(KeycloakConfigServlet.ENABLE_BASIC_AUTH)));
            adapterConfig.setExposeToken(Boolean.valueOf((String) config.get(KeycloakConfigServlet.EXPOSE_TOKEN)));
            adapterConfig.setCredentials(credentials);
            adapterConfig.setConnectionPoolSize(poolSize);
            adapterConfig.setDisableTrustManager(Boolean.valueOf(KeycloakConfigServlet.DISABLE_TRUST_MANAGER));
            adapterConfig.setAllowAnyHostname(Boolean.valueOf(KeycloakConfigServlet.ALLOW_ANY_HOSTNAME));
            if (!StringUtils.isEmpty(proxy))
                adapterConfig.setProxyUrl(proxy);
            if (!StringUtils.isEmpty(truststore))
                adapterConfig.setTruststore(truststore);
            if (!StringUtils.isEmpty(truststorePassword))
                adapterConfig.setTruststorePassword(truststorePassword);
            if (!StringUtils.isEmpty(clientKeystore)) {
                adapterConfig.setClientKeystore(clientKeystore);
                if (!StringUtils.isEmpty((String) config.get(KeycloakConfigServlet.CLIENT_KEYSTORE_PASSWORD)))
                    adapterConfig.setClientKeystorePassword((String) config.get(KeycloakConfigServlet.CLIENT_KEYSTORE_PASSWORD));
                if (!StringUtils.isEmpty((String) config.get(KeycloakConfigServlet.CLIENT_KEY_PASSWORD)))
                    adapterConfig.setClientKeyPassword((String) config.get(KeycloakConfigServlet.CLIENT_KEY_PASSWORD));
            }

            adapterConfig.setAlwaysRefreshToken(Boolean.valueOf((String) config.get(KeycloakConfigServlet.ALWAYS_REFRESH_TOKEN)));
            adapterConfig.setRegisterNodeAtStartup(Boolean.valueOf((String) config.get(KeycloakConfigServlet.REGISTER_NODE_AT_STARTUP)));
            adapterConfig.setRegisterNodePeriod(registerNodePeriod);
            adapterConfig.setTokenStore(tokenStore);
            if (tokenStore.equalsIgnoreCase("Cookie")) {
                adapterConfig.setTokenCookiePath((String) config.get(KeycloakConfigServlet.TOKEN_COOKIE_PATH));
            }
            adapterConfig.setPrincipalAttribute(principalAttribute);
            adapterConfig.setTurnOffChangeSessionIdOnLogin(Boolean.valueOf((String) config.get(KeycloakConfigServlet.TURN_OFF_CHANGE_SESSION_ID_ON_LOGIN)));
            adapterConfig.setTokenMinimumTimeToLive(minTimeToLive);
            adapterConfig.setMinTimeBetweenJwksRequests(timeBetweenJWKS);
            adapterConfig.setPublicKeyCacheTtl(keyCacheTTL);
            adapterConfig.setVerifyTokenAudience(Boolean.valueOf((String) config.get(KeycloakConfigServlet.VERIFY_AUDIENCE)));

            KeycloakDeployment ment = KeycloakDeploymentBuilder.build(adapterConfig);
            deploymentContext = new AdapterDeploymentContext(ment);
            log.warn("updated settings");
        } catch (Exception e) {
            log.warn("failed during updated due to " + e.getMessage());
        }


    }

    private void initFromConfig(AdapterConfig config, PluginSettings toStore) {

        log.warn("Started initial configuration");
        toStore.put(KeycloakConfigServlet.REALM, config.getRealm());
        toStore.put(KeycloakConfigServlet.RESOURCE, config.getResource());
        toStore.put(KeycloakConfigServlet.REALM_PUBLIC_KEY, config.getRealmKey());
        toStore.put(KeycloakConfigServlet.AUTH_SERVER_URL, config.getAuthServerUrl());
        toStore.put(KeycloakConfigServlet.SSL_REQUIRED, config.getSslRequired());
        toStore.put(KeycloakConfigServlet.CONFIDENTIAL_PORT, getString(config.getConfidentialPort()));
        toStore.put(KeycloakConfigServlet.USE_RESOURCE_ROLE_MAPPINGS, getString(config.isUseResourceRoleMappings()));
        toStore.put(KeycloakConfigServlet.PUBLIC_CLIENT, getString(config.isPublicClient()));
        log.warn("setting CORS options");
        toStore.put(KeycloakConfigServlet.ENABLE_CORS, getString(config.isCors()));
        toStore.put(KeycloakConfigServlet.CORS_ALLOWED_HEADERS, config.getCorsAllowedHeaders());
        toStore.put(KeycloakConfigServlet.CORS_ALLOWED_METHODS, config.getCorsAllowedMethods());
        toStore.put(KeycloakConfigServlet.CORS_EXPOSED_HEADERS, config.getCorsExposedHeaders());
        toStore.put(KeycloakConfigServlet.CORS_MAX_AGE, getString(config.getCorsMaxAge()));
        toStore.put(KeycloakConfigServlet.BEARER_ONLY, getString(config.isBearerOnly()));
        toStore.put(KeycloakConfigServlet.AUTODETECT_BEARER_ONLY, getString(config.isAutodetectBearerOnly()));
        toStore.put(KeycloakConfigServlet.ENABLE_BASIC_AUTH, getString(config.isEnableBasicAuth()));
        toStore.put(KeycloakConfigServlet.EXPOSE_TOKEN, getString(config.isExposeToken()));
        toStore.put(KeycloakConfigServlet.SECRET, (String) config.getCredentials().get("secret"));
        toStore.put(KeycloakConfigServlet.CONNECTION_POOL_SIZE, getString(config.getConnectionPoolSize()));
        toStore.put(KeycloakConfigServlet.DISABLE_TRUST_MANAGER, getString(config.isDisableTrustManager()));
        toStore.put(KeycloakConfigServlet.ALLOW_ANY_HOSTNAME, getString(config.isAllowAnyHostname()));
        toStore.put(KeycloakConfigServlet.PROXY_URL, config.getProxyUrl());
        log.warn("setting truststore stuff");
        toStore.put(KeycloakConfigServlet.TRUSTSTORE, config.getTruststore());
        toStore.put(KeycloakConfigServlet.TRUSTSTORE_PASSWORD, config.getTruststorePassword());
        toStore.put(KeycloakConfigServlet.CLIENT_KEYSTORE, config.getClientKeystore());
        toStore.put(KeycloakConfigServlet.CLIENT_KEYSTORE_PASSWORD, config.getClientKeystorePassword());
        toStore.put(KeycloakConfigServlet.CLIENT_KEY_PASSWORD, config.getClientKeyPassword());
        toStore.put(KeycloakConfigServlet.ALWAYS_REFRESH_TOKEN, getString(config.isAlwaysRefreshToken()));
        toStore.put(KeycloakConfigServlet.REGISTER_NODE_PERIOD, getString(config.getRegisterNodePeriod()));
        toStore.put(KeycloakConfigServlet.REGISTER_NODE_AT_STARTUP, getString(config.isRegisterNodeAtStartup()));
        toStore.put(KeycloakConfigServlet.TOKEN_STORE, config.getTokenStore());
        toStore.put(KeycloakConfigServlet.TOKEN_COOKIE_PATH, config.getTokenCookiePath());
        toStore.put(KeycloakConfigServlet.PRINCIPAL_ATTRIBUTE, "sub");
        toStore.put(KeycloakConfigServlet.TURN_OFF_CHANGE_SESSION_ID_ON_LOGIN, getString(config.getTurnOffChangeSessionIdOnLogin()));
        toStore.put(KeycloakConfigServlet.TOKEN_MINIMUM_TIME_TO_LIVE, getString(config.getTokenMinimumTimeToLive()));
        toStore.put(KeycloakConfigServlet.MIN_TIME_BETWEEN_JWKS_REQUEST, getString(config.getMinTimeBetweenJwksRequests()));
        toStore.put(KeycloakConfigServlet.PUBLIC_KEY_CACHE_TTL, getString(config.getPublicKeyCacheTtl()));
        toStore.put(KeycloakConfigServlet.IGNORE_OAUTH_QUERY_PARAM, getString(config.isIgnoreOAuthQueryParameter()));
        toStore.put(KeycloakConfigServlet.VERIFY_AUDIENCE, getString(config.isVerifyTokenAudience()));
    }

    private String getString(Integer number) {

        if (number == null) {
            number = -1;
        }
        return number.toString();
    }

    private String getString(Boolean bool) {

        if (bool == null)
            bool = Boolean.FALSE;
        return bool.toString();
    }

    @Override
    public void destroy() {

        super.destroy();
        PluginSettings settings = pluginSettingsFactory.createSettingsForKey(SETTINGS_KEY);
        settings.remove(SETTINGS_KEY);
        log.warn("destroyed the filter");
    }
}