package com.schmalz.servlet;


import com.atlassian.plugin.spring.scanner.annotation.component.Scanned;
import com.atlassian.plugin.spring.scanner.annotation.imports.ComponentImport;
import com.atlassian.sal.api.auth.LoginUriProvider;
import com.atlassian.sal.api.pluginsettings.PluginSettings;
import com.atlassian.sal.api.pluginsettings.PluginSettingsFactory;
import com.atlassian.sal.api.user.UserManager;
import com.atlassian.sal.api.user.UserProfile;
import com.atlassian.sal.api.user.UserRole;
import com.atlassian.templaterenderer.TemplateRenderer;
import com.schmalz.servlet.filter.AdaptedKeycloakOIDCFilter;
import org.keycloak.KeycloakSecurityContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;

@Scanned
public class KeycloakConfigServlet extends HttpServlet {
    private static final Logger log = LoggerFactory.getLogger(KeycloakConfigServlet.class);
    public static final String UPDATED_SETTINGS_KEY = KeycloakConfigServlet.class.getName() + "-keycloakJiraPlugin-settingsUpdatedKey";
    private static List<String> validValues;
    public static final String REALM_KEY = "realm";
    public static final String PUBLIC_CLIENT_KEY = "publicClient";
    public static final String RESOURCE_KEY = "resource";
    public static final String AUTH_SERVER_BASEURL_KEY = "authServerUrl";
    public static final String SECRET_KEY = "secret";
    private final static String CONFIG_TEMPLATE = "/templates/keycloakJiraPlugin_ConfigPage.vm";

    @ComponentImport
    private final LoginUriProvider loginUriProvider;

    @ComponentImport
    private final UserManager userManager;

    @ComponentImport
    private final PluginSettingsFactory pluginSettingsFactory;

    @ComponentImport
    private TemplateRenderer templateRenderer;

    public KeycloakConfigServlet(PluginSettingsFactory factory, TemplateRenderer renderer, UserManager manager, LoginUriProvider loginUriProvider) {

        pluginSettingsFactory = factory;
        templateRenderer = renderer;
        userManager = manager;
        this.loginUriProvider = loginUriProvider;
        validValues = new ArrayList<>();
        validValues.add(REALM_KEY);
        validValues.add(AUTH_SERVER_BASEURL_KEY);
        validValues.add(RESOURCE_KEY);
        validValues.add(PUBLIC_CLIENT_KEY);
        validValues.add(SECRET_KEY);
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {

        UserProfile user = userManager.getRemoteUser(request);
        if (user == null) {
            redirectToLogin(request, response);
            return;
        }
        if (!hasAccessRights(user)) {
            handleUnauthorizedAccess(request, response);

            return;
        }

        PluginSettings settings = pluginSettingsFactory.createGlobalSettings();

        Map<String, String> config = (Map<String, String>) settings.get(AdaptedKeycloakOIDCFilter.SETTINGS_KEY);
        Map<String, Object> context = new HashMap<>();
        log.warn(config.get(PUBLIC_CLIENT_KEY));
        context.put("map", config);
        context.put("requestUrl", URLDecoder.decode(request.getRequestURL().toString(), StandardCharsets.UTF_8.name()));
        context.put("username", user.getUsername());
        templateRenderer.render(CONFIG_TEMPLATE, context, response.getWriter());
        //https://developer.atlassian.com/server/jira/platform/creating-a-jira-issue-crud-servlet-and-issue-search/
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {

        PluginSettings settings = pluginSettingsFactory.createGlobalSettings();
        Map<String, String> config = (Map<String, String>) settings.get(AdaptedKeycloakOIDCFilter.SETTINGS_KEY);
        Enumeration<String> parameters = request.getParameterNames();

        while (parameters.hasMoreElements()) {
            retrieveAndStore(request, parameters.nextElement(), config);
        }
        settings.put(AdaptedKeycloakOIDCFilter.SETTINGS_KEY, config);
        settings.put(UPDATED_SETTINGS_KEY, "True");
        response.sendRedirect(request.getContextPath() + request.getServletPath());

    }


    /**
     * tests, whether a given parameter is a supported/valid configuration key
     *
     * @param param the param to test
     * @return TRUE, if the param was a valid configuration key, false otherwise
     */
    private boolean isValidValue(String param) {

        return validValues.contains(param);
    }

    /**
     * @param profile the user to test
     * @return returns (@code TRUE) if the user is an admin or systemadmin
     */
    private boolean hasAccessRights(UserProfile profile) {

        return userManager.isAdmin(profile.getUserKey()) || userManager.isSystemAdmin(profile.getUserKey());
    }

    /**
     * redirects a user to jira's login page if he was not logged in. wont be called if the user wants to use keycloak
     * since the filter will act prior
     *
     * @param request  the request with the missing user
     * @param response the response to redirect
     * @throws IOException if the redirect fails
     */
    private void redirectToLogin(HttpServletRequest request, HttpServletResponse response) throws IOException {

        response.sendRedirect(loginUriProvider.getLoginUri(getUri(request)).toASCIIString());
    }

    private URI getUri(HttpServletRequest request) {

        StringBuffer builder = request.getRequestURL();
        if (request.getQueryString() != null) {
            builder.append("?");
            builder.append(request.getQueryString());
        }
        return URI.create(builder.toString());
    }


    /**
     * redirects the user, when it was determined that he does not have sufficient privileges. this differs, when a user
     * is authenticated to keycloak or not
     *
     * @param request  the given http-request
     * @param response the response to redirect
     * @throws IOException if the redirect cannot be send
     */
    private void handleUnauthorizedAccess(HttpServletRequest request, HttpServletResponse response) throws IOException {

        if (request.getSession().getAttribute(KeycloakSecurityContext.class.getName()) == null) {
            response.sendRedirect(loginUriProvider.getLoginUriForRole(getUri(request), UserRole.ADMIN).toASCIIString());
        } else
            response.sendRedirect(request.getContextPath());
    }


    /**
     * Retrieves and removes the value of the given key from the settings
     *
     * @param settings the settings to search
     * @param key      the key whose value should be retrieved
     * @return the value of the key, NULL if the key is missing
     */
    private Object retrieveAndRemove(PluginSettings settings, String key) {

        Object returnObject = settings.get(key);
        settings.remove(key);
        return returnObject;
    }


    /**
     * retrieves a given parameter of a request and puts its value into a map
     *
     * @param request      the request holding the parameter
     * @param parameterKey the parameter to retrieve
     * @param storage      the map where the parameter, value pair should be stored
     */
    private void retrieveAndStore(HttpServletRequest request, String parameterKey, Map<String, String> storage) {

        if (isValidValue(parameterKey)) {
            String temp = request.getParameter(parameterKey);
            storage.put(parameterKey, temp);
        }
    }
}
//https://community.atlassian.com/t5/Answers-Developer-Questions/Retrieving-Plug-in-settings-using-PluginSettingsFactory/qaq-p/483804
