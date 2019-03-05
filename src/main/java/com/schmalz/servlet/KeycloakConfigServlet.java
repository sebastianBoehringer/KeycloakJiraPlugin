package com.schmalz.servlet;


import com.atlassian.plugin.spring.scanner.annotation.component.Scanned;
import com.atlassian.plugin.spring.scanner.annotation.imports.ComponentImport;
import com.atlassian.sal.api.auth.LoginUriProvider;
import com.atlassian.sal.api.pluginsettings.PluginSettings;
import com.atlassian.sal.api.pluginsettings.PluginSettingsFactory;
import com.atlassian.sal.api.user.UserManager;
import com.atlassian.sal.api.user.UserProfile;
import com.atlassian.templaterenderer.TemplateRenderer;
import com.schmalz.servlet.filter.AdaptedKeycloakOIDCFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Scanned
public class KeycloakConfigServlet extends HttpServlet {
    private static final Logger log = LoggerFactory.getLogger(KeycloakConfigServlet.class);
    public static final String UPDATED_SETTINGS_KEY = KeycloakConfigServlet.class.getName() + "-keycloakJiraPlugin-settingsUpdatedKey";
    private static List<String> validValues;
    public static final String REALM_KEY = "realm";
    public static final String UNUSUED_KEY = "upforgrabz";
    public static final String RESOURCE_KEY = "resource";
    public static final String AUTH_SERVER_BASEURL_KEY = "authServerUrl";
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
        if (handleQueryString(request.getQueryString(), settings)) {
            response.sendRedirect(request.getRequestURL().toString());
            return;
        }

        Map<String, String> kd = (Map<String, String>) settings.get(AdaptedKeycloakOIDCFilter.SETTINGS_KEY);
        Map<String, Object> context = new HashMap<>();

        String stuff = (String) settings.get("myExceptionKEY");
        stuff = stuff == null ? "no Exception" : stuff;
        context.put("map", kd);
        settings.remove("myExceptionKEY");
        context.put("stuff", stuff);
        context.put("requestUrl", URLDecoder.decode(request.getRequestURL().toString(), StandardCharsets.UTF_8.name()));
        context.put("username", user.getUsername());
        templateRenderer.render(CONFIG_TEMPLATE, context, response.getWriter());
        //https://developer.atlassian.com/server/jira/platform/creating-a-jira-issue-crud-servlet-and-issue-search/
    }


    private boolean handleQueryString(String query, PluginSettings settings) {
        if (query == null) {
            return false;
        }

        Map<String, String> config = (Map<String, String>) settings.get(AdaptedKeycloakOIDCFilter.SETTINGS_KEY);
        String[] keyValuePairs = query.split("&");
        for (String keyValuePair : keyValuePairs) {
            String[] splitKeyValuePairs = keyValuePair.split("=");

            if (isValidValue(splitKeyValuePairs[0])) {
                if (splitKeyValuePairs[0].contains("Url")) {
                    try {
                        splitKeyValuePairs[1] = URLDecoder.decode(splitKeyValuePairs[1], StandardCharsets.UTF_8.name());
                    } catch (UnsupportedEncodingException e) {
                        e.printStackTrace();
                    }
                }
                config.put(splitKeyValuePairs[0], splitKeyValuePairs[1]);
            }
        }
        settings.put(AdaptedKeycloakOIDCFilter.SETTINGS_KEY, config);
        settings.put(UPDATED_SETTINGS_KEY, "True");
        return true;
    }

    private boolean isValidValue(String toTest) {
        return validValues.contains(toTest);
    }

    /**
     * @param profile the user to test
     * @return returns (@code TRUE) if the user is an admin or systemadmin
     */
    private boolean hasAccessRights(UserProfile profile) {
        return userManager.isAdmin(profile.getUserKey()) || userManager.isSystemAdmin(profile.getUserKey());
    }

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

    private void handleUnauthorizedAccess(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.sendRedirect("https://google.com");
        //TODO do something useful here
    }
}
//https://community.atlassian.com/t5/Answers-Developer-Questions/Retrieving-Plug-in-settings-using-PluginSettingsFactory/qaq-p/483804
