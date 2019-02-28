package com.schmalz.servlet;

import com.atlassian.jira.security.login.JiraSeraphAuthenticator;
import com.atlassian.plugin.spring.scanner.annotation.component.Scanned;
import com.atlassian.plugin.spring.scanner.annotation.imports.ComponentImport;
import com.atlassian.sal.api.pluginsettings.PluginSettings;
import com.atlassian.sal.api.pluginsettings.PluginSettingsFactory;
import com.atlassian.templaterenderer.TemplateRenderer;
import com.schmalz.servlet.filter.AdaptedKeycloakOIDCFilter;
import org.keycloak.adapters.KeycloakDeployment;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.Principal;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Scanned
public class KeycloakConfigServlet extends HttpServlet {
    private static final Logger log = LoggerFactory.getLogger(KeycloakConfigServlet.class);

    private static List<String> validValues;
    public final String configTemplate = "/templates/keycloakJiraPlugin_ConfigPage.vm";

    @ComponentImport
    private final PluginSettingsFactory pluginSettingsFactory;

    @ComponentImport
    private TemplateRenderer templateRenderer;

    public KeycloakConfigServlet(PluginSettingsFactory factory, TemplateRenderer renderer) {
        pluginSettingsFactory = factory;
        templateRenderer = renderer;
        validValues = new ArrayList<>();
        validValues.add("resource");
        validValues.add("baseUrl");
        validValues.add("realm");
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        Principal user = (Principal) request.getSession().getAttribute(JiraSeraphAuthenticator.LOGGED_IN_KEY);
        if (user == null) {
            //handleInvalidAccess();
            response.sendRedirect("https://google.com");
            return;
        }

        PluginSettings settings = pluginSettingsFactory.createGlobalSettings();
        if (handleQueryString(request.getQueryString(), settings)) {
            response.sendRedirect("https://google.com");
            //handleSuccessfulUpdate
            return;
        }

        Map<String, String> kd = (Map<String, String>) settings.get(AdaptedKeycloakOIDCFilter.SETTINGS_KEY);
        Map<String, Object> context = new HashMap<>();


        context.put("map", kd);
        context.put("requestUrl", request.getRequestURL().toString());
        templateRenderer.render(configTemplate, context, response.getWriter());
        //https://developer.atlassian.com/server/jira/platform/creating-a-jira-issue-crud-servlet-and-issue-search/
    }

    private void updateDeployment(KeycloakDeployment updatedDeployment) {

    }

    private boolean handleQueryString(String query, PluginSettings settings) {
        if (query == null) {
            return false;
        }
        Map<String, String> config = (Map<String, String>) settings.get(AdaptedKeycloakOIDCFilter.SETTINGS_KEY);
        String[] keyValuePairs = query.split("&");
        for (int i = 0; i < keyValuePairs.length; i++) {
            String[] splitKeyValuePairs = keyValuePairs[i].split("=");
            if (isValidValue(splitKeyValuePairs[0])) {
                config.put(splitKeyValuePairs[0], splitKeyValuePairs[1]);
            }
        }
        return true;
    }

    private boolean isValidValue(String toTest) {
        return validValues.contains(toTest);
    }
}
//https://community.atlassian.com/t5/Answers-Developer-Questions/Retrieving-Plug-in-settings-using-PluginSettingsFactory/qaq-p/483804
