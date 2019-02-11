#Preamble and warnings
This plugin was created with the Atlassian SDK. See, for example, [the official introduction](https://developer.atlassian.com/display/DOCS/Introduction+to+the+Atlassian+Plugin+SDK).
To run it, go to the root directory and enter 'atlas-run' in your favorite command shell.
You may configure keycloak by editing the keycloak.json file according to the documentation [here](https://www.keycloak.org/docs/latest/securing_apps/index.html#java-adapters).
This was originally developed with Keycloak 4.8.3.Final and Jira 7.12.
Please do notice that this is not necessarily the most efficient way possible to authenticate to Jira with [Keycloak](https://www.keycloak.org/). 
Also if you are looking for actual support please investigate the marketplace for your needs. There should be way better options available to you than using this plugin

#Getting this plugin running
1. Make sure keycloak is running on localhost:8180. You can get that done via docker or just by downloading and unziping the official [distribution](https://www.keycloak.org/downloads.html)
2. Create a user admin, so you can test immediately
3. Make a basic realm and configure a client for Jira. Here are [some](https://www.keycloak.org/docs/latest/server_admin/index.html#_clients) [links](https://www.keycloak.org/docs/latest/server_admin/index.html#_create-realm) that might prove useful for this
4. Edit the keycloak.json file according to your configuration
2. If you did not already install the Atlassian SDK. Here is a link to a [tutorial](https://developer.atlassian.com/server/framework/atlassian-sdk/install-the-atlassian-sdk-on-a-windows-system/) for windows
3. Clone this repository
4. Open your favourite command prompt and navigate into the root folder of this plugin, e.g C:/Users/user/Desktop/myFirstPlugin
5. Run 'atlas-run' in your command shell
6. Wait for Jira deployment to be finished
7. Navigate to http://localhost:2990/jira. You should be redirected to a login page from keycloak. Login with user 'admin' and the password you configured
8. You should now be logged into jira as well

If you just want to use this plugin in your Jira deployment without making changes to it
1. Create an appropriate client for Jira at your Keycloak server
2. Adjust the keycloak.json file accordingly
3. Open your favourite command shell and navigate into the root directory of this git project, that is the folder holding the pom.xml
4. Execute 'atlas-package' or 'atlas-mvn package' in your shell, they basically do the same exact thing anyways
5. Upload the plugin to your Jira deployment
#Troubleshooting
* If you are using Atlassian's quick reload feature in development you should delete your session cookies before further testing. You will run into Classcastexceptions otherwise. This is most often accomplished by simply restarting your browser since session cookies usually expire upon browser shutdown.
* You can send me an email at [sebastian.boehringer@freenet.de](mailto:sebastian.boehringer@freenet.de). Please be aware that I will most likely *not* answer requests concerning this plugin or security issues. This plugin neither claims its the most optimal nor most efficient solution to integrate Keycloak into your Jira deployment. You are most likely better of using a commercial plugin.
* If you are avoiding the usage of the Atlassian SDK you might have to manually install the [jndi](https://www.oracle.com/technetwork/java/javasebusiness/downloads/java-archive-downloads-java-plat-419418.html) and [jta](http://download.oracle.com/otn-pub/java/jndi/1.2.1/jndi-1_2_1.zip) dependencies into your local maven repository as the needed versions aren't hosted on maven central anymore.