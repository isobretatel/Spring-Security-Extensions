This folder contains configuration files for the following security configuration:

Preauth

Use SSO server for authentication.
Get userId from RemoteUser property of the HTTP header.
Get projectId from the \projectid-source\property\projectid-source.properties property file.

To use this configuration: 
1. Copy \request-parameter\appContext.xml file to WEB-INF\config folder.
2. Modify appContext.xml file: replace reference to "\security\preauth\username-source\request-parameter\username-source.xml" with "\security\preauth\username-source\remote-user\username-source.xml".
3. Enter projectId parameter in \projectid-source\property\projectid-source.properties file.

