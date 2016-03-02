This folder contains configuration files for the following security configuration:

Authority-by-prefix.
Use ActiveDirectory server for authentication, map ActiveDirectory account to secondary user account. 
Each LDAP account has authority (user role) with the specified prefix. 
That authority will be used as secondary user account name. 

To use this configuration: 
1. Copy \many-to-one\appContext.xml file to WEB-INF\config folder.
2. Modify appContext.xml file: replace reference to "\security\ldap\activedirectory\mapping\many-to-one\account-mapper.xml" with "\security\ldap\activedirectory\mapping\authority-by-prefix\account-mapper.xml".
3. Enter ldap.root and ldap.url parameters in activedirectory\ldap.properties file.
4. Enter authorityPrefix parameter in account-mapper.properties file.