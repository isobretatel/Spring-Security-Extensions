This folder contains configuration files for the following security configuration:

Many-to-one.
Use ActiveDirectory server for authentication, map ActiveDirectory account to secondary user account. 
All LDAP accounts mapped to single secondary user account with accountMapper.userName, specified in account-mapper.properties file. 

To use this configuration: 
1. Copy appContext.xml file to WEB-INF\config folder.
2. Enter ldap.root and ldap.url parameters in activedirectory\ldap.properties file.
3. Enter userName parameter in account-mapper.properties file.