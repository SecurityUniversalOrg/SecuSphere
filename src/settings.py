## Authentication  ##
SET_AUTH_TYPE = 'local'  # options: local, ldap, saml
SET_INSECURE_OAUTH = True
SET_AZURE_KEYVAULT_NAME = 'BkDevSecOpsKeyVault'
SET_ENV = 'test'  # options: test, prod
SET_PROD_DB_URI_REF = 'PROD-DB-URI'
# Non-Secure Settings - DO NOT USE IN PRODUCTION DEPLOYMENTS
SET_PROD_DB_URI = 'changeme'

##
## Local Instance Settings ##
SET_APP_EXT_URL = '192.168.0.150'

##
## Email Variables ##
SET_SMTP_HOST = 'smtp.sendgrid.net:587'
SET_SMTP_USER = 'apikey'
SET_SMTP_ADMIN_EMAIL = 'admin@securityuniversal.com'
SET_SMTP_PW_REF = 'SENDGRID-SMTP-PW'
# Non-Secure Settings - DO NOT USE IN PRODUCTION DEPLOYMENTS
SET_SMTP_PW = 'changeme'

##
## LDAP Settings (Optional) ##
SET_LDAP_HOST = '192.168.0.54'
SET_LDAP_PORT = 389  # Use 636 for LDAPS
SET_LDAP_BASE_DN = 'ou=users,dc=jbfantasyfactory,dc=local'
SET_LDAP_USER_DN = 'ou=users'
SET_LDAP_GROUP_DN = 'ou=groups'
SET_LDAP_USER_RDN_ATTR = 'uid'
SET_LDAP_USER_LOGIN_ATTR = 'uid'
SET_LDAP_BIND_USER_DN = 'cn=Administrator,dc=jbfantasyfactory,dc=local'
SET_LDAP_BIND_USER_PASSWORD = 'Dynamically Set'

##
## Jenkins Webhook Settings (Optional) ##
SET_JENKINS_KEY_REF = 'JENKINS-KEY'
SET_JENKINS_USER_REF = 'JENKINS-USER'
SET_JENKINS_HOST = 'http://192.168.0.68:8080'
SET_JENKINS_PROJECT = 'Security%20Testing'
# Non-Secure Settings - DO NOT USE IN PRODUCTION DEPLOYMENTS
SET_JENKINS_KEY = 'changeme'
SET_JENKINS_USER = 'changeme'
