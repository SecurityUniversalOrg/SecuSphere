## Authentication  ##
SET_AUTH_TYPE = 'local'  # options: local, ldap, saml, azuread
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
## AZURE AD Settings (Optional) ##
SET_AZAD_CLIENT_ID = "e2efe60c-84f9-41ba-bfba-1cc4fb1fc837"
SET_AZAD_CLIENT_SECRET = "AZAD-CLIENT-SECRET"
SET_AZAD_AUTHORITY = "https://login.microsoftonline.com/8da368d4-070a-47bd-9530-798f0ad6a651"

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
SET_JENKINS_TOKEN_REF = 'JENKINS-TOKEN'
SET_JENKINS_HOST = 'http://192.168.0.68:8080'
SET_JENKINS_PROJECT = 'OnDemandSecurityTesting'
# Non-Secure Settings - DO NOT USE IN PRODUCTION DEPLOYMENTS
SET_JENKINS_KEY = 'changeme'
SET_JENKINS_USER = 'changeme'
SET_JENKINS_TOKEN = 'changeme'

## ServiceNOW Settings
SET_SNOW_INSTANCE_NAME = 'dev124268'
SET_SNOW_CLIENT_ID = '1ab21bf476013110e1ce39e1f368c2fa'
SET_SNOW_CLIENT_SECRET_REF = 'SNOW-SECRET'
SET_SNOW_USERNAME = 'admin'
SET_SNOW_PASSWORD_REF = 'SNOW-PASSWORD'
# Non-Secure Settings - DO NOT USE IN PRODUCTION DEPLOYMENTS
SET_SNOW_CLIENT_SECRET  = 'changeme'
SET_SNOW_PASSWORD = 'changeme'

