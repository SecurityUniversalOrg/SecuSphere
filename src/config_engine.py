import os
from azure.keyvault.secrets import SecretClient
from azure.keyvault.keys import KeyClient
from azure.keyvault.certificates import CertificateClient, CertificatePolicy
from azure.identity import DefaultAzureCredential, EnvironmentCredential
from settings import SET_ENV, SET_AZURE_KEYVAULT_NAME, SET_AUTH_TYPE, SET_INSECURE_OAUTH, SET_SMTP_HOST, SET_SMTP_USER, \
    SET_SMTP_ADMIN_EMAIL, SET_LDAP_HOST, SET_LDAP_PORT, SET_LDAP_BASE_DN, SET_LDAP_USER_DN, SET_LDAP_GROUP_DN, \
    SET_LDAP_USER_RDN_ATTR, SET_LDAP_USER_LOGIN_ATTR, SET_LDAP_BIND_USER_DN, SET_LDAP_BIND_USER_PASSWORD, \
    SET_APP_EXT_URL
from settings import SET_PROD_DB_URI_REF, SET_SMTP_PW_REF, SET_JENKINS_KEY_REF, SET_JENKINS_USER_REF, SET_JENKINS_TOKEN_REF
from settings import SET_PROD_DB_URI, SET_SMTP_PW, SET_JENKINS_KEY, SET_JENKINS_USER, \
    SET_JENKINS_HOST, SET_JENKINS_PROJECT, SET_JENKINS_TOKEN
from settings import SET_AZAD_CLIENT_ID, SET_AZAD_CLIENT_SECRET, SET_AZAD_AUTHORITY
from settings import SET_SNOW_INSTANCE_NAME, SET_SNOW_CLIENT_ID, SET_SNOW_CLIENT_SECRET, SET_SNOW_USERNAME, SET_SNOW_PASSWORD, SET_SNOW_CLIENT_SECRET_REF, SET_SNOW_PASSWORD_REF


VERSION = '0.1.0-beta'

if os.getenv('AZURE_KEYVAULT_NAME'):
    AZURE_KEYVAULT_NAME = os.getenv('AZURE_KEYVAULT_NAME')
else:
    AZURE_KEYVAULT_NAME = SET_AZURE_KEYVAULT_NAME

if os.getenv('AUTH_TYPE'):
    AUTH_TYPE = os.getenv('AUTH_TYPE')
else:
    AUTH_TYPE = SET_AUTH_TYPE

if os.getenv('INSECURE_OAUTH'):
    INSECURE_OAUTH = os.getenv('INSECURE_OAUTH')
else:
    INSECURE_OAUTH = SET_INSECURE_OAUTH

if INSECURE_OAUTH:
    os.environ['AUTHLIB_INSECURE_TRANSPORT'] = '1'

if os.getenv('APP_EXT_URL'):
    APP_EXT_URL = os.getenv('APP_EXT_URL')
else:
    APP_EXT_URL = SET_APP_EXT_URL

if os.getenv('SMTP_HOST'):
    SMTP_HOST = os.getenv('SMTP_HOST')
else:
    SMTP_HOST = SET_SMTP_HOST

if os.getenv('SMTP_USER'):
    SMTP_USER = os.getenv('SMTP_USER')
else:
    SMTP_USER = SET_SMTP_USER

if os.getenv('SMTP_ADMIN_EMAIL'):
    SMTP_ADMIN_EMAIL = os.getenv('SMTP_ADMIN_EMAIL')
else:
    SMTP_ADMIN_EMAIL = SET_SMTP_ADMIN_EMAIL

if os.getenv('LDAP_HOST'):
    LDAP_HOST = os.getenv('LDAP_HOST')
else:
    LDAP_HOST = SET_LDAP_HOST

if os.getenv('LDAP_PORT'):
    LDAP_PORT = os.getenv('LDAP_PORT')
else:
    LDAP_PORT = SET_LDAP_PORT

if os.getenv('LDAP_BASE_DN'):
    LDAP_BASE_DN = os.getenv('LDAP_BASE_DN')
else:
    LDAP_BASE_DN = SET_LDAP_BASE_DN

if os.getenv('LDAP_USER_DN'):
    LDAP_USER_DN = os.getenv('LDAP_USER_DN')
else:
    LDAP_USER_DN = SET_LDAP_USER_DN

if os.getenv('LDAP_GROUP_DN'):
    LDAP_GROUP_DN = os.getenv('LDAP_GROUP_DN')
else:
    LDAP_GROUP_DN = SET_LDAP_GROUP_DN

if os.getenv('LDAP_USER_RDN_ATTR'):
    LDAP_USER_RDN_ATTR = os.getenv('LDAP_USER_RDN_ATTR')
else:
    LDAP_USER_RDN_ATTR = SET_LDAP_USER_RDN_ATTR

if os.getenv('LDAP_USER_LOGIN_ATTR'):
    LDAP_USER_LOGIN_ATTR = os.getenv('LDAP_USER_LOGIN_ATTR')
else:
    LDAP_USER_LOGIN_ATTR = SET_LDAP_USER_LOGIN_ATTR

if os.getenv('LDAP_BIND_USER_DN'):
    LDAP_BIND_USER_DN = os.getenv('LDAP_BIND_USER_DN')
else:
    LDAP_BIND_USER_DN = SET_LDAP_BIND_USER_DN

if os.getenv('LDAP_BIND_USER_PASSWORD'):
    LDAP_BIND_USER_PASSWORD = os.getenv('LDAP_BIND_USER_PASSWORD')
else:
    LDAP_BIND_USER_PASSWORD = SET_LDAP_BIND_USER_PASSWORD


class KeyVaultManager(object):
    def __init__(self):
        if os.getenv('AZURE_KEYVAULT_NAME'):
            key_vault_uri = f"https://{os.getenv('AZURE_KEYVAULT_NAME')}.vault.azure.net"
        else:
            key_vault_uri = f"https://{AZURE_KEYVAULT_NAME}.vault.azure.net"
        if os.getenv('AZURE_AUTH_METHOD'):
            if os.getenv('AZURE_AUTH_METHOD') == 'env':
                self.credential = EnvironmentCredential(
                    additionally_allowed_tenants=[os.getenv('AZURE_TENANT_ID')]
                )
        else:
            self.credential = DefaultAzureCredential()
        self.secret_client = SecretClient(vault_url=key_vault_uri, credential=self.credential)
        self.key_client = KeyClient(vault_url=key_vault_uri, credential=self.credential)
        self.cert_client = CertificateClient(vault_url=key_vault_uri, credential=self.credential)


    def get_secret(self, secret_name):
        retrieved_secret = self.secret_client.get_secret(secret_name)
        secret_value = retrieved_secret.value
        return secret_value


    def set_secret(self, secret_name, secret_value):
        self.secret_client.set_secret(secret_name, secret_value)


    def delete_secret(self, secret_name):
        poller = self.secret_client.begin_delete_secret(secret_name)
        deleted_secret = poller.result()
        return deleted_secret

    def get_key(self, secret_name):
        retrieved_secret = self.key_client.get_key(secret_name)
        secret_value = retrieved_secret.value
        return secret_value

    def set_key(self, secret_name):
        self.key_client.create_rsa_key(secret_name, size=2048)

    def delete_key(self, secret_name):
        deleted_key = self.key_client.begin_delete_key(secret_name).result()
        return deleted_key

    def get_cert(self, secret_name):
        retrieved_secret = self.cert_client.get_certificate(secret_name)
        secret_value = retrieved_secret.value
        return secret_value

    def set_cert(self, secret_name):
        create_certificate_poller = self.cert_client.begin_create_certificate(
            certificate_name=secret_name, policy=CertificatePolicy.get_default()
        )
        return create_certificate_poller

    def delete_cert(self, secret_name):
        poller = self.cert_client.begin_delete_certificate(secret_name)
        deleted_secret = poller.result()
        return deleted_secret


## CORE Config Variables ##
if os.getenv('VM_RUNTIME'):
    ENV = os.getenv('VM_RUNTIME')
else:
    ENV = SET_ENV

if ENV == 'prod':
    if os.getenv('PROD_DB_URI_REF'):
        PROD_DB_URI = KeyVaultManager().get_secret(os.getenv('PROD_DB_URI_REF'))
    else:
        PROD_DB_URI = KeyVaultManager().get_secret(SET_PROD_DB_URI_REF)
else:
    PROD_DB_URI = SET_PROD_DB_URI

if AUTH_TYPE == 'azuread':
    if os.getenv('AZAD_CLIENT_ID'):
        AZAD_CLIENT_ID = os.getenv('AZAD_CLIENT_ID')
    else:
        AZAD_CLIENT_ID = SET_AZAD_CLIENT_ID
    if os.getenv('AZAD_CLIENT_SECRET'):
        AZAD_CLIENT_SECRET = KeyVaultManager().get_secret(os.getenv('AZAD_CLIENT_SECRET'))
    else:
        AZAD_CLIENT_SECRET = KeyVaultManager().get_secret(SET_AZAD_CLIENT_SECRET)
    if os.getenv('AZAD_AUTHORITY'):
        AZAD_AUTHORITY = os.getenv('AZAD_AUTHORITY')
    else:
        AZAD_AUTHORITY = SET_AZAD_AUTHORITY
else:
    AZAD_CLIENT_ID = ""
    AZAD_CLIENT_SECRET = ""
    AZAD_AUTHORITY = ""

## Email Variables ##
if ENV == 'prod':
    if os.getenv('SMTP_PW_REF'):
        SMTP_PASSWORD = KeyVaultManager().get_secret(os.getenv('SMTP_PW_REF'))
    else:
        SMTP_PASSWORD = KeyVaultManager().get_secret(SET_SMTP_PW_REF)
else:
    SMTP_PASSWORD = SET_SMTP_PW

##
## GitHub to Jenkins Webhook ##
if ENV == 'prod':
    if os.getenv('JENKINS_USER'):
        JENKINS_USER = KeyVaultManager().get_secret(os.getenv('JENKINS_USER'))
    else:
        JENKINS_USER = KeyVaultManager().get_secret(SET_JENKINS_USER_REF)
    if os.getenv('JENKINS_KEY'):
        JENKINS_KEY = KeyVaultManager().get_secret(os.getenv('JENKINS_KEY'))
    else:
        JENKINS_KEY = KeyVaultManager().get_secret(SET_JENKINS_KEY_REF)
    if os.getenv('JENKINS_TOKEN'):
        JENKINS_TOKEN = KeyVaultManager().get_secret(os.getenv('JENKINS_TOKEN'))
    else:
        JENKINS_TOKEN = KeyVaultManager().get_secret(SET_JENKINS_TOKEN_REF)
else:
    JENKINS_USER = SET_JENKINS_USER
    JENKINS_KEY = SET_JENKINS_KEY
    JENKINS_TOKEN = SET_JENKINS_TOKEN

if os.getenv('JENKINS_PROJECT'):
    JENKINS_PROJECT = os.getenv('JENKINS_PROJECT')
else:
    JENKINS_PROJECT = SET_JENKINS_PROJECT

if os.getenv('JENKINS_HOST'):
    JENKINS_HOST = os.getenv('JENKINS_HOST')
else:
    JENKINS_HOST = SET_JENKINS_HOST


## ServiceNOW Integration
if ENV == 'prod':
    if os.getenv('SNOW_PASSWORD'):
        SNOW_PASSWORD = KeyVaultManager().get_secret(os.getenv('SNOW_PASSWORD'))
    else:
        SNOW_PASSWORD = KeyVaultManager().get_secret(SET_SNOW_PASSWORD_REF)
    if os.getenv('SNOW_CLIENT_SECRET'):
        SNOW_CLIENT_SECRET = KeyVaultManager().get_secret(os.getenv('SNOW_CLIENT_SECRET'))
    else:
        SNOW_CLIENT_SECRET = KeyVaultManager().get_secret(SET_SNOW_CLIENT_SECRET_REF)
    if os.getenv('SNOW_INSTANCE_NAME'):
        SNOW_INSTANCE_NAME = KeyVaultManager().get_secret(os.getenv('SNOW_INSTANCE_NAME'))
    else:
        SNOW_INSTANCE_NAME = KeyVaultManager().get_secret(SET_SNOW_INSTANCE_NAME)
    if os.getenv('SNOW_CLIENT_ID'):
        SNOW_CLIENT_ID = KeyVaultManager().get_secret(os.getenv('SNOW_CLIENT_ID'))
    else:
        SNOW_CLIENT_ID = KeyVaultManager().get_secret(SET_SNOW_CLIENT_ID)
    if os.getenv('SNOW_USERNAME'):
        SNOW_USERNAME = KeyVaultManager().get_secret(os.getenv('SNOW_USERNAME'))
    else:
        SNOW_USERNAME = KeyVaultManager().get_secret(SET_SNOW_USERNAME)
else:
    SNOW_PASSWORD = SET_SNOW_PASSWORD
    SNOW_CLIENT_SECRET = SET_SNOW_CLIENT_SECRET
    SNOW_INSTANCE_NAME = SET_SNOW_INSTANCE_NAME
    SNOW_CLIENT_ID = SET_SNOW_CLIENT_ID
    SNOW_USERNAME = SET_SNOW_USERNAME

