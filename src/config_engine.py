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
    SET_JENKINS_HOST, SET_JENKINS_PROJECT, SET_JENKINS_TOKEN, SET_JENKINS_STAGING_PROJECT, SET_JENKINS_ENABLED, SET_SNOW_ENABLED
from settings import SET_AZAD_CLIENT_ID, SET_AZAD_CLIENT_SECRET, SET_AZAD_AUTHORITY
from settings import SET_SNOW_INSTANCE_NAME, SET_SNOW_CLIENT_ID, SET_SNOW_CLIENT_SECRET, SET_SNOW_USERNAME, SET_SNOW_PASSWORD, SET_SNOW_CLIENT_SECRET_REF, SET_SNOW_PASSWORD_REF


def getConfigs(config):
    config['TEST_SETTING'] = 'set'

    config['VERSION'] = '0.1.0-beta'

    if os.getenv('AZURE_KEYVAULT_NAME'):
        config['AZURE_KEYVAULT_NAME'] = os.getenv('AZURE_KEYVAULT_NAME')
    else:
        config['AZURE_KEYVAULT_NAME'] = SET_AZURE_KEYVAULT_NAME

    if os.getenv('AUTH_TYPE'):
        config['AUTH_TYPE'] = os.getenv('AUTH_TYPE')
    else:
        config['AUTH_TYPE'] = SET_AUTH_TYPE

    if os.getenv('INSECURE_OAUTH'):
        config['INSECURE_OAUTH'] = os.getenv('INSECURE_OAUTH')
    else:
        config['INSECURE_OAUTH'] = SET_INSECURE_OAUTH

    if config['INSECURE_OAUTH']:
        os.environ['AUTHLIB_INSECURE_TRANSPORT'] = '1'

    if os.getenv('APP_EXT_URL'):
        config['APP_EXT_URL'] = os.getenv('APP_EXT_URL')
    else:
        config['APP_EXT_URL'] = SET_APP_EXT_URL

    if os.getenv('SMTP_HOST'):
        config['SMTP_HOST'] = os.getenv('SMTP_HOST')
    else:
        config['SMTP_HOST'] = SET_SMTP_HOST

    if os.getenv('SMTP_USER'):
        config['SMTP_USER'] = os.getenv('SMTP_USER')
    else:
        config['SMTP_USER'] = SET_SMTP_USER

    if os.getenv('SMTP_ADMIN_EMAIL'):
        config['SMTP_ADMIN_EMAIL'] = os.getenv('SMTP_ADMIN_EMAIL')
    else:
        config['SMTP_ADMIN_EMAIL'] = SET_SMTP_ADMIN_EMAIL

    if os.getenv('LDAP_HOST'):
        config['LDAP_HOST'] = os.getenv('LDAP_HOST')
    else:
        config['LDAP_HOST'] = SET_LDAP_HOST

    if os.getenv('LDAP_PORT'):
        config['LDAP_PORT'] = os.getenv('LDAP_PORT')
    else:
        config['LDAP_PORT'] = SET_LDAP_PORT

    if os.getenv('LDAP_BASE_DN'):
        config['LDAP_BASE_DN'] = os.getenv('LDAP_BASE_DN')
    else:
        config['LDAP_BASE_DN'] = SET_LDAP_BASE_DN

    if os.getenv('LDAP_USER_DN'):
        config['LDAP_USER_DN'] = os.getenv('LDAP_USER_DN')
    else:
        config['LDAP_USER_DN'] = SET_LDAP_USER_DN

    if os.getenv('LDAP_GROUP_DN'):
        config['LDAP_GROUP_DN'] = os.getenv('LDAP_GROUP_DN')
    else:
        config['LDAP_GROUP_DN'] = SET_LDAP_GROUP_DN

    if os.getenv('LDAP_USER_RDN_ATTR'):
        config['LDAP_USER_RDN_ATTR'] = os.getenv('LDAP_USER_RDN_ATTR')
    else:
        config['LDAP_USER_RDN_ATTR'] = SET_LDAP_USER_RDN_ATTR

    if os.getenv('LDAP_USER_LOGIN_ATTR'):
        config['LDAP_USER_LOGIN_ATTR'] = os.getenv('LDAP_USER_LOGIN_ATTR')
    else:
        config['LDAP_USER_LOGIN_ATTR'] = SET_LDAP_USER_LOGIN_ATTR

    if os.getenv('LDAP_BIND_USER_DN'):
        config['LDAP_BIND_USER_DN'] = os.getenv('LDAP_BIND_USER_DN')
    else:
        config['LDAP_BIND_USER_DN'] = SET_LDAP_BIND_USER_DN

    if os.getenv('LDAP_BIND_USER_PASSWORD'):
        config['LDAP_BIND_USER_PASSWORD'] = os.getenv('LDAP_BIND_USER_PASSWORD')
    else:
        config['LDAP_BIND_USER_PASSWORD'] = SET_LDAP_BIND_USER_PASSWORD

    ## CORE Config Variables ##
    if os.getenv('ENV'):
        config['ENV'] = os.getenv('ENV')
    else:
        config['ENV'] = SET_ENV

    if config['ENV'] == 'prod':
        if os.getenv('PROD_DB_URI_REF'):
            config['PROD_DB_URI'] = KeyVaultManager(config).get_secret(os.getenv('PROD_DB_URI_REF'))
        else:
            config['PROD_DB_URI'] = KeyVaultManager(config).get_secret(SET_PROD_DB_URI_REF)
    else:
        config['PROD_DB_URI'] = SET_PROD_DB_URI

    if config['AUTH_TYPE'] == 'azuread':
        if os.getenv('AZAD_CLIENT_ID'):
            config['AZAD_CLIENT_ID'] = os.getenv('AZAD_CLIENT_ID')
        else:
            config['AZAD_CLIENT_ID'] = SET_AZAD_CLIENT_ID
        if os.getenv('AZAD_CLIENT_SECRET'):
            config['AZAD_CLIENT_SECRET'] = KeyVaultManager(config).get_secret(os.getenv('AZAD_CLIENT_SECRET'))
        else:
            config['AZAD_CLIENT_SECRET'] = KeyVaultManager(config).get_secret(SET_AZAD_CLIENT_SECRET)
        if os.getenv('AZAD_AUTHORITY'):
            config['AZAD_AUTHORITY'] = os.getenv('AZAD_AUTHORITY')
        else:
            config['AZAD_AUTHORITY'] = SET_AZAD_AUTHORITY
    else:
        config['AZAD_CLIENT_ID'] = ""
        config['AZAD_CLIENT_SECRET'] = ""
        config['AZAD_AUTHORITY'] = ""

    ## Email Variables ##
    if config['ENV'] == 'prod':
        if os.getenv('SMTP_PW_REF'):
            config['SMTP_PASSWORD'] = KeyVaultManager(config).get_secret(os.getenv('SMTP_PW_REF'))
        else:
            config['SMTP_PASSWORD'] = KeyVaultManager(config).get_secret(SET_SMTP_PW_REF)
    else:
        config['SMTP_PASSWORD'] = SET_SMTP_PW

    ##
    ## GitHub to Jenkins Webhook ##
    if os.getenv('JENKINS_ENABLED'):
        config['JENKINS_ENABLED'] = os.getenv('JENKINS_ENABLED')
    else:
        config['JENKINS_ENABLED'] = SET_JENKINS_ENABLED
    if config['JENKINS_ENABLED'] == 'yes':
        if config['ENV'] == 'prod':
            if os.getenv('JENKINS_USER'):
                config['JENKINS_USER'] = KeyVaultManager(config).get_secret(os.getenv('JENKINS_USER'))
            else:
                config['JENKINS_USER'] = KeyVaultManager(config).get_secret(SET_JENKINS_USER_REF)
            if os.getenv('JENKINS_KEY'):
                config['JENKINS_KEY'] = KeyVaultManager(config).get_secret(os.getenv('JENKINS_KEY'))
            else:
                config['JENKINS_KEY'] = KeyVaultManager(config).get_secret(SET_JENKINS_KEY_REF)
            if os.getenv('JENKINS_TOKEN'):
                config['JENKINS_TOKEN'] = KeyVaultManager(config).get_secret(os.getenv('JENKINS_TOKEN'))
            else:
                config['JENKINS_TOKEN'] = KeyVaultManager(config).get_secret(SET_JENKINS_TOKEN_REF)
        else:
            config['JENKINS_USER'] = SET_JENKINS_USER
            config['JENKINS_KEY'] = SET_JENKINS_KEY
            config['JENKINS_TOKEN'] = SET_JENKINS_TOKEN

        if os.getenv('JENKINS_PROJECT'):
            config['JENKINS_PROJECT'] = os.getenv('JENKINS_PROJECT')
        else:
            config['JENKINS_PROJECT'] = SET_JENKINS_PROJECT

        if os.getenv('JENKINS_HOST'):
            config['JENKINS_HOST'] = os.getenv('JENKINS_HOST')
        else:
            config['JENKINS_HOST'] = SET_JENKINS_HOST

        if os.getenv('JENKINS_STAGING_PROJECT'):
            config['JENKINS_STAGING_PROJECT'] = os.getenv('JENKINS_STAGING_PROJECT')
        else:
            config['JENKINS_STAGING_PROJECT'] = SET_JENKINS_STAGING_PROJECT
    else:
        config['JENKINS_USER'] = ""
        config['JENKINS_KEY'] = ""
        config['JENKINS_TOKEN'] = ""
        config['JENKINS_PROJECT'] = ""
        config['JENKINS_HOST'] = ""
        config['JENKINS_STAGING_PROJECT'] = ""

    ## ServiceNOW Integration
    if os.getenv('SNOW_ENABLED'):
        config['SNOW_ENABLED'] = os.getenv('SNOW_ENABLED')
    else:
        config['SNOW_ENABLED'] = SET_SNOW_ENABLED
    if config['SNOW_ENABLED'] == 'yes':
        if config['ENV'] == 'prod':
            if os.getenv('SNOW_PASSWORD'):
                config['SNOW_PASSWORD'] = KeyVaultManager(config).get_secret(os.getenv('SNOW_PASSWORD'))
            else:
                config['SNOW_PASSWORD'] = KeyVaultManager(config).get_secret(SET_SNOW_PASSWORD_REF)
            if os.getenv('SNOW_CLIENT_SECRET'):
                config['SNOW_CLIENT_SECRET'] = KeyVaultManager(config).get_secret(os.getenv('SNOW_CLIENT_SECRET'))
            else:
                config['SNOW_CLIENT_SECRET'] = KeyVaultManager(config).get_secret(SET_SNOW_CLIENT_SECRET_REF)
            if os.getenv('SNOW_INSTANCE_NAME'):
                config['SNOW_INSTANCE_NAME'] = os.getenv('SNOW_INSTANCE_NAME')
            else:
                config['SNOW_INSTANCE_NAME'] = SET_SNOW_INSTANCE_NAME
            if os.getenv('SNOW_CLIENT_ID'):
                config['SNOW_CLIENT_ID'] = os.getenv('SNOW_CLIENT_ID')
            else:
                config['SNOW_CLIENT_ID'] = SET_SNOW_CLIENT_ID
            if os.getenv('SNOW_USERNAME'):
                config['SNOW_USERNAME'] = os.getenv('SNOW_USERNAME')
            else:
                config['SNOW_USERNAME'] = SET_SNOW_USERNAME
        else:
            config['SNOW_PASSWORD'] = SET_SNOW_PASSWORD
            config['SNOW_CLIENT_SECRET'] = SET_SNOW_CLIENT_SECRET
            config['SNOW_INSTANCE_NAME'] = SET_SNOW_INSTANCE_NAME
            config['SNOW_CLIENT_ID'] = SET_SNOW_CLIENT_ID
            config['SNOW_USERNAME'] = SET_SNOW_USERNAME
    else:
        config['SNOW_PASSWORD'] = ""
        config['SNOW_CLIENT_SECRET'] = ""
        config['SNOW_INSTANCE_NAME'] = ""
        config['SNOW_CLIENT_ID'] = ""
        config['SNOW_USERNAME'] = ""


class KeyVaultManager(object):
    def __init__(self, config=None):
        if os.getenv('AZURE_KEYVAULT_NAME'):
            key_vault_uri = f"https://{os.getenv('AZURE_KEYVAULT_NAME')}.vault.azure.net"
        else:
            key_vault_uri = f"https://{config['AZURE_KEYVAULT_NAME']}.vault.azure.net"
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


