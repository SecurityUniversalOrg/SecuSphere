# Production Deployments
[Back to User Guide](./README.md)

Production deployments can be complex and often require customization to the unique aspects of your environment.  If you require additional assistance, please contact Security Universal [support](mailto:admin@securityuniversal.com).

1. Setup Infrastructure
2. Setup Production Credentials
3. Deploy SecuSphere via Helm Charts

## 1. Setup Infrastructure

Requirements
* Azure Kubernetes Services Cluster
* Azure Managed MySQL Database
* SMTP Configuration Details

[Back to the Top](#production-deployments)

## 2. Setup Production Credentials
Currently, Azure is the supported cloud platform for production deployments.

Configure Azure Key Vault
1. In your Azure web console, either navigate to an existing or create a new Key Vault resource.  Be sure to make note of the Key Vault name.
2. Navigate to the Azure Key Vault and select the Secrets tab and then click on the `Generate/Import` tab.
![Diagram](./screenshots/azure_key_vault_menu.png)
3. First, provide a name for the secret and then add your MySQL Database URI string (ex: mysql+mysqlconnector://[db_user]:[db_password]@[db_host]:[db_port]/VulnRemediator).  Be sure to make note of the name of the secret. 
![Diagram](./screenshots/azure_key_vault_prod_db.png)
4. Next, create another secret for the SMTP Password used to send system alerts from SecuSphere.  Again, be sure to make note of the name of the secret.
![Diagram](./screenshots/azure_key_vault_smtp_pw.png)

[Back to the Top](#production-deployments)

## 3. Deploy SecuSphere via Helm Charts
1. From the source code root directory, navigate to the helm directory
```shell
$ cd ci_cd/helm 
```
2. Update the variables below and save them as environment variables in your current shell:
```shell
YOUR_DOMAIN="acme.com"   # Set the domain here.  Your hostname will be secusphere.YOUR_DOMAIN
TLS_SECRET_NAME = "tls-wildcard"   # Set the Kubernetes TLS Secret Name here
TLS_CERT_B64_ENCODED = "LS0tLS1CRUdJTiBDRV....."   # Add the Base64-encoded TLS Certificate
TLS_KEY_B64_ENCODED = "LS0tLS1CRUdJTiBSU0....."   # Add the Base64-encoded TLS Key
AZURE_KEYVAULT_NAME = "MyAzureKeyVaultName"    # Add the Azure Key Vault Name
AZURE_CLIENT_ID = "a21f3bab-0253-...."     # Add the Azure Client ID with necessary permissions to read/write to Azure Key Vault
AZURE_CLIENT_SECRET = "58af2bba...."     # Add the Azure Client Secret with necessary permissions to read/write to Azure Key Vault
AZURE_TENANT_ID = "71f0c7fe-8e01-...."     # Add the Azure Tenant ID with necessary permissions to read/write to Azure Key Vault
AZURE_KV_PROD_DB_URI_REF = "PROD-DB-URI"     # Add the Azure Key Vault Secret Name reference for the Database URI
AZURE_KV_SMTP_PW_REF = "SMTP-PW"     # Add the Azure Key Vault Secret Name reference for the SMTP Password
```

3. Deploy the Kubernetes Secrets Resources
```
helm upgrade su-secrets ./su-secrets -n secusphere -i --values ./su-secrets/values.yaml --create-namespace \
    --set azClientId=$AZURE_CLIENT_ID --set azClientSecret=$AZURE_CLIENT_SECRET --set azTenantId=$AZURE_TENANT_ID \
    --set tls.name=$TLS_SECRET_NAME --set tls.crt=$TLS_CERT_B64_ENCODED --set tls.key=$TLS_KEY_B64_ENCODED
```

4. Deploy the Kubernetes Ingress Resources
```
helm upgrade nginx-ingress ./su-ingress/ingress-nginx -n secusphere -i --values /su-ingress/ingress-nginx/values.yaml
```

5. Deploy the SecuSphere Application
```
helm upgrade secusphere ./secusphere -n secusphere -i --values ./secusphere/values.yaml \
    --set tlsSecretName=$TLS_SECRET_NAME --set appDomain=$YOUR_DOMAIN --set azKeyVaultName=$AZURE_KEYVAULT_NAME \
    --set azKeyVaultDbUriRefName=AZURE_KV_PROD_DB_URI_REF --set azKeyVaultSmtpPasswordRefName=AZURE_KV_SMTP_PW_REF
```

6. If the deployment was successful, you should be able to reach the web console at https://[your-instance-url]


[Back to the Top](#production-deployments)