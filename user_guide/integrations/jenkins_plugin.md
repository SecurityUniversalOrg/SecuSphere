# SecuSphere Jenkins plugin

## Table of Contents

* [SecuSphere Jenkins Plugin](#secusphere-jenkins-plugin)
    * [Features](#features)
    * [Integrations](#integrations)
    * [Usage - SecuSphereSecureDispatch](#usage---secuspheresecuredispatch)
    * [Sample Pipeline Script - SecuSphereSecureDispatch](#sample-pipeline-script---secuspheresecuredispatch)
    * [Usage - enforceSecurityQualityGate](#usage---enforcesecurityqualitygate)
    * [Sample Pipeline Script - enforceSecurityQualityGate](#sample-pipeline-script---enforcesecurityqualitygate)
    * [Installing the Plugin](#installing-the-plugin)
    * [Configuration](#configuration)
      * [SecuSphere Global Configuration](#secusphere-global-configuration)
      * [Security Gate Thresholds](#security-gate-thresholds)
      * [Archiving Assessment Reports](#archiving-assessment-reports)
      * [GitHub DevSecOps Maturity Reporting](#github-devsecops-maturity-reporting)
    * [SecuSphere Results](#secusphere-results)
      * [Viewing SecuSphere Results](#viewing-secusphere-results)
      * [Interpreting SecuSphere Results](#interpreting-secusphere-results)
    * [Optional Features](#optional-features)
      * [Azure Blob Storage Integration](#azure-blob-storage-integration)
      * [Scorecard Reporting](#scorecard-reporting)
    * [License](#license)

## SecuSphere Jenkins plugin

The SecuSphere Jenkins plugin is a security analysis plugin that provides an automated way to aggregate security assessment reports. The plugin integrates with SecuSphere and sends the findings to the SecuSphere API for further analysis.

[Source Code](https://github.com/SecurityUniversalOrg/SecuSphere-JenkinsPlugin)

## Features


* Parses and sends assessment reports from various CI/CD Pipeline tools to the SecuSphere API
* Archives original assessment reports in Azure Blob storage (optional)
* Adds assessment summary report DevOps scorecard reporting (optional)
* Implements a security quality gate to enforce thresholds on critical and high findings (optional)

## Integrations
To view a complete list of DevSecOps Tool integrations, click [here](resources/user_guide/integrations/index.md)

## Usage - SecuSphereSecureDispatch
The `SecuSphereSecureDispatch` plugin parses, normalizes, and summarizes security assessment reports from various CI/CD Pipeline tools and submits the report data to the SecuSphere API.

During each stage, the summarized report (findings per severity level) is written to the `threatbuster_results.json` file.

To use this plugin, add a `SecuSphereSecureDispatch` step to your Jenkins pipeline script.

## Sample Pipeline Script - SecuSphereSecureDispatch
```groovy
pipeline {
    agent any

    stages {
        stage('Report Vulnerabilities to SecuSphere') {
            steps {
                script {
                    SecuSphereSecureDispatch(
                        reportType: '...',
                        appName: '...',
                        giturl: '...',
                        gitBranch: '...'
                    )
                }
            }
        }
    }
}
```
### Parameters

* `reportType`: The type of the assessment report.
* `appName`: The unique acronym for the application.
* `giturl`: The URL of the Git repository.
* `gitBranch`: The name of the Git branch.

## Usage - enforceSecurityQualityGate
The `enforceSecurityQualityGate` plugin enforces a Security Quality Gate that evaluates the total findings per severity for the following CI/CD Pipeline stages:
* Secret Scanning
* Software Composition Analysis (SCA)
* Static Application Security Testing (SAST)
* Infrastructure-as-Code (IaC) Security Testing
* Container Security Testing
* Infrastructure Security Testing
* Dynamic Application Security Testing (DAST)

This function will evaluate a user provided thresholds json file and compare each previously conducted security assessment against those thresholds.  If the reported value exceeds the established threshold, the build will be marked as 'Failed' and the Jenkins job will not proceed to subsequent pipeline stages.  Users can disable a specific assessment severity level to remove that criteria from the evaluation process. 

Both the user provided thresholds and report data are submitted to the SecuSphere API.

To use this plugin, add a `enforceSecurityQualityGate` step to your Jenkins pipeline script.

## Sample Pipeline Script - enforceSecurityQualityGate
```groovy
pipeline {
    agent any

    stages {
        stage('SecurityQualityGate') {
            steps {
                script {
                    enforceSecurityQualityGate(
                        configFile: '...',
                        resultsFile: '...',
                        appName: '...',
                        gitUrl: '...',
                        gitBranch: '...',
                    )
                }
            }
        }
    }
}
```
### Parameters

* `configFile`: The path to the thresholds configuration file.  Recommended location: `ci_cd/secusphere-thresholds.json`
* `resultsFile`: The path to the report file that each security stage writes to and that is used during the Gate evaluation.  **Required location: `threatbuster_results.json`**
* `appName`: The unique acronym for the application.
* `giturl`: The URL of the Git repository.
* `gitBranch`: The name of the Git branch.

### secusphere-thresholds.json
Below is the secusphere-thresholds.json file with the following default settings:
```json
{ 
  "thresholds": {
    "secrets": {"low": null, "medium": null, "high": 5, "critical": 1},
    "sca": {"low": null, "medium": null, "high": 5, "critical": 1},
    "sast": {"low": null, "medium": null, "high": 5, "critical": 1},
    "iac": {"low": null, "medium": null, "high": 5, "critical": 1},
    "container": {"low": null, "medium": null, "high": 5, "critical": 1},
    "infrastructure": {"low": null, "medium": null, "high": 5, "critical": 1},
    "dast": {"low": null, "medium": null, "high": 5, "critical": 1},
    "dastapi": {"low": null, "medium": null, "high": 5, "critical": 1}
  }
}
```
>[Download](resources/secusphere-thresholds.json?raw=true) the secusphere-thresholds.json file

>To disable a specific finding category, use the `null` value.   

>By default, the low and medium categories are disabled for all assessment types.


## Installing the Plugin

This section will guide you through the process of installing this Jenkins plugin. Plugins are essential components that extend the functionality of Jenkins, making it more versatile and adaptable to various use cases.
### Prerequisites

1. Ensure you have administrative access to your Jenkins instance.
2. Verify that your Jenkins instance is running and accessible via a web browser.

### Step-by-Step Guide
#### Step 1: Access the Plugin Manager

1. Open your web browser and navigate to your Jenkins instance. Typically, it is accessible at http://<Jenkins-URL>:<port-number>.
2. Log in to your Jenkins account with administrative access.
3. Click on Manage Jenkins in the left sidebar.
4. On the Manage Jenkins page, click on Manage Plugins.

#### Step 2: Install the Desired Plugin

1. In the Plugin Manager interface, click on the Available tab. This tab displays a list of available plugins that can be installed on your Jenkins instance.

2. Use the search bar at the top right of the page to search for the plugin you wish to install. You can search using the plugin name, description, or related keywords.

3. Once you've located the desired plugin, check the box to the left of the plugin name.

4. (Optional) If the plugin has any dependencies, Jenkins will automatically select them for installation. Review the list of dependencies, and deselect any that you do not want to install.

5. Click the Install without restart button at the bottom of the page. Jenkins will download and install the plugin and its dependencies.

6. Alternatively, you can choose the Download now and install after restart option if you prefer to install the plugin after a Jenkins restart.

#### Step 3: Verify the Installation

1. After the installation is complete, click on the Installed tab in the Plugin Manager.
2. Search for the plugin using the search bar at the top right of the page.
3. Verify that the plugin is listed and its status is displayed as "Enabled."

>Plugin Installation Complete


## Configuration

Global configuration settings for the SecuSphere Jenkins plugin are accessible from the Jenkins global configuration page. These settings include:

* SecuSphere API Base URL
* SecuSphere API credentials (client ID and secret)
* Enable report archiving in Azure Blob storage (optional)
* Azure Blob storage settings (optional)
* Enable scorecard reporting (optional)
* Scorecard Parquet file settings (optional)

### Overview

#### SecuSphere Global Configuration

This section will guide end-users on how to configure the SecuSphere plugin's global settings.

1. **Base URL**: Enter the base URL of your SecuSphere server (e.g., https://secusphere.yourorg.com).
2. **Credentials ID**: Input the Jenkins Credentials ID for the RiskBuster OAuth2 Credentials.

#### Security Gate Thresholds

Enable or disable the enforcement of security gates and configure the thresholds for various security findings.

1. **Enforce Security Gates**: Check the box to enable security gate enforcement.
2. Set the limits for different categories of security findings, such as:
   * **Secret Scanning Findings**
   * **Software Composition Analysis (SCA) Findings**
   * **Static Application Security Testing (SAST) Findings**
   * **Infrastructure as Code (IAC) Findings**
   * **Container Scanning Findings**
   * **Dynamic Application Security Testing (DAST) Findings**
   * **Infrastructure Security Findings**
   * **Policy Violation Findings**

For each category, specify the allowed number of Critical, High, Medium, and Low findings.

#### Archiving Assessment Reports

Enable or disable the storage of archived assessment reports and configure the Azure Blob Storage settings.

1. **Enable Archived Report Storage**: Check the box to enable archival storage of security assessment reports.
2. **Azure Blob Storage Account Name**: Input the Azure Blob Storage account name to be used for archival storage.
3. **Azure Blob Storage Jenkins Credential ID**: Provide the Jenkins Credentials ID for the Azure Blob Storage credentials.

#### GitHub DevSecOps Maturity Reporting

Enable or disable GitHub DevSecOps Maturity Reporting and configure the GitHub repository and credentials.

1. **Enable GitHub DevSecOps Maturity Reporting**: Check the box to enable DevSecOps maturity reporting.
2. **GitHub Repo URL**: Enter the GitHub repository URL for the DevSecOps Scorecard Maturity Report. 
3. **CSV File Path**: Input the CSV file path for the DevSecOps Scorecard Maturity Report.
4. **GitHub Jenkins Credential ID**: Provide the Jenkins Credentials ID for the GitHub credentials.

Save the configuration after completing the settings. The SecuSphere plugin is now ready to use.

### SecuSphere Results

This section describes how to view and interpret the SecuSphere Results displayed in the Jenkins UI. The SecuSphere plugin provides a summary of the security findings discovered during the analysis.

#### Viewing SecuSphere Results

To view the SecuSphere Results:

1. Navigate to the Jenkins job where the SecuSphere plugin is configured.
2. Click on the build number in which the SecuSphere analysis was executed.
3. Locate the "SecuSphere Results" section in the build summary.
![View Results](resources/screenshots/Results All Stages.png)

#### Interpreting SecuSphere Results

The SecuSphere Results section displays the number of security findings identified during the analysis, categorized by their severity levels:

* **Critical Security Findings**: These findings represent the most severe security issues that require immediate attention and remediation. Critical findings may indicate the presence of vulnerabilities that could be exploited by an attacker to gain unauthorized access, execute arbitrary code, or perform other malicious activities.
 
* **High Security Findings**: High findings are significant security issues that need to be addressed as soon as possible. They may not be as severe as critical findings, but they still pose a considerable risk to the security of your application or infrastructure.
 
* **Medium Security Findings**: Medium findings are moderate security issues that should be reviewed and addressed based on your organization's risk tolerance and security policies. These findings may not pose an immediate threat, but they can still have a negative impact on your security posture if left unaddressed.
 
* **Low Security Findings**: Low findings are minor security issues that, while not posing a significant risk, should still be considered for remediation. Addressing low findings can help improve the overall security and maintainability of your application or infrastructure.

It is essential to address security findings based on their severity and your organization's security policies to maintain a secure and robust application or infrastructure.


## Optional Features

### Azure Blob Storage Integration
The SecuSphere Jenkins plugin includes an optional integration with Azure Blob storage, allowing you to archive the original assessment reports. The integration uses the Azure SDK for Java to interact with Azure Blob storage.

#### AzureBlobUploader Class

The `AzureBlobUploader` class is responsible for uploading files to Azure Blob storage. It provides a simple interface to authenticate and interact with the storage service.

#### Usage

To use the Azure Blob storage integration, you must provide the following settings in the Jenkins global configuration page:

* Azure Blob storage account name
* Azure Blob storage account key
* Azure Blob storage container name

The `uploadFile()` method of the `AzureBlobUploader` class takes the following parameters:

* `filePath`: The local path to the file to be uploaded.
* `fileName`: The name of the file to be uploaded.
* `contentType`: The content type of the file (e.g., "text/plain").
* `category`: The category of the assessment report (e.g., "static", "dynamic", etc.).
* `appName`: The unique acronym for the application.

Upon successful file upload, the file will be stored in the specified Azure Blob storage container with a timestamp appended to the file name.

### Scorecard Reporting
The `SummaryReportHandler` class is responsible for processing summary reports and saving them in a CSV file hosted on a remote Git repository.

#### Dependencies

The class relies on the following external libraries:

* Eclipse JGit library for Git operations
* JSON library for JSON object manipulation

#### Usage

To use the `SummaryReportHandler` class, create a new instance by providing a `JSONObject` containing the summary report information. Then, call the `submitToCsvFile()` method with the following parameters:

* `gitRepoUrl`: The remote Git repository URL.
* `csvFilePath`: The relative path to the CSV file within the repository.
* `gitUsername`: The Git username for authentication.
* `gitPassword`: The Git password for authentication.
* `listener`: A TaskListener instance for logging purposes.
* `appName`: The unique acronym for the application.

The `submitToCsvFile()` method performs the following steps:

* Clones the remote Git repository to a local directory using JGit.
* Appends the summary report JSON object as a new row in the specified CSV file. If the CSV file does not exist, it will be created with a header.
* Pushes the changes back to the remote Git repository using JGit.

This class provides a convenient way to store summary report data in a CSV file, which can be used for further analysis and reporting purposes.

## License

The SecuSphere Jenkins plugin is released under the GNU General Public License v3.0.