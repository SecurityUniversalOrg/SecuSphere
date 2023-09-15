# Jenkins Shared Library Documentation - Docker Container Scanning
## Overview

This document outlines the shared library functions made available for Docker Container Scanning, designed to provide a standardized way to scan Docker containers and ensure their security.
## Table of Contents

1. Shared Library Overview
2. Using the Library in Jenkinsfiles
3. Available Functions
   * Docker Container Scanning Function
4. Examples
5. Support and Feedback

## Shared Library Overview

Shared Libraries in Jenkins are used to maintain reusable pieces of Pipeline code that can be referenced from multiple pipelines.

This shared library function was crafted to enable development and security teams to scan Docker containers in their pipelines. This helps to maintain a robust security posture for containerized applications.

## Using the Library in Jenkinsfiles

To use the Docker Container Scanning shared library in your Jenkinsfile, you'll need to import it at the top of your Jenkinsfile:

```groovy
@Library('security-library') _
```

Replace security-library with the name used for the shared library in your Jenkins setup.

## Available Functions
Docker Container Scanning Function

### Description:

This function scans Docker containers to ensure their security by leveraging the grype tool for vulnerability scanning. The results are then archived and dispatched to SecuSphere for further analysis.

### Parameters:

* `servicename`: (Optional) The name of the service. Defaults to the app name in lowercase.
* `dockerTag`: (Optional) Tag of the Docker image. Defaults to sectesting.
* `dockerReg`: (Optional) Docker registry URL. If provided, it is prefixed with the image name.
* `appName`: (Optional) Application name. If not provided, attempts to retrieve from Jenkins environment variables.
* `setEnv`: (Optional) Set the environment. Defaults to 'ci/cd'.

### Returns:

This function doesn't return values but will generate an Anchore report for the scanned Docker image.

### Example:
```groovy
steps {
    script {
        jslContainerSecurityScanning('myServiceName', 'latest', 'my.docker-registry.com', 'myAppName', 'production')
    }
}
```

## Examples
Using Docker Container Scanning Function with Jenkinsfile

Here's a practical example of how to integrate the Docker Container Scanning function into a Jenkins pipeline:
```groovy
@Library('security-library') _

pipeline {
    agent any

    stages {
        stage('Docker Scan') {
            steps {
                script {
                    jslContainerSecurityScanning('myServiceName', 'latest', 'my.docker-registry.com', 'myAppName', 'production')
                }
            }
        }
    }
}
```

In the above Jenkinsfile, the Docker image with the tag `latest` under the service name `myServiceName` from the registry `my.docker-registry.com` is scanned. The results will be archived and sent to SecuSphere for the application named `myAppName`.

## Support and Feedback

For support and feedback regarding the Docker Container Scanning shared library function, please contact:

* Primary Contact: [Name], [Email]
* Backup Contact: [Name], [Email]
* Slack Channel: #docker-scan-lib
* Documentation Last Updated: [Date]

With this documentation, Development teams should have a comprehensive understanding of how to utilize the Docker Container Scanning function within their Jenkinsfiles.

