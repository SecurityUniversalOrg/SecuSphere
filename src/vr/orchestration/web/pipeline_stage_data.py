

OPTS = [
        {
            "platform": "Jenkins",
            "stage": "Secret Scanning",
            "vendor": "Trufflehog",
            "stage_data": """stage('Secret Scanning') {
    when {
         expression {
            env.BRANCH_NAME ==~ /^release\/.*\/.*/
         }
    }
    steps {
        jslSecSecretScanning()
    }
}""",
            "env_data": "@Library('security-pipeline-library')_",
            "pre_reqs": """To add Trufflehog Secret Scanning services to a Jenkins Declarative CI/CD pipeline, follow these steps:

1. **Install Trufflehog**: Trufflehog is a Python-based tool, so it can be installed with pip. Install Trufflehog on your Jenkins build agent by running `pip install truffleHog` or follow the instructions in the [official documentation](https://github.com/dxa4481/truffleHog).

2. **Configure Trufflehog**: There's no need for API keys with Trufflehog, but you may need to configure certain aspects of it, like the entropy checks, depending on the requirements of your project.

3. **Create a Jenkinsfile**: Create a Jenkinsfile in your project's root directory if you don't have one already. This file will define your declarative pipeline.

4. **Define stages**: Define the stages and steps for your pipeline in the Jenkinsfile. Incorporate the Trufflehog Secret Scanning.
"""
        },
        {
            "platform": "Jenkins",
            "stage": "SCA",
            "vendor": "Snyk",
            "stage_data": """stage('Software Composition Analysis') {
    when {
         expression {
            env.BRANCH_NAME ==~ /^release\/.*\/.*/
         }
    }
    steps {
        jslSecSoftwareCompositionAnalysis({{languages}})
    }
}""",
            "env_data": """@Library('security-pipeline-library')_

environment {
    ...
    SNYK_API_KEY = credentials('snyk-api-key')
}
""",
            "pre_reqs": """To add Snyk Software Composition Analysis (SCA) services to a Jenkins Declarative CI/CD pipeline, follow these steps:

1. **Install Snyk CLI**: Install the Snyk CLI on your Jenkins build agent by following the instructions in the [official documentation](https://support.snyk.io/hc/en-us/articles/360003812458-Install-the-Snyk-CLI).

2. **Acquire API key**: Sign up for a Snyk account and obtain an API key for authentication from the [Snyk dashboard](https://app.snyk.io/).

3. **Store API key securely**: Store the API key securely as a Jenkins credential. This will allow you to use the key in your pipeline without exposing it in your code.

4. **Create a Jenkinsfile**: Create a Jenkinsfile in your project's root directory if you don't have one already. This file will define your declarative pipeline.

5. **Define stages**: Define the stages and steps for your pipeline in the Jenkinsfile. Incorporate the Snyk SCA.
"""
        },
        {
            "platform": "Jenkins",
            "stage": "SAST",
            "vendor": "SonarQube",
            "stage_data": """stage('Static Application Security Testing') {
    when {
         expression {
            env.BRANCH_NAME ==~ /^release\/.*\/.*/
         }
    }
    steps {
        jslStaticApplicationSecurityTesting({{languages}})
    }
}""",
            "env_data": """@Library('security-pipeline-library')_

environment {
    ...
    SONARQUBE_SERVER_URL = 'https://your-sonarqube-server-url'
    SONARQUBE_AUTH_TOKEN = credentials('sonarqube-auth-token')
}
""",
            "pre_reqs": """To integrate SonarQube SAST into a Jenkins declarative CI/CD pipeline and generate an output JSON file with the most recent scan results, follow these steps:

1. **Install SonarQube Scanner for Jenkins**: In your Jenkins instance, go to "Manage Jenkins" > "Manage Plugins" > "Available" tab, then search for and install the "SonarQube Scanner" plugin. Restart Jenkins if needed.

2. **Configure SonarQube Scanner**: In Jenkins, go to "Manage Jenkins" > "Global Tool Configuration" > "SonarQube Scanner", and add a new SonarQube Scanner installation. Provide a name and the version of the scanner you want to use.

3. **Configure SonarQube server**: In Jenkins, go to "Manage Jenkins" > "Configure System" > "SonarQube servers", and add your SonarQube server information, including the server URL and authentication token.

4. **Create a Jenkinsfile**: If you don't have one already, create a Jenkinsfile in your project's root directory. This file will define your declarative pipeline.

5. **Define stages**: Define the stages and steps for your pipeline in the Jenkinsfile. Incorporate the SonarQube scan stage.
"""
        },
        {
            "platform": "Jenkins",
            "stage": "IaC Security Scanning",
            "vendor": "Terrascan",
            "stage_data": """stage('Infrastructure-as-Code Security Testing') {
    when {
         expression {
            env.BRANCH_NAME ==~ /^release\/.*\/.*/
         }
    }
    steps {
        jslInfrastructureAsCodeAnalysis()
    }
}""",
            "env_data": "@Library('security-pipeline-library')_",
            "pre_reqs": """"""
        },
        {
            "platform": "Jenkins",
            "stage": "Container Security Scanning",
            "vendor": "Anchore",
            "stage_data": """stage('Docker Container Scanning') {
    when {
         expression {
            env.BRANCH_NAME ==~ /^release\/.*\/.*/
         }
    }
    steps {
        jslContainerSecurityScanning(env.K8_NAMESPACE)
    }
}""",
            "env_data": """@Library('security-pipeline-library')_

environment {
    ...
    ANCHORE_URL = "${globalVars.ANCHORE_URL}"
    K8_NAMESPACE = "replace-this"
}""",
            "pre_reqs": """"""
        },
        {
            "platform": "Jenkins",
            "stage": "Infrastructure Security Scanning",
            "vendor": "",
            "stage_data": """""",
            "env_data": "",
            "pre_reqs": """"""
        },
        {
            "platform": "Jenkins",
            "stage": "Dynamic Application Security Testing (DAST)",
            "vendor": "OWASP-ZAP",
            "stage_data": """stage('Test Release') {
    when {
         expression {
            env.BRANCH_NAME ==~ /^release\/.*\/.*/
         }
    }
    steps {
        jslDynamicApplicationSecurityTesting("http://192.168.0.150:5080")
    }
    post {
         always {
             jslTestReleasePost()
         }
    }
}""",
            "env_data": "",
            "pre_reqs": """"""
        },
        {
            "platform": "Jenkins",
            "stage": "Dynamic API Security Testing (DAST-API)",
            "vendor": "OWASP-ZAP",
            "stage_data": """stage('Test Release') {
    when {
         expression {
            env.BRANCH_NAME ==~ /^release\/.*\/.*/
         }
    }
    steps {
        jslDynamicApiSecurityTesting("http://192.168.0.150:5080")
    }
    post {
         always {
             jslTestReleasePost()
         }
    }
}""",
            "env_data": """@Library('security-pipeline-library')_

environment {
    ...
    API_DEFINITION_FILE = "src/vr/templates/openapi.yaml"
}""",
            "pre_reqs": """"""
        },
        {
            "platform": "Jenkins",
            "stage": "Security Quality Gate",
            "vendor": "SecurityUniversal",
            "stage_data": """stage("Quality Gate - Security") {
    when {
         expression {
            env.BRANCH_NAME ==~ /^release\/.*\/.*/
         }
    }
    steps {
        jslSecurityQualityGate()
    }
}""",
            "env_data": "",
            "pre_reqs": """"""
        },
        {
            "platform": "GitHub Actions",
            "stage": "Secret Scanning",
            "vendor": "",
            "stage_data": """""",
            "env_data": "",
            "pre_reqs": """"""
        },
        {
            "platform": "GitHub Actions",
            "stage": "SCA",
            "vendor": "",
            "stage_data": """""",
            "env_data": "",
            "pre_reqs": """"""
        },
        {
            "platform": "GitHub Actions",
            "stage": "SAST",
            "vendor": "",
            "stage_data": """""",
            "env_data": "",
            "pre_reqs": """"""
        },
        {
            "platform": "GitHub Actions",
            "stage": "IaC Security Scanning",
            "vendor": "",
            "stage_data": """""",
            "env_data": "",
            "pre_reqs": """"""
        },
        {
            "platform": "GitHub Actions",
            "stage": "Container Security Scanning",
            "vendor": "",
            "stage_data": """""",
            "env_data": "",
            "pre_reqs": """"""
        },
        {
            "platform": "GitHub Actions",
            "stage": "Infrastructure Security Scanning",
            "vendor": "",
            "stage_data": """""",
            "env_data": "",
            "pre_reqs": """"""
        },
        {
            "platform": "GitHub Actions",
            "stage": "Dynamic Application Security Testing (DAST)",
            "vendor": "",
            "stage_data": """""",
            "env_data": "",
            "pre_reqs": """"""
        },
        {
            "platform": "GitHub Actions",
            "stage": "Dynamic API Security Testing (DAST-API)",
            "vendor": "",
            "stage_data": """""",
            "env_data": "",
            "pre_reqs": """"""
        },
        {
            "platform": "Azure DevOps",
            "stage": "Secret Scanning",
            "vendor": "",
            "stage_data": """""",
            "env_data": "",
            "pre_reqs": """"""
        },
        {
            "platform": "Azure DevOps",
            "stage": "SCA",
            "vendor": "",
            "stage_data": """""",
            "env_data": "",
            "pre_reqs": """"""
        },
        {
            "platform": "Azure DevOps",
            "stage": "SAST",
            "vendor": "",
            "stage_data": """""",
            "env_data": "",
            "pre_reqs": """"""
        },
        {
            "platform": "Azure DevOps",
            "stage": "IaC Security Scanning",
            "vendor": "",
            "stage_data": """""",
            "env_data": "",
            "pre_reqs": """"""
        },
        {
            "platform": "Azure DevOps",
            "stage": "Container Security Scanning",
            "vendor": "",
            "stage_data": """""",
            "env_data": "",
            "pre_reqs": """"""
        },
        {
            "platform": "Azure DevOps",
            "stage": "Infrastructure Security Scanning",
            "vendor": "",
            "stage_data": """""",
            "env_data": "",
            "pre_reqs": """"""
        },
        {
            "platform": "Azure DevOps",
            "stage": "Dynamic Application Security Testing (DAST)",
            "vendor": "",
            "stage_data": """""",
            "env_data": "",
            "pre_reqs": """"""
        },
        {
            "platform": "Azure DevOps",
            "stage": "Dynamic API Security Testing (DAST-API)",
            "vendor": "",
            "stage_data": """""",
            "env_data": "",
            "pre_reqs": """"""
        },

]