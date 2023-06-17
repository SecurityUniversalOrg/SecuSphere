@Library('security-pipeline-library')_

pipeline {

    options {
        // Build auto timeout
        timeout(time: 600, unit: 'MINUTES')
    }

    // Some global default variables
    environment {
//        GIT_BRANCH = "${globalVars.GIT_BRANCH}"
        EMAIL_FROM = "${globalVars.EMAIL_FROM}"
        SUPPORT_EMAIL = "${globalVars.SUPPORT_EMAIL}"
        RELEASE_NUMBER = "${globalVars.RELEASE_NUMBER}"
        DOCKER_REG = "${globalVars.DOCKER_REG}"
        DOCKER_TAG = "${globalVars.DOCKER_TAG}"
        IMG_PULL_SECRET = "${globalVars.IMG_PULL_SECRET}"
        GIT_CREDS_ID = "${globalVars.GIT_CREDS_ID}"
        ANCHORE_URL = "${globalVars.ANCHORE_URL}"
        VULNMANAGER_URL = "${globalVars.VULNMANAGER_URL}"
        SONARQUBE_SERVER_URL = "${globalVars.SONARQUBE_SERVER_URL}"
        SONARQUBE_SCANNER_HOME = "${globalVars.SONARQUBE_SCANNER_HOME}"
        SONARQUBE_AUTH_TOKEN = credentials('SonarQube Global Analysis')
        SNYK_API_KEY = credentials('snyk-api-key')
        // App-specific settings
        appName = "SUVULNMGMR"
        K8_ENV = "su_pubweb"
        K8_NAMESPACE = "su-vulnmgr"
        SOURCE_DIR = "src"
        API_DEFINITION_FILE = "src/vr/templates/openapi.yaml"
        KUBECONFIG = "${WORKSPACE}/kubeconfig"
    }


    // In this example, all is built and run from the master
    agent any



    // Pipeline stages
    stages {

        stage('Prep Job') {
            when {
                expression {
                    env.BRANCH_NAME ==~ /^release\/.*\/.*/
                }
            }
            steps {
                script {
                    jslCountLinesOfCode()
                }
            }
        }

        stage('Unit Testing') {
            when {
                 expression {
                    env.BRANCH_NAME ==~ /^release\/.*\/.*/
                 }
            }
            steps {
                echo "Placeholder for Unit Testing"
            }
        }

        stage('Secret Scanning') {
            when {
                 expression {
                    env.BRANCH_NAME ==~ /^release\/.*\/.*/
                 }
            }
            steps {
                jslSecretScanning()
            }
        }

        stage('Software Composition Analysis') {
            when {
                 expression {
                    env.BRANCH_NAME ==~ /^release\/.*\/.*/
                 }
            }
            steps {
                jslPythonSoftwareCompositionAnalysis()
            }
        }

        stage('Static Application Security Testing') {
            when {
                 expression {
                    env.BRANCH_NAME ==~ /^release\/.*\/.*/
                 }
            }
            steps {
                jslStaticApplicationSecurityTesting()
            }
        }

        stage('Infrastructure-as-Code Security Testing') {
            when {
                 expression {
                    env.BRANCH_NAME ==~ /^release\/.*\/.*/
                 }
            }
            steps {
                jslInfrastructureAsCodeAnalysis()
            }
        }

        ////////// Build //////////
        stage('Build Docker Service') {
            when {
                expression {
                    env.BRANCH_NAME ==~ /^release\/.*\/.*/
                }
            }
            steps {
                jslBuildDocker(env.K8_NAMESPACE)
            }
        }

        stage('Docker Container Scanning') {
            when {
                 expression {
                    env.BRANCH_NAME ==~ /^release\/.*\/.*/
                 }
            }
            steps {
                jslContainerSecurityScanning(env.K8_NAMESPACE)
            }
        }

        ////////// Release //////////
        stage('Release to Test') {
            when {
                 expression {
                    env.BRANCH_NAME ==~ /^release\/.*\/.*/
                 }
            }
            steps {
                jslSetupTestDB("mysqldb")
                jslVerifyTcpServiceReady('127.0.0.1', 3306)
                jslRunDockerCompose("web")
            }
        }

        stage('Test Release') {
            when {
                 expression {
                    env.BRANCH_NAME ==~ /^release\/.*\/.*/
                 }
            }
            steps {
                jslDynamicApplicationSecurityTesting("http://192.168.0.150:5080")
                jslDynamicApiSecurityTesting("http://192.168.0.150:5080")
            }
            post {
                 always {
                     jslTestReleasePost()
                 }
            }
        }

        ////////// Quality Gate //////////
        stage("Quality Gate - Security") {
            when {
                 expression {
                    env.BRANCH_NAME ==~ /^release\/.*\/.*/
                 }
            }
            steps {
                jslSecurityQualityGate()
            }
        }

        ////////// Deploy to Production //////////
        stage('Deploy') {
            when {
                branch 'release/*/PROD'
            }
            steps {
                jslDeployToProdWithSecrets()
            }
        }

    }
}