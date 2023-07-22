@Library('security-pipeline-library')_

def parseJson(String jsonText) {
    def lazyMap = new groovy.json.JsonSlurper().parseText(jsonText)
    return convertToSerializableMap(lazyMap)
}

def convertToSerializableMap(def lazyMap) {
    def serializableMap = [:]
    lazyMap.each { key, value ->
        serializableMap[key] = (value instanceof Map) ? convertToSerializableMap(value) : value
    }
    return serializableMap
}

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
        DOCKER_TAG = "0.1.0-beta"
        IMG_PULL_SECRET = "${globalVars.IMG_PULL_SECRET}"
        GIT_CREDS_ID = "${globalVars.GIT_CREDS_ID}"
        ANCHORE_URL = "${globalVars.ANCHORE_URL}"
        VULNMANAGER_URL = "${globalVars.VULNMANAGER_URL}"
        SONARQUBE_SERVER_URL = "${globalVars.SONARQUBE_SERVER_URL}"
        SONARQUBE_SCANNER_HOME = "${globalVars.SONARQUBE_SCANNER_HOME}"
        SONARQUBE_AUTH_TOKEN = credentials('SonarQube Global Analysis')
        SNYK_API_KEY = credentials('snyk-api-key')
        // App-specific settings
        appName = "SECUSPHERE"
        K8_ENV = "su_pubweb"
        K8_NAMESPACE = "secusphere"
        SOURCE_DIR = "src"
        API_DEFINITION_FILE = "src/vr/templates/openapi.yaml"
        KUBECONFIG = "${WORKSPACE}/kubeconfig"
        TEST_ENV_HOSTNAME = "192.168.0.68"
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
                jslPythonUnitTesting()
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
                jslSoftwareCompositionAnalysis('Python')
            }
        }

        stage('Static Application Security Testing') {
            when {
                 expression {
                    env.BRANCH_NAME ==~ /^release\/.*\/.*/
                 }
            }
            steps {
                jslStaticApplicationSecurityTesting('Python')
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
                jslContainerSecurityScanning(env.K8_NAMESPACE, 'latest', 'securityuniversal')
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
                jslRunDockerCompose("secusphere")
            }
        }

        stage('Test Release') {
            when {
                 expression {
                    env.BRANCH_NAME ==~ /^release\/.*\/.*/
                 }
            }
            steps {
                script {
                    jslDynamicApplicationSecurityTesting("http://${env.TEST_ENV_HOSTNAME}:5010")
                    jslDynamicApiSecurityTesting("http://${env.TEST_ENV_HOSTNAME}:5010/openapi.yaml")
                }
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




        stage('Send report') {
            steps {
                script {
                    // Read the JSON report
                    def jsonReport = readFile(file: "threatbuster_results.json")

                    // Parse the JSON content using Groovy's JSONSlurper
                    def jsonContent = parseJson(jsonReport)

                    // Generate a simple HTML summary from the JSON report
                    def htmlSummary = """
                    <h1>Report Summary</h1>
                    <p>${jsonContent.summary}</p>
                    """

                    // Write the HTML summary to a file
                    writeFile(file: "summary.html", text: htmlSummary)
        
                    // Read the content of the summary.html file
                    def emailBody = readFile('summary.html')

                    // Send an email with the HTML summary as the body and the JSON report as an attachment
                    emailext (
                        to: 'brian@jbfinegoods.com',
                        subject: 'Report Summary',
                        body: emailBody,
                        attachmentsPattern: "threatbuster_results.json",
                        mimeType: 'text/html'
                    )
                }
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
