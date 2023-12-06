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
        appName = "SECUSPHERE--${env.GIT_URL.split('/')[-1].split('\\.')[0]}"
        K8_ENV = "su_pubweb"
        K8_NAMESPACE = "secusphere"
        SOURCE_DIR = "src"
        API_DEFINITION_FILE = "src/vr/templates/openapi.yaml"
        KUBECONFIG = "${WORKSPACE}/kubeconfig"
        TEST_ENV_HOSTNAME = "192.168.0.68"
        OPENAPI_URL = 'http://192.168.0.68:5010/api/openapi.yaml'
        TEST_URL = 'http://192.168.0.68:5010'
        API_KEY = "API_KEY"
        CONFIG = ''
    }


    // In this example, all is built and run from the master
    agent any



    // Pipeline stages
    stages {

        //stage('Prep Job') {
        //    when {
        //        expression {
        //            env.BRANCH_NAME ==~ /^release\/.*\/.*/
        //        }
        //    }
        //    steps {
        //        script {
        //            jslCountLinesOfCode()
        //        }
        //    }
        //}

        //stage('Unit Testing') {
        //    when {
        //         expression {
        //            env.BRANCH_NAME ==~ /^release\/.*\/.*/
        //         }
        //    }
        //    steps {
        //        jslPythonUnitTesting()
        //    }
        //}

        //stage('Secret Scanning') {
        //    when {
        //         expression {
        //            env.BRANCH_NAME ==~ /^release\/.*\/.*/
        //         }
        //    }
        //    steps {
        //        jslSecretScanning()
        //    }
        //}

        //stage('Software Composition Analysis') {
        //    when {
        //         expression {
        //            env.BRANCH_NAME ==~ /^release\/.*\/.*/
        //         }
        //    }
        //    steps {
        //        jslSecuritySCA('Python,Javascript')
        //    }
        //}

        //stage('Static Application Security Testing') {
        //    when {
        //         expression {
        //            env.BRANCH_NAME ==~ /^release\/.*\/.*/
        //         }
        //    }
        //    steps {
        //        jslStaticApplicationSecurityTesting('Python')
        //    }
        //}

        //stage('Infrastructure-as-Code Security Testing') {
        //    when {
        //         expression {
        //            env.BRANCH_NAME ==~ /^release\/.*\/.*/
        //         }
        //    }
        //    steps {
        //        jslInfrastructureAsCodeAnalysis()
        //    }
        //}

        ////////// Build //////////
        //stage('Build Docker Service') {
        //    when {
        //        expression {
        //            env.BRANCH_NAME ==~ /^release\/.*\/.*/
        //        }
        //    }
        //    steps {
        //        script {
        //            jslBuildDocker([
        //                'serviceName': appName
        //            ])
        //        }
        //    }
        //}

        //stage('Docker Container Scanning') {
        //    when {
        //         expression {
        //            env.BRANCH_NAME ==~ /^release\/.*\/.*/
        //         }
        //    }
        //    steps {
        //        jslContainerSecurityScanning(env.K8_NAMESPACE, 'latest', 'securityuniversal')
        //    }
        //}

        ////////// Release //////////
        //stage('Release to Test') {
        //    when {
        //         expression {
        //            env.BRANCH_NAME ==~ /^release\/.*\/.*/
        //         }
        //    }
        //    steps {
        //        jslRunDockerCompose("secusphere")
        //    }
        //}

        //stage('Test Release') {
        //    when {
        //         expression {
        //            env.BRANCH_NAME ==~ /^release\/.*\/.*/
        //         }
        //    }
        //    steps {
        //        script {
        //            jslDastOWASP('full', TEST_URL, API_KEY)
        //            jslDastAPIOWASP(OPENAPI_URL, TEST_URL, API_KEY)
        //        }
        //    }
        //}

        ////////// Quality Gate //////////
        //stage("Quality Gate - Security") {
        //    when {
        //         expression {
        //            env.BRANCH_NAME ==~ /^release\/.*\/.*/
        //         }
        //    }
        //    steps {
        //        jslSecurityQualityGate()
        //    }
        //}

        //stage('Send Report') {
        //    when {
        //         expression {
        //            env.BRANCH_NAME ==~ /^release\/.*\/.*/
        //         }
        //    }
        //    steps {
        //        script {
        //            jslSendMicrosoftTeamsMessage()
        //            jslSendSecurityReportEmail()
        //        }
        //    }
        //}

        stage('Initialize') {
            steps {
                script {
                    def config = jslReadYamlConfig(env.WORKSPACE, 'pipeline-config.yaml')
                    echo "Loaded config: ${config.toString()}"

                    CONFIG = jslGroovyToJsonString(config)
                    echo "Converted to JSON: ${CONFIG}"
                }
            }
        }

        ////////// Deploy to Production //////////
        stage('Deploy') {
            when {
                anyOf {
                    // Condition for the PROD branch
                    branch 'release/*/PROD'
                    // Condition for a Test-* branch
                    expression {
                        // Split the branch name by '/' and check if the last segment starts with 'Test-'
                        env.BRANCH_NAME.split('/').last().startsWith('Test-')
                    }
                }
            }
            steps {
                script {
                    def parsedConfig = jslGroovyFromJsonString(CONFIG)

                    // Ensure the top-level keys are correctly accessed
                    def globalConfig = parsedConfig?.get('global') ?: [:]
                    def stagesConfig = parsedConfig?.get('stages') ?: [:]
                    def deployConfig = stagesConfig?.get('deploy') ?: [:]

                    echo "Global Config: ${globalConfig}"
                    echo "Deploy Config: ${deployConfig}"

                    if (!deployConfig.isEmpty()) {
                            jslKubernetesDeploy([
                                'serviceName': deployConfig.get('serviceName'),
                                'tlsCredId': deployConfig.get('tlsCredId'),
                                'secretsCredentials': deployConfig.get('secretsCredentials') ?: [:],
                                'secretsSetStrings': deployConfig.get('secretsSetStrings') ?: [:],
                                'serviceCredentials': deployConfig.get('serviceCredentials') ?: [:]
                            ])
                    } else {
                        echo "Deploy configuration not found"
                    }
                }
            }
        }

    }
}
