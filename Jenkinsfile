@Library('security-pipeline-library')_


pipeline {

    agent any

    environment {
        SNYK_API_KEY = credentials('snyk-api-key')
    }

    stages {
        stage('Initialize Config') {
            agent any
            steps {
                script {
                    def config = jslReadYamlConfig()
                    env.appName = config.global.appName

                    // Set the global branch list
                    env.GLOBAL_BRANCH_LIST = config.global.defaultBranches.join(',')
                    env.CURRENT_STAGE_BRANCH_LIST = ""

                    jslStageWrapper.initReport(config)

                }
            }
        }

        stage('Prep Job') {
            agent any
            when {
                expression {
                    def config = jslReadYamlConfig('prepJob')
                    env.CURRENT_STAGE_BRANCH_LIST = env.GLOBAL_BRANCH_LIST
                    if (config.branches) {
                        env.CURRENT_STAGE_BRANCH_LIST = config.branches.join(',')
                    }
                    def branchType = env.BRANCH_NAME.tokenize('/')[0]
                    env.CURRENT_STAGE_BRANCH_LIST.tokenize(',').contains(branchType) && config.enabled
                }
            }
            steps {
                jslStageWrapper('Prep Job') {
                    script {
                        jslCountLinesOfCode()
                    }
                }
            }
        }

        stage('Unit Testing') {
            agent any
            when {
                 expression {
                    def config = jslReadYamlConfig('unitTesting')
                    env.CURRENT_STAGE_BRANCH_LIST = env.GLOBAL_BRANCH_LIST
                    if (config.branches) {
                        env.CURRENT_STAGE_BRANCH_LIST = config.branches.join(',')
                    }
                    def branchType = env.BRANCH_NAME.tokenize('/')[0]
                    env.CURRENT_STAGE_BRANCH_LIST.tokenize(',').contains(branchType) && config.enabled
                 }
            }
            steps {
                jslStageWrapper('Unit Testing') {
                    jslPythonUnitTesting()
                }
            }
        }

        stage('Secret Scanning') {
            agent any
            when {
                 expression {
                    def config = jslReadYamlConfig('secretScanning')
                    env.CURRENT_STAGE_BRANCH_LIST = env.GLOBAL_BRANCH_LIST
                    if (config.branches) {
                        env.CURRENT_STAGE_BRANCH_LIST = config.branches.join(',')
                    }
                    def branchType = env.BRANCH_NAME.tokenize('/')[0]
                    env.CURRENT_STAGE_BRANCH_LIST.tokenize(',').contains(branchType) && config.enabled
                 }
            }
            steps {
                jslStageWrapper('Secret Scanning') {
                    jslSecretScanning()
                }
            }
        }

        stage('Software Composition Analysis') {
            agent any
            when {
                 expression {
                    def config = jslReadYamlConfig('sca')
                    env.CURRENT_STAGE_BRANCH_LIST = env.GLOBAL_BRANCH_LIST
                    if (config.branches) {
                        env.CURRENT_STAGE_BRANCH_LIST = config.branches.join(',')
                    }
                    def branchType = env.BRANCH_NAME.tokenize('/')[0]
                    env.CURRENT_STAGE_BRANCH_LIST.tokenize(',').contains(branchType) && config.enabled
                 }
            }
            steps {
                jslStageWrapper('Software Composition Analysis') {
                    script {
                        def stageConfig = jslReadYamlConfig('sca')
                        def codeLanguages = stageConfig?.codeLanguages.join(',')
                        jslSoftwareCompositionAnalysis(codeLanguages, env.appName)
                    }
                }
            }
        }

        stage('Static Application Security Testing') {
            agent any
            when {
                 expression {
                    def config = jslReadYamlConfig('sast')
                    env.CURRENT_STAGE_BRANCH_LIST = env.GLOBAL_BRANCH_LIST
                    if (config.branches) {
                        env.CURRENT_STAGE_BRANCH_LIST = config.branches.join(',')
                    }
                    def branchType = env.BRANCH_NAME.tokenize('/')[0]
                    env.CURRENT_STAGE_BRANCH_LIST.tokenize(',').contains(branchType) && config.enabled
                 }
            }
            steps {
                jslStageWrapper('Static Application Security Testing') {
                    script {
                        def stageConfig = jslReadYamlConfig('sast')
                        def codeLanguages = stageConfig?.codeLanguages
                        jslStaticApplicationSecurityTesting(codeLanguages)
                    }
                }
            }
        }

        stage('Infrastructure-as-Code Security Testing') {
            agent any
            when {
                 expression {
                    def config = jslReadYamlConfig('iac')
                    env.CURRENT_STAGE_BRANCH_LIST = env.GLOBAL_BRANCH_LIST
                    if (config.branches) {
                        env.CURRENT_STAGE_BRANCH_LIST = config.branches.join(',')
                    }
                    def branchType = env.BRANCH_NAME.tokenize('/')[0]
                    env.CURRENT_STAGE_BRANCH_LIST.tokenize(',').contains(branchType) && config.enabled
                 }
            }
            steps {
                jslStageWrapper('Infrastructure-as-Code Security Testing') {
                    jslInfrastructureAsCodeAnalysis()
                }
            }
        }

        stage('Build Docker Service') {
            agent any
            when {
                expression {
                    def config = jslReadYamlConfig('buildDocker')
                    env.CURRENT_STAGE_BRANCH_LIST = env.GLOBAL_BRANCH_LIST
                    if (config.branches) {
                        env.CURRENT_STAGE_BRANCH_LIST = config.branches.join(',')
                    }
                    def branchType = env.BRANCH_NAME.tokenize('/')[0]
                    env.CURRENT_STAGE_BRANCH_LIST.tokenize(',').contains(branchType) && config.enabled
                }
            }
            steps {
                jslStageWrapper('Build Docker Service') {
                    script {
                        jslBuildDocker([
                            'serviceName': env.appName
                        ])
                    }
                }
            }
        }

        stage('Docker Container Scanning') {
            agent any
            when {
                 expression {
                    def config = jslReadYamlConfig('containerScan')
                    env.CURRENT_STAGE_BRANCH_LIST = env.GLOBAL_BRANCH_LIST
                    if (config.branches) {
                        env.CURRENT_STAGE_BRANCH_LIST = config.branches.join(',')
                    }
                    def branchType = env.BRANCH_NAME.tokenize('/')[0]
                    env.CURRENT_STAGE_BRANCH_LIST.tokenize(',').contains(branchType) && config.enabled
                 }
            }
            steps {
                jslStageWrapper('Docker Container Scanning') {
                    script {
                        def stageConfig = jslReadYamlConfig('containerScan')
                        def containerName = stageConfig?.containerName
                        def containerTag = stageConfig?.containerTag
                        jslContainerSecurityScanning(containerName, containerTag)
                    }
                }

            }
        }

        stage('Release to Test') {
            agent any
            when {
                 expression {
                    def config = jslReadYamlConfig('releaseToTest')
                    env.CURRENT_STAGE_BRANCH_LIST = env.GLOBAL_BRANCH_LIST
                    if (config.branches) {
                        env.CURRENT_STAGE_BRANCH_LIST = config.branches.join(',')
                    }
                    def branchType = env.BRANCH_NAME.tokenize('/')[0]
                    env.CURRENT_STAGE_BRANCH_LIST.tokenize(',').contains(branchType) && config.enabled
                 }
            }
            steps {
                jslStageWrapper('Release to Test') {
                    script {
                        def stageConfig = jslReadYamlConfig('releaseToTest')
                        def serviceName = stageConfig?.serviceName
                        def containerTag = stageConfig?.containerTag
                        jslRunDockerCompose(serviceName, containerTag)
                    }
                }
            }
        }

        stage('Test Release') {
            agent any
            when {
                 expression {
                    def config = jslReadYamlConfig('testRelease')
                    env.CURRENT_STAGE_BRANCH_LIST = env.GLOBAL_BRANCH_LIST
                    if (config.branches) {
                        env.CURRENT_STAGE_BRANCH_LIST = config.branches.join(',')
                    }
                    def branchType = env.BRANCH_NAME.tokenize('/')[0]
                    env.CURRENT_STAGE_BRANCH_LIST.tokenize(',').contains(branchType) && config.enabled
                 }
            }
            steps {
                jslStageWrapper('Test Release') {
                    script {
                        def stageConfig = jslReadYamlConfig('testRelease')
                        def targetUrl = stageConfig?.targetUrl
                        def dastTestType = stageConfig?.dastTestType
                        def apiTargetUrl = stageConfig?.apiTargetUrl
                        jslDastOWASP(dastTestType, targetUrl)
                        jslDastAPIOWASP(apiTargetUrl, targetUrl)
                    }
                }
            }
        }

        ////////// Quality Gate //////////
        stage("Quality Gate - Security") {
            agent any
            when {
                 expression {
                    def config = jslReadYamlConfig('securityQualityGate')
                    env.CURRENT_STAGE_BRANCH_LIST = env.GLOBAL_BRANCH_LIST
                    if (config.branches) {
                        env.CURRENT_STAGE_BRANCH_LIST = config.branches.join(',')
                    }
                    def branchType = env.BRANCH_NAME.tokenize('/')[0]
                    env.CURRENT_STAGE_BRANCH_LIST.tokenize(',').contains(branchType) && config.enabled
                 }
            }
            steps {
                jslStageWrapper('Quality Gate - Security') {
                    jslSecurityQualityGate()
                }
            }
        }

        ////////// Deploy to Production //////////
        stage('Deploy') {
            agent any
            when {
                anyOf {
                    // Condition for the PROD branch
                    branch 'release/*/PROD'
                    // Condition for a Test-* branch
                    expression {
                        // Split the branch name by '/' and check if the last segment starts with 'Test-'
                        env.BRANCH_NAME.split('/').last().startsWith('staging') || env.BRANCH_NAME.split('/').last().startsWith('Prod')
                    }
                }
            }
            steps {

                jslStageWrapper('Deploy') {
                    script {
                        def stageConfig = jslReadYamlConfig('deploy')

                        jslKubernetesDeploy([
                            'serviceName': env.appName,
                            'tlsCredId': stageConfig?.tlsCredId,
                            'secretsCredentials': stageConfig?.secretsCredentials,
                            'secretsSetStrings': stageConfig?.secretsSetStrings,
                            'serviceCredentials': stageConfig?.serviceCredentials,
                            'serviceSetStrings': stageConfig?.serviceSetStrings
                        ])

                    }
                }

            }
        }
    }
    post {
        always {

            script {
                jslPipelineReporter()
            }

        }
    }

}
