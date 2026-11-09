pipeline {
    agent any
    stages {
        stage('Build and verify') {
            steps {
                sh './mvnw -B -ntp clean verify'
            }
        }
    }
    post {
        always {
            junit testResults: 'target/surefire-reports/*.xml', allowEmptyResults: false
        }
        success {
            archiveArtifacts artifacts: 'target/certlocker.hpi', fingerprint: true
        }
    }
}
