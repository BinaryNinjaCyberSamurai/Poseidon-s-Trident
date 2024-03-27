pipeline {
    agent any

    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Build') {
            steps {
                sh 'python setup.py build'
            }
        }

        stage('Test') {
            steps {
                sh 'python setup.py test'
            }
        }

        stage('Package') {
            steps {
                sh 'python setup.py sdist'
            }
        }

        stage('Publish') {
            steps {
                // Assuming you have a Nexus or Artifactory repository
                sh 'python setup.py upload -r nexus-repo'
            }
        }
    }

    post {
        always {
            // Clean up artifacts
            deleteDir()
        }
    }
}
