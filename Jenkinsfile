pipeline {
    environment {
      TAG = "v02"
    }
    agent none   
    stages {
        stage('Image creation') {
            agent any
            steps {
                echo 'Creating the image...'
                sh "docker build -f Dockerfile.testing -t \"ditas/vdc-request-monitor:testing\" ."
                sh "docker build -f Dockerfile.artifact -t \"ditas/vdc-request-monitor:${TAG}\" ."
                echo "Done"
            }
        }
        stage('Testing'){
            agent {
                docker { 
                    image 'ditas/vdc-request-monitor:testing' 
                }
            }
            steps{
                sh "pwd"
                sh "ls -la"
                sh "go test ./..."
            }
        }
        stage('Push image') {
            agent any
            steps {
                echo 'Retrieving Docker Hub password from /opt/ditas-docker-hub.passwd...'
        
                script {
                    password = readFile '/opt/ditas-docker-hub.passwd'
                }
                echo "Done"
               
                sh "docker login -u ditasgeneric -p ${password}"
                echo 'Login to Docker Hub as ditasgeneric...'
                sh "docker login -u ditasgeneric -p ${password}"
                echo "Done"
                echo "Pushing the image ditas/vdc-request-monitor:${TAG}..."
                
                sh "docker push ditas/vdc-request-monitor:${TAG}"
                echo "Done"
            }
        }
    }
}