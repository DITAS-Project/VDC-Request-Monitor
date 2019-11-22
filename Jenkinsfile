pipeline {
    environment {
      TAG = "v02.3"
      IMAGENAME = "ditas/vdc-request-monitor"
    }
    agent any   
    stages {
        stage('Image creation') {
            steps {
                echo 'Creating the image...'
                sh "docker build -f Dockerfile.testing -t \"${IMAGENAME}:testing\" . --no-cache"
                sh "docker build -f Dockerfile.artifact -t \"${IMAGENAME}:${TAG}\" . --no-cache"
                echo "Done"
            }
        }
        stage('Testing'){
            steps{
                sh "docker run --rm ${IMAGENAME}:testing go test -short ./..."
                sh "docker rmi ${IMAGENAME}:testing"
            }
        }
        stage('Push image') {
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
                echo "Pushing the image ${IMAGENAME}:${TAG}..."
                
                sh "docker push ${IMAGENAME}:${TAG}"
                echo "Done"
            }
        }
        stage('Deployment in Staging') {
            options {
                // Don't need to checkout Git again
                skipDefaultCheckout true
            }
            steps {
                sh './jenkins/deploy-staging.sh'
            }
        }
        stage('check if the monitor could be deployed') {
            agent any
            steps {
                sh './jenkins/test.sh'
            }
        }
        stage('Production image creation and push') {
            when {
                expression {
                   // only create production image from master branch
                   branch 'master'
                }
            }
            steps {                
                // Change the tag from staging to production 
                sh "docker tag ${IMAGENAME}:${TAG} ${IMAGENAME}:production"
                sh "docker push ${IMAGENAME}:production"
            }
        }
    }
}