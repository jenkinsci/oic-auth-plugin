@Library(["ised-cicd-lib", "ised-cicd-lib-api"]) _

pipeline {
	agent {
       	label 'maven'
   	} 
  
    tools {
      jdk 'openjdk-17'
    }
   	
    options {
        disableConcurrentBuilds()
    }
  
   	environment {
		// GLobal Vars
		
		MVN_DEBUG_LOGGING = "true"
    }
  
    stages {
    	stage('build') {
			steps {
				script{
                  	sh """
                      mvn clean install -Dskiptests=true
                    """
				}
			}
    	}
    }
}