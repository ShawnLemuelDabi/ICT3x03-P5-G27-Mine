pipeline {
    agent any

    environment {
        TEST_STAGE = 'test'
        PROD_STAGE = 'prod'
    }
    stages {
		stage('check if test is already running') {
            steps {
                sh 'docker ps | grep ${TEST_STAGE}_flasks || exit 0'
            }
        }
        stage('git clone') {
            steps {
                git branch: 'fl',
					credentialsId: 'e7eca3bf-9a67-4cc0-87d6-822db0f6677a',
					url: 'https://github.com/angpeihao98/jenkinstest.git'
            }
        }
		stage('OWASP DependencyCheck') {
			steps {
				dependencyCheck additionalArguments: '--format HTML --format XML', odcInstallation: 'Default'
			}
		}
		stage('unpack secrets') {
			withCredentials([file(credentialsId: 'flask.env', variable: 'flask_secret')]) {
				def secret_src = new File(flask_secret)
				def secret_dst = new File('./flasks/flask.env')
				Files.copy(secret_src.toPath(), secret_dst.toPath())
			}
			withCredentials([file(credentialsId: 'mysql.env', variable: 'mysql_secret')]) {
				def secret_src = new File(mysql_secret)
				def secret_dst = new File('./flasks/mysql.env')
				Files.copy(secret_src.toPath(), secret_dst.toPath())
			}
			withCredentials([file(credentialsId: 'mysql_root.env', variable: 'mysql_root_secret')]) {
				def secret_src = new File(mysql_root_secret)
				def secret_dst = new File('./mariadb/mysql_root.env')
				Files.copy(secret_src.toPath(), secret_dst.toPath())
			}
		}
        stage('build webapp') {
            environment {
                FLASK_PORT = '5001'
                MARIA_DB_VOLUME = 'mariadb-test-data'
				FLASK_DEBUG = '1'
            }
            steps {
                sh 'docker-compose -p ${TEST_STAGE} up --build -d'
            }
        }
        stage('starting selenium') {
            steps {
                sh 'docker run --rm -d -p 4444:4444 --net ${TEST_STAGE}_default --name selenium-worker selenium/standalone-firefox:4.5.3-20221024 || (docker ps | grep selenium-worker && exit 0)'
            }
        }
        stage('connect jenkins with flask app') {
            steps {
                sh 'docker network connect ${TEST_STAGE}_default jenkins || echo already connected'
            }
        }
        stage('unit testing') {
            steps {
                sh 'echo optimistic wait for db to be ready && sleep 30'
                sh 'curl http://flasks:5000/dev/init'
                sh 'cd selenium/tests && pytest -v --junitxml=result.xml || exit 0'
            }
            post {
                always {
                    sh 'docker network disconnect ${TEST_STAGE}_default jenkins || echo already disconnected'
	            sh 'docker container kill selenium-worker'
                }
            }
        }
        stage('deployment') {
            environment {
                FLASK_PORT = '5000'
                MARIA_DB_VOLUME = 'mariadb-data'
				FLASK_DEBUG = '0'
            }
            steps {
                sh 'docker-compose -p ${PROD_STAGE} down '
                sh 'docker-compose -p ${PROD_STAGE} up --build -d'
            }
        }
    }
    post {
        always {
            sh 'docker-compose -p ${TEST_STAGE} down'
            sh 'docker container prune -f'
            sh 'docker volume rm -f ${TEST_STAGE}_mariadb-test-data'
        }
		success {
			dependencyCheckPublisher pattern: 'DependencyCheck-report.xml'
			junit 'selenium/tests/result.xml'
		}
    }
}