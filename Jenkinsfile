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
		stage('OWASP DependencyCheck') {
			steps {
				dependencyCheck additionalArguments: '--format HTML --format XML', odcInstallation: 'Default'
			}
		}
		stage('unpack secrets') {
			steps {
				withCredentials([
					file(credentialsId: 'flask_prod.env', variable: 'flask_prod_secret'),
					file(credentialsId: 'flask_test.env', variable: 'flask_test_secret'),
					file(credentialsId: 'mysql.env', variable: 'mysql_secret'),
					file(credentialsId: 'mysql_root.env', variable: 'mysql_root_secret')
				]) {
					sh 'cp $flask_prod_secret ./flasks/flask_prod.env'
					sh 'cp $flask_test_secret ./flasks/flask_test.env'
					sh 'cp $mysql_secret ./flasks/mysql.env'
					sh 'cp $mysql_root_secret ./mariadb/mysql_root.env'
				}
			}
		}
        stage('build webapp') {
            environment {
                FLASK_PORT = '5001'
                MARIA_DB_VOLUME = 'mariadb-test-data'
				FLASK_ENV = 'flask_test.env'
            }
            steps {
				sh 'echo $FLASK_ENV'
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
		stage('cleanup build stage') {
			environment {
                FLASK_PORT = '5001'
                MARIA_DB_VOLUME = 'mariadb-test-data'
				FLASK_ENV = 'flask_test.env'
            }
			steps {
				sh 'docker-compose -p ${TEST_STAGE} down'
				sh 'docker container prune -f'
				sh 'docker volume rm -f ${TEST_STAGE}_mariadb-test-data'
			}
		}
        stage('deployment') {
            environment {
                FLASK_PORT = '5000'
                MARIA_DB_VOLUME = 'mariadb-data'
				FLASK_ENV = 'flask_prod.env'
            }
            steps {
				sh 'echo $FLASK_ENV'
                sh 'docker ps | grep ${PROD_STAGE}_flasks && docker-compose -p ${PROD_STAGE} down || exit 0'
                sh 'docker-compose -p ${PROD_STAGE} up --build -d'
            }
        }
    }
    post {
		success {
			dependencyCheckPublisher pattern: 'dependency-check-report.xml'
			junit 'selenium/tests/result.xml'
		}
    }
}