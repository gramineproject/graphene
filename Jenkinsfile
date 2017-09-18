pipeline {
        agent any
        stages {
                stage('Build') {
                    steps {
                        sh '''
                            ls
                            cd Pal/src
                            make
                            cd ../ipc/linux
                            ./load.sh
                            cd ../../../LibOS
                            make
                            cd ..
                           '''
                    }
                }
                stage('Test') {
                    steps {
                        sh '''
                            cd LibOS/shim/test/native
                            make
                            ./pal_loader helloworld
                            cd ../apps/lmbench
                            make
                            cd lmbench-2.5/bin/linux
                            ./pal_loader lat_syscall null
                            ./pal_loader lat_syscall open
                            ./pal_loader lat_syscall read
                            ./pal_loader lat_proc fork
                           '''
                        input 'Tests complete. Do you wish to deploy?'
                    }
                }
                stage('Deploy') {
                    steps {
                        sh 'echo Deploying code'
                    }
                }
        }
        post {
                success {
                        echo 'Deployment successful'
                }
                failure {
                        echo 'Failure while on the pipeline'
                }
                unstable {
                        echo 'Pipeline marked as "unstable"'
                }
        }
}

