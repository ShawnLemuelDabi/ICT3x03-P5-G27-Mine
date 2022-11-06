# ICT3X03-P5-G27

Welcome to our repo pentesters.

While you can access our website directly using [https://shallot-rental.shop/](https://shallot-rental.shop/), I am sure some of you might want to access it locally.

This is a condensed guide to our docker container up.

# Repo structure
```bash

./flasks/            # Code base for the back-end Flask server
./jenkins/           # Contains the Dockerfile for our Jenkins
./mariadb/           # Contains the .env files (required) and the initial .sql file (optional)
./selenium/          # Contains the pytests
docker-compose.yml   # The docker-compose for our web app
generate_secrets.py  # Script to semi-auto generated env files
Jenkinsfile          # Our Jenkins CI/CD pipeline. Might be too complicated to debug as you need docker-in-docker whereby you pass the docker socket into the Jenkins container
README.md            # This file
```

# Setting up the server

## Setting up secrets

As with all services, we have sensitive information such as SMTP credentials and signing key which we have stored in the .env files.

The script `generate_secrets.py` should facilitate the setting up of the env variables. For further instructions, please refer to the script and fill in the variables before running it.

If you prefer to manually write your own env files, you can do so by reading how the env files are generated from the script.

You **MUST** setup the env variables before trying to bring up the services. Failure to do so may result in a broken web server.

## Running the services

On the directory that contains the git repo's root (the path that contains the .git folder), run the command below

```bash
# add a -d switch to detach it
docker-compose up
```

## Error on first page load

When you first load our webpage, you might encounter an error saying some tables doesn't exists as the tables are not present.

You can use the route [http://localhost:5001/dev/init](http://localhost:5001/dev/init) to initialize all the tables.

## Delete all SQL data
```bash
# probably something followed by mariadb-data
# (e.g., if your folder that contains this repo is ssd.
# the name of the volume is likely to be ssd_mariadb-data)
docker volume rm "VOLUME_NAME"
```

If the command does not work as the container is still running, try any/all of the following command(s) before running the command above.

```bash
docker-compose down
```

```bash
# you should not be using force. you should be understanding why it doesn't work before forcing
docker container prune --force
```

# Accessing the server
After running the services, you can access the webpage with [http://localhost:5001](http://localhost:5001).

# Advanced debugging

## Getting console access to the services
You can access the services directly by running the following.

Note that the containers have very limited tools/commands that may not be useful for debugging.

```bash
docker exec -it "ID_OF_CONTAINER_OR_NAME_OF_CONTAINER" bash
```

You can get the ID or name of the container by running

```bash
docker ps
```