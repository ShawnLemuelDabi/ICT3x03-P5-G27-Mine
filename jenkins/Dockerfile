FROM docker.io/jenkins/jenkins:lts-jdk11
USER root
RUN apt-get -y update \
    && apt-get upgrade -y \
    && apt-get install --no-install-recommends -y \
    	python3-pip \
        python3-dev \
        docker.io \
    && apt clean -y
RUN python3 -m pip install pytest
RUN python3 -m pip install selenium
RUN curl -L \
    "https://github.com/docker/compose/releases/download/1.25.3/docker-compose-$(uname -s)-$(uname -m)" \  
    -o /usr/local/bin/docker-compose \  
    && chmod +x /usr/local/bin/docker-compose
COPY . .