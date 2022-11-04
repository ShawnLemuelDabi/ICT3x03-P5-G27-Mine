FROM selenium/standalone-firefox:4.5.3-20221024
USER root
RUN apt-get -y update \
    && apt-get upgrade -y \
    && apt-get install -y \
        python3-dev \
        python3-pip
RUN pip install --no-cache-dir --upgrade pip
RUN pip install --no-cache-dir pytest
RUN pip install --no-cache-dir selenium
WORKDIR /tests
COPY . .
RUN chmod 777 /tests
USER seluser
RUN pwd
CMD pytest -v --junitxml=tests/result.xml