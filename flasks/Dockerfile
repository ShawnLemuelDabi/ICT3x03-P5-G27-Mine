FROM docker.io/library/python:latest
EXPOSE 5000
WORKDIR /app
RUN DEBIAN_FRONTEND=noninteractive apt-get -y update \
    && apt-get upgrade -y \
    && apt-get install -y \
        python3-dev \
        default-libmysqlclient-dev \
        build-essential \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir --upgrade pip
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
CMD python3 app.py
# CMD flask run --host=0.0.0.0