FROM python:3.11-slim-bullseye

# Install libvirt which requires system dependencies.
RUN apt update && \
    apt install -y git build-essential g++ gcc cargo gnupg ca-certificates \
    libssl-dev libffi-dev libvirt-dev libxml2-dev libxslt-dev zlib1g-dev vim \
    libmemcached-dev procps netcat wget curl jq inetutils-ping && \
    rm -rf /var/lib/apt/lists/*

RUN wget https://dl.influxdata.com/influxdb/releases/influxdb-1.8.4-static_linux_amd64.tar.gz && \
    tar xvfz influxdb-1.8.4-static_linux_amd64.tar.gz && rm influxdb-1.8.4-static_linux_amd64.tar.gz

RUN ln -s /influxdb-1.8.4-1/influxd /usr/local/bin/influxd && \
    ln -s /usr/bin/pip3 /usr/bin/pip && \
    ln -s /usr/bin/python3 /usr/bin/python

# Download VictoriaMetrics promql middleware .so file
# ARG CI_API_V4_URL
# RUN wget -O promql_middleware.so  `curl "${CI_API_V4_URL}/projects/126/releases" | jq -r .[0].assets.links[0].url`

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir --upgrade setuptools && \
    pip install libvirt-python==8.8.0 uwsgi==2.0.21 && \
    pip install --no-cache-dir ipython ipdb flake8 pytest pytest-cov

# Remove `-frozen` to build without strictly pinned dependencies.
COPY requirements-frozen.txt /mist.api/requirements.txt
COPY requirements-frozen.txt /requirements-frozen-mist.api.txt
COPY requirements.txt /requirements-mist.api.txt

WORKDIR /mist.api/

COPY paramiko /mist.api/paramiko
COPY lc /mist.api/lc
COPY v2 /mist.api/v2

RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r /mist.api/requirements.txt && \
    pip install -e paramiko/ && \
    pip install -e lc/ && \
    pip install -e v2/ && \
    pip install --no-cache-dir -r v2/requirements.txt

COPY . /mist.api/

RUN pip install -e src/

# This file gets overwritten when mounting code, which lets us know code has
# been mounted.
RUN touch clean

ENTRYPOINT ["/mist.api/bin/docker-init"]

ARG API_VERSION_SHA
ARG API_VERSION_NAME

# Variables defined solely by ARG are accessible as environmental variables
# during build but not during runtime. To persist these in the image, they're
# redefined as ENV in addition to ARG.
ENV JS_BUILD=1 \
    VERSION_REPO=mistio/mist.api \
    VERSION_SHA=$API_VERSION_SHA \
    VERSION_NAME=$API_VERSION_NAME


RUN echo "{\"sha\":\"$VERSION_SHA\",\"name\":\"$VERSION_NAME\",\"repo\":\"$VERSION_REPO\",\"modified\":false}" \
    > /mist-version.json
