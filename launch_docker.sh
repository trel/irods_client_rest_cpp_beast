#!/bin/bash

mkdir -p packages

if [ ! -d "genquery2/.git" ]; then
    git clone https://github.com/irods/irods_api_plugin_genquery2.git genquery2
else
    echo "genquery2 repository already exists."
fi

sudo docker build -t irods-http-api-builder -f irods_builder.Dockerfile .

sudo docker run -it --rm \
    -v ./genquery2:/genquery2_source:ro \
    -v .:/http_api_source:ro \
    -v ./packages:/packages_output \
    irods-http-api-builder

deb_count=$(find packages -type f -name "*.deb" | wc -l)
if [ "$deb_count" -ne 2 ]; then
    echo "Error: Expected 2 DEB packages but found $deb_count."
    exit 1
fi

sudo docker build -t irods-http-api-runner \
    -f irods_runner.Dockerfile \
    ./packages

echo "checking version installed:"
sudo docker run -it --rm irods-http-api-runner -v

sudo docker run -d --rm --name irods_http_api \
    -v ./config.json:/config.json:ro \
    -p 9000:9000 \
    irods-http-api-runner

