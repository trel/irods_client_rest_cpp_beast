#! /bin/bash

set -x

# Compile the GenQuery2 project.
mkdir /_build_genquery2
cd /_build_genquery2
cmake -GNinja /genquery2_source
ninja package
apt-get install -y ./*.deb
cp ./*.deb /packages_output

# Return to the root directory.
cd /

# Compile the HTTP API project.
mkdir /_build_http_api
cd /_build_http_api
cmake -GNinja -DIRODS_ENABLE_GENQUERY2=YES /http_api_source
ninja package
cp ./*.deb /packages_output
