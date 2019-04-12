#!/bin/zsh

# This builds a completely new image. You really don't need to run this every
# time you want to run the container.
#docker build -t openssl_tool:v0.1 .

# This is used to run a particular version of the container, and bind mounts
# the current directory to /app in the container. This bind mount is important,
# because the Dockerfile sets /app as the working directory for the cert
# generation script and expects certain input files to be there and places all
# output files there 
docker run -d \
  -it \
  # --name openssl_test \
  --mount type=bind,source="$(pwd)",target=/app \
  openssl_tool:v0.1
