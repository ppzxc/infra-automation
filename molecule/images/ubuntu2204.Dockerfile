# Test Image: see rockylinux8.Dockerfile for what is (not) baked and why.
# apt lists are kept because the stock image ships an empty cache. /run/sshd is
# NOT baked: /run is a tmpfs at container start, so it must be created at run
# time (molecule/shared/prepare.yml, PREPARE-003).
FROM geerlingguy/docker-ubuntu2204-ansible:latest
ARG DOCKERFILE_SHA=unknown
LABEL infra.dockerfile.sha=$DOCKERFILE_SHA
RUN apt-get update && apt-get install -y --no-install-recommends openssh-server \
    && ssh-keygen -A \
    && rm -f /etc/apt/apt.conf.d/docker-clean \
    && echo 'Binary::apt::APT::Keep-Downloaded-Packages "true";' > /etc/apt/apt.conf.d/99keep-downloads
