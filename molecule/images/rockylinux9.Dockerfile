# Test Image: see rockylinux8.Dockerfile for what is (not) baked and why.
FROM geerlingguy/docker-rockylinux9-ansible:latest
ARG DOCKERFILE_SHA=unknown
LABEL infra.dockerfile.sha=$DOCKERFILE_SHA
RUN dnf install -y openssh-server && ssh-keygen -A && dnf clean all \
    && echo 'keepcache=1' >> /etc/dnf/dnf.conf
