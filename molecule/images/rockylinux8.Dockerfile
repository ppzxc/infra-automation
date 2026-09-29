# Test Image: everything molecule/default/prepare.yml used to redo on every run.
# - python3.11: stock 3.6 cannot parse the AnsiballZ wrapper (PEP 563).
# - openssh-server + host keys: images are built for `docker exec`, not SSH,
#   but roles/security validates sshd_config with `sshd -t`.
# Deliberately NOT baked: PREPARE-004 (removal-scenario seed) and any package a
# role installs, so the scenarios still exercise the real install paths.
FROM geerlingguy/docker-rockylinux8-ansible:latest
ARG DOCKERFILE_SHA=unknown
LABEL infra.dockerfile.sha=$DOCKERFILE_SHA
RUN dnf install -y python3.11 openssh-server && ssh-keygen -A && dnf clean all \
    && echo 'keepcache=1' >> /etc/dnf/dnf.conf
