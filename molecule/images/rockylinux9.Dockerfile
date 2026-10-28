# Test Image: see rockylinux8.Dockerfile for what is (not) baked and why.
FROM geerlingguy/docker-rockylinux9-ansible:latest
ARG DOCKERFILE_SHA=unknown
LABEL infra.dockerfile.sha=$DOCKERFILE_SHA
RUN dnf install -y openssh-server && ssh-keygen -A && dnf clean all \
    && echo 'keepcache=1' >> /etc/dnf/dnf.conf
# GitHub Actions 러너(커널 6.17)에서 /etc/shadow가 기본 0000이면 setuid sudo의 PAM 계정 검사가 shadow를 읽지 못해
# "PAM account management error"로 모든 become이 실패한다(0600이면 통과, 로컬 Docker Desktop에서는 재현되지 않는다). 테스트 이미지에서만 0600으로 둔다.
RUN chmod 0600 /etc/shadow
