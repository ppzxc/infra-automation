FROM python:3.11-slim-bookworm

LABEL maintainer="Overseer Team"
LABEL description="Overseer Ansible Execution Environment"

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    ANSIBLE_FORCE_COLOR=True

# 기본 필수 시스템 패키지 설치
RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-client \
    sshpass \
    git \
    curl \
    jq \
    rsync \
    docker.io \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Ansible 및 Molecule 관련 의존성 패키지 설치
RUN pip install --no-cache-dir \
    ansible \
    ansible-lint \
    molecule \
    "molecule-plugins[docker]" \
    pytest-testinfra \
    docker \
    hvac \
    cryptography \
    jmespath \
    netaddr


WORKDIR /ansible

# 기본 명령어 설정
ENTRYPOINT ["ansible-playbook"]
CMD ["--help"]
