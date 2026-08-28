#!/usr/bin/env bash
set -e

# Overseer Ansible Docker Execution Wrapper Script
# Usage: ./docker-run.sh [ansible / ansible-playbook arguments...]
# Example: ./docker-run.sh playbooks/provision.yml --limit storage-01.idc.internal

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE_NAME="overseer-ansible:latest"

# 1. 이미지 빌드 (없거나 필요 시)
if ! docker image inspect "${IMAGE_NAME}" >/dev/null 2>&1; then
    echo "[*] Building ${IMAGE_NAME} image..."
    docker build -t "${IMAGE_NAME}" "${SCRIPT_DIR}"
fi

# 2. SSH 에이전트 및 볼륨 마운트 옵션 구성
DOCKER_RUN_OPTS=(
    --rm -it
    -v "${SCRIPT_DIR}:/ansible"
    -w /ansible
)

# 호스트 ~/.ssh 디렉토리 마운트 (키 파일 참조용)
if [ -d "${HOME}/.ssh" ]; then
    DOCKER_RUN_OPTS+=(-v "${HOME}/.ssh:/root/.ssh:ro")
fi

# SSH Agent 소켓 포워딩 지원
if [ -n "${SSH_AUTH_SOCK}" ] && [ -S "${SSH_AUTH_SOCK}" ]; then
    DOCKER_RUN_OPTS+=(
        -v "${SSH_AUTH_SOCK}:/ssh-agent"
        -e SSH_AUTH_SOCK=/ssh-agent
    )
fi

# Docker 소켓 마운트 (Molecule 컨테이너 테스트 지원)
if [ -S "/var/run/docker.sock" ]; then
    DOCKER_RUN_OPTS+=(-v "/var/run/docker.sock:/var/run/docker.sock")
fi

# 환경 변수 전달 (OpenBao 토큰, Ansible 환경변수 등)
[ -n "${BAO_ADDR}" ] && DOCKER_RUN_OPTS+=(-e BAO_ADDR="${BAO_ADDR}")
[ -n "${BAO_TOKEN}" ] && DOCKER_RUN_OPTS+=(-e BAO_TOKEN="${BAO_TOKEN}")

# 3. 명령어 실행
if [ $# -eq 0 ]; then
    # 인자가 없으면 ansible-playbook 도움말 출력
    exec docker run "${DOCKER_RUN_OPTS[@]}" "${IMAGE_NAME}" --help
elif [[ "$1" == "ansible" || "$1" == "ansible-lint" || "$1" == "molecule" || "$1" == "pytest" || "$1" == "bash" || "$1" == "sh" ]]; then
    # 특정 바이너리나 쉘을 실행하려는 경우 entrypoint 오버라이드
    CMD="$1"
    shift
    exec docker run --entrypoint "${CMD}" "${DOCKER_RUN_OPTS[@]}" "${IMAGE_NAME}" "$@"
else
    # 일반 인자는 ansible-playbook 인자로 전달
    exec docker run "${DOCKER_RUN_OPTS[@]}" "${IMAGE_NAME}" "$@"
fi

