#!/usr/bin/env bash
set -e

# Infra Automation Ansible Docker Execution Wrapper Script
# Usage: ./docker-run.sh [ansible / ansible-playbook arguments...]
# Example: ./docker-run.sh playbooks/site.yml --limit storage-01.idc.internal

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
    # ssh-agent에 키 등록 여부 확인 및 안내
    if command -v ssh-add >/dev/null 2>&1; then
        if ! ssh-add -l >/dev/null 2>&1; then
            echo "[!] Warning: SSH agent가 실행 중이나 등록된 개인키가 없습니다."
            echo "    패스프레이즈가 있는 키를 사용 중인 경우 'ssh-add ~/.ssh/id_ed25519'를 실행하면 비밀번호 재입력 없이 자동 인증됩니다."
        fi
    fi
else
    # SSH_AUTH_SOCK이 없을 때 안내
    if [ -f "${HOME}/.ssh/id_ed25519" ] || [ -f "${HOME}/.ssh/id_rsa" ]; then
        echo "[i] Tip: SSH Agent를 사용하려면 다음을 실행하세요: eval \$(ssh-agent -s) && ssh-add"
    fi
fi

# Docker 소켓 마운트 (Molecule 컨테이너 테스트 지원)
if [ -S "/var/run/docker.sock" ]; then
    DOCKER_RUN_OPTS+=(-v "/var/run/docker.sock:/var/run/docker.sock")
fi

# OpenBao 읽기 지점(lookup_plugins/_openbao_reader.py)이 받는 환경 변수만 넘긴다: 주소 + AppRole(+ 사설 CA·검증 끄기).
# 평문 토큰으로 넘기는 경로는 없다. 값은 호출하는 셸의 환경에 있어야 하고 이 스크립트가 출력하지 않는다.
for var in VAULT_ADDR VAULT_ROLE_ID VAULT_SECRET_ID VAULT_SKIP_VERIFY; do
    [ -n "${!var}" ] && DOCKER_RUN_OPTS+=(-e "${var}")
done
# 사설 CA는 파일 경로다: 같은 경로로 읽기 전용 마운트해 컨테이너 안에서도 그 경로가 맞게 한다.
if [ -n "${VAULT_CACERT}" ]; then
    if [ ! -f "${VAULT_CACERT}" ]; then
        echo "[!] VAULT_CACERT 파일이 없습니다: ${VAULT_CACERT} (경로를 확인하세요)" >&2
        exit 2
    fi
    DOCKER_RUN_OPTS+=(-v "${VAULT_CACERT}:${VAULT_CACERT}:ro" -e "VAULT_CACERT")
fi

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
