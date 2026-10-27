# 보안 기준선 스냅샷 수집기 (#368)

ns0266·ns0331의 보안 상태를 같은 명령으로 반복 수집해 적용 전후를 diff한다. 읽기 전용이며 시크릿 파일의 내용은 읽지 않는다(권한·소유자·경로만).

```bash
scripts/collect-security-baseline.sh --label ns0266 --ssh <user>@<host> [--port N]
diff <이전>/snapshot.txt <이후>/snapshot.txt   # 같은 상태면 비어 있다
```

- 결과: `~/.local/share/infra-automation/sec-review-20261026/baseline/<label>/<시각>/snapshot.txt`(0600). `--out`/`INFRA_PRIVATE_DIR`로 바꿀 수 있으나 git 저장소 안 경로는 거부한다. 결과 원본은 커밋하지 않는다.
- 수집 항목: 열린 접점·컨테이너 게시 포트, 방화벽(firewalld·nft 무카운터·DOCKER-USER), sshd 실효 설정, fail2ban·auditd 상태와 적재 규칙, 시스템 로그 저장 방식, 시크릿 후보 파일 메타데이터, 컨테이너 이미지.
- 시각·PID·패킷 카운터는 수집 단계에서 제거한다. 수집 결과에 시크릿 패턴이 보이면 결과를 폐기하고 실패한다.
- sudo가 필요한 명령이 있어 원격 계정은 `sudo -n`이 되어야 한다.
- 백업 저장소 서비스 계정 정책은 RustFS 관리 자격이 필요해 이 스크립트가 아닌 별도 승인 절차로 수집한다.
