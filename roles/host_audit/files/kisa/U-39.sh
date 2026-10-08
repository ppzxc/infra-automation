# KISA-2026:U-39 (상) 불필요한 NFS 서비스 비활성화
# 양호: 불필요한 NFS 서버 데몬(nfsd, nfs-server)이 비활성화된 경우. 필요성은 예외 레지스터로 남긴다.
(
  if kisa_service_on nfsd nfs-server nfs-kernel-server; then
    kisa_emit U-39 VULN "NFS server active"
  else
    kisa_emit U-39 GOOD "NFS server not active"
  fi
)
