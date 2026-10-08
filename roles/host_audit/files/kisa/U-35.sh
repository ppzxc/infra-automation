# KISA-2026:U-35 (상) 공유 서비스에 대한 익명 접근 제한 설정
# 양호: 공유 서비스(FTP·NFS·Samba)를 쓰지 않거나, 익명 접근을 제한한 경우.
# vsftpd anonymous_enable=YES, proftpd <Anonymous>, /etc/exports anonuid·anongid·insecure 없음 대신
# all_squash 아닌 no_root_squash, smb.conf guest ok = yes / map to guest = bad user 를 익명 허용으로 본다.
(
  used=""
  bad=""
  if kisa_service_on vsftpd; then
    used="$used vsftpd"
    f=$(kisa_first_file /etc/vsftpd/vsftpd.conf /etc/vsftpd.conf)
    # vsftpd 기본값은 anonymous_enable=NO(3.x)·YES(2.x)라 지정이 없으면 값을 모른다 → 지정값만 본다.
    [ -n "$f" ] && grep -Eiq '^[[:space:]]*anonymous_enable[[:space:]]*=[[:space:]]*YES' "$f" && bad="$bad vsftpd:anonymous_enable=YES"
  fi
  if kisa_service_on proftpd; then
    used="$used proftpd"
    f=$(kisa_first_file /etc/proftpd.conf /etc/proftpd/proftpd.conf)
    [ -n "$f" ] && grep -Eiq '^[[:space:]]*<Anonymous' "$f" && bad="$bad proftpd:<Anonymous>"
  fi
  if kisa_service_on nfsd nfs-server nfs-kernel-server; then
    used="$used nfs"
    if [ -r "$R/etc/exports" ] && grep -Ev '^[[:space:]]*(#|$)' "$R/etc/exports" | grep -Eq 'no_root_squash|anonuid=0|anongid=0'; then
      bad="$bad nfs:no_root_squash/anon=0"
    fi
  fi
  if kisa_service_on smbd smb; then
    used="$used samba"
    f=$(kisa_first_file /etc/samba/smb.conf)
    [ -n "$f" ] && grep -Eiq '^[[:space:]]*(guest ok|public)[[:space:]]*=[[:space:]]*yes' "$f" && bad="$bad samba:guest ok"
  fi
  if [ -z "$used" ]; then
    kisa_emit U-35 GOOD "no shared service (ftp, nfs, samba) active"
  elif [ -n "$bad" ]; then
    kisa_emit U-35 VULN "anonymous access allowed:$bad"
  else
    kisa_emit U-35 GOOD "active:$used; no anonymous access setting found"
  fi
)
