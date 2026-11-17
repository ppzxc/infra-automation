# OpenBao 구성(마운트·정책·AppRole·userpass)을 OpenTofu로 관리한다(Spec #511 / Ticket-6).
# 전용 OpenBao provider가 아직 없어 hashicorp/vault를 쓴다. 버전은 정확히 고정하고 올릴 때는 PR로 한다.
terraform {
  required_version = ">= 1.11.0, < 2.0.0"

  required_providers {
    vault = {
      source  = "hashicorp/vault"
      version = "= 5.13.0"
    }
  }

  # state는 기존 S3 호환 저장소(RustFS)에 둔다. 주소·자격은 저장소에 쓰지 않는다.
  # init 때 환경변수로 받는다: AWS_ENDPOINT_URL_S3, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY (Semaphore Environment).
  backend "s3" {
    bucket = "opentofu-state"
    key    = "openbao/terraform.tfstate"
    region = "us-east-1"

    use_lockfile                = true
    use_path_style              = true
    skip_credentials_validation = true
    skip_region_validation      = true
    skip_requesting_account_id  = true
    skip_metadata_api_check     = true
    skip_s3_checksum            = true
  }

  # state·plan을 pbkdf2로 암호화한다. openbao key provider는 쓰지 않는다(OpenBao가 고장 나면
  # 고칠 state를 못 여는 순환 의존). passphrase는 코드에 쓰지 못하므로(암호화 블록은 변수를 받지 않는다)
  # 환경변수 TF_ENCRYPTION이 key_provider "pbkdf2" "main"을 채운다. 형식은 docs/openbao_opentofu.md.
  # enforced = true라서 TF_ENCRYPTION이 없으면 평문으로 쓰지 않고 실패한다.
  encryption {
    method "aes_gcm" "main" {
      keys = key_provider.pbkdf2.main
    }

    state {
      method   = method.aes_gcm.main
      enforced = true
    }

    plan {
      method   = method.aes_gcm.main
      enforced = true
    }
  }
}
