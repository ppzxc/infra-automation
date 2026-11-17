variable "namespace" {
  description = "관리 대상 OpenBao 네임스페이스"
  type        = string
  default     = "infra"
}

variable "runner_cidrs" {
  description = "Semaphore 러너 출발지 CIDR 목록. secret_id_bound_cidrs·token_bound_cidrs에 쓴다. TF_VAR_runner_cidrs로 넣고 저장소에 쓰지 않는다."
  type        = list(string)

  validation {
    condition     = length(var.runner_cidrs) > 0
    error_message = "runner_cidrs는 비어 있을 수 없다(TF_VAR_runner_cidrs)."
  }
}

variable "agent_session_cidrs" {
  description = "에이전트 세션(agent_session AppRole) 출발지 CIDR 목록. TF_VAR_agent_session_cidrs로 넣고 저장소에 쓰지 않는다."
  type        = list(string)

  validation {
    condition     = length(var.agent_session_cidrs) > 0
    error_message = "agent_session_cidrs는 비어 있을 수 없다(TF_VAR_agent_session_cidrs)."
  }
}

variable "operator_password_hashes" {
  description = "userpass 운영자 사용자별 bcrypt 비밀번호 해시(이름 => 해시). TF_VAR_operator_password_hashes로 넣는다. 평문 비밀번호는 다루지 않는다. 해시 만드는 법은 docs/openbao_opentofu.md."
  type        = map(string)
  sensitive   = true
  default     = {}
}
