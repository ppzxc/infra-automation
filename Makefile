.PHONY: help provision provision-overseer provision-hosts check spec-check lint test test-unit test-molecule test-fast test-slow test-full test-role test-images test-scripts clean init-hooks

# Default Target
help:
	@echo "================================================================================"
	@echo "                     Infra Automation (Ansible Automation)                      "
	@echo "================================================================================"
	@echo "  make init-hooks                 - Install Git Pre-Commit security & lint hooks"
	@echo "  make provision                  - Run full provisioning (overseer + servers)"
	@echo "  make provision-overseer         - Run provisioning for Overseer Control Plane host"
	@echo "  make provision-hosts            - Run baseline provisioning for IDC target hosts"
	@echo "  make check                      - Dry-run simulation (--check --diff)"
	@echo "  make spec-check                 - Validate 3-way consistency (Docs <-> Code <-> Tests)"
	@echo "  make lint                       - Run ansible-lint and spec validation"
	@echo "  make test                       - Run all fast verification tests (Spec + Unit + Scripts)"
	@echo "  make test-unit                  - Run Pytest contract & structure tests"
	@echo "  make test-fast                  - Molecule Fast Scenario (pre-push tier: Rocky 9, +Rocky 8 if security/common changed)"
	@echo "  make test-slow                  - Molecule Slow Scenario (docker_engine + monitoring, all OS)"
	@echo "  make test-full                  - Molecule Full Matrix (fast + slow, all OS) -- required before a release"
	@echo "  make test-role ROLE=<role>      - One role (+ common Base Layer) on Rocky 9; MOLECULE_SKIP_IDEMPOTENCE=1 for a faster dev loop"
	@echo "  make test-images                - Build/refresh molecule Test Images (FORCE=1 to rebuild)"
	@echo "  make test-scripts               - Run shell script unit tests"
	@echo "  make clean                      - Clean up temporary/cache files"
	@echo "================================================================================"

init-hooks:
	@chmod +x scripts/pre-commit.sh
	@cp scripts/pre-commit.sh .git/hooks/pre-commit
	@chmod +x .git/hooks/pre-commit
	@echo "Git pre-commit hook installed successfully."


provision:
	@./docker-run.sh playbooks/site.yml

provision-overseer:
	@./docker-run.sh playbooks/provision_overseer.yml

provision-hosts:
	@./docker-run.sh playbooks/provision_hosts.yml

check:
	@./docker-run.sh playbooks/site.yml --check --diff

spec-check:
	@python3 scripts/validate-ansible-specs.py

test-unit:
	@pytest tests/ -v

test-scripts:
	@./scripts/test_firewalld_docker.sh

test: spec-check test-unit test-scripts
	@echo "All fast verification tests passed successfully!"

lint: spec-check
	@./docker-run.sh ansible-lint

test-fast:
	@bash scripts/run-molecule.sh fast

test-slow:
	@bash scripts/run-molecule.sh slow

test-full:
	@bash scripts/run-molecule.sh full

test-role:
	@test -n "$(ROLE)" || { echo "usage: make test-role ROLE=<common|security|access_security|docker_engine|monitoring>"; exit 2; }
	@bash scripts/run-molecule.sh role $(ROLE)

test-images:
	@bash scripts/build-test-images.sh

clean:
	@rm -rf .pytest_cache molecule/*/.molecule .cache
