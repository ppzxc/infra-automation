.PHONY: help provision provision-overseer provision-servers check spec-check lint test test-unit test-molecule test-scripts clean init-hooks

# Default Target
help:
	@echo "================================================================================"
	@echo "                      Node Provisioner (Ansible Automation)                     "
	@echo "================================================================================"
	@echo "  make init-hooks                 - Install Git Pre-Commit security & lint hooks"
	@echo "  make provision                  - Run full provisioning (overseer + servers)"
	@echo "  make provision-overseer         - Run provisioning for Overseer Control Plane host"
	@echo "  make provision-servers          - Run baseline provisioning for IDC target hosts"
	@echo "  make check                      - Dry-run simulation (--check --diff)"
	@echo "  make spec-check                 - Validate 3-way consistency (Docs <-> Code <-> Tests)"
	@echo "  make lint                       - Run ansible-lint and spec validation"
	@echo "  make test                       - Run all fast verification tests (Spec + Unit + Scripts)"
	@echo "  make test-unit                  - Run Pytest contract & structure tests"
	@echo "  make test-molecule              - Run Molecule integration tests in containers"
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

provision-servers:
	@./docker-run.sh playbooks/provision_servers.yml

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

test-molecule:
	@./docker-run.sh molecule test

clean:
	@rm -rf .pytest_cache molecule/*/.molecule .cache
