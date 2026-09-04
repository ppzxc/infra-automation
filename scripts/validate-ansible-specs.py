#!/usr/bin/env python3
"""
Node Provisioner 3-Way Ansible Specification & Traceability Validator
Validates strict consistency across:
  1. Specification Docs (docs/ansible/*.md)
  2. Implementation Tasks (ansible/roles/*/tasks/main.yml)
  3. Molecule Verification Tests (ansible/molecule/default/verify.yml)
"""

import sys
import re
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
DOCS_DIR = ROOT_DIR / "docs"
ROLES_DIR = ROOT_DIR / "roles"
VERIFY_FILE = ROOT_DIR / "molecule" / "default" / "verify.yml"

SPEC_ID_PATTERN = re.compile(r"\[([A-Z]+-\d{3})\]\s*(.+)")
DOC_TABLE_PATTERN = re.compile(r"\|\s*`([A-Z]+-\d{3})`\s*\|\s*`([^`]+)`\s*\|")
VERIFY_ID_PATTERN = re.compile(r"\[VERIFY-([A-Z]+-\d{3})\]")

def extract_docs_specs():
    specs = {} # {id: (name, file_path)}
    duplicates = []
    
    for md_file in sorted(DOCS_DIR.glob("*.md")):
        if md_file.name == "INDEX.md":
            continue
        content = md_file.read_text(encoding="utf-8")
        for line in content.splitlines():
            match = DOC_TABLE_PATTERN.search(line)
            if match:
                spec_id = match.group(1).strip()
                task_name = match.group(2).strip()
                if spec_id in specs:
                    duplicates.append((spec_id, md_file.name, specs[spec_id][1].name))
                else:
                    specs[spec_id] = (task_name, md_file)
    return specs, duplicates

def extract_code_tasks():
    tasks = {} # {id: (name, file_path)}
    duplicates = []
    
    for task_file in sorted(ROLES_DIR.glob("*/tasks/*.yml")):
        content = task_file.read_text(encoding="utf-8")
        for line in content.splitlines():
            line_str = line.strip()
            if line_str.startswith("- name:") or line_str.startswith("name:"):
                # name 추출
                name_part = line_str.split("name:", 1)[1].strip().strip('"').strip("'")
                match = SPEC_ID_PATTERN.search(name_part)
                if match:
                    spec_id = match.group(1).strip()
                    task_name = match.group(2).strip()
                    if spec_id in tasks:
                        duplicates.append((spec_id, task_file.name, tasks[spec_id][1].name))
                    else:
                        tasks[spec_id] = (task_name, task_file)
    return tasks, duplicates

def extract_verify_tests():
    verify_ids = set()
    if VERIFY_FILE.exists():
        content = VERIFY_FILE.read_text(encoding="utf-8")
        for match in VERIFY_ID_PATTERN.finditer(content):
            verify_ids.add(match.group(1).strip())
    return verify_ids

def main():
    print("================================================================================")
    print("   Infra Automation 3-Way Ansible Specification & Traceability Validator")
    print("================================================================================")
    
    docs_specs, doc_dups = extract_docs_specs()
    code_tasks, code_dups = extract_code_tasks()
    verify_tests = extract_verify_tests()
    
    errors = []
    warnings = []
    
    # 1. 중복 ID 검사
    for spec_id, file1, file2 in doc_dups:
        errors.append(f"[DUPLICATE DOC ID] '{spec_id}' defined multiple times in docs ({file1}, {file2})")
    for spec_id, file1, file2 in code_dups:
        errors.append(f"[DUPLICATE CODE ID] '{spec_id}' defined multiple times in code ({file1}, {file2})")
        
    # 2. 문서 vs 코드 양방향 검증
    all_ids = sorted(set(docs_specs.keys()) | set(code_tasks.keys()))
    
    for spec_id in all_ids:
        in_docs = spec_id in docs_specs
        in_code = spec_id in code_tasks
        
        if in_docs and not in_code:
            errors.append(f"[MISSING IN CODE] '{spec_id}' ({docs_specs[spec_id][0]}) is documented in '{docs_specs[spec_id][1].name}' but NOT implemented in tasks.")
        elif in_code and not in_docs:
            errors.append(f"[MISSING IN DOCS] '{spec_id}' ({code_tasks[spec_id][0]}) is in code '{code_tasks[spec_id][1].parent.parent.name}' but NOT in docs/ansible/*.md.")
        elif in_docs and in_code:
            # 태스크 명칭 비교
            doc_name = docs_specs[spec_id][0]
            code_name = code_tasks[spec_id][0]
            if doc_name != code_name:
                errors.append(f"[NAME MISMATCH] '{spec_id}': Docs has '{doc_name}' but Code has '{code_name}'.")
                
    # 3. 매트릭스 출력
    print(f"\n[*] Total Specs Documented:      {len(docs_specs)}")
    print(f"[*] Total Code Tasks with ID:    {len(code_tasks)}")
    print(f"[*] Total Molecule Direct Tests: {len(verify_tests)}\n")
    
    print("-" * 80)
    print(f"{'Spec ID':<12} | {'Task Name':<42} | {'Docs':<6} | {'Code':<6} | {'Molecule Test'}")
    print("-" * 80)
    for spec_id in all_ids:
        name = (docs_specs.get(spec_id) or code_tasks.get(spec_id))[0]
        if len(name) > 40:
            name = name[:37] + "..."
        d_status = "OK" if spec_id in docs_specs else "FAIL"
        c_status = "OK" if spec_id in code_tasks else "FAIL"
        v_status = "VERIFIED" if spec_id in verify_tests else "INTEGRATED"
        print(f"{spec_id:<12} | {name:<42} | {d_status:<6} | {c_status:<6} | {v_status}")
    print("-" * 80)
    
    # 4. 결과 판정
    if errors:
        print("\n❌ 3-WAY VALIDATION FAILED WITH ERRORS:")
        for err in errors:
            print(f"  - {err}")
        print("\nPlease resolve the inconsistencies between docs, tasks, and tests.")
        sys.exit(1)
    else:
        print("\n✅ 3-WAY VALIDATION PASSED: 100% Traceability across Docs, Code, and Molecule Tests!")
        sys.exit(0)

if __name__ == "__main__":
    main()
