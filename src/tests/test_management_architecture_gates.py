from __future__ import annotations

import ast
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
BASELINE = "172661a"


def python_files(directory: str):
    return sorted((ROOT / directory).rglob("*.py"))


def imported_modules(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    modules = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            modules.append(node.module)
    return modules


def test_management_api_imports_only_auth_control_schemas_and_transport():
    violations = []
    for path in python_files("src/management_api"):
        for module in imported_modules(path):
            if module == "src" or (
                module.startswith("src.")
                and not module.startswith(("src.management_auth", "src.management_control"))
            ):
                violations.append((path.relative_to(ROOT).as_posix(), module))
    assert violations == []


def test_management_control_has_no_fastapi_http_or_telegram_imports():
    violations = []
    for path in python_files("src/management_control"):
        for module in imported_modules(path):
            if module.startswith(("fastapi", "starlette", "src.telegram")):
                violations.append((path.relative_to(ROOT).as_posix(), module))
    assert violations == []


def test_business_modules_do_not_reverse_import_management():
    violations = []
    for path in python_files("src"):
        relative = path.relative_to(ROOT).as_posix()
        if relative.startswith(("src/management_", "src/tests/", "src/telegram/")):
            continue
        for module in imported_modules(path):
            if module.startswith("src.management_"):
                violations.append((relative, module))
    assert violations == []


def test_every_python_file_added_since_p0_baseline_is_at_most_1000_lines():
    baseline_files = set(
        subprocess.check_output(
            ["git", "ls-tree", "-r", "--name-only", BASELINE],
            cwd=ROOT,
            text=True,
        ).splitlines()
    )
    current_files = {
        path.relative_to(ROOT).as_posix()
        for path in ROOT.rglob("*.py")
        if ".git" not in path.parts
    }
    added = sorted(path for path in current_files if path not in baseline_files)
    assert added, "the P0 gate expects added Python files"
    too_large = []
    for relative in added:
        line_count = len((ROOT / relative).read_text(encoding="utf-8").splitlines())
        if line_count > 1000:
            too_large.append((relative, line_count))
    assert too_large == []
