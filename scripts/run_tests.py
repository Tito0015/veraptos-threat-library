#!/usr/bin/env python3
"""Run one or all Veraptos Threat Library rule tests."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
DVD = REPO / ".targets" / "damn-vulnerable-defi"
def _opengrep_binary() -> Path:
    if os.environ.get("OPENGREP_BIN"):
        return Path(os.environ["OPENGREP_BIN"])
    for candidate in (REPO / ".tools" / "opengrep.exe", REPO / ".tools" / "opengrep"):
        if candidate.exists():
            return candidate
    return REPO / ".tools" / "opengrep.exe"


OPENGREP = _opengrep_binary()
LOG_DIR = REPO / "test-logs"
WEB3 = REPO / "web3-slither-dvd"

USER_HOME = Path.home()
HOST = os.environ.get("COMPUTERNAME", "localhost")


def sanitize(text: str) -> str:
    out = text
    out = out.replace(str(REPO), "<REPO>")
    out = out.replace(str(DVD), "<TARGET>/damn-vulnerable-defi")
    out = out.replace(str(WEB3), "<REPO>/web3-slither-dvd")
    out = out.replace(str(USER_HOME), "<USERHOME>")
    out = re.sub(r"[A-Za-z]:\\[^\s\"']+", "<ABS_PATH>", out)
    out = re.sub(r"/home/[^\s\"']+", "<USERHOME>", out)
    out = re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", "<IP>", out)
    out = re.sub(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", "<REDACTED>", out)
    out = out.replace(str(USER_HOME.name), "<USER>")
    if HOST:
        out = out.replace(HOST, "<HOST>")
    return out


@dataclass
class RuleSpec:
    rule_id: str
    kind: str
    detect: str | None = None
    dvd_contract: str | None = None
    safe_sol: Path | None = None
    yaml_path: Path | None = None
    test_path: Path | None = None


RULES: dict[str, RuleSpec] = {
    "veraptos-truster-arbitrary-call": RuleSpec(
        rule_id="veraptos-truster-arbitrary-call",
        kind="slither",
        detect="veraptos-truster-arbitrary-call",
        dvd_contract="TrusterLenderPool",
        safe_sol=WEB3 / "veraptos_dvd" / "truster" / "safe.sol",
    ),
    "veraptos-side-entrance-state-hijack": RuleSpec(
        rule_id="veraptos-side-entrance-state-hijack",
        kind="slither",
        detect="veraptos-side-entrance-state-hijack",
        dvd_contract="SideEntranceLenderPool",
        safe_sol=WEB3 / "veraptos_dvd" / "side_entrance" / "safe.sol",
    ),
    "veraptos-rewarder-snapshot-manipulation": RuleSpec(
        rule_id="veraptos-rewarder-snapshot-manipulation",
        kind="slither",
        detect="veraptos-rewarder-snapshot-manipulation",
        dvd_contract="TheRewarderPool",
        safe_sol=WEB3 / "veraptos_dvd" / "the_rewarder" / "safe.sol",
    ),
    "veraptos-puppet-spot-oracle": RuleSpec(
        rule_id="veraptos-puppet-spot-oracle",
        kind="slither",
        detect="veraptos-puppet-spot-oracle",
        dvd_contract="PuppetPool",
        safe_sol=WEB3 / "veraptos_dvd" / "puppet" / "safe.sol",
    ),
    "veraptos-selfie-governance-snapshot": RuleSpec(
        rule_id="veraptos-selfie-governance-snapshot",
        kind="slither",
        detect="veraptos-selfie-governance-snapshot",
        dvd_contract="SimpleGovernance",
        safe_sol=WEB3 / "veraptos_dvd" / "selfie" / "safe.sol",
    ),
    "graphql-ssrf": RuleSpec(
        rule_id="graphql-ssrf",
        kind="opengrep",
        yaml_path=REPO / "web2-opengrep" / "01-graphql-ssrf" / "graphql-ssrf.yaml",
        test_path=REPO / "web2-opengrep" / "01-graphql-ssrf" / "graphql-ssrf.ts",
    ),
    "dom-xss-postmessage": RuleSpec(
        rule_id="dom-xss-postmessage",
        kind="opengrep",
        yaml_path=REPO / "web2-opengrep" / "02-dom-xss-postmessage" / "dom-xss-postmessage.yaml",
        test_path=REPO / "web2-opengrep" / "02-dom-xss-postmessage" / "dom-xss-postmessage.tsx",
    ),
    "mass-assignment-fastapi": RuleSpec(
        rule_id="mass-assignment-fastapi",
        kind="opengrep",
        yaml_path=REPO / "web2-opengrep" / "03-mass-assignment-fastapi" / "mass-assignment-fastapi.yaml",
        test_path=REPO / "web2-opengrep" / "03-mass-assignment-fastapi" / "mass-assignment-fastapi.py",
    ),
    "express-auth-bypass": RuleSpec(
        rule_id="express-auth-bypass",
        kind="opengrep",
        yaml_path=REPO / "web2-opengrep" / "04-express-auth-bypass" / "express-auth-bypass.yaml",
        test_path=REPO / "web2-opengrep" / "04-express-auth-bypass" / "express-auth-bypass.ts",
    ),
    "jwt-none-alg-go": RuleSpec(
        rule_id="jwt-none-alg-go",
        kind="opengrep",
        yaml_path=REPO / "web2-opengrep" / "05-jwt-none-alg-go" / "jwt-none-alg-go.yaml",
        test_path=REPO / "web2-opengrep" / "05-jwt-none-alg-go" / "jwt-none-alg-go.go",
    ),
    "jwt-none-alg-go-parse-unverified": RuleSpec(
        rule_id="jwt-none-alg-go-parse-unverified",
        kind="opengrep",
        yaml_path=REPO / "web2-opengrep" / "05-jwt-none-alg-go" / "jwt-none-alg-go.yaml",
        test_path=REPO / "web2-opengrep" / "05-jwt-none-alg-go" / "jwt-none-alg-go.go",
    ),
}


DVD_REMAPS = "@openzeppelin=node_modules/@openzeppelin solmate=node_modules/solmate solady=node_modules/solady"

SLITHER_DVD_TARGETS: dict[str, str | list[str]] = {
    "veraptos-truster-arbitrary-call": "contracts/truster/TrusterLenderPool.sol",
    "veraptos-side-entrance-state-hijack": "contracts/side-entrance/SideEntranceLenderPool.sol",
    "veraptos-rewarder-snapshot-manipulation": "contracts/the-rewarder",
    "veraptos-puppet-spot-oracle": "contracts/puppet/PuppetPool.sol",
    "veraptos-selfie-governance-snapshot": "contracts/selfie",
}


def slither_json(target: Path, detect: str, rule_id: str | None = None) -> dict:
    dvd_target = SLITHER_DVD_TARGETS.get(rule_id or "")
    if dvd_target and target.resolve() == DVD.resolve():
        cmd = [
            "slither",
            dvd_target,
            "--solc-remaps",
            DVD_REMAPS,
            "--detect",
            detect,
            "--exclude-dependencies",
            "--json",
            "-",
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, cwd=str(DVD))
    else:
        cmd = [
            "slither",
            str(target.resolve()),
            "--detect",
            detect,
            "--exclude-dependencies",
            "--json",
            "-",
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, cwd=str(REPO))
    if proc.returncode not in (0, 255) and not (proc.stdout or "").strip():
        raise RuntimeError(f"slither failed: {(proc.stderr or proc.stdout)[:800]}")
    raw = proc.stdout.strip() or proc.stderr.strip()
    if not raw:
        return {"results": {"detectors": []}}
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        # slither sometimes prints logs before JSON
        idx = raw.find("{")
        return json.loads(raw[idx:])


def findings_in_contract(payload: dict, contract: str) -> list[dict]:
    hits = []
    for det in payload.get("results", {}).get("detectors", []):
        desc = det.get("description", "") or ""
        elements = det.get("elements", [])
        names = " ".join(el.get("name", "") for el in elements)
        blob = desc + names
        if contract in blob:
            hits.append(det)
    return hits


def count_all_findings(payload: dict) -> int:
    return len(payload.get("results", {}).get("detectors", []))


def parse_rule_markers(path: Path, rule_id: str) -> tuple[set[int], set[int]]:
    ruleid_lines: set[int] = set()
    ok_lines: set[int] = set()
    lines = path.read_text(encoding="utf-8").splitlines()
    for i, line in enumerate(lines, start=1):
        if f"ruleid: {rule_id}" in line:
            ruleid_lines.add(i + 1 if line.strip().startswith(("#", "//")) else i)
        if f"ok: {rule_id}" in line:
            ok_lines.add(i + 1 if line.strip().startswith(("#", "//")) else i)
    return ruleid_lines, ok_lines


def opengrep_scan(yaml_path: Path, test_path: Path, rule_id: str | None = None) -> list[int]:
    cmd = [
        str(OPENGREP),
        "scan",
        "--taint-intrafile",
        "--config",
        str(yaml_path),
        str(test_path),
        "--json",
        "--quiet",
    ]
    proc = subprocess.run(
        cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", cwd=str(REPO)
    )
    if proc.returncode not in (0, 1):
        raise RuntimeError((proc.stderr or proc.stdout or "opengrep failed")[:800])
    raw = proc.stdout or ""
    idx = raw.find("{")
    if idx < 0:
        return []
    data = json.loads(raw[idx:])
    lines: set[int] = set()
    for r in data.get("results", []):
        check = r.get("check_id", "")
        if rule_id and rule_id not in check:
            continue
        start = r.get("start", {}).get("line")
        if start:
            lines.add(int(start))
    return sorted(lines)


def write_log(rule_id: str, body: str) -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    (LOG_DIR / f"{rule_id}.log").write_text(sanitize(body), encoding="utf-8")


def run_slither_rule(spec: RuleSpec) -> tuple[bool, str]:
    if not DVD.exists():
        return False, "DVD target missing; run Phase 0 setup"
    dvd_payload = slither_json(DVD, spec.detect or "", spec.rule_id)
    dvd_hits = findings_in_contract(dvd_payload, spec.dvd_contract or "")
    cross = count_all_findings(dvd_payload) - len(dvd_hits)
    safe_payload = slither_json(spec.safe_sol, spec.detect or "", spec.rule_id)
    safe_count = count_all_findings(safe_payload)
    passed = len(dvd_hits) >= 1 and safe_count == 0
    log = (
        f"rule_id={spec.rule_id}\n"
        f"tool=slither\n"
        f"detect={spec.detect}\n"
        f"dvd_contract={spec.dvd_contract}\n"
        f"expected_dvd_hits>=1 actual_dvd_hits={len(dvd_hits)}\n"
        f"expected_safe_hits=0 actual_safe_hits={safe_count}\n"
        f"cross_level_findings={cross}\n"
        f"result={'PASS' if passed else 'FAIL'}\n"
    )
    if dvd_hits:
        log += f"sample={dvd_hits[0].get('check', spec.detect)}\n"
    write_log(spec.rule_id, log)
    return passed, log


def run_opengrep_rule(spec: RuleSpec) -> tuple[bool, str]:
    if not OPENGREP.exists():
        return False, "opengrep binary missing"
    assert spec.yaml_path and spec.test_path
    ruleid_lines, ok_lines = parse_rule_markers(spec.test_path, spec.rule_id)
    matched = set(opengrep_scan(spec.yaml_path, spec.test_path, spec.rule_id))
    missed = ruleid_lines - matched
    bad = matched & ok_lines
    passed = not missed and not bad and bool(ruleid_lines)
    log = (
        f"rule_id={spec.rule_id}\n"
        f"tool=opengrep\n"
        f"expected_ruleid_lines={sorted(ruleid_lines)}\n"
        f"expected_ok_lines={sorted(ok_lines)}\n"
        f"matched_lines={sorted(matched)}\n"
        f"missed={sorted(missed)}\n"
        f"unexpected_ok_hits={sorted(bad)}\n"
        f"result={'PASS' if passed else 'FAIL'}\n"
    )
    write_log(spec.rule_id, log)
    return passed, log


def phase0_info() -> str:
    slither_v = subprocess.run(["slither", "--version"], capture_output=True, text=True).stdout.strip()
    og_v = subprocess.run([str(OPENGREP), "--version"], capture_output=True, text=True).stdout.strip()
    sha = ""
    if DVD.exists():
        sha = subprocess.run(
            ["git", "-C", str(DVD), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
        ).stdout.strip()
    return sanitize(
        f"phase=0\nslither={slither_v}\nopengrep={og_v}\ndvd_tag=v3.0.0\ndvd_sha={sha}\nharness=ready\n"
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--only", default="all", help="rule id or 'all' or 'phase0'")
    args = parser.parse_args()
    LOG_DIR.mkdir(exist_ok=True)

    if args.only == "phase0":
        body = phase0_info()
        write_log("phase-0", body)
        print(body)
        return 0

    ids = list(RULES.keys()) if args.only == "all" else [args.only]
    # jwt yaml contains two rules; running either id executes the same file scan once per invocation
    ok_all = True
    for rid in ids:
        spec = RULES.get(rid)
        if not spec:
            print(f"unknown rule {rid}")
            return 2
        if spec.kind == "slither":
            ok, log = run_slither_rule(spec)
        else:
            ok, log = run_opengrep_rule(spec)
        print(log)
        ok_all = ok_all and ok
    return 0 if ok_all else 1


if __name__ == "__main__":
    sys.exit(main())
