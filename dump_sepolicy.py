#!/usr/bin/env python3
"""
SEPolicy Dumper
Extracts and dumps an Android precompiled_sepolicy binary into human-readable
text using seinfo and sesearch. Produces a single output file containing the
full policy summary, all types/attributes/classes/roles/booleans, and every
TE/RBAC/MLS rule in the policy.

Requires: setools (provides sesearch and seinfo)
  apt install setools  OR  pip install setools
"""

import argparse
import os
import subprocess
import sys
import time


def run_tool(cmd, label):
    """Run an setools command and return its stdout."""
    print(f"  [*] {label}...")
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=300,
        )
        if result.returncode != 0:
            stderr = result.stderr.strip()
            if stderr:
                print(f"  [-] {label}: {stderr}")
            return None
        return result.stdout
    except FileNotFoundError:
        print(f"  [-] Command not found: {cmd[0]}")
        return None
    except subprocess.TimeoutExpired:
        print(f"  [-] {label}: timed out")
        return None


def dump_sepolicy(policy_path, output_path):
    """Extract all policy information and write to output file."""

    if not os.path.isfile(policy_path):
        print(f"[-] Policy file not found: {policy_path}")
        return False

    print(f"[*] Policy: {policy_path}")
    print(f"[*] Output: {output_path}")
    print()

    sections = []

    def add_section(title, content):
        if content is None:
            sections.append(f"{'=' * 72}\n{title}\n{'=' * 72}\n(not available)\n")
        else:
            line_count = content.count("\n")
            sections.append(
                f"{'=' * 72}\n{title}  ({line_count} lines)\n{'=' * 72}\n{content}\n"
            )

    # ── seinfo: policy summary ──────────────────────────────────────────
    print("[*] Gathering policy metadata with seinfo...")

    add_section(
        "POLICY SUMMARY",
        run_tool(["seinfo", policy_path], "policy summary"),
    )

    seinfo_queries = [
        (["-t", "-x"],    "TYPES (expanded)"),
        (["-a", "-x"],    "ATTRIBUTES (expanded)"),
        (["-c", "-x"],    "CLASSES (expanded)"),
        (["-r", "-x"],    "ROLES (expanded)"),
        (["-u", "-x"],    "USERS (expanded)"),
        (["-b", "-x"],    "BOOLEANS (expanded)"),
        (["--permissive"],         "PERMISSIVE TYPES"),
        (["--polcap"],             "POLICY CAPABILITIES"),
        (["--initialsid", "-x"],   "INITIAL SIDS"),
        (["--fs_use"],             "FS_USE STATEMENTS"),
        (["--genfscon"],           "GENFSCON STATEMENTS"),
        (["--portcon"],            "PORTCON STATEMENTS"),
        (["--netifcon"],           "NETIFCON STATEMENTS"),
        (["--nodecon"],            "NODECON STATEMENTS"),
        (["--typebounds"],         "TYPEBOUNDS"),
        (["--constrain", "-x"],    "CONSTRAINTS"),
        (["--default"],            "DEFAULT RULES"),
    ]

    for flags, title in seinfo_queries:
        add_section(
            title,
            run_tool(["seinfo", policy_path] + flags, title.lower()),
        )

    # ── sesearch: all rule types ────────────────────────────────────────
    print()
    print("[*] Extracting rules with sesearch...")

    sesearch_queries = [
        (["--allow"],              "ALLOW RULES"),
        (["--allowxperm"],         "ALLOWXPERM RULES"),
        (["--auditallow"],         "AUDITALLOW RULES"),
        (["--auditallowxperm"],    "AUDITALLOWXPERM RULES"),
        (["--dontaudit"],          "DONTAUDIT RULES"),
        (["--dontauditxperm"],     "DONTAUDITXPERM RULES"),
        (["-T"],                   "TYPE_TRANSITION RULES"),
        (["--type_change"],        "TYPE_CHANGE RULES"),
        (["--type_member"],        "TYPE_MEMBER RULES"),
        (["--role_allow"],         "ROLE_ALLOW RULES"),
        (["--role_transition"],    "ROLE_TRANSITION RULES"),
        (["--range_transition"],   "RANGE_TRANSITION RULES"),
    ]

    for flags, title in sesearch_queries:
        add_section(
            title,
            run_tool(["sesearch", policy_path] + flags, title.lower()),
        )

    # ── sesearch: targeted domain searches ─────────────────────────────
    print()
    print("[*] Extracting rules for interesting domains...")

    # Domains/attributes of interest: app sandbox + shell
    target_domains = [
        "untrusted_app_all",
        "shell",
        "isolated_app",
    ]

    rule_types = [
        (["--allow"],      "allow"),
        (["--dontaudit"],  "dontaudit"),
        (["-T"],           "type_transition"),
        (["--type_change"], "type_change"),
    ]

    for domain in target_domains:
        # Rules where this domain is the source
        for flags, rule_label in rule_types:
            add_section(
                f"{domain} (source) — {rule_label}",
                run_tool(
                    ["sesearch", policy_path] + flags + ["-s", domain],
                    f"{rule_label} -s {domain}",
                ),
            )

        # Rules where this domain is the target
        for flags, rule_label in rule_types:
            add_section(
                f"{domain} (target) — {rule_label}",
                run_tool(
                    ["sesearch", policy_path] + flags + ["-t", domain],
                    f"{rule_label} -t {domain}",
                ),
            )

        # seinfo: attributes for this type
        add_section(
            f"{domain} — type info",
            run_tool(
                ["seinfo", policy_path, "-t", domain, "-x"],
                f"seinfo -t {domain}",
            ),
        )

    # ── Write output ────────────────────────────────────────────────────
    print()
    print("[*] Writing output...")

    header = (
        f"# SEPolicy dump of: {os.path.basename(policy_path)}\n"
        f"# Source: {os.path.abspath(policy_path)}\n"
        f"# Generated by dump_sepolicy.py\n"
        f"#\n\n"
    )

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w") as f:
        f.write(header)
        f.write("\n".join(sections))

    size = os.path.getsize(output_path)
    if size > 1024 * 1024:
        size_str = f"{size / 1024 / 1024:.1f} MB"
    else:
        size_str = f"{size / 1024:.1f} KB"

    print(f"[+] Done — wrote {size_str} to {output_path}")
    return True


def main():
    parser = argparse.ArgumentParser(
        description="Dump an Android precompiled_sepolicy to human-readable text"
    )
    parser.add_argument(
        "policy",
        help="Path to precompiled_sepolicy (or any SELinux binary policy file)",
    )
    parser.add_argument(
        "-o", "--output",
        help="Output file path (default: <policy_basename>.dump.txt)",
    )

    args = parser.parse_args()

    if not args.output:
        base = os.path.basename(args.policy)
        args.output = base + ".dump.txt"

    start = time.monotonic()
    ok = dump_sepolicy(args.policy, args.output)
    elapsed = time.monotonic() - start
    print(f"[*] Elapsed: {elapsed:.1f}s")

    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
