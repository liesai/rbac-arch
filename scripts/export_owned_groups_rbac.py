#!/usr/bin/env python3
import argparse
import csv
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any
from urllib.parse import quote


def run_az(args: list[str], *, text_output: bool = False) -> Any:
    cmd = ["az", *args]
    if "-o" not in args and "--output" not in args:
        cmd.extend(["-o", "tsv" if text_output else "json"])
    proc = subprocess.run(cmd, text=True, capture_output=True)
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip()
        raise RuntimeError(f"az command failed: {' '.join(cmd)}\n{detail}")
    out = proc.stdout.strip()
    if text_output:
        return out
    return json.loads(out or "null")


def normalize_role(raw: str) -> str:
    aliases = {
        "global admin": "Global Administrator",
        "global administrator": "Global Administrator",
        "security admin": "Security Administrator",
        "privileged role admin": "Privileged Role Administrator",
        "privileged access admin": "Privileged Access Administrator",
        "application admin": "Application Administrator",
        "app operator": "Application Operator",
        "user access admin": "User Access Administrator",
        "billing reader role": "Billing Reader",
    }
    role = str(raw or "").strip()
    return aliases.get(role.lower(), role)


def scope_level(scope: str) -> int:
    lowered = str(scope or "/").lower()
    if "/providers/" in lowered:
        return 1
    if "/resourcegroups/" in lowered:
        return 2
    if "/subscriptions/" in lowered:
        return 3
    return 4


def resolve_owner(owner: str) -> dict[str, str]:
    user = run_az(
        [
            "ad",
            "user",
            "show",
            "--id",
            owner,
            "--query",
            "{id:id,userPrincipalName:userPrincipalName,mail:mail,displayName:displayName}",
        ]
    )
    if not isinstance(user, dict) or not user.get("id"):
        raise RuntimeError(f"Unable to resolve owner user: {owner}")
    return {k: str(v or "") for k, v in user.items()}


def list_accessible_subscriptions(include_disabled: bool) -> list[dict[str, str]]:
    query = "[].{id:id,name:name,state:state,tenantId:tenantId}" if include_disabled else "[?state=='Enabled'].{id:id,name:name,state:state,tenantId:tenantId}"
    rows = run_az(["account", "list", "--all", "--query", query])
    if not isinstance(rows, list):
        return []
    return [{k: str(v or "") for k, v in row.items()} for row in rows if isinstance(row, dict) and row.get("id")]


def graph_get_all(url: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    next_url = url
    while next_url:
        payload = run_az(["rest", "--method", "GET", "--url", next_url])
        if not isinstance(payload, dict):
            raise RuntimeError(f"Unexpected Graph response for {next_url}")
        value = payload.get("value") or []
        if not isinstance(value, list):
            raise RuntimeError(f"Unexpected Graph value for {next_url}")
        rows.extend([item for item in value if isinstance(item, dict)])
        next_url = str(payload.get("@odata.nextLink") or "")
    return rows


def list_owned_groups_via_graph(owner_id: str) -> list[dict[str, Any]]:
    encoded_id = quote(owner_id, safe="")
    select = "id,displayName,mail,securityEnabled,groupTypes"
    url = f"https://graph.microsoft.com/v1.0/users/{encoded_id}/ownedObjects/microsoft.graph.group?$select={select}&$top=999"
    return graph_get_all(url)


def list_owned_groups_by_scanning(owner: dict[str, str]) -> list[dict[str, Any]]:
    groups = run_az(["ad", "group", "list", "--all", "--query", "[].{id:id,displayName:displayName,mail:mail,securityEnabled:securityEnabled,groupTypes:groupTypes}"])
    if not isinstance(groups, list):
        return []

    owner_needles = {
        owner.get("id", "").lower(),
        owner.get("userPrincipalName", "").lower(),
        owner.get("mail", "").lower(),
        owner.get("displayName", "").lower(),
    }
    owner_needles.discard("")

    matched: list[dict[str, Any]] = []
    for idx, group in enumerate(groups, start=1):
        group_id = str((group or {}).get("id") or "")
        if not group_id:
            continue
        print(f"checking group owners {idx}/{len(groups)}: {group_id}", file=sys.stderr)
        try:
            owners = run_az(["ad", "group", "owner", "list", "--group", group_id, "--query", "[].{id:id,userPrincipalName:userPrincipalName,mail:mail,displayName:displayName}"])
        except Exception as exc:
            print(f"warning: cannot read owners for {group_id}: {exc}", file=sys.stderr)
            continue
        for item in owners if isinstance(owners, list) else []:
            values = {str(v or "").lower() for v in (item or {}).values()}
            if values.intersection(owner_needles):
                matched.append(group)
                break
    return matched


def get_member_count(group_id: str) -> int:
    try:
        out = run_az(["ad", "group", "member", "list", "--group", group_id, "--query", "length(@)"], text_output=True)
        return int(out or 0)
    except Exception as exc:
        print(f"warning: cannot count members for {group_id}: {exc}", file=sys.stderr)
        return 0


def list_group_assignments(group_id: str, subscriptions: list[dict[str, str]]) -> list[dict[str, str]]:
    details: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    for sub in subscriptions:
        sub_id = sub["id"]
        scope = f"/subscriptions/{sub_id}"
        try:
            rows = run_az(
                [
                    "role",
                    "assignment",
                    "list",
                    "--all",
                    "--assignee-object-id",
                    group_id,
                    "--scope",
                    scope,
                    "--query",
                    "[].{role:roleDefinitionName,scope:scope,principalId:principalId,principalName:principalName}",
                ]
            )
        except Exception as exc:
            print(f"warning: cannot read role assignments for group {group_id} on subscription {sub_id}: {exc}", file=sys.stderr)
            continue
        if not isinstance(rows, list):
            continue
        for row in rows:
            role = normalize_role(str((row or {}).get("role") or ""))
            assignment_scope = str((row or {}).get("scope") or scope)
            key = (sub_id, role, assignment_scope)
            if not role or key in seen:
                continue
            seen.add(key)
            details.append(
                {
                    "role": role,
                    "scope": assignment_scope,
                    "subscription_id": sub_id,
                    "subscription_name": sub.get("name", ""),
                    "principal_id": str((row or {}).get("principalId") or group_id),
                    "principal_name": str((row or {}).get("principalName") or ""),
                }
            )
    return details


def build_export(
    owner: dict[str, str],
    groups: list[dict[str, Any]],
    subscriptions: list[dict[str, str]],
    *,
    include_empty: bool,
    skip_members: bool,
) -> dict[str, Any]:
    exported_groups: list[dict[str, Any]] = []
    owner_upn = owner.get("userPrincipalName") or owner.get("mail") or owner.get("displayName") or owner.get("id", "")

    for idx, group in enumerate(groups, start=1):
        group_id = str(group.get("id") or "")
        if not group_id:
            continue
        display_name = str(group.get("displayName") or group.get("name") or group_id)
        print(f"exporting RBAC assignments {idx}/{len(groups)}: {display_name} ({group_id})", file=sys.stderr)
        assignments = list_group_assignments(group_id, subscriptions)
        if not assignments and not include_empty:
            continue

        role_assignments: list[str] = []
        seen_roles: set[str] = set()
        scopes: list[str] = []
        for item in assignments:
            role = item["role"]
            if role not in seen_roles:
                role_assignments.append(role)
                seen_roles.add(role)
            if item.get("scope"):
                scopes.append(item["scope"])

        selected_scope = sorted(scopes, key=lambda s: (scope_level(s), len(s)))[0] if scopes else "/"
        tags = {
            "owner": owner_upn,
            "source": "azure_cli_export",
        }
        if assignments:
            tags["subscription_count"] = str(len({a["subscription_id"] for a in assignments if a.get("subscription_id")}))

        exported_groups.append(
            {
                "group_id": group_id,
                "display_name": display_name,
                "members_count": 0 if skip_members else get_member_count(group_id),
                "owner": owner_upn,
                "scope": selected_scope,
                "role_assignments": role_assignments,
                "assignment_details": assignments,
                "tags": tags,
                "naming_ok": display_name.upper().startswith(("AAD-", "GRP-")),
                "last_review_days": 0,
            }
        )

    return {
        "metadata": {
            "source": "azure_cli",
            "owner": owner,
            "subscriptions": subscriptions,
            "groups_owned": len(groups),
            "groups_exported": len(exported_groups),
        },
        "groups": exported_groups,
    }


def write_json(payload: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)
        fh.write("\n")


def write_csv(payload: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "group_id",
        "display_name",
        "members_count",
        "owner",
        "scope",
        "role_assignments",
        "tags",
        "naming_ok",
        "last_review_days",
    ]
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for group in payload["groups"]:
            writer.writerow(
                {
                    "group_id": group.get("group_id", ""),
                    "display_name": group.get("display_name", ""),
                    "members_count": group.get("members_count", 0),
                    "owner": group.get("owner", ""),
                    "scope": group.get("scope", "/"),
                    "role_assignments": ",".join(group.get("role_assignments") or []),
                    "tags": ",".join(f"{k}={v}" for k, v in (group.get("tags") or {}).items()),
                    "naming_ok": str(bool(group.get("naming_ok", True))).lower(),
                    "last_review_days": group.get("last_review_days", 0),
                }
            )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Export Entra groups owned by a person with Azure RBAC assignments from subscriptions visible to the current az account."
    )
    parser.add_argument("--owner", required=True, help="Owner UPN, mail, or object id, e.g. jane.doe@contoso.com")
    parser.add_argument("--output", type=Path, default=Path("owned-groups-rbac.json"), help="Output file path.")
    parser.add_argument("--format", choices=["json", "csv"], default="json", help="Output format compatible with /aad/load-groups.")
    parser.add_argument("--include-empty", action="store_true", help="Include owned groups even if they have no RBAC assignment in accessible subscriptions.")
    parser.add_argument("--skip-members", action="store_true", help="Do not call az ad group member list for member counts.")
    parser.add_argument("--include-disabled-subscriptions", action="store_true", help="Also inspect disabled subscriptions returned by az account list.")
    parser.add_argument(
        "--fallback-scan-all-groups",
        action="store_true",
        help="If Graph ownedObjects is unavailable, scan all groups and call az ad group owner list for each group.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if shutil.which("az") is None:
        raise SystemExit("Azure CLI `az` is required. Run `az login` before this script.")

    owner = resolve_owner(args.owner)
    subscriptions = list_accessible_subscriptions(args.include_disabled_subscriptions)
    if not subscriptions:
        raise SystemExit("No accessible subscriptions found with `az account list --all`.")

    try:
        groups = list_owned_groups_via_graph(owner["id"])
    except Exception as exc:
        if not args.fallback_scan_all_groups:
            raise SystemExit(
                "Could not list owned groups through Microsoft Graph.\n"
                f"{exc}\n"
                "Retry with --fallback-scan-all-groups if your account can list group owners through Azure CLI."
            )
        print(f"warning: Graph ownedObjects failed, scanning all groups instead: {exc}", file=sys.stderr)
        groups = list_owned_groups_by_scanning(owner)

    payload = build_export(
        owner,
        groups,
        subscriptions,
        include_empty=args.include_empty,
        skip_members=args.skip_members,
    )
    if args.format == "csv":
        write_csv(payload, args.output)
    else:
        write_json(payload, args.output)

    print(
        f"Exported {len(payload['groups'])} groups from {len(groups)} owned groups "
        f"across {len(subscriptions)} accessible subscriptions to {args.output}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
