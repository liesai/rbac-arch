from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import List, Dict, Optional, Any
import csv
from datetime import datetime
from copy import deepcopy
from concurrent.futures import ThreadPoolExecutor, as_completed
import subprocess
import shutil
import re
from pathlib import Path
import json
import ipaddress
try:
    import yaml  # type: ignore
except Exception:
    yaml = None

app = FastAPI(
    title="RBAC Auditor for Azure AD",
    description="Outil de génération de matrices d'accès RBAC pour Azure Active Directory",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:8111",
        "http://127.0.0.1:8111",
        "http://localhost:8011",
        "http://127.0.0.1:8011",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configuration initiale des groupes AD
INITIAL_GROUPS = [
    {
        "group_id": "GRP001",
        "display_name": "Admins Globaux",
        "members_count": 3,
        "role_assignments": ["Contributor", "Privileged Access Administrator"],
        "owner": "secops@contoso.com",
        "scope": "/subscriptions/sub-prod-001",
        "tags": {"env": "prod", "criticality": "high", "owner": "secops"},
        "naming_ok": True,
        "last_review_days": 12,
    },
    {
        "group_id": "GRP002",
        "display_name": "Comptabilité",
        "members_count": 8,
        "role_assignments": ["Reader", "User Creator"],
        "owner": "finance-it@contoso.com",
        "scope": "/subscriptions/sub-fin-002/resourceGroups/rg-fin-apps",
        "tags": {"env": "prod", "criticality": "medium", "owner": "finance"},
        "naming_ok": True,
        "last_review_days": 46,
    },
    {
        "group_id": "GRP003",
        "display_name": "Développeurs DevOps",
        "members_count": 12,
        "role_assignments": ["Contributor"],
        "owner": "",
        "scope": "/subscriptions/sub-dev-003/resourceGroups/rg-dev-shared",
        "tags": {"env": "dev", "criticality": "low"},
        "naming_ok": False,
        "last_review_days": 91,
    },
]

# Dictionnaire de mapping des rôles built-in Azure
ROLES_MAPPING = {
    "Owner": {"data_access": True, "config_modify": True, "security_admin": True, "billing_read": True},
    "Global Administrator": {"data_access": True, "config_modify": True, "security_admin": True, "billing_read": True},
    "Contributor": {"data_access": True, "config_modify": True, "security_admin": False, "billing_read": True},
    "Reader": {"data_access": False, "config_modify": False, "security_admin": False, "billing_read": True},
    "User Access Administrator": {"data_access": False, "config_modify": True, "security_admin": True, "billing_read": False},
    "Security Administrator": {"data_access": False, "config_modify": True, "security_admin": True, "billing_read": False},
    "Privileged Role Administrator": {"data_access": False, "config_modify": True, "security_admin": True, "billing_read": False},
    "User Creator": {"data_access": False, "config_modify": True, "security_admin": False, "billing_read": False},
    "Privileged Access Administrator": {"data_access": False, "config_modify": True, "security_admin": True, "billing_read": False},
    "Application Administrator": {"data_access": False, "config_modify": True, "security_admin": False, "billing_read": False},
    "Application Developer": {"data_access": False, "config_modify": True, "security_admin": False, "billing_read": False},
    "Application Operator": {"data_access": False, "config_modify": True, "security_admin": False, "billing_read": False},
    "Billing Reader": {"data_access": False, "config_modify": False, "security_admin": False, "billing_read": True},
}

ROLE_ALIASES = {
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

ROLE_DESCRIPTIONS = {
    "Owner": "Contrôle total sur les ressources et délégation d'accès",
    "Global Administrator": "Administration globale Entra ID/Azure",
    "Contributor": "Pouvoirs administrateur complet (sauf abonnements)",
    "Reader": "Lecture seule complète sur toutes les ressources",
    "User Access Administrator": "Gestion des attributions d'accès RBAC",
    "Security Administrator": "Administration sécurité et posture",
    "Privileged Role Administrator": "Gestion des rôles privilégiés",
    "User Creator": "Création et gestion des comptes utilisateurs",
    "Privileged Access Administrator": "Gestion accès privilégiés PIM",
    "Application Administrator": "Gestion des applications d'entreprise",
    "Application Developer": "Développement/intégration d'applications",
    "Application Operator": "Gestion des applications Azure AD",
    "Billing Reader": "Consultation des informations de facturation",
}

# Etat runtime (config importée)
CURRENT_GROUPS = deepcopy(INITIAL_GROUPS)
CURRENT_SOURCE = "default"
LAST_CONFIG_UPDATE = datetime.now().isoformat()
POLICY_PATH = Path(__file__).resolve().parent / "config" / "governance-policy.yaml"

DEFAULT_POLICY = {
    "version": "2.0",
    "naming": {
        "template": "AAD-{domain}-{purpose}-{env}-{access}",
        "variables": [
            {"key": "domain", "pattern": "^[A-Z]{2,5}$", "transform": "upper"},
            {"key": "purpose", "pattern": "^[A-Z0-9-]{3,30}$", "transform": "upper"},
            {"key": "env", "pattern": "^(DEV|TST|PRD)$", "transform": "upper"},
            {"key": "access", "pattern": "^(USR|ADM|SEC)$", "transform": "upper"},
        ],
        "domains": {
            "FIN": {
                "template": "AAD-{domain}-{purpose}-{env}-{access}",
                "allowed_group_types": ["USR", "ADM"],
                "default_tags": {"domain": "finance", "cost_center": "fin"},
            },
            "SEC": {
                "template": "AAD-{domain}-{purpose}-{env}-{access}",
                "allowed_group_types": ["SEC", "ADM"],
                "default_tags": {"domain": "security", "cost_center": "sec"},
            },
            "ENG": {
                "template": "AAD-{domain}-{purpose}-{env}-{access}",
                "allowed_group_types": ["USR", "ADM"],
                "default_tags": {"domain": "engineering", "cost_center": "eng"},
            },
        },
    },
    "domain_routing": {
        "default_domain": "ENG",
        "allowed_domains": ["FIN", "SEC", "ENG"],
    },
    "requirements": {
        "owner_required": True,
        "tags_required": ["env", "criticality", "cost_center"],
        "last_review_max_days": 90,
    },
    "governance_profiles": {
        "shared_user_nonprod": {
            "group_type": "USR",
            "env": "dev",
            "criticality": "low",
            "max_scope_level": "resource_group",
            "recommended_controls": ["owner", "naming", "quarterly_review"],
        },
        "finance_admin_prod": {
            "group_type": "ADM",
            "domain": "FIN",
            "env": "prod",
            "criticality": "high",
            "max_scope_level": "resource_group",
            "recommended_controls": ["owner", "pim", "monthly_review", "ticket_reference"],
        },
        "security_privileged": {
            "group_type": "SEC",
            "domain": "SEC",
            "env": "prod",
            "criticality": "high",
            "max_scope_level": "subscription",
            "recommended_controls": ["owner", "pim", "mfa", "monthly_review", "approval_record"],
        },
    },
    "group_catalog": {
        "matchers": [
            {
                "id": "finance-admins",
                "match": {"display_name_regex": "(?i)finance|compta|billing", "role_any": ["Contributor", "Owner"]},
                "profile": "finance_admin_prod",
                "tags": {"domain": "finance", "cost_center": "fin"},
            },
            {
                "id": "security-privileged",
                "match": {"display_name_regex": "(?i)sec|security|priv", "role_any": ["Privileged Access Administrator", "Security Administrator", "Owner"]},
                "profile": "security_privileged",
                "tags": {"domain": "security", "cost_center": "sec"},
            },
            {
                "id": "default-shared",
                "match": {"group_id_regex": "^(AAD|GRP)-"},
                "profile": "shared_user_nonprod",
            },
        ],
        "overrides": {},
    },
    "allowed_roles_by_group_type": {
        "USR": ["Reader", "Billing Reader"],
        "ADM": ["Contributor", "User Access Administrator", "Application Administrator"],
        "SEC": ["Security Administrator", "Privileged Role Administrator", "Privileged Access Administrator"],
    },
    "forbidden_rules": [
        {
            "id": "no-owner-outside-sec",
            "description": "Owner n'est autorisé que pour SEC",
            "scope_contains": "/subscriptions/",
            "forbidden_roles": ["Owner"],
            "allowed_group_types": ["SEC"],
        }
    ],
    "access_control": {
        "enabled": False,
        "default_role": "admin",
        "role_groups": {
            "admin": ["AAD-RBAC-ADMINS"],
            "user": ["AAD-RBAC-USERS", "AAD-RBAC-ADMINS"],
        },
    },
}


# Model Pydantic pour la configuration
class RBACConfig(BaseModel):
    group_id: str
    display_name: str
    members_count: int
    role_assignments: List[str]
    owner: str = ""
    scope: str = "/"
    tags: Dict[str, str] = Field(default_factory=dict)
    naming_ok: bool = True
    last_review_days: int = 0


class GroupDraft(BaseModel):
    group_id: str = ""
    display_name: str = ""
    domain: str = ""
    group_type: str = "USR"
    owner: str = ""
    scope: str = "/"
    tags: Dict[str, str] = Field(default_factory=dict)
    role_assignments: List[str] = Field(default_factory=list)
    members_count: int = 0
    last_review_days: int = 0


class NamingPreviewRequest(BaseModel):
    domain: str = ""
    values: Dict[str, str] = Field(default_factory=dict)


class GroupExportRequest(BaseModel):
    groups: List[GroupDraft] = Field(default_factory=list)
    output_format: str = "json"


class CatalogOverrideEntry(BaseModel):
    group_id: str
    profile: str = ""
    tags: Dict[str, str] = Field(default_factory=dict)
    group_type: str = ""
    domain: str = ""
    env: str = ""
    criticality: str = ""
    max_scope_level: str = ""
    notes: str = ""


class CatalogOverrideUpsertRequest(BaseModel):
    overrides: List[CatalogOverrideEntry] = Field(default_factory=list)
    replace_existing: bool = False


def _load_policy() -> Dict[str, Any]:
    if not POLICY_PATH.exists():
        POLICY_PATH.parent.mkdir(parents=True, exist_ok=True)
        if yaml is not None:
            POLICY_PATH.write_text(yaml.safe_dump(DEFAULT_POLICY, sort_keys=False), encoding="utf-8")
        else:
            POLICY_PATH.write_text(json.dumps(DEFAULT_POLICY, indent=2), encoding="utf-8")
        return deepcopy(DEFAULT_POLICY)
    text = POLICY_PATH.read_text(encoding="utf-8")
    try:
        if yaml is not None:
            raw = yaml.safe_load(text) or {}
        else:
            raw = json.loads(text or "{}")
    except Exception:
        # File exists but cannot be parsed in current runtime: fall back safely.
        _save_policy(DEFAULT_POLICY)
        raw = deepcopy(DEFAULT_POLICY)
    merged = deepcopy(DEFAULT_POLICY)
    if isinstance(raw, dict):
        for key, value in raw.items():
            if isinstance(value, dict) and isinstance(merged.get(key), dict):
                merged[key].update(value)
            else:
                merged[key] = value
    return merged


def _save_policy(policy: Dict[str, Any]) -> None:
    POLICY_PATH.parent.mkdir(parents=True, exist_ok=True)
    if yaml is not None:
        POLICY_PATH.write_text(yaml.safe_dump(policy, sort_keys=False), encoding="utf-8")
    else:
        POLICY_PATH.write_text(json.dumps(policy, indent=2), encoding="utf-8")


def _resolve_template(policy: Dict[str, Any], domain: str) -> str:
    naming = policy.get("naming", {}) if isinstance(policy.get("naming"), dict) else {}
    domains = naming.get("domains", {}) if isinstance(naming.get("domains"), dict) else {}
    default_template = str(naming.get("template", "AAD-{domain}-{purpose}-{env}-{access}"))
    domain_cfg = domains.get(domain, {}) if isinstance(domains.get(domain), dict) else {}
    return str(domain_cfg.get("template", default_template))


def _resolve_domain(policy: Dict[str, Any], domain: str = "") -> str:
    routing = policy.get("domain_routing", {}) if isinstance(policy.get("domain_routing"), dict) else {}
    allowed = routing.get("allowed_domains", [])
    if not isinstance(allowed, list):
        allowed = []
    requested = (domain or "").upper().strip()
    if requested and (not allowed or requested in allowed):
        return requested
    return str(routing.get("default_domain", "ENG")).upper()


def _compute_group_name(policy: Dict[str, Any], domain: str, values: Dict[str, str]) -> Dict[str, Any]:
    naming = policy.get("naming", {}) if isinstance(policy.get("naming"), dict) else {}
    variables = naming.get("variables", [])
    if not isinstance(variables, list):
        variables = []

    resolved_domain = _resolve_domain(policy, domain)
    template = _resolve_template(policy, resolved_domain)
    merged_values = {"domain": resolved_domain, **{k: str(v) for k, v in values.items()}}

    violations: List[str] = []
    normalized_values: Dict[str, str] = {}

    for variable in variables:
        if not isinstance(variable, dict):
            continue
        key = str(variable.get("key", "")).strip()
        if not key:
            continue
        raw = str(merged_values.get(key, "")).strip()
        transform = str(variable.get("transform", "")).lower()
        if transform == "upper":
            raw = raw.upper()
        elif transform == "lower":
            raw = raw.lower()
        pattern = str(variable.get("pattern", "")).strip()
        if pattern and not re.match(pattern, raw):
            violations.append(f"Variable '{key}' invalide: '{raw}'")
        normalized_values[key] = raw

    try:
        generated = template.format(**normalized_values)
    except KeyError as exc:
        missing = str(exc).strip("'")
        violations.append(f"Variable manquante dans template: {missing}")
        generated = ""

    return {
        "group_name": generated,
        "domain": resolved_domain,
        "values": normalized_values,
        "template": template,
        "violations": violations,
        "valid": len(violations) == 0,
    }


def _extract_user_context(request: Request, policy: Dict[str, Any]) -> Dict[str, Any]:
    groups_raw = request.headers.get("x-aad-groups", "")
    groups = [g.strip().upper() for g in groups_raw.split(",") if g.strip()]
    user = request.headers.get("x-user", "anonymous")

    ac = policy.get("access_control", {}) if isinstance(policy.get("access_control"), dict) else {}
    enabled = bool(ac.get("enabled", False))
    default_role = str(ac.get("default_role", "admin"))
    role_groups = ac.get("role_groups", {}) if isinstance(ac.get("role_groups"), dict) else {}
    admin_groups = [str(g).upper() for g in role_groups.get("admin", [])]
    user_groups = [str(g).upper() for g in role_groups.get("user", [])]

    if not enabled:
        role = default_role
    elif not groups and _is_local_request(request):
        # Local dashboard runs without an upstream auth proxy.
        role = "admin"
    elif set(groups).intersection(admin_groups):
        role = "admin"
    elif set(groups).intersection(user_groups):
        role = "user"
    else:
        role = "none"

    return {
        "user": user,
        "groups": groups,
        "role": role,
        "access_control_enabled": enabled,
    }


def _is_local_request(request: Request) -> bool:
    client_host = (request.client.host if request.client else "") or ""
    if client_host in {"127.0.0.1", "::1", "localhost"}:
        return True

    try:
        if client_host and ipaddress.ip_address(client_host).is_loopback:
            return True
    except ValueError:
        pass

    for header_name in ("origin", "referer"):
        header_value = (request.headers.get(header_name) or "").lower()
        if "://localhost" in header_value or "://127.0.0.1" in header_value or "://[::1]" in header_value:
            return True

    return False


def _require_role(request: Request, allowed_roles: List[str]) -> Dict[str, Any]:
    policy = _load_policy()
    ctx = _extract_user_context(request, policy)
    if ctx["role"] not in allowed_roles:
        raise HTTPException(status_code=403, detail=f"Access denied for role '{ctx['role']}'")
    return ctx


def _infer_group_type(name_or_id: str) -> str:
    text = (name_or_id or "").upper()
    if text.endswith("-SEC") or "SEC" in text:
        return "SEC"
    if text.endswith("-ADM") or "ADMIN" in text or "ADM" in text:
        return "ADM"
    return "USR"


def _validate_group_against_policy(draft: GroupDraft, policy: Dict[str, Any]) -> Dict[str, Any]:
    violations: List[str] = []
    recommendations: List[str] = []

    domain = _resolve_domain(policy, draft.domain)
    name_values = {
        "domain": domain,
        "purpose": draft.tags.get("purpose", draft.display_name or "GENERAL"),
        "env": draft.tags.get("env", ""),
        "access": draft.group_type or _infer_group_type(draft.group_id or draft.display_name),
    }
    naming_preview = _compute_group_name(policy, domain, name_values)
    target_name = draft.group_id or draft.display_name
    if target_name and naming_preview.get("group_name") and target_name != naming_preview["group_name"]:
        violations.append(f"Nom proposé '{target_name}' différent du nom attendu '{naming_preview['group_name']}'.")
    for issue in naming_preview.get("violations", []):
        violations.append(f"Naming: {issue}")
    if naming_preview.get("violations"):
        recommendations.append("Corriger les variables de naming (domain/purpose/env/access).")

    req = policy.get("requirements", {}) if isinstance(policy.get("requirements"), dict) else {}
    owner_required = bool(req.get("owner_required", True))
    if owner_required and not draft.owner.strip():
        violations.append("Owner requis.")
        recommendations.append("Renseigner un owner (UPN/mail).")

    required_tags = req.get("tags_required", [])
    if isinstance(required_tags, list):
        missing = [tag for tag in required_tags if not str(draft.tags.get(tag, "")).strip()]
        if missing:
            violations.append(f"Tags obligatoires manquants: {', '.join(missing)}")
            recommendations.append("Compléter les tags de gouvernance obligatoires.")

    max_days = int(req.get("last_review_max_days", 90) or 90)
    if int(draft.last_review_days or 0) > max_days:
        violations.append(f"Dernière revue trop ancienne ({draft.last_review_days}j > {max_days}j).")
        recommendations.append("Forcer une revue d'accès avant approbation.")

    group_type = (draft.group_type or _infer_group_type(draft.group_id or draft.display_name)).upper()
    domain_cfg = policy.get("naming", {}).get("domains", {}).get(domain, {})
    domain_allowed_types = domain_cfg.get("allowed_group_types", []) if isinstance(domain_cfg, dict) else []
    if isinstance(domain_allowed_types, list) and domain_allowed_types and group_type not in [str(x).upper() for x in domain_allowed_types]:
        violations.append(f"Type {group_type} non autorisé pour domaine {domain}.")
        recommendations.append("Sélectionner un type de groupe autorisé pour ce domaine.")
    allowed_roles = policy.get("allowed_roles_by_group_type", {}).get(group_type, [])
    if isinstance(allowed_roles, list) and draft.role_assignments:
        not_allowed = [r for r in draft.role_assignments if r not in allowed_roles]
        if not_allowed:
            violations.append(f"Rôles non autorisés pour type {group_type}: {', '.join(not_allowed)}")
            recommendations.append("Retirer les rôles non autorisés ou changer le type du groupe.")

    forbidden_rules = policy.get("forbidden_rules", [])
    if isinstance(forbidden_rules, list):
        for rule in forbidden_rules:
            if not isinstance(rule, dict):
                continue
            scope_contains = str(rule.get("scope_contains", "")).strip()
            if scope_contains and scope_contains.lower() not in draft.scope.lower():
                continue
            forbidden_roles = rule.get("forbidden_roles", [])
            if not isinstance(forbidden_roles, list):
                continue
            allowed_types = [str(t).upper() for t in (rule.get("allowed_group_types") or [])]
            if allowed_types and group_type in allowed_types:
                continue
            hit_roles = [r for r in draft.role_assignments if r in forbidden_roles]
            if hit_roles:
                violations.append(f"Règle '{rule.get('id', 'forbidden')}' violée: {', '.join(hit_roles)}")
                recommendations.append(str(rule.get("description", "Ajuster les rôles/scopes.")))

    risk_level = "LOW"
    if len(violations) >= 4:
        risk_level = "CRITICAL"
    elif len(violations) >= 2:
        risk_level = "HIGH"
    elif len(violations) == 1:
        risk_level = "MEDIUM"

    return {
        "compliant": len(violations) == 0,
        "risk_level": risk_level,
        "violations": violations,
        "recommendations": recommendations,
        "group_type": group_type,
        "suggested_group_id": naming_preview.get("group_name", ""),
        "allowed_roles": policy.get("allowed_roles_by_group_type", {}).get(group_type, []),
    }


def _normalize_role_name(raw_role: str, role_map: Optional[Dict[str, str]] = None) -> str:
    role = str(raw_role or "").strip()
    if not role:
        return ""
    key = role.lower()
    if role_map and key in role_map:
        return role_map[key]
    return ROLE_ALIASES.get(key, role)


def _extract_role_assignments(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [part.strip() for part in value.split(",") if part.strip()]
    if isinstance(value, list):
        roles: List[str] = []
        for item in value:
            if isinstance(item, str):
                if item.strip():
                    roles.append(item.strip())
            elif isinstance(item, dict):
                candidate = (
                    item.get("role")
                    or item.get("role_name")
                    or item.get("roleDefinitionName")
                    or item.get("displayName")
                    or item.get("name")
                    or item.get("builtinRole")
                )
                if candidate:
                    roles.append(str(candidate).strip())
        return roles
    return []


def _normalize_role_map(raw_role_map: Any) -> Dict[str, str]:
    if not isinstance(raw_role_map, dict):
        return {}
    normalized: Dict[str, str] = {}
    for source, target in raw_role_map.items():
        src = str(source or "").strip().lower()
        dst = _normalize_role_name(str(target or ""))
        if src and dst:
            normalized[src] = dst
    return normalized


def _normalize_group_row(row: Dict[str, Any], role_map: Optional[Dict[str, str]] = None, idx: int = 0) -> RBACConfig:
    if not isinstance(row, dict):
        raise HTTPException(status_code=400, detail=f"Ligne groupe invalide à l'index {idx}: objet attendu")

    group_id = str(
        row.get("group_id")
        or row.get("id")
        or row.get("object_id")
        or row.get("objectId")
        or f"GROUP_{idx+1:03d}"
    ).strip()
    display_name = str(
        row.get("display_name")
        or row.get("displayName")
        or row.get("name")
        or row.get("principalDisplayName")
        or group_id
    ).strip()
    members_raw = row.get("members_count", row.get("memberCount", row.get("members", 0)))
    members_count = int(members_raw or 0)

    roles_raw = (
        row.get("role_assignments")
        or row.get("roleAssignments")
        or row.get("roles")
        or row.get("assigned_roles")
        or row.get("appRoleAssignments")
    )
    parsed_roles = _extract_role_assignments(roles_raw)
    normalized_roles: List[str] = []
    seen = set()
    for role in parsed_roles:
        canonical = _normalize_role_name(role, role_map=role_map)
        if canonical and canonical not in seen:
            normalized_roles.append(canonical)
            seen.add(canonical)

    owner = str(
        row.get("owner")
        or row.get("owner_upn")
        or row.get("ownerUpn")
        or row.get("managedBy")
        or ""
    ).strip()
    scope = str(
        row.get("scope")
        or row.get("scope_id")
        or row.get("scopeId")
        or "/"
    ).strip() or "/"

    tags_raw = row.get("tags")
    tags: Dict[str, str] = {}
    if isinstance(tags_raw, dict):
        tags = {str(k).strip(): str(v).strip() for k, v in tags_raw.items() if str(k).strip()}
    elif isinstance(tags_raw, str):
        for chunk in tags_raw.split(","):
            part = chunk.strip()
            if not part:
                continue
            if "=" in part:
                k, v = part.split("=", 1)
                if k.strip():
                    tags[k.strip()] = v.strip()
            else:
                tags[part] = "true"

    naming_raw = row.get("naming_ok", row.get("namingOk"))
    if naming_raw is None:
        naming_ok = group_id.upper().startswith(("AAD-", "GRP-"))
    elif isinstance(naming_raw, bool):
        naming_ok = naming_raw
    else:
        naming_ok = str(naming_raw).strip().lower() in {"1", "true", "yes", "ok"}

    last_review_raw = row.get("last_review_days", row.get("lastReviewDays", 0))
    try:
        last_review_days = int(last_review_raw or 0)
    except Exception:
        last_review_days = 0

    return RBACConfig(
        group_id=group_id,
        display_name=display_name,
        members_count=members_count,
        role_assignments=normalized_roles,
        owner=owner,
        scope=scope,
        tags=tags,
        naming_ok=naming_ok,
        last_review_days=last_review_days,
    )


def _config_payload() -> Dict[str, Any]:
    return {
        "roles": [{"role_name": role, "description": ROLE_DESCRIPTIONS.get(role, "")} for role in ROLES_MAPPING.keys()],
        "groups": deepcopy(CURRENT_GROUPS),
        "source": CURRENT_SOURCE,
        "last_updated": LAST_CONFIG_UPDATE,
        "total_roles": len(ROLES_MAPPING),
        "total_groups": len(CURRENT_GROUPS),
    }


def _matches_tag(group: Dict[str, Any], tag_filter: Optional[str]) -> bool:
    if not tag_filter:
        return True
    tags = group.get("tags") or {}
    if not isinstance(tags, dict):
        return False
    needle = tag_filter.strip().lower()
    if "=" in needle:
        k, v = needle.split("=", 1)
        return str(tags.get(k.strip(), "")).lower() == v.strip()
    return any(
        needle in str(k).lower() or needle in str(v).lower()
        for k, v in tags.items()
    )


def _scope_level(scope: str) -> str:
    normalized = str(scope or "/").lower()
    if "/providers/" in normalized:
        return "resource"
    if "/resourcegroups/" in normalized:
        return "resource_group"
    if "/subscriptions/" in normalized:
        return "subscription"
    return "tenant"


def _scope_level_rank(level: str) -> int:
    order = {"resource": 1, "resource_group": 2, "subscription": 3, "tenant": 4}
    return order.get(str(level or "").lower(), 99)


def _match_catalog_entry(group: Dict[str, Any], matcher: Dict[str, Any]) -> bool:
    display_name = str(group.get("display_name", ""))
    group_id = str(group.get("group_id", ""))
    roles = set(_normalize_role_name(r) for r in (group.get("role_assignments") or []))
    tags = group.get("tags") if isinstance(group.get("tags"), dict) else {}

    display_regex = str(matcher.get("display_name_regex", "")).strip()
    if display_regex and not re.search(display_regex, display_name):
        return False

    group_id_regex = str(matcher.get("group_id_regex", "")).strip()
    if group_id_regex and not re.search(group_id_regex, group_id):
        return False

    role_any = matcher.get("role_any", [])
    if isinstance(role_any, list) and role_any:
        expected = {_normalize_role_name(str(role)) for role in role_any}
        if not roles.intersection(expected):
            return False

    required_tags = matcher.get("tags", {})
    if isinstance(required_tags, dict):
        for key, value in required_tags.items():
            if str(tags.get(str(key), "")).lower() != str(value).lower():
                return False

    return True


def _resolve_governance_context(group: Dict[str, Any], policy: Dict[str, Any]) -> Dict[str, Any]:
    catalog = policy.get("group_catalog", {}) if isinstance(policy.get("group_catalog"), dict) else {}
    profiles = policy.get("governance_profiles", {}) if isinstance(policy.get("governance_profiles"), dict) else {}
    matchers = catalog.get("matchers", [])
    overrides = catalog.get("overrides", {})
    tags = deepcopy(group.get("tags") if isinstance(group.get("tags"), dict) else {})

    profile_name = ""
    profile: Dict[str, Any] = {}
    match_source = "heuristic"
    override = {}

    override_key = str(group.get("group_id", ""))
    if isinstance(overrides, dict) and isinstance(overrides.get(override_key), dict):
        override = overrides.get(override_key) or {}
        profile_name = str(override.get("profile", "")).strip()
        match_source = "catalog_override"
    elif isinstance(matchers, list):
        for entry in matchers:
            if not isinstance(entry, dict):
                continue
            matcher = entry.get("match", {})
            if not isinstance(matcher, dict):
                continue
            if _match_catalog_entry(group, matcher):
                profile_name = str(entry.get("profile", "")).strip()
                tags.update(entry.get("tags", {}) if isinstance(entry.get("tags"), dict) else {})
                match_source = f"catalog_match:{entry.get('id', 'unnamed')}"
                break

    if profile_name and isinstance(profiles.get(profile_name), dict):
        profile = deepcopy(profiles.get(profile_name) or {})

    if isinstance(override, dict):
        tags.update(override.get("tags", {}) if isinstance(override.get("tags"), dict) else {})
        for key, value in override.items():
            if key not in {"profile", "tags"}:
                profile[key] = value

    group_type = str(profile.get("group_type") or _infer_group_type(str(group.get("group_id") or group.get("display_name") or ""))).upper()
    domain = str(profile.get("domain") or tags.get("domain") or "").upper()
    env = str(profile.get("env") or tags.get("env") or "").lower()
    criticality = str(profile.get("criticality") or tags.get("criticality") or "").lower()
    max_scope_level = str(profile.get("max_scope_level") or "")

    return {
        "profile_name": profile_name,
        "profile": profile,
        "match_source": match_source,
        "group_type": group_type,
        "domain": domain,
        "env": env,
        "criticality": criticality,
        "max_scope_level": max_scope_level,
        "tags": tags,
        "recommended_controls": profile.get("recommended_controls", []) if isinstance(profile.get("recommended_controls"), list) else [],
    }


def _suggest_override_for_group(group: Dict[str, Any], policy: Dict[str, Any]) -> Dict[str, Any]:
    governance = _resolve_governance_context(group, policy)
    tags = governance.get("tags", {}) if isinstance(governance.get("tags"), dict) else {}
    roles = [_normalize_role_name(r) for r in (group.get("role_assignments") or [])]
    profile_name = str(governance.get("profile_name", "")).strip()
    reasons: List[str] = []
    confidence = "medium"

    if governance.get("match_source") == "catalog_override":
        confidence = "high"
        reasons.append("Explicit override already exists for this group.")
    elif profile_name:
        confidence = "medium" if str(governance.get("match_source", "")).startswith("catalog_match:") else "low"
        reasons.append(f"Resolved profile '{profile_name}' from {governance.get('match_source', 'matching rules')}.")
    else:
        group_type = _infer_group_type(str(group.get("group_id") or group.get("display_name") or ""))
        if any(role in {"Privileged Access Administrator", "Security Administrator", "Owner"} for role in roles):
            profile_name = "security_privileged"
            reasons.append("Privileged/security roles detected.")
            confidence = "medium"
        elif any(role in {"Contributor", "Application Administrator", "User Access Administrator"} for role in roles):
            profile_name = "finance_admin_prod" if "fin" in str(group.get("display_name", "")).lower() else "shared_user_nonprod"
            reasons.append("Administrative roles detected.")
            confidence = "low"
        else:
            profile_name = "shared_user_nonprod"
            reasons.append("Fallback to least-privileged shared profile.")
            confidence = "low"
        governance["group_type"] = group_type

    override = {
        "group_id": str(group.get("group_id", "")),
        "profile": profile_name,
        "tags": tags,
        "group_type": governance.get("group_type", ""),
        "domain": governance.get("domain", ""),
        "env": governance.get("env", ""),
        "criticality": governance.get("criticality", ""),
        "max_scope_level": governance.get("max_scope_level", ""),
    }

    return {
        "group_id": override["group_id"],
        "display_name": group.get("display_name", ""),
        "current_match_source": governance.get("match_source", ""),
        "suggested_override": override,
        "confidence": confidence,
        "reasons": reasons,
        "roles": roles,
        "owner": group.get("owner", ""),
        "scope": group.get("scope", "/"),
    }


def _apply_group_filters(
    groups: List[Dict[str, Any]],
    owner_filter: Optional[str] = None,
    tag_filter: Optional[str] = None,
    scope_filter: Optional[str] = None,
    naming_only: bool = False,
    orphan_only: bool = False,
    min_members: Optional[int] = None,
    max_members: Optional[int] = None,
) -> List[Dict[str, Any]]:
    owner_needle = (owner_filter or "").strip().lower()
    scope_needle = (scope_filter or "").strip().lower()
    out: List[Dict[str, Any]] = []
    for group in groups:
        owner = str(group.get("owner", "")).strip()
        members_count = int(group.get("members_count", 0) or 0)
        scope = str(group.get("scope", "/")).strip().lower()
        naming_ok = bool(group.get("naming_ok", True))
        if owner_needle and owner_needle not in owner.lower():
            continue
        if scope_needle and scope_needle not in scope:
            continue
        if tag_filter and not _matches_tag(group, tag_filter):
            continue
        if naming_only and not naming_ok:
            continue
        if orphan_only and owner:
            continue
        if min_members is not None and members_count < min_members:
            continue
        if max_members is not None and members_count > max_members:
            continue
        out.append(group)
    return out


def _matches_group_search(group: Dict[str, Any], search: Optional[str]) -> bool:
    if not search:
        return True
    needle = str(search).strip().lower()
    if not needle:
        return True
    tags = group.get("tags") if isinstance(group.get("tags"), dict) else {}
    roles = group.get("role_assignments") or []
    haystack = [
        group.get("group_id", ""),
        group.get("display_name", ""),
        group.get("owner", ""),
        group.get("scope", ""),
        " ".join(str(r) for r in roles),
        " ".join(f"{k}={v}" for k, v in tags.items()),
    ]
    return any(needle in str(value).lower() for value in haystack)


def _sort_groups(groups: List[Dict[str, Any]], sort_by: str = "display_name", sort_dir: str = "asc") -> List[Dict[str, Any]]:
    reverse = str(sort_dir or "asc").lower() == "desc"

    def key_func(group: Dict[str, Any]) -> Any:
        if sort_by == "members_count":
            return int(group.get("members_count", 0) or 0)
        if sort_by == "owner":
            return str(group.get("owner", "")).lower()
        if sort_by == "scope":
            return str(group.get("scope", "")).lower()
        if sort_by == "risk":
            return _group_risk_score(group).get("score", 0)
        return str(group.get("display_name", "") or group.get("group_id", "")).lower()

    return sorted(groups, key=key_func, reverse=reverse)


def _paginate_list(items: List[Any], page: int = 1, page_size: int = 50) -> Dict[str, Any]:
    safe_page_size = max(1, min(200, int(page_size or 50)))
    safe_page = max(1, int(page or 1))
    total = len(items)
    total_pages = max(1, (total + safe_page_size - 1) // safe_page_size)
    start = (safe_page - 1) * safe_page_size
    end = start + safe_page_size
    return {
        "items": items[start:end],
        "pagination": {
            "page": safe_page,
            "page_size": safe_page_size,
            "total": total,
            "total_pages": total_pages,
            "has_prev": safe_page > 1,
            "has_next": safe_page < total_pages,
        },
    }


def _group_risk_score(group: Dict[str, Any]) -> Dict[str, Any]:
    score = 0
    reasons: List[str] = []
    roles = set(group.get("role_assignments") or [])
    owner = str(group.get("owner", "")).strip()
    naming_ok = bool(group.get("naming_ok", True))
    last_review_days = int(group.get("last_review_days", 0) or 0)
    scope = str(group.get("scope", "/")).lower()
    tags = group.get("tags") if isinstance(group.get("tags"), dict) else {}
    criticality = str(tags.get("criticality", "")).lower()

    if not owner:
        score += 20
        reasons.append("No owner")
    if not naming_ok:
        score += 10
        reasons.append("Naming non compliant")
    if "owner" in roles or "global administrator" in roles:
        score += 35
        reasons.append("Critical privileged role")
    if "contributor" in roles or "security administrator" in roles:
        score += 20
        reasons.append("High privilege role")
    if "privileged access administrator" in roles:
        score += 25
        reasons.append("PIM sensitive role")
    if "/subscriptions/" in scope and "/resourcegroups/" not in scope:
        score += 15
        reasons.append("Wide subscription scope")
    if last_review_days > 90:
        score += 10
        reasons.append("Review overdue > 90d")
    if criticality == "high" and roles.intersection({"Owner", "Global Administrator", "Contributor"}):
        score += 10
        reasons.append("High criticality asset with elevated role")

    if score >= 70:
        level = "CRITICAL"
    elif score >= 45:
        level = "HIGH"
    elif score >= 20:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {"score": score, "level": level, "reasons": reasons}


def _severity_rank(level: str) -> int:
    order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    return order.get(str(level or "").upper(), 0)


def _confidence_rank(level: str) -> int:
    order = {"high": 3, "medium": 2, "low": 1}
    return order.get(str(level or "").lower(), 0)


def _make_finding(
    group: Dict[str, Any],
    finding_type: str,
    severity: str,
    title: str,
    description: str,
    recommendation: str,
    *,
    evidence: Optional[List[Dict[str, Any]]] = None,
    confidence: str = "medium",
    basis: str = "observed",
    rule_id: str = "",
) -> Dict[str, Any]:
    return {
        "group_id": group.get("group_id", ""),
        "group": group.get("display_name", ""),
        "type": finding_type,
        "severity": severity,
        "title": title,
        "description": description,
        "recommendation": recommendation,
        "confidence": confidence,
        "basis": basis,
        "rule_id": rule_id,
        "owner": group.get("owner", ""),
        "scope": group.get("scope", "/"),
        "tags": group.get("tags", {}),
        "evidence": evidence or [],
    }


def _build_group_findings(group: Dict[str, Any], policy: Dict[str, Any], source: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    governance = _resolve_governance_context(group, policy)
    roles = [_normalize_role_name(r) for r in (group.get("role_assignments") or [])]
    owner = str(group.get("owner", "")).strip()
    scope = str(group.get("scope", "/")).strip()
    scope_lower = scope.lower()
    tags = governance["tags"]
    naming_ok = bool(group.get("naming_ok", True))
    last_review_days = int(group.get("last_review_days", 0) or 0)
    group_type = governance["group_type"]
    allowed_roles = policy.get("allowed_roles_by_group_type", {}).get(group_type, [])
    req = policy.get("requirements", {}) if isinstance(policy.get("requirements"), dict) else {}
    owner_required = bool(req.get("owner_required", True))
    max_days = int(req.get("last_review_max_days", 90) or 90)
    criticality = governance["criticality"]
    env = governance["env"]
    observed_confidence = "high" if source == "azure_sync" else "medium"

    if governance["profile_name"]:
        findings.append(_make_finding(
            group,
            "governance_profile_match",
            "INFO",
            f"Profil de gouvernance {governance['profile_name']}",
            f"Le groupe correspond au profil '{governance['profile_name']}' via {governance['match_source']}.",
            "Utiliser ce profil comme base de décision et documenter les exceptions éventuelles.",
            evidence=[
                {"field": "profile_name", "value": governance["profile_name"], "source": "policy"},
                {"field": "match_source", "value": governance["match_source"], "source": "policy"},
            ],
            confidence="high" if governance["match_source"].startswith("catalog_") else "medium",
            basis="policy",
            rule_id=f"governance_profiles.{governance['profile_name']}",
        ))

    if owner_required and not owner:
        findings.append(_make_finding(
            group,
            "ownership_missing",
            "HIGH",
            "Groupe sans owner",
            "Le groupe ne déclare aucun owner alors que la policy l'exige.",
            "Renseigner au moins un owner responsable et vérifier le processus de revue.",
            evidence=[{"field": "owner", "value": owner, "source": source}],
            confidence=observed_confidence,
            basis="observed",
            rule_id="requirements.owner_required",
        ))

    if last_review_days > max_days:
        findings.append(_make_finding(
            group,
            "review_overdue",
            "MEDIUM",
            "Revue d'accès en retard",
            f"La dernière revue date de {last_review_days} jours, au-delà du seuil de {max_days} jours.",
            "Planifier une recertification des accès et mettre à jour la date de revue.",
            evidence=[
                {"field": "last_review_days", "value": last_review_days, "source": source},
                {"field": "policy_limit_days", "value": max_days, "source": "policy"},
            ],
            confidence="medium",
            basis="observed",
            rule_id="requirements.last_review_max_days",
        ))

    if not naming_ok:
        findings.append(_make_finding(
            group,
            "naming_non_compliant",
            "LOW",
            "Nomenclature non conforme",
            "Le groupe ne respecte pas la convention de nommage attendue.",
            "Renommer le groupe pour respecter le standard ou documenter une exception.",
            evidence=[{"field": "naming_ok", "value": naming_ok, "source": source}],
            confidence="low",
            basis="derived",
            rule_id="naming.template",
        ))

    privileged_roles = {"Owner", "Global Administrator", "Privileged Role Administrator", "Privileged Access Administrator"}
    elevated_roles = {"Contributor", "Security Administrator", "User Access Administrator", "Application Administrator"}

    for role_name in roles:
        if role_name in privileged_roles:
            findings.append(_make_finding(
                group,
                "privileged_role_assignment",
                "CRITICAL",
                f"Rôle privilégié {role_name}",
                f"Le groupe possède le rôle {role_name}, considéré comme hautement sensible.",
                "Vérifier si ce droit doit être remplacé par un rôle moins puissant, un scope plus réduit, ou du PIM.",
                evidence=[
                    {"field": "role_assignments", "value": role_name, "source": source},
                    {"field": "scope", "value": scope, "source": source},
                ],
                confidence=observed_confidence,
                basis="observed",
                rule_id="role_assignment.privileged",
            ))
        elif role_name in elevated_roles:
            findings.append(_make_finding(
                group,
                "elevated_role_assignment",
                "HIGH",
                f"Rôle élevé {role_name}",
                f"Le groupe possède le rôle {role_name}, avec capacité de modification significative.",
                "Confirmer la nécessité métier du rôle et réduire le scope si possible.",
                evidence=[
                    {"field": "role_assignments", "value": role_name, "source": source},
                    {"field": "scope", "value": scope, "source": source},
                ],
                confidence=observed_confidence,
                basis="observed",
                rule_id="role_assignment.elevated",
            ))

        if isinstance(allowed_roles, list) and allowed_roles and role_name not in allowed_roles:
            findings.append(_make_finding(
                group,
                "role_outside_group_type_policy",
                "HIGH",
                f"Rôle {role_name} hors policy pour type {group_type}",
                f"Le rôle {role_name} n'est pas autorisé par la policy pour le type de groupe {group_type}.",
                f"Retirer {role_name} ou requalifier explicitement le type du groupe si l'exception est valide.",
                evidence=[
                    {"field": "role_assignments", "value": role_name, "source": source},
                    {"field": "resolved_group_type", "value": group_type, "source": governance["match_source"]},
                    {"field": "allowed_roles", "value": allowed_roles, "source": "policy"},
                ],
                confidence="high" if governance["profile_name"] else "medium",
                basis="policy+catalog" if governance["profile_name"] else "policy+derived",
                rule_id=f"allowed_roles_by_group_type.{group_type}",
            ))

        if "/subscriptions/" in scope_lower and "/resourcegroups/" not in scope_lower and role_name in privileged_roles.union(elevated_roles):
            findings.append(_make_finding(
                group,
                "wide_scope_assignment",
                "HIGH",
                "Scope large sur abonnement",
                f"Le rôle {role_name} est attribué au niveau abonnement sans restriction à un resource group.",
                "Réduire le scope au resource group ou à la ressource lorsque c'est possible.",
                evidence=[
                    {"field": "scope", "value": scope, "source": source},
                    {"field": "role_assignments", "value": role_name, "source": source},
                ],
                confidence=observed_confidence,
                basis="observed",
                rule_id="scope.subscription_wide",
            ))

        if env == "prod" and criticality == "high" and role_name in {"Contributor", "Owner", "Security Administrator"}:
            findings.append(_make_finding(
                group,
                "high_criticality_exposure",
                "CRITICAL",
                "Accès élevé sur périmètre critique",
                f"Le groupe combine environnement prod, criticité élevée et rôle {role_name}.",
                "Imposer une revue manuelle, vérifier le besoin réel et privilégier un accès temporaire/PIM.",
                evidence=[
                    {"field": "tags.env", "value": env, "source": source},
                    {"field": "tags.criticality", "value": criticality, "source": source},
                    {"field": "role_assignments", "value": role_name, "source": source},
                ],
                confidence=observed_confidence,
                basis="observed+policy",
                rule_id="criticality.prod_high_privilege",
            ))

    max_scope_level = governance.get("max_scope_level", "")
    if max_scope_level and _scope_level_rank(_scope_level(scope)) > _scope_level_rank(max_scope_level):
        findings.append(_make_finding(
            group,
            "scope_exceeds_profile",
            "HIGH",
            "Scope supérieur au profil attendu",
            f"Le scope réel '{_scope_level(scope)}' dépasse le maximum '{max_scope_level}' prévu par le profil de gouvernance.",
            "Réduire le scope ou ajuster explicitement le profil si ce groupe constitue une exception approuvée.",
            evidence=[
                {"field": "actual_scope", "value": scope, "source": source},
                {"field": "actual_scope_level", "value": _scope_level(scope), "source": source},
                {"field": "max_scope_level", "value": max_scope_level, "source": "policy"},
            ],
            confidence="high" if governance["profile_name"] else "medium",
            basis="policy+observed",
            rule_id=f"governance_profiles.{governance['profile_name']}.max_scope_level" if governance["profile_name"] else "governance.max_scope_level",
        ))

    required_tags = req.get("tags_required", [])
    if isinstance(required_tags, list):
        missing = [tag for tag in required_tags if not str(tags.get(tag, "")).strip()]
        if missing:
            findings.append(_make_finding(
                group,
                "required_tags_missing",
                "MEDIUM",
                "Tags de gouvernance manquants",
                f"Le groupe ne porte pas tous les tags obligatoires: {', '.join(missing)}.",
                "Compléter les tags de gouvernance pour fiabiliser les décisions automatiques.",
                evidence=[
                    {"field": "missing_tags", "value": missing, "source": governance["match_source"]},
                    {"field": "required_tags", "value": required_tags, "source": "policy"},
                ],
                confidence="high" if governance["profile_name"] else "medium",
                basis="policy+catalog" if governance["profile_name"] else "policy+derived",
                rule_id="requirements.tags_required",
            ))

    forbidden_rules = policy.get("forbidden_rules", [])
    if isinstance(forbidden_rules, list):
        for rule in forbidden_rules:
            if not isinstance(rule, dict):
                continue
            scope_contains = str(rule.get("scope_contains", "")).strip().lower()
            if scope_contains and scope_contains not in scope_lower:
                continue
            forbidden_roles = [str(r) for r in (rule.get("forbidden_roles") or [])]
            allowed_types = [str(t).upper() for t in (rule.get("allowed_group_types") or [])]
            if allowed_types and group_type in allowed_types:
                continue
            hits = [r for r in roles if r in forbidden_roles]
            if not hits:
                continue
            findings.append(_make_finding(
                group,
                "policy_rule_violation",
                "CRITICAL",
                f"Violation de règle {rule.get('id', 'forbidden')}",
                f"Le groupe enfreint la règle de gouvernance '{rule.get('description', '')}'.",
                "Supprimer le rôle interdit ou déplacer l'attribution vers un groupe de type autorisé.",
                evidence=[
                    {"field": "forbidden_roles_hit", "value": hits, "source": source},
                    {"field": "group_type", "value": group_type, "source": governance["match_source"]},
                    {"field": "rule", "value": rule, "source": "policy"},
                ],
                confidence="high" if governance["profile_name"] else "medium",
                basis="policy+observed+catalog" if governance["profile_name"] else "policy+observed+derived",
                rule_id=str(rule.get("id", "forbidden")),
            ))

    findings.sort(key=lambda item: (-_severity_rank(item["severity"]), -_confidence_rank(item["confidence"]), item["title"]))
    return findings


def _summarize_recommendations(findings: List[Dict[str, Any]], group: Dict[str, Any]) -> List[Dict[str, Any]]:
    actions: Dict[str, Dict[str, Any]] = {}
    for finding in findings:
        action_key = finding["recommendation"]
        current = actions.get(action_key)
        candidate = {
            "group": group.get("display_name", ""),
            "group_id": group.get("group_id", ""),
            "priority": 5 - _severity_rank(finding["severity"]),
            "risk_level": finding["severity"],
            "confidence": finding["confidence"],
            "basis": finding["basis"],
            "recommended_action": finding["recommendation"],
            "why": finding["title"],
            "backed_by_rules": [finding["rule_id"]] if finding.get("rule_id") else [],
        }
        if current is None:
            actions[action_key] = candidate
            continue
        if _severity_rank(candidate["risk_level"]) > _severity_rank(current["risk_level"]):
            current["risk_level"] = candidate["risk_level"]
            current["priority"] = candidate["priority"]
            current["why"] = candidate["why"]
        if _confidence_rank(candidate["confidence"]) > _confidence_rank(current["confidence"]):
            current["confidence"] = candidate["confidence"]
        if candidate["backed_by_rules"]:
            current["backed_by_rules"] = sorted(set(current["backed_by_rules"] + candidate["backed_by_rules"]))
    return sorted(actions.values(), key=lambda item: (item["priority"], -_confidence_rank(item["confidence"])))


def _run_az_json(args: List[str]) -> Any:
    cmd = ["az", *args, "-o", "json"]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or "az command failed")
    return __import__("json").loads(proc.stdout or "null")


def _run_az_tsv(args: List[str]) -> str:
    cmd = ["az", *args, "-o", "tsv"]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or "az command failed")
    return (proc.stdout or "").strip()


def _infer_tags_from_name(name: str) -> Dict[str, str]:
    lower = name.lower()
    tags: Dict[str, str] = {}
    if any(k in lower for k in ["prod", "production", "-p-"]):
        tags["env"] = "prod"
    elif any(k in lower for k in ["dev", "sandbox", "test", "qa"]):
        tags["env"] = "dev"
    if any(k in lower for k in ["admin", "sec", "priv", "root"]):
        tags["criticality"] = "high"
    elif any(k in lower for k in ["finance", "billing"]):
        tags["criticality"] = "medium"
    else:
        tags.setdefault("criticality", "low")
    return tags

@app.get("/", summary="Documentation")
def root():
    """API RBAC Auditor - Visualisez vos matrices d'accès Azure AD"""
    return {
        "title": "RBAC Auditor for Azure Active Directory",
        "description": "Génération de fichiers d'audit pour la gouvernance des accès",
        "endpoints": {
            "/config": "Lecture de la configuration actuelle",
            "/upload-config": "Import de votre fichier CSV/JSON AD",
            "/aad/load-groups": "Alias upload AAD + mapping rôles built-in",
            "/aad/sync-azure": "Synchroniser groupes depuis Azure CLI",
            "/config/reset": "Réinitialiser vers le dataset mock",
            "/policy": "Lire/mettre à jour la policy gouvernance",
            "/policy/domains": "Lister domaines et variables de naming",
            "/policy/naming/preview": "Prévisualiser la nomenclature dynamique",
            "/policy/groups/export": "Générer un fichier de groupes depuis des drafts",
            "/policy/allowed-roles": "Rôles permis pour un type de groupe",
            "/policy/validate-group": "Valider un blueprint de groupe",
            "/policy/group-catalog": "Lire le catalogue de gouvernance et ses overrides",
            "/policy/group-catalog/suggest-overrides": "Générer des overrides explicites depuis les groupes courants",
            "/policy/group-catalog/overrides": "Appliquer des overrides de gouvernance",
            "/auth/me": "Contexte utilisateur + rôle (admin/user)",
            "/generate-matrix": "Génération de la matrice d'accès (JSON/Excel)",
            "/simulate": "Simulation d'assignation de rôle à un groupe",
            "/compliance-check": "Vérification de conformité (privilèges excessifs)",
        },
        "usage_note": "Déployable sans Azure AD connecté - données mockées par défaut"
    }

@app.get("/config", summary="Récupérer la configuration RBAC")
def get_config():
    """Affiche les rôles et groupes configurés actuels"""
    return _config_payload()


@app.get("/auth/me", summary="Contexte utilisateur (role résolu via groupes AAD)")
def auth_me(request: Request):
    policy = _load_policy()
    return {"status": "success", "context": _extract_user_context(request, policy)}


@app.get("/policy", summary="Récupérer la policy gouvernance")
def get_policy(request: Request):
    _require_role(request, ["admin", "user"])
    return {"status": "success", "policy": _load_policy()}


@app.get("/policy/group-catalog", summary="Lire le catalogue de gouvernance")
def get_group_catalog(request: Request):
    _require_role(request, ["admin", "user"])
    policy = _load_policy()
    catalog = policy.get("group_catalog", {}) if isinstance(policy.get("group_catalog"), dict) else {}
    profiles = policy.get("governance_profiles", {}) if isinstance(policy.get("governance_profiles"), dict) else {}
    return {
        "status": "success",
        "profiles": profiles,
        "catalog": catalog,
        "current_source": CURRENT_SOURCE,
        "groups_loaded": len(CURRENT_GROUPS),
    }


@app.get("/policy/group-catalog/suggest-overrides", summary="Proposer des overrides de gouvernance")
def suggest_group_catalog_overrides(request: Request, only_unmatched: bool = True):
    _require_role(request, ["admin", "user"])
    policy = _load_policy()
    suggestions: List[Dict[str, Any]] = []
    for group in CURRENT_GROUPS:
        suggestion = _suggest_override_for_group(group, policy)
        if only_unmatched and suggestion.get("current_match_source") == "catalog_override":
            continue
        suggestions.append(suggestion)
    suggestions.sort(
        key=lambda item: (
            {"high": 0, "medium": 1, "low": 2}.get(str(item.get("confidence", "low")).lower(), 9),
            item.get("display_name", ""),
        )
    )
    return {
        "status": "success",
        "total_groups": len(CURRENT_GROUPS),
        "suggestions": suggestions,
    }


@app.put("/policy/group-catalog/overrides", summary="Appliquer des overrides de gouvernance")
def put_group_catalog_overrides(payload: CatalogOverrideUpsertRequest, request: Request):
    _require_role(request, ["admin"])
    policy = _load_policy()
    catalog = policy.get("group_catalog", {}) if isinstance(policy.get("group_catalog"), dict) else {}
    overrides = catalog.get("overrides", {}) if isinstance(catalog.get("overrides"), dict) else {}
    updated = {} if payload.replace_existing else deepcopy(overrides)

    for entry in payload.overrides:
        group_id = str(entry.group_id or "").strip()
        if not group_id:
            continue
        row = {
            "profile": str(entry.profile or "").strip(),
            "tags": {str(k): str(v) for k, v in entry.tags.items() if str(k).strip()},
            "group_type": str(entry.group_type or "").strip().upper(),
            "domain": str(entry.domain or "").strip().upper(),
            "env": str(entry.env or "").strip().lower(),
            "criticality": str(entry.criticality or "").strip().lower(),
            "max_scope_level": str(entry.max_scope_level or "").strip(),
            "notes": str(entry.notes or "").strip(),
        }
        updated[group_id] = {k: v for k, v in row.items() if v not in ("", {}, [])}

    catalog["overrides"] = updated
    policy["group_catalog"] = catalog
    _save_policy(policy)

    return {
        "status": "success",
        "message": f"{len(payload.overrides)} override(s) processed",
        "total_overrides": len(updated),
        "overrides": updated,
    }


@app.put("/policy", summary="Mettre à jour la policy gouvernance")
def put_policy(policy: Dict[str, Any], request: Request):
    _require_role(request, ["admin"])
    if not isinstance(policy, dict):
        raise HTTPException(status_code=400, detail="Policy invalide (objet attendu)")
    base = _load_policy()
    for key, value in policy.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            base[key].update(value)
        else:
            base[key] = value
    _save_policy(base)
    return {"status": "success", "message": "Policy mise à jour", "policy": base}


@app.get("/policy/allowed-roles", summary="Lister les rôles autorisés pour un type de groupe")
def get_allowed_roles(request: Request, group_type: str = "USR", scope: str = "/", domain: str = ""):
    _require_role(request, ["admin", "user"])
    policy = _load_policy()
    gt = (group_type or "USR").upper()
    allowed = policy.get("allowed_roles_by_group_type", {}).get(gt, [])
    if not isinstance(allowed, list):
        allowed = []
    # Small dynamic filter based on scope (example: prevent billing roles outside subscription scope)
    if "/subscriptions/" not in scope.lower():
        allowed = [r for r in allowed if r != "Billing Reader"]
    domain_cfg = policy.get("naming", {}).get("domains", {}).get(_resolve_domain(policy, domain), {})
    if isinstance(domain_cfg, dict):
        allowed_types = [str(x).upper() for x in domain_cfg.get("allowed_group_types", [])]
        if allowed_types and gt not in allowed_types:
            allowed = []
    return {"status": "success", "group_type": gt, "scope": scope, "domain": _resolve_domain(policy, domain), "allowed_roles": allowed}


@app.get("/policy/domains", summary="Lister les domaines de nomenclature")
def get_policy_domains(request: Request):
    _require_role(request, ["admin", "user"])
    policy = _load_policy()
    naming = policy.get("naming", {}) if isinstance(policy.get("naming"), dict) else {}
    domains = naming.get("domains", {}) if isinstance(naming.get("domains"), dict) else {}
    return {
        "status": "success",
        "default_domain": _resolve_domain(policy),
        "domains": domains,
        "variables": naming.get("variables", []),
        "template": naming.get("template", ""),
    }


@app.post("/policy/naming/preview", summary="Prévisualiser un nom de groupe depuis les variables")
def preview_naming(payload: NamingPreviewRequest, request: Request):
    _require_role(request, ["admin", "user"])
    policy = _load_policy()
    result = _compute_group_name(policy, payload.domain, payload.values)
    return {"status": "success", "preview": result}


@app.post("/policy/groups/export", summary="Générer un fichier de groupes (json/csv)")
def export_groups_from_blueprint(payload: GroupExportRequest, request: Request):
    _require_role(request, ["admin", "user"])
    policy = _load_policy()
    rows: List[Dict[str, Any]] = []
    for idx, draft in enumerate(payload.groups):
        base = draft.dict()
        if not base.get("group_id"):
            values = {
                "domain": base.get("domain", ""),
                "purpose": base.get("tags", {}).get("purpose", base.get("display_name", f"GROUP{idx+1}")),
                "env": base.get("tags", {}).get("env", ""),
                "access": base.get("group_type", "USR"),
            }
            preview = _compute_group_name(policy, base.get("domain", ""), values)
            if preview.get("group_name"):
                base["group_id"] = preview["group_name"]
            if not base.get("display_name"):
                base["display_name"] = base["group_id"]
        rows.append(base)

    fmt = (payload.output_format or "json").lower()
    if fmt == "csv":
        import io
        csv_out = io.StringIO()
        fieldnames = ["group_id", "display_name", "domain", "group_type", "owner", "scope", "members_count", "role_assignments", "tags"]
        writer = csv.DictWriter(csv_out, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({
                "group_id": row.get("group_id", ""),
                "display_name": row.get("display_name", ""),
                "domain": row.get("domain", ""),
                "group_type": row.get("group_type", ""),
                "owner": row.get("owner", ""),
                "scope": row.get("scope", "/"),
                "members_count": row.get("members_count", 0),
                "role_assignments": "|".join(row.get("role_assignments", [])),
                "tags": ",".join(f"{k}={v}" for k, v in (row.get("tags", {}) or {}).items()),
            })
        return {"status": "success", "format": "csv", "filename": "group-blueprint.csv", "content": csv_out.getvalue()}
    return {"status": "success", "format": "json", "filename": "group-blueprint.json", "content": rows}


@app.post("/policy/validate-group", summary="Valider un draft de groupe contre la policy")
def validate_group(draft: GroupDraft, request: Request):
    _require_role(request, ["admin", "user"])
    policy = _load_policy()
    result = _validate_group_against_policy(draft, policy)
    return {"status": "success", "validation": result}

@app.post("/upload-config", summary="Importer configuration AD personnalisée")
async def upload_config(request: Request):
    """Charge les groupes AAD et mappe les rôles vers les built-in Azure."""
    _require_role(request, ["admin"])
    global CURRENT_GROUPS, CURRENT_SOURCE, LAST_CONFIG_UPDATE
    try:
        content_type = (request.headers.get("content-type") or "").lower()
        groups: List[RBACConfig] = []
        role_map: Dict[str, str] = {}

        if "application/json" in content_type:
            payload = await request.json()

            if isinstance(payload, dict) and isinstance(payload.get("groups"), list):
                rows = payload["groups"]
                role_map = _normalize_role_map(payload.get("role_mappings") or payload.get("role_mapping"))
            elif isinstance(payload, dict) and isinstance(payload.get("value"), list):
                rows = payload["value"]
                role_map = _normalize_role_map(payload.get("role_mappings") or payload.get("role_mapping"))
            elif isinstance(payload, list):
                rows = payload
            else:
                raise HTTPException(
                    status_code=400,
                    detail="JSON invalide: attendu liste, objet {groups: []} ou objet Graph {value: []}",
                )

            groups = [_normalize_group_row(row, role_map=role_map, idx=idx) for idx, row in enumerate(rows)]
        else:
            raw = await request.body()
            content = raw.decode("utf-8", errors="ignore")
            from io import StringIO
            reader = csv.DictReader(StringIO(content))
            groups = [_normalize_group_row(row, idx=idx) for idx, row in enumerate(reader)]

        valid_groups = [
            g for g in groups
            if g.group_id and g.display_name
        ]
        if not valid_groups:
            raise HTTPException(status_code=400, detail="Aucun groupe valide trouvé dans la payload")

        CURRENT_GROUPS = [g.dict() for g in valid_groups]
        CURRENT_SOURCE = "uploaded"
        LAST_CONFIG_UPDATE = datetime.now().isoformat()

        return {
            "status": "success",
            "message": f"{len(valid_groups)} groupes importés et mappés",
            "groups": CURRENT_GROUPS,
            "source": CURRENT_SOURCE,
            "last_updated": LAST_CONFIG_UPDATE,
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Erreur parsing configuration: {e}")


@app.post("/aad/load-groups", summary="Charger les groupes AAD + mapping built-in")
async def aad_load_groups(request: Request):
    return await upload_config(request)


@app.post("/aad/sync-azure", summary="Synchroniser la configuration depuis Azure CLI")
def aad_sync_azure(request: Request, max_groups: int = 200, workers: int = 8):
    """
    Synchronise les groupes Entra ID via Azure CLI local:
    - groups: az ad group list
    - members_count: az ad group member list
    - owners: az ad group owner list
    - role assignments + scope: az role assignment list
    """
    _require_role(request, ["admin"])
    global CURRENT_GROUPS, CURRENT_SOURCE, LAST_CONFIG_UPDATE
    if shutil.which("az") is None:
        raise HTTPException(status_code=503, detail="Azure CLI (az) introuvable sur cette machine.")

    try:
        try:
            raw_groups = _run_az_json(["ad", "group", "list", "--all"])
        except Exception:
            raw_groups = _run_az_json(["ad", "group", "list"])
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Echec récupération groupes Azure: {e}")

    if not isinstance(raw_groups, list):
        raise HTTPException(status_code=500, detail="Réponse az ad group list invalide.")

    if max_groups > 0:
        raw_groups = raw_groups[:max_groups]

    def enrich_group(row: Dict[str, Any], idx: int) -> Dict[str, Any]:
        group_id = str(row.get("id") or f"GROUP_{idx+1:03d}")
        display_name = str(row.get("displayName") or row.get("name") or group_id)

        try:
            members_count = int(_run_az_tsv(["ad", "group", "member", "list", "--group", group_id, "--query", "length(@)"]) or 0)
        except Exception:
            members_count = 0

        owner = ""
        try:
            owners = _run_az_json(["ad", "group", "owner", "list", "--group", group_id, "--query", "[].{upn:userPrincipalName,mail:mail,displayName:displayName}"])
            if isinstance(owners, list) and owners:
                top = owners[0] or {}
                owner = str(top.get("upn") or top.get("mail") or top.get("displayName") or "").strip()
        except Exception:
            owner = ""

        role_assignments: List[str] = []
        scope = "/"
        try:
            assignments = _run_az_json(["role", "assignment", "list", "--all", "--assignee-object-id", group_id, "--query", "[].{role:roleDefinitionName,scope:scope}"])
            if isinstance(assignments, list):
                scopes = []
                seen_roles = set()
                for item in assignments:
                    role_name = _normalize_role_name(str((item or {}).get("role") or ""))
                    if role_name and role_name not in seen_roles:
                        role_assignments.append(role_name)
                        seen_roles.add(role_name)
                    s = str((item or {}).get("scope") or "").strip()
                    if s:
                        scopes.append(s)
                if scopes:
                    scope = min(scopes, key=len)
        except Exception:
            pass

        naming_ok = bool(re.match(r"^(AAD-|GRP-)", group_id, flags=re.IGNORECASE))
        tags = _infer_tags_from_name(display_name)

        return RBACConfig(
            group_id=group_id,
            display_name=display_name,
            members_count=members_count,
            role_assignments=role_assignments,
            owner=owner,
            scope=scope,
            tags=tags,
            naming_ok=naming_ok,
            last_review_days=0,
        ).dict()

    safe_workers = max(1, min(32, workers))
    enriched: List[Dict[str, Any]] = [None] * len(raw_groups)  # type: ignore
    with ThreadPoolExecutor(max_workers=safe_workers) as pool:
        future_map = {
            pool.submit(enrich_group, row, idx): idx
            for idx, row in enumerate(raw_groups)
        }
        for future in as_completed(future_map):
            idx = future_map[future]
            try:
                enriched[idx] = future.result()
            except Exception:
                # fallback minimal row if one group fails
                src = raw_groups[idx] or {}
                enriched[idx] = RBACConfig(
                    group_id=str(src.get("id") or f"GROUP_{idx+1:03d}"),
                    display_name=str(src.get("displayName") or src.get("name") or f"GROUP_{idx+1:03d}"),
                    members_count=0,
                    role_assignments=[],
                    owner="",
                    scope="/",
                    tags={},
                    naming_ok=True,
                    last_review_days=0,
                ).dict()

    CURRENT_GROUPS = [g for g in enriched if g]
    CURRENT_SOURCE = "azure_sync"
    LAST_CONFIG_UPDATE = datetime.now().isoformat()
    return {
        "status": "success",
        "message": f"Azure sync OK: {len(CURRENT_GROUPS)} groupes",
        "source": CURRENT_SOURCE,
        "last_updated": LAST_CONFIG_UPDATE,
        "total_groups": len(CURRENT_GROUPS),
    }


@app.post("/config/reset", summary="Restaurer la configuration mock par défaut")
def reset_config(request: Request):
    _require_role(request, ["admin"])
    global CURRENT_GROUPS, CURRENT_SOURCE, LAST_CONFIG_UPDATE
    CURRENT_GROUPS = deepcopy(INITIAL_GROUPS)
    CURRENT_SOURCE = "default"
    LAST_CONFIG_UPDATE = datetime.now().isoformat()
    return {"status": "success", "message": "Configuration réinitialisée", "groups": CURRENT_GROUPS}

@app.post("/generate-matrix", summary="Générer matrice d'accès complète")
def generate_access_matrix(
    request: Request,
    output_format: str = "json",
    roles_filter: Optional[List[str]] = None,
    compliance_only: bool = False,
    search: Optional[str] = None,
    owner_filter: Optional[str] = None,
    tag_filter: Optional[str] = None,
    scope_filter: Optional[str] = None,
    naming_only: bool = False,
    orphan_only: bool = False,
    min_members: Optional[int] = None,
    max_members: Optional[int] = None,
    sort_by: str = "display_name",
    sort_dir: str = "asc",
    page: int = 1,
    page_size: int = 50,
):
    """
    Génère une matrice d'accès complète pour audit.
    Format de sortie:
    - JSON: fichier JSON téléchargeable
    - Excel (CSV): format compatible avec Microsoft Excel
    """
    _require_role(request, ["admin", "user"])
    config = get_config()
    normalized_filter = {_normalize_role_name(role) for role in (roles_filter or [])}
    selected_groups = _apply_group_filters(
        groups=config["groups"],
        owner_filter=owner_filter,
        tag_filter=tag_filter,
        scope_filter=scope_filter,
        naming_only=naming_only,
        orphan_only=orphan_only,
        min_members=min_members,
        max_members=max_members,
    )
    selected_groups = [group for group in selected_groups if _matches_group_search(group, search)]
    sorted_groups = _sort_groups(selected_groups, sort_by=sort_by, sort_dir=sort_dir)
    paged = _paginate_list(sorted_groups, page=page, page_size=page_size)
    paged_groups = paged["items"]

    # Construction de la matrice
    matrix = {
        "audit_metadata": {
            "generated_at": datetime.now().isoformat(),
            "tool_version": "1.0.0",
            "scope": "Azure Active Directory Groups → RBAC Roles"
        },
        "matrix": [],
        "summary": {}
    }
    
    # Générer la ligne pour chaque groupe
    for group in paged_groups:
        matrix_matrix_entry = {
            "group_id": group["group_id"],
            "display_name": group["display_name"],
            "members_count": group["members_count"],
            "owner": group.get("owner", ""),
            "scope": group.get("scope", "/"),
            "tags": group.get("tags", {}),
            "naming_ok": group.get("naming_ok", True),
            "last_review_days": group.get("last_review_days", 0),
            "roles_assigned": [],
        }
        
        # Pour chaque rôle assigné
        for role_name in group["role_assignments"]:
            if normalized_filter and role_name not in normalized_filter:
                continue
                
            matrix_matrix_entry["roles_assigned"].append({
                "role": role_name,
                "data_access_permitted": ROLES_MAPPING.get(role_name, {}).get("data_access", False),
                "config_modify_permitted": ROLES_MAPPING.get(role_name, {}).get("config_modify", False),
                "security_admin_permitted": ROLES_MAPPING.get(role_name, {}).get("security_admin", False),
                "billing_read_permitted": ROLES_MAPPING.get(role_name, {}).get("billing_read", False),
            })
        
        matrix["matrix"].append(matrix_matrix_entry)
    
    # Résumé
    scored_groups = [
        {
            "group_id": g["group_id"],
            "display_name": g["display_name"],
            **_group_risk_score(g),
        }
        for g in sorted_groups
    ]
    top_risks = sorted(scored_groups, key=lambda r: r["score"], reverse=True)[:5]
    matrix["summary"] = {
        "total_groups_analyzed": len(sorted_groups),
        "total_groups_before_filter": len(config["groups"]),
        "unique_roles_assigned": list(set(
            role for g in sorted_groups for role in g["role_assignments"]
        )),
        "privilege_risks": count_privilege_risks({"groups": sorted_groups}, matrix),
        "top_risks": top_risks,
        "applied_filters": {
            "search": search,
            "owner_filter": owner_filter,
            "tag_filter": tag_filter,
            "scope_filter": scope_filter,
            "naming_only": naming_only,
            "orphan_only": orphan_only,
            "min_members": min_members,
            "max_members": max_members,
            "sort_by": sort_by,
            "sort_dir": sort_dir,
        },
        "pagination": paged["pagination"],
    }
    
    # Retour du résultat
    response = {"status": "success", "matrix": matrix}
    return response

@app.get("/generate-matrix/json")
def generate_matrix_json():
    """Génère et retourne la matrice JSON (téléchargement direct)"""
    config = get_config()
    matrix_data = {
        "metadata": {"generated_at": datetime.now().isoformat(), "tool": "RBAC Auditor 1.0"},
        "groups": [],
        "summary": {"total_groups": len(config["groups"]), "unique_roles": list(set(role for g in config["groups"] for role in g["role_assignments"]))}
    }
    
    for group in config["groups"]:
        roles_list = []
        for role_name in group["role_assignments"]:
            info = ROLES_MAPPING.get(role_name, {})
            roles_list.append({
                "name": role_name,
                "data_access": info.get("data_access", False),
                "config_modify": info.get("config_modify", False),
                "security_admin": info.get("security_admin", False),
                "billing_read": info.get("billing_read", False),
            })
        
        matrix_data["groups"].append({
            "group_id": group["group_id"],
            "display_name": group["display_name"],
            "members_count": group["members_count"],
            "roles": roles_list
        })
    
    return matrix_data, {"filename": "rbac-matrix.json", "content_type": "application/json"}

@app.get("/simulate", summary="Simuler assignment de rôle à un groupe")
def simulate_role_assignment(
    group_id: str = "GRP003",
    role_name: str = "Contributor"
):
    """
    Simule l'ajout d'un rôle à un groupe.
    Affiche l'impact de cette attribution sur la matrice globale.
    """
    # Chercher le groupe
    group = next((g for g in CURRENT_GROUPS if g["group_id"] == group_id), None)
    if not group:
        raise HTTPException(status_code=404, detail="Groupe non trouvé")

    canonical_role = _normalize_role_name(role_name)
    role_info = ROLES_MAPPING.get(canonical_role)
    if not role_info:
        raise HTTPException(status_code=404, detail="Rôle non valide")
    
    # Simulation
    impact = {
        "action": f"Ajouter {canonical_role} au groupe {group['display_name']}",
        "current_members_count": group["members_count"],
        "new_permissions": {
            "data_access_enabled": role_info.get("data_access", False),
            "config_modify_enabled": role_info.get("config_modify", False),
            "security_admin_enabled": role_info.get("security_admin", False),
            "billing_read_enabled": role_info.get("billing_read", False)
        },
        "risk_assessment": (
            "[HIGH] RISQUE ELEVEE - acces admin/securite"
            if role_info.get("security_admin")
            else "[OK] Risque standard - acces conforme aux attentes"
            if role_info.get("data_access")
            else "[INFO] Impact limite - role de lecture uniquement"
        )
    }
    return impact

@app.get("/compliance-check", summary="Vérification de conformité et privilèges excessifs")
def compliance_check(
    request: Request,
    search: Optional[str] = None,
    owner_filter: Optional[str] = None,
    tag_filter: Optional[str] = None,
    scope_filter: Optional[str] = None,
    naming_only: bool = False,
    orphan_only: bool = False,
    min_members: Optional[int] = None,
    max_members: Optional[int] = None,
    findings_page: int = 1,
    findings_page_size: int = 50,
    findings_severity: str = "ALL",
):
    """
    Analyse les groupes pour détecter:
    - Privilèges excessifs (ex: groupe 'Comptabilité' avec Contributor)
    - Attribution à des rôles sensibles sans justification
    - Recommandations de remédiation
    """
    _require_role(request, ["admin", "user"])
    config = get_config()
    selected_groups = _apply_group_filters(
        groups=config["groups"],
        owner_filter=owner_filter,
        tag_filter=tag_filter,
        scope_filter=scope_filter,
        naming_only=naming_only,
        orphan_only=orphan_only,
        min_members=min_members,
        max_members=max_members,
    )
    selected_groups = [group for group in selected_groups if _matches_group_search(group, search)]

    policy = _load_policy()
    risks = []
    recommendations = []
    findings = []
    governance_context = []
    
    for group in selected_groups:
        group_score = _group_risk_score(group)
        governance = _resolve_governance_context(group, policy)
        governance_context.append({
            "group": group.get("display_name", ""),
            "group_id": group.get("group_id", ""),
            "profile_name": governance.get("profile_name", ""),
            "match_source": governance.get("match_source", ""),
            "group_type": governance.get("group_type", ""),
            "domain": governance.get("domain", ""),
            "env": governance.get("env", ""),
            "criticality": governance.get("criticality", ""),
            "max_scope_level": governance.get("max_scope_level", ""),
            "recommended_controls": governance.get("recommended_controls", []),
        })
        group_findings = _build_group_findings(group, policy, config.get("source", "default"))
        findings.extend(group_findings)

        for finding in group_findings:
            risks.append({
                "group": finding["group"],
                "group_id": finding["group_id"],
                "role": finding["type"],
                "risk_level": finding["severity"],
                "description": finding["description"],
                "owner": finding.get("owner", ""),
                "scope": finding.get("scope", "/"),
                "tags": finding.get("tags", {}),
                "confidence": finding.get("confidence", "medium"),
                "basis": finding.get("basis", "observed"),
                "rule_id": finding.get("rule_id", ""),
            })

        for action in _summarize_recommendations(group_findings, group):
            action["risk_score"] = group_score["score"]
            action["reasons"] = group_score["reasons"]
            recommendations.append(action)
    
    findings.sort(key=lambda item: (-_severity_rank(item["severity"]), -_confidence_rank(item["confidence"]), item["group"], item["title"]))
    severity_filter = str(findings_severity or "ALL").upper()
    filtered_findings = [
        item for item in findings
        if severity_filter == "ALL" or str(item.get("severity", "")).upper() == severity_filter
    ]
    paged_findings = _paginate_list(filtered_findings, page=findings_page, page_size=findings_page_size)
    recommendations = sorted(
        recommendations,
        key=lambda item: (item.get("priority", 99), -item.get("risk_score", 0), -_confidence_rank(item.get("confidence", "medium"))),
    )

    return {
        "status": "report_ready",
        "total_groups_scanned": len(selected_groups),
        "total_groups_before_filter": len(config["groups"]),
        "risks_detected": len(risks),
        "high_risk_count": sum(1 for r in risks if r["risk_level"] == "HIGH" or r["risk_level"] == "CRITICAL"),
        "risks": risks,
        "findings": paged_findings["items"],
        "findings_total": len(filtered_findings),
        "findings_pagination": paged_findings["pagination"],
        "recommendations": recommendations,
        "governance_context": governance_context,
        "recommendation_model": {
            "version": "2.0",
            "inputs": [
                "observed_role_assignments",
                "observed_scope",
                "observed_owner",
                "policy_rules",
                "catalog_governance_profile",
                "resolved_group_type",
            "derived_naming_compliance",
            ],
            "limitations": [
                "No Azure activity log usage yet",
                "No nested group expansion yet",
                "Some groups may still fall back to naming heuristics when no catalog match exists",
                "No PIM eligibility/activation evidence yet",
            ],
        },
        "applied_filters": {
            "search": search,
            "owner_filter": owner_filter,
            "tag_filter": tag_filter,
            "scope_filter": scope_filter,
            "naming_only": naming_only,
            "orphan_only": orphan_only,
            "min_members": min_members,
            "max_members": max_members,
            "findings_severity": findings_severity,
        },
    }

@app.get("/export", summary="Exporter la matrice complète")
def export_matrix(format: str = "csv"):
    """
    Exporte la matrice actuelle au format demandé.
    Formats supportés: csv (Excel compatible), json
    """
    config = get_config()
    rows = []
    
    for group in config["groups"]:
        # Ligne avec les permissions agrégées
        data_access = any(
            ROLES_MAPPING.get(role, {}).get("data_access", False)
            for role in group["role_assignments"]
        ) if group["role_assignments"] else False
        
        row = {
            "Group_ID": group["group_id"],
            "Group_Display_Name": group["display_name"],
            "Members_Count": group["members_count"],
            "Role_1": group["role_assignments"][0] if group["role_assignments"] else "",
            "Role_2": group["role_assignments"][1] if len(group["role_assignments"]) > 1 else "",
            "Permission_Data_Access": data_access,
            "Permission_Config_Modify": any(
                ROLES_MAPPING.get(role, {}).get("config_modify", False)
                for role in group["role_assignments"]
            ) if group["role_assignments"] else False,
            "Permission_Security_Admin": any(
                ROLES_MAPPING.get(role, {}).get("security_admin", False)
                for role in group["role_assignments"]
            ) if group["role_assignments"] else False,
            "Permitted_Billing_Read": any(
                ROLES_MAPPING.get(role, {}).get("billing_read", False)
                for role in group["role_assignments"]
            ) if group["role_assignments"] else False
        }
        rows.append(row)
    
    if format == "csv":
        # Convertir en CSV simple (Excel compatible)
        import io
        csv_output = io.StringIO()
        fieldnames = list(rows[0].keys())
        writer = csv.DictWriter(csv_output, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
        return csv_output.getvalue(), {"content_type": "text/csv", "filename": "rbac_matrix.csv"}
    else:
        # JSON
        import json
        return json.dumps(rows, indent=2), {"content_type": "application/json", "filename": "rbac_matrix.json"}

def count_privilege_risks(config, matrix):
    """Compte les privilèges risqués (simplifié)"""
    risky_roles = {"Privileged Access Administrator", "Privileged Role Administrator", "Security Administrator", "Global Administrator", "Owner", "Contributor"}
    count = 0
    for group in config["groups"]:
        count += sum(1 for role in group["role_assignments"] if role in risky_roles)
    return {"total_privilege_risks": count}

if __name__ == "__main__":
    import uvicorn
    print("🚀 RBAC Auditor starting on http://0.0.0.0:8000")
    uvicorn.run(app, host="0.0.0.0", port=8000)
