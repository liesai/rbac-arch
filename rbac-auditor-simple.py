#!/usr/bin/env python3
"""
RBAC Auditor - Prototype Standalone
Génération de matrices d'accès Azure AD pour gouvernance des rôles RBAC.
Déployable sans dépendances externes.
Usage : python3 rbac-auditor-simple.py
"""

from datetime import datetime
import json

# Configuration initiale des rôles Azure RBAC
ROLES = {
    "Contributor": {"description": "Admin complet (sauf abonnements)", 
                    "data_access": True, "config_modify": True, 
                    "security_admin": False, "billing_read": True},
    "Reader": {"description": "Lecture seule complète",
               "data_access": False, "config_modify": False,
               "security_admin": False, "billing_read": True},
    "User Creator": {"description": "Création utilisateurs",
                     "data_access": False, "config_modify": True,
                     "security_admin": False, "billing_read": False},
    "Privileged Access Administrator": {"description": "Gestion accès PIM",
                                        "data_access": False, "config_modify": True,
                                        "security_admin": True, "billing_read": False},
    "Application Operator": {"description": "Gestion applications AD",
                             "data_access": False, "config_modify": True,
                             "security_admin": False, "billing_read": False},
}

# Groupe Azure AD par défaut
GROUPS = [
    {"group_id": "GRP001", "display_name": "Admins Globaux", 
     "members_count": 3, "role_assignments": ["Contributor", "Privileged Access Administrator"]},
    {"group_id": "GRP002", "display_name": "Comptabilité",
     "members_count": 8, "role_assignments": ["Reader", "User Creator"]},
    {"group_id": "GRP003", "display_name": "Développeurs DevOps",
     "members_count": 12, "role_assignments": ["Contributor"]},
]

def generate_matrix(roles_filter=None):
    """Génère la matrice d'accès"""
    matrix = {
        "metadata": {
            "generated_at": datetime.now().isoformat(),
            "tool": "RBAC Auditor Standalone",
            "scope": "Azure Active Directory Groups → RBAC Roles"
        },
        "groups": [],
        "summary": {}
    }
    
    # Filtrer les rôles si nécessaire
    roles = [r for r in ROLES if r not in roles_filter] if roles_filter else ROLES
    
    for group in GROUPS:
        group_roles = []
        for role_name in group["role_assignments"]:
            if roles and role_name not in roles:
                continue
            role_info = ROLES.get(role_name, {})
            group_roles.append({
                "name": role_name,
                "data_access": role_info.get("data_access", False),
                "config_modify": role_info.get("config_modify", False),
                "security_admin": role_info.get("security_admin", False),
                "billing_read": role_info.get("billing_read", False),
            })
        
        matrix["groups"].append({
            "group_id": group["group_id"],
            "display_name": group["display_name"],
            "members_count": group["members_count"],
            "roles": group_roles
        })
    
    # Résumé
    matrix["summary"] = {
        "total_groups": len(GROUPS),
        "unique_roles": list(set(role for g in GROUPS for role in g["role_assignments"])),
        "risk_level": "LOW" if sum(1 for g in GROUPS 
            for role in ["Privileged Access Administrator", "Contributor"])
            <= 2 else "HIGH"
    }
    return matrix

def save_json(data, filename="rbac_matrix.json"):
    """Sauvegarde en JSON formaté"""
    with open(f"./{filename}", "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"✅ Matrice sauvegardée : {filename}")
    return data

def simulate_assignment(group_id, role_name):
    """Simule une attribution de rôle"""
    group = next((g for g in GROUPS if g["group_id"] == group_id), None)
    if not group:
        print(f"❌ Groupe {group_id} non trouvé")
        return
    
    risk_level = "⚠️ RISQUE ÉLEVÉ" if role_name in ["Privileged Access Administrator", "Contributor"] else "✅ Risque standard"
    impact = f"Ajouter {role_name} au groupe {group['display_name']} → {risk_level}"
    
    print(f"\n📊 Simulation : {impact}")
    print(f"   Membres affectés : {group['members_count']}")
    print(f"   Accès données : {ROLES.get(role_name, {}).get('data_access', False)}")
    return impact

def main():
    """
    RBAC Auditor - Prototype fonctionnel
    Génération de visibilité sur les modèles d'accès Azure AD.
    
    Usage :
        python3 rbac-auditor-simple.py --generate  # Générer et sauvegarder
        python3 rbac-auditor-simple.py --simulate GRP003 Contributor  # Simulation
        python3 rbac-auditor-simple.py --help       # Aide complète
    """
    import argparse
    
    parser = argparse.ArgumentParser(description="RBAC Auditor - Gouvernance accès Azure AD")
    parser.add_argument("--generate", action="store_true", help="Générer matrice d'accès")
    parser.add_argument("--simulate", nargs=2, metavar=["GROUP_ID", "ROLE"], 
                        help="Simuler attribution de rôle à un groupe")
    parser.add_argument("--export", metavar="FILE", help="Exporter fichier JSON/CSV spécifique")
    parser.add_argument("--roles", nargs="*", metavar="[ROL1,ROL2]", help="Filtrer rôles (ex: Contributor,Reader)")
    
    args = parser.parse_args()
    
    if args.simulate:
        simulate_assignment(args.simulate[0], args.simulate[1])
    elif args.export:
        save_json(generate_matrix(args.roles), args.export)
    else:
        # Action par défaut : générer et afficher
        matrix = generate_matrix(args.roles)
        
        print("\n" + "="*60)
        print("📋 RBAC AUDITOR - MATRICE D'ACCÈS AZURE AD")
        print("="*60 + "\n")
        
        # Affichage formaté
        print(f"Généré le : {matrix['metadata']['generated_at']}")
        print(f"Total groupes analysés : {len(matrix['groups'])}")
        print()
        
        for group in matrix["groups"]:
            print(f"🔹 Groupe : {group['display_name']} ({group['members_count']} membres)")
            if group["roles"]:
                for role in group["roles"]:
                    status = "✅" if not role["security_admin"] else "⚠️"
                    data_str = "(💾 Accès données)" if role["data_access"] else "(🔒 Pas d'accès données)"
                    print(f"   {status} {role['name']}: {data_str}")
            print()
        
        summary = matrix["summary"]
        risk_symbol = "⚠️" if summary["risk_level"] == "HIGH" else "✅"
        print("="*60)
        print(f"Résumé : {len(summary['unique_roles'])} rôles uniques")
        print(f"Niveau risque : {risk_symbol} {summary['risk_level']}")
        print("="*60 + "\n")
        
        # Sauvegarder automatiquement
        save_json(matrix, "rbac_matrix.json")

if __name__ == "__main__":
    main()
