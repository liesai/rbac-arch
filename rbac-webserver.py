#!/usr/bin/env python3
"""
RBAC Auditor Web Server
Simplified HTTP endpoints serving RBAC audit data.
No external dependencies required.
Usage: python3 rbac-webserver.py
"""

import json
from http.server import HTTPServer, SimpleHTTPRequestHandler
from datetime import datetime
import sys
import os
import argparse

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# RBAC Roles configuration
ROLES = {
    "Contributor": {
        "description": "Admin complete (sans abonnements)",
        "data_access": True,
        "config_modify": True,
        "security_admin": False,
        "billing_read": True
    },
    "Reader": {
        "description": "Lecture seule complète",
        "data_access": False,
        "config_modify": False,
        "security_admin": False,
        "billing_read": True
    },
    "User Creator": {
        "description": "Creation utilisateurs",
        "data_access": False,
        "config_modify": True,
        "security_admin": False,
        "billing_read": False
    },
    "Privileged Access Administrator": {
        "description": "Gestion acces PIM",
        "data_access": False,
        "config_modify": True,
        "security_admin": True,
        "billing_read": False
    },
    "Application Operator": {
        "description": "Gestion applications AD",
        "data_access": False,
        "config_modify": True,
        "security_admin": False,
        "billing_read": False
    }
}

# Azure AD Groups configuration
GROUPS = [
    {
        "group_id": "GRP001",
        "display_name": "Admins Globaux",
        "members_count": 3,
        "role_assignments": ["Contributor", "Privileged Access Administrator"]
    },
    {
        "group_id": "GRP002",
        "display_name": "Comptabilite",
        "members_count": 8,
        "role_assignments": ["Reader", "User Creator"]
    },
    {
        "group_id": "GRP003",
        "display_name": "Developpeurs DevOps",
        "members_count": 12,
        "role_assignments": ["Contributor"]
    }
]

# In-memory cache for generated matrices
_cache = {
    "last_generated": None,
    "matrix_data": None,
    "risks": []
}

def get_matrix(roles_filter=None):
    """Generate RBAC access matrix"""
    global _cache
    
    # Check cache first (5 minute expiry)
    if _cache["last_generated"] and (_cache["last_generated"] + 300) > datetime.now():
        return _cache["matrix_data"], True
    
    matrix = {
        "metadata": {
            "generated_at": datetime.now().isoformat(),
            "tool": "RBAC Auditor Web Server",
            "scope": "Azure Active Directory Groups -> RBAC Roles"
        },
        "groups": [],
        "summary": {}
    }
    
    # Filter roles if specified
    target_roles = [r for r in ROLES if r not in roles_filter] if roles_filter else ROLES
    
    for group in GROUPS:
        group_roles = []
        for role_name in group["role_assignments"]:
            if target_roles and role_name not in target_roles:
                continue
            role_info = ROLES.get(role_name, {})
            group_roles.append({
                "name": role_name,
                "data_access": role_info.get("data_access", False),
                "config_modify": role_info.get("config_modify", False),
                "security_admin": role_info.get("security_admin", False),
                "billing_read": role_info.get("billing_read", False)
            })
        
        matrix["groups"].append({
            "group_id": group["group_id"],
            "display_name": group["display_name"],
            "members_count": group["members_count"],
            "roles": group_roles
        })
    
    # Summary
    risky_roles = ["Privileged Access Administrator", "Contributor"]
    risk_count = sum(1 for g in GROUPS for role in g["role_assignments"] if role in risky_roles)
    matrix["summary"] = {
        "total_groups": len(GROUPS),
        "unique_roles": list(set(role for g in GROUPS for role in g["role_assignments"])),
        "risk_level": "HIGH" if risk_count > 2 else "LOW",
        "high_risk_roles": risk_count
    }
    
    # Cache result
    _cache["matrix_data"] = matrix
    _cache["last_generated"] = datetime.now()
    return matrix, False

def get_risks():
    """Get compliance risks analysis"""
    global _cache
    
    if not _cache.get("risks"):
        risks = []
        for group in GROUPS:
            for role_name in group["role_assignments"]:
                if role_name == "Contributor":
                    risk_entry = {
                        "group_id": group["group_id"],
                        "display_name": group["display_name"],
                        "role": role_name,
                        "risk_level": "HIGH",
                        "description": f"Group '{group['display_name']}' has Contributor (can modify all resources except subscriptions)."
                    }
                    risks.append(risk_entry)
                elif role_name == "Privileged Access Administrator":
                    risk_entry = {
                        "group_id": group["group_id"],
                        "display_name": group["display_name"],
                        "role": role_name,
                        "risk_level": "CRITICAL",
                        "description": f"Privileged Access Administrator detected on group '{group['display_name']}'."
                    }
                    risks.append(risk_entry)
                elif role_name == "User Creator":
                    risk_entry = {
                        "group_id": group["group_id"],
                        "display_name": group["display_name"],
                        "role": role_name,
                        "risk_level": "MEDIUM",
                        "description": f"User Creator role assigned to '{group['display_name']}'. Verify justification."
                    }
                    risks.append(risk_entry)
        
        _cache["risks"] = {
            "total_groups_scanned": len(GROUPS),
            "high_risk_count": sum(1 for r in risks if r["risk_level"] in ["HIGH", "CRITICAL"]),
            "total_risks": len(risks),
            "risks": risks,
            "recommendations": [{
                "priority": 1 if any(r["risk_level"] == "CRITICAL" for r in risks) else 2,
                "suggestion": "Audit manually the flagged groups."
            }]
        }
    
    return _cache["risks"]


class RBACHandler(SimpleHTTPRequestHandler):
    """Custom HTTP handler for RBAC auditor endpoints"""
    
    def do_GET(self):
        """Handle GET requests for API endpoints"""
        path = self.path.split("?", 1)[0] if "?" in self.path else self.path
        
        if path == "/" or path == "/health":
            # Health check and home page
            response = {
                "service": "RBAC Auditor Web Server",
                "status": "running",
                "version": "1.0.0",
                "endpoints": {
                    "/": "API documentation",
                    "/matrix": "Get access matrix (all roles)",
                    "/matrix?roles=Contributor,Reader":"Get filtered matrix",
                    "/risks": "Compliance risks analysis",
                    "/export.json": "Download full JSON export"
                },
                "note": "No Azure AD connection required - uses mock data by default"
            }
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(response, indent=2).encode())
            
        elif path == "/matrix":
            # Get matrix
            roles_filter = None
            if "roles" in self.query_string:
                roles_filter = self.query_string.split("=")[1].replace("&", "").split(",")
            
            data, from_cache = get_matrix(roles_filter)
            response = {"status": "success", "from_cache": from_cache, "data": data}
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(response, indent=2).encode())
            
        elif path == "/risks":
            # Get compliance risks
            data = get_risks()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(data, indent=2).encode())
            
        elif path == "/export.json":
            # Export full JSON file
            matrix_data, _ = get_matrix(None)
            risks_data = get_risks()
            combined = {
                "rbac_audit_export": True,
                "metadata": matrix_data["metadata"],
                "groups": matrix_data["groups"],
                "summary": matrix_data["summary"],
                "compliance_risks": risks_data,
                "generated_at": datetime.now().isoformat()
            }
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Disposition", 'filename="rbac_audit_export.json"')
            self.end_headers()
            self.wfile.write(json.dumps(combined, indent=2).encode())
            
        else:
            # Fallback to static file serving
            super().do_GET()
    
    def log_message(self, format, *args):
        """Log with timestamp"""
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {self.client_address[0]} - {format % args}")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="RBAC Auditor Web Server")
    parser.add_argument("--host", default="0.0.0.0", help="Bind address (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8010, help="Port number (default: 8010)")
    parser.add_argument("--reloading", action="store_true", help="Enable auto-reload (not implemented yet)")
    
    args = parser.parse_args()
    
    server_address = (args.host, args.port)
    httpd = HTTPServer(server_address, RBACHandler)
    
    print("\n" + "="*60)
    print("🚀 RBAC AUDITOR WEB SERVER")
    print("="*60 + "\n")
    print(f"✅ Server listening on: {args.host}:{args.port}")
    print(f"   Full URL: http://{args.host}:{args.port}/")
    print()
    print("📋 Available endpoints:")
    print("   /               → API documentation")
    print("   /matrix         → Get access matrix")
    print("   /matrix?roles=X → Get filtered matrix")
    print("   /risks          → Compliance risks analysis")
    print("   /export.json    → Download full JSON export")
    print()
    print("⚙️  Using mock Azure AD data by default")
    print("="*60 + "\n")
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n\n👋 Shutting down server...")
        httpd.shutdown()


if __name__ == "__main__":
    main()
