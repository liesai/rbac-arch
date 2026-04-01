#!/bin/bash
# Script de lancement RBAC Auditor (simplifié)

echo "🚀 Démarrage RBAC Auditor pour Azure AD"
echo ""
echo "Lecture configuration initiale..."
echo "Rôles pré-configurés : Contributor, Reader, User Creator, Privileged Access Administrator, Application Operator"
echo ""
echo "Démarrage serveur local..."

python3 /home/node/.openclaw/workspace/rbac-auditor/app.py &

PID=$!

echo ""
echo "Serveur démarré (PID: $PID)"
echo "Accédez à : http://localhost:8000"
echo ""
echo "Arrêt rapide : kill \$PID"
wait $PID
