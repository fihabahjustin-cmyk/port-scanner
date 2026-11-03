# Port Scanner CLI

Scanner de ports TCP en Python, avec parallélisation par threads.

## ⚠️ Usage responsable
À utiliser uniquement sur des machines/réseaux dont vous êtes propriétaire
ou pour lesquels vous avez une autorisation explicite. Scanner un système
tiers sans autorisation est illégal dans la plupart des juridictions.

## Installation
\`\`\`bash
python3 -m venv venv
source venv/bin/activate
\`\`\`
(aucune dépendance externe : tout vient de la bibliothèque standard Python)

## Utilisation
\`\`\`bash
python3 main.py <host> [--ports 1-1024] [--timeout 1.0] [--workers 100]
\`\`\`

Exemple :
\`\`\`bash
python3 main.py 127.0.0.1 --ports 1-1000
\`\`\`
