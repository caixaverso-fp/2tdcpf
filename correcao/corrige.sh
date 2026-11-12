#!/usr/bin/env bash
# GLOBAL SOLUTION - CITIZEN TECH MARKET (DevSecOps) - corretor automatico
# Uso:  sudo ./corrige.sh <RM> ["Nome Completo"]
AQUI="$(cd "$(dirname "$0")" && pwd)"
command -v python3 >/dev/null 2>&1 || { echo "python3 e necessario para o corretor."; exit 1; }
python3 -c "import yaml" 2>/dev/null || { echo "[!] Instalando python3-yaml (necessario para avaliar a esteira)..."; apt-get install -y python3-yaml >/dev/null 2>&1 || echo "    nao foi possivel instalar; a Q06 nao sera avaliada."; }
exec python3 "$AQUI/corrige.py" "$@"
