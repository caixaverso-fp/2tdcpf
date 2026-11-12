#!/usr/bin/env bash
# GLOBAL SOLUTION - CITIZEN TECH MARKET (DevSecOps v2)
# Prepara o ambiente EXCLUSIVO do aluno. Uso:  sudo ./preparar_ambiente.sh <RM>
# Requer: python3, git e openssl. Nao instala ferramentas de seguranca (responsabilidade do aluno).
AQUI="$(cd "$(dirname "$0")" && pwd)"
command -v python3 >/dev/null 2>&1 || { echo "python3 e necessario."; exit 1; }
exec python3 "$AQUI/preparar.py" "$@"
