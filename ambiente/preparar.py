#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Citizen Tech Market (DevSecOps v2) - prepara o ambiente UNICO do aluno a partir do RM."""
import json
import os
import shutil
import subprocess
import sys

AQUI = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, AQUI)
import ctcomum as ct  # noqa: E402

GS = "/opt/gs"
APP = os.path.join(GS, "app")
MODELO = os.path.join(AQUI, "modelo")
ENV_GIT = dict(os.environ, GIT_AUTHOR_NAME="Equipe Market", GIT_AUTHOR_EMAIL="dev@citizen.tech",
               GIT_COMMITTER_NAME="Equipe Market", GIT_COMMITTER_EMAIL="dev@citizen.tech")


def sh(args, cwd=None, env=None):
    subprocess.run(args, cwd=cwd, env=env, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def render(texto, p):
    for k, v in p.items():
        texto = texto.replace("@@%s@@" % k, v)
    return texto


def copiar(origem_dir, destino_dir, p, pular=()):
    for base, pastas, nomes in os.walk(origem_dir):
        pastas[:] = [d for d in pastas if d not in pular]
        for nome in nomes:
            origem = os.path.join(base, nome)
            rel = render(os.path.relpath(origem, origem_dir), p)
            destino = os.path.join(destino_dir, rel)
            os.makedirs(os.path.dirname(destino), exist_ok=True)
            with open(origem, encoding="utf-8") as f:
                conteudo = render(f.read(), p)
            with open(destino, "w", encoding="utf-8") as f:
                f.write(conteudo)


def main():
    if len(sys.argv) < 2 or not sys.argv[1].isdigit():
        sys.exit("Uso: sudo ./preparar_ambiente.sh <RM>   (somente numeros)")
    rm = sys.argv[1]
    refazer = "--refazer" in sys.argv
    if os.geteuid() != 0:
        sys.exit("Execute como root (sudo).")
    for cmd in ("git", "openssl"):
        if not shutil.which(cmd):
            sys.exit("Instale o '%s' antes de preparar o ambiente (apt install %s)." % (cmd, cmd))
    if os.path.exists(APP):
        if not refazer:
            sys.exit("O ambiente ja existe em %s. Para recriar (apaga /opt/gs/app): acrescente --refazer" % APP)
        shutil.rmtree(APP)

    p = ct.parametros(rm)
    for d in ("threat-model", "reports", "esteira"):
        os.makedirs(os.path.join(GS, d), exist_ok=True)

    # 1) historico git: credenciais que foram "removidas" em um commit posterior
    os.makedirs(APP)
    sh(["git", "init", "-q", "-b", "main"], cwd=APP)
    copiar(os.path.join(MODELO, "_historico"), APP, p)
    with open(os.path.join(APP, "README.md"), "w") as f:
        f.write("# Citizen Tech Market\n")
    sh(["git", "add", "-A"], cwd=APP)
    sh(["git", "commit", "-q", "-m", "estrutura inicial do projeto",
        "--date", "2026-03-02T10:00:00"], cwd=APP, env=ENV_GIT)
    sh(["git", "rm", "-q", "-r", "infra", "docs"], cwd=APP)
    sh(["git", "commit", "-q", "-m", "remove arquivos de infraestrutura do repositorio",
        "--date", "2026-03-09T16:30:00"], cwd=APP, env=ENV_GIT)

    # 2) aplicacao
    copiar(MODELO, APP, p, pular=("_historico",))
    chave = os.path.join(APP, "deploy", "id_rsa")
    sh(["openssl", "genrsa", "-out", chave, "2048"])
    sh(["git", "add", "-A"], cwd=APP)
    sh(["git", "commit", "-q", "-m", "versao 1.0 do marketplace",
        "--date", "2026-04-20T09:15:00"], cwd=APP, env=ENV_GIT)

    # 3) modelo de ameacas e ficha do ambiente
    shutil.copy(os.path.join(AQUI, "threat-model", "dfd.json"), os.path.join(GS, "threat-model", "dfd.json"))
    with open(os.path.join(GS, ".ambiente.json"), "w") as f:
        json.dump({"rm": rm, "versao": 2}, f)
    with open(os.path.join(GS, "MEU_AMBIENTE.txt"), "w", encoding="utf-8") as f:
        f.write(
            "GLOBAL SOLUTION - CITIZEN TECH MARKET (DevSecOps)\n"
            "Ambiente exclusivo do RM %(RM)s - os relatorios de outro aluno NAO sao aceitos.\n\n"
            "Aplicacao ...............: /opt/gs/app\n"
            "Porta da aplicacao ......: %(PORTA)s\n"
            "Nome/tag da imagem ......: %(IMAGEM)s\n"
            "Modelo de ameacas (DFD) .: /opt/gs/threat-model/dfd.json\n"
            "Relatorios (JSON) .......: /opt/gs/reports/\n"
            "Repositorio da esteira ..: /opt/gs/esteira\n" % p)

    dono = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    if all(dono):
        sh(["chown", "-R", "%s:%s" % dono, GS])
    sh(["chmod", "-R", "a+rwX", GS])
    print("[+] Ambiente do RM %s preparado." % rm)
    print(open(os.path.join(GS, "MEU_AMBIENTE.txt"), encoding="utf-8").read())


if __name__ == "__main__":
    main()
