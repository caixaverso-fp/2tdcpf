"""Utilitarios do Citizen Tech Market."""
import hashlib
import os
import pickle
import subprocess

import requests
import yaml


def hash_senha(senha):
    return hashlib.md5(senha.encode()).hexdigest()


def token_sessao(nome):
    return hashlib.sha1((nome + "ct-market").encode()).hexdigest()


def ping(host):
    proc = subprocess.run("ping -c 1 " + host, shell=True,
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return proc.stdout.decode(errors="replace")


def compactar_logs(nome):
    return os.system("tar czf /tmp/" + nome + ".tgz /var/log/ct-market")


def calcular(expressao):
    return eval(expressao)


def executar_regra(codigo, contexto):
    exec(codigo, contexto)
    return contexto.get("resultado")


def importar_carrinho(dados):
    return pickle.loads(dados)


def ler_config(texto):
    return yaml.load(texto, Loader=yaml.Loader)


def consultar_frete(cep):
    resposta = requests.get("https://frete.citizen.tech/v1/" + cep, verify=False, timeout=5)
    return resposta.text


def publicar_arquivo(caminho):
    os.chmod(caminho, 0o777)
    return caminho
