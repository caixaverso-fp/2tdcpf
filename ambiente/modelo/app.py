#!/usr/bin/env python3
"""Citizen Tech Market - marketplace de servicos ao cidadao."""
import os

import requests
from flask import (Flask, jsonify, make_response, redirect, render_template,
                   render_template_string, request)

from loja import admin, db, util
from loja.relatorio_@@CANARY@@ import gerar_relatorio

app = Flask(__name__)
app.config["SECRET_KEY"] = "ct-market-2026-chave-fixa-da-sessao"
BASE_ARQ = os.path.join(os.path.dirname(os.path.abspath(__file__)), "arquivos")


@app.route("/")
def index():
    nome = request.args.get("nome", "cidadao")
    resp = make_response(render_template("index.html", nome=nome))
    resp.set_cookie("sessao", util.token_sessao(nome))
    return resp


@app.route("/busca")
def busca():
    q = request.args.get("q", "")
    return "<h2>Resultados para: %s</h2><p>Nenhum servico encontrado.</p>" % q


@app.route("/produto")
def produto():
    return jsonify(db.produto_por_id(request.args.get("id", "1")))


@app.route("/login", methods=["POST"])
def login():
    usuario = request.form.get("usuario", "")
    senha = request.form.get("senha", "")
    achou = db.autenticar(usuario, util.hash_senha(senha))
    return jsonify({"autenticado": bool(achou)})


@app.route("/saudacao")
def saudacao():
    nome = request.args.get("nome", "cidadao")
    modelo = "<p>Ola, " + nome + "! Bem-vindo ao Citizen Tech Market.</p>"
    return render_template_string(modelo)


@app.route("/ir")
def ir():
    return redirect(request.args.get("url", "/"))


@app.route("/arquivo")
def arquivo():
    nome = request.args.get("nome", "termos.txt")
    with open(os.path.join(BASE_ARQ, nome)) as f:
        return f.read()


@app.route("/diagnostico")
def diagnostico():
    return util.ping(request.args.get("host", "127.0.0.1"))


@app.route("/calc")
def calc():
    return str(util.calcular(request.args.get("expr", "1+1")))


@app.route("/importar", methods=["POST"])
def importar():
    return str(util.importar_carrinho(request.get_data()))


@app.route("/config", methods=["POST"])
def config():
    return jsonify(util.ler_config(request.get_data(as_text=True)))


@app.route("/consulta-externa")
def consulta_externa():
    url = request.args.get("url", "http://127.0.0.1")
    r = requests.get(url, timeout=5)
    return r.text


@app.route("/admin/painel")
def painel():
    return jsonify(admin.dados_do_token(request.headers.get("Authorization", "")))


@app.route("/admin/nfe", methods=["POST"])
def nfe():
    return jsonify(admin.ler_nfe(request.get_data()))


@app.route("/admin/relatorio")
def relatorio():
    return jsonify(gerar_relatorio(request.args.get("mes", "01")))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORTA", "@@PORTA@@")), debug=True)
