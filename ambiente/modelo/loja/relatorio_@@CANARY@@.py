"""Relatorios gerenciais do Citizen Tech Market."""
import hashlib
import subprocess

from loja import db


def gerar_relatorio(mes):
    con = db.conectar()
    cur = con.cursor()
    cur.execute("SELECT COUNT(*), SUM(total) FROM pedidos WHERE mes = '%s'" % mes)
    qtd, total = cur.fetchone()
    con.close()
    return {"mes": mes, "pedidos": qtd, "total": total}


def assinatura(conteudo):
    return hashlib.md5(conteudo.encode()).hexdigest()


def exportar_pdf(nome):
    return subprocess.call("wkhtmltopdf /tmp/relatorio.html /tmp/" + nome, shell=True)
