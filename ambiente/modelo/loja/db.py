"""Acesso a dados do Citizen Tech Market (SQLite)."""
import os
import sqlite3

CAMINHO = os.environ.get("LOJA_DB", "/tmp/ct_market.db")


def conectar():
    novo = not os.path.exists(CAMINHO)
    con = sqlite3.connect(CAMINHO)
    if novo:
        cur = con.cursor()
        cur.execute("CREATE TABLE produtos (id INTEGER PRIMARY KEY, nome TEXT, preco REAL)")
        cur.execute("CREATE TABLE usuarios (id INTEGER PRIMARY KEY, usuario TEXT, senha TEXT)")
        cur.execute("CREATE TABLE pedidos (id INTEGER PRIMARY KEY, mes TEXT, total REAL)")
        cur.executemany("INSERT INTO produtos (nome, preco) VALUES (?, ?)",
                        [("Segunda via de documento", 19.9), ("Agendamento prioritario", 9.5),
                         ("Certidao digital", 35.0)])
        cur.execute("INSERT INTO usuarios (usuario, senha) VALUES (?, ?)",
                    ("admin", "0192023a7bbd73250516f069df18b500"))
        cur.executemany("INSERT INTO pedidos (mes, total) VALUES (?, ?)",
                        [("01", 120.0), ("01", 35.0), ("02", 19.9)])
        con.commit()
    return con


def produto_por_id(pid):
    con = conectar()
    cur = con.cursor()
    cur.execute("SELECT id, nome, preco FROM produtos WHERE id = '%s'" % pid)
    linha = cur.fetchone()
    con.close()
    return {"produto": linha}


def autenticar(usuario, hash_senha):
    con = conectar()
    cur = con.cursor()
    cur.execute(f"SELECT id FROM usuarios WHERE usuario = '{usuario}' AND senha = '{hash_senha}'")
    linha = cur.fetchone()
    con.close()
    return linha
