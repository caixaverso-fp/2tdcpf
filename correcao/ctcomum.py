# -*- coding: utf-8 -*-
"""Citizen Tech Market (DevSecOps v2) - funcoes comuns ao preparo e ao corretor.
Deriva, a partir do RM, os parametros unicos do ambiente de cada aluno."""
import base64
import hashlib
import hmac
import json

_S = bytes.fromhex("63742d6d61726b65742d76322d32746463" "70662d6e6f76323032362d78394b71")
SAL_GAB = "ctm2|"

ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
MAIUS_NUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
DIG = "0123456789"
HEXA = "0123456789abcdef"
CAN = "abcdefghjkmnpqrstuvwxyz23456789"
B64U = ALNUM + "-_"

PILLOW_VARS = ["5.2.0", "5.3.0", "5.4.1", "6.0.0"]
LXML_VARS = ["4.2.5", "4.3.0", "4.3.3", "4.4.1"]


def _d(rm, rotulo):
    return hmac.new(_S, ("%s|%s" % (rm, rotulo)).encode(), hashlib.sha256).digest()


def tok(rm, rotulo, alfabeto, n):
    saida, i = [], 0
    while len(saida) < n:
        for b in _d(rm, "%s#%d" % (rotulo, i)):
            saida.append(alfabeto[b % len(alfabeto)])
            if len(saida) == n:
                break
        i += 1
    return "".join(saida)


def canary(rm):
    return tok(rm, "canary", CAN, 8)


def porta(rm):
    return 8100 + int.from_bytes(_d(rm, "porta")[:2], "big") % 800


def variantes(rm):
    b = _d(rm, "variantes")
    return {"PILLOW": PILLOW_VARS[b[0] % len(PILLOW_VARS)], "LXML": LXML_VARS[b[1] % len(LXML_VARS)]}


def _b64u(b):
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def segredos(rm):
    """Segredos FALSOS (aleatorios, sem validade) plantados no ambiente do aluno."""
    rm = str(rm)
    jwt_h = _b64u(b'{"alg":"HS256","typ":"JWT"}')
    jwt_p = _b64u(json.dumps({"sub": "admin", "rm": rm, "c": canary(rm)}, separators=(",", ":")).encode())
    return {
        "G01": "AKIA" + tok(rm, "G01", B32, 16),
        "G02": tok(rm, "G02", ALNUM, 40),
        "G03": "ghp_" + tok(rm, "G03", ALNUM, 36),
        "G04": "xoxb-" + tok(rm, "G04a", DIG, 12) + "-" + tok(rm, "G04b", DIG, 12) + "-" + tok(rm, "G04c", ALNUM, 24),
        "G05": "sk_" + "live_" + tok(rm, "G05", ALNUM, 24),
        "G07": jwt_h + "." + jwt_p + "." + tok(rm, "G07", B64U, 43),
        "G08": "SG." + tok(rm, "G08a", ALNUM, 22) + "." + tok(rm, "G08b", ALNUM, 43),
        "G09": "glpat-" + tok(rm, "G09", ALNUM, 20),
        "G10": tok(rm, "G10", ALNUM, 24),
        "G12": "pypi-AgEIcHlwaS5vcmc" + tok(rm, "G12", ALNUM, 60),
        "G13": "https://hooks.slack.com/services/T" + tok(rm, "G13a", MAIUS_NUM, 10) + "/B"
               + tok(rm, "G13b", MAIUS_NUM, 10) + "/" + tok(rm, "G13c", ALNUM, 24),
        "G14": tok(rm, "G14", HEXA, 40),
        "G15": "AKIA" + tok(rm, "G15", B32, 16),
    }


def parametros(rm):
    rm = str(rm)
    p = {"RM": rm, "CANARY": canary(rm), "PORTA": str(porta(rm)), "IMAGEM": "ctmarket:%s" % rm}
    p.update(variantes(rm))
    p.update(segredos(rm))
    return p


def H(x):
    """Hash usado para ofuscar o gabarito distribuido aos alunos."""
    return hashlib.sha256((SAL_GAB + x).encode()).hexdigest()[:16]
