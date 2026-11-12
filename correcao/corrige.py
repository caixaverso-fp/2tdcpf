#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""GLOBAL SOLUTION - CITIZEN TECH MARKET (DevSecOps v2) - corretor automatico.

Confronta os entregaveis do aluno com o gabarito das vulnerabilidades plantadas
(minimo de 60% por item), confere se os relatorios pertencem ao ambiente do RM,
gera o pacote compactado das respostas e envia nota + pacote ao professor.
"""
import base64
import collections
import datetime
import glob
import hashlib
import json
import math
import os
import re
import socket
import subprocess
import sys
import unicodedata
import zipfile

AQUI = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, AQUI)
import ctcomum as ct  # noqa: E402

GS = "/opt/gs"


# ----------------------------------------------------------------------------- util
def ler_json(caminho):
    try:
        with open(caminho, encoding="utf-8", errors="replace") as f:
            return json.load(f)
    except Exception:
        return None


def sem_acento(s):
    return "".join(c for c in unicodedata.normalize("NFD", str(s)) if unicodedata.category(c) != "Mn")


def minimo(n, limiar):
    return int(math.ceil(n * limiar - 1e-9))


def fator(achados, total, gab):
    """1.0 se atingiu o limiar (60%); 0.5 se ficou entre 40% e 60%; 0 abaixo disso."""
    if total <= 0:
        return 0.0
    if achados >= minimo(total, gab["limiar"]):
        return 1.0
    if achados >= minimo(total, gab["meio"]):
        return 0.5
    return 0.0


def nome_pkg(n):
    return str(n).strip().lower().replace("_", "-")


# ----------------------------------------------------------------------------- Q02 SAST
def casar_sast(rel, gab, p):
    """Devolve (codigos detectados, relatorio_e_do_ambiente, total de achados)."""
    achados = []  # (caminho, linha)
    varridos = []
    if isinstance(rel, dict) and isinstance(rel.get("results"), list):          # semgrep --json
        for r in rel["results"]:
            if isinstance(r, dict):
                achados.append((str(r.get("path", "")), (r.get("start") or {}).get("line")))
        varridos = (rel.get("paths") or {}).get("scanned") or []
    elif isinstance(rel, dict) and isinstance(rel.get("runs"), list):           # SARIF
        for run in rel["runs"]:
            for r in run.get("results") or []:
                for loc in r.get("locations") or []:
                    fis = loc.get("physicalLocation") or {}
                    achados.append((str((fis.get("artifactLocation") or {}).get("uri", "")),
                                    (fis.get("region") or {}).get("startLine")))
    arquivos = {fid: rel_.replace("@@CANARY@@", p["CANARY"]) for fid, rel_ in gab["arquivos"].items()}
    inverso = {}
    for cod, hashes in gab["sast"]["itens"].items():
        for h in hashes:
            inverso[h] = cod
    textos = [a[0] for a in achados] + [str(v) for v in varridos]
    do_ambiente = any(p["CANARY"] in t for t in textos)
    detectados = set()
    for caminho, linha in achados:
        caminho = caminho.replace("\\", "/")
        if caminho.startswith("file://"):
            caminho = caminho[7:]
        for fid, relativo in arquivos.items():
            if caminho == relativo or caminho.endswith("/" + relativo):
                try:
                    cod = inverso.get(ct.H("S|%s:%d" % (fid, int(linha))))
                except Exception:
                    cod = None
                if cod:
                    detectados.add(cod)
    return detectados, do_ambiente, len(achados)


# ----------------------------------------------------------------------------- Q02 segredos
def casar_segredos(rel, p, base=GS):
    achados = []
    if isinstance(rel, list):
        achados = [a for a in rel if isinstance(a, dict)]
    elif isinstance(rel, dict):
        for v in rel.values():
            if isinstance(v, list):
                achados += [a for a in v if isinstance(a, dict)]
    textos = [json.dumps(a, ensure_ascii=False).replace("\\/", "/") for a in achados]
    detectados = set()
    for cod, valor in ct.segredos(p["RM"]).items():
        if any(valor in t for t in textos):
            detectados.add(cod)
    try:
        with open(os.path.join(base, "app", "deploy", "id_rsa")) as f:
            corpo = [ln.strip() for ln in f if ln.strip() and not ln.startswith("-----")]
        trecho = corpo[0][:48]
        if any(trecho in t.replace("\\n", "") for t in textos):
            detectados.add("G06")
    except Exception:
        pass
    return detectados, len(achados)


# ----------------------------------------------------------------------------- Q03 Trivy
def _resultados_trivy(rel):
    return [r for r in (rel.get("Results") or []) if isinstance(r, dict)] if isinstance(rel, dict) else []


def casar_trivy_config(rel, gab):
    inverso = {h: c for c, h in gab["trivy_config"]["itens"].items()}
    detectados, total = set(), 0
    for r in _resultados_trivy(rel):
        for m in r.get("Misconfigurations") or []:
            total += 1
            for campo in ("ID", "AVDID"):
                achou = re.search(r"DS-?0*(\d+)", str(m.get(campo, "")), re.I)
                if achou:
                    cod = inverso.get(ct.H("T|%d" % int(achou.group(1))))
                    if cod:
                        detectados.add(cod)
                    break
    return detectados, total


def casar_imagem(rel, gab, p):
    """Devolve (pacotes python vulneraveis detectados, vulns HIGH/CRITICAL de SO, imagem_e_do_aluno)."""
    inverso = {h: c for c, h in gab["imagem"]["itens"].items()}
    artefato = str(rel.get("ArtifactName", "")).lower() if isinstance(rel, dict) else ""
    do_aluno = p["IMAGEM"].lower() in artefato
    detectados, so = set(), 0
    for r in _resultados_trivy(rel):
        eh_so = r.get("Class") == "os-pkgs"
        for v in r.get("Vulnerabilities") or []:
            if eh_so and str(v.get("Severity", "")).upper() in ("HIGH", "CRITICAL"):
                so += 1
            cod = inverso.get(ct.H("P|" + nome_pkg(v.get("PkgName", ""))))
            if cod and not eh_so:
                detectados.add(cod)
    return detectados, so, do_aluno


# ----------------------------------------------------------------------------- Q04 DAST
def casar_dast(rel, gab, p):
    sites = rel.get("site") if isinstance(rel, dict) else None
    if isinstance(sites, dict):
        sites = [sites]
    porta_ok, detectados, total = False, set(), 0
    for s in sites or []:
        if not isinstance(s, dict):
            continue
        if str(s.get("@port", "")) != p["PORTA"] and (":%s" % p["PORTA"]) not in str(s.get("@name", "")):
            continue
        porta_ok = True
        for a in s.get("alerts") or []:
            total += 1
            hp = ct.H("Z|" + str(a.get("pluginid", "")).strip())
            hc = ct.H("ZC|" + str(a.get("cweid", "")).strip())
            for cod, it in gab["dast"]["itens"].items():
                if hp in it["p"] or hc in it["c"]:
                    detectados.add(cod)
    return detectados, porta_ok, total


# ----------------------------------------------------------------------------- Q05 SCA
def _pacotes_vulneraveis(rel):
    """Extrai (nome, versao) dos pacotes COM vulnerabilidade de varios formatos de SCA."""
    saida = []
    if isinstance(rel, dict) and "Results" in rel:                               # trivy fs
        for r in _resultados_trivy(rel):
            for v in r.get("Vulnerabilities") or []:
                saida.append((v.get("PkgName"), v.get("InstalledVersion")))
    deps = rel.get("dependencies") if isinstance(rel, dict) else (rel if isinstance(rel, list) else None)
    for d in deps or []:                                                         # pip-audit / dependency-check
        if not isinstance(d, dict):
            continue
        if d.get("vulns"):
            saida.append((d.get("name"), d.get("version")))
        if d.get("vulnerabilities"):
            for pk in d.get("packages") or []:
                m = re.search(r"pkg:pypi/([^@]+)@([^?\s]+)", str(pk.get("id", "")))
                if m:
                    saida.append((m.group(1), m.group(2)))
    if isinstance(rel, dict):
        for m in rel.get("matches") or []:                                       # grype
            art = m.get("artifact") or {}
            saida.append((art.get("name"), art.get("version")))
        for r in rel.get("results") or []:                                       # osv-scanner
            for pk in (r.get("packages") or []) if isinstance(r, dict) else []:
                if pk.get("vulnerabilities"):
                    saida.append(((pk.get("package") or {}).get("name"), (pk.get("package") or {}).get("version")))
    return [(nome_pkg(n), str(v or "")) for n, v in saida if n]


def casar_sca(relatorios, gab, p):
    inverso = {h: c for c, h in gab["sca"]["itens"].items()}
    esperado = {"pillow": p["PILLOW"], "lxml": p["LXML"]}
    detectados, divergentes, variante_ok = set(), set(), False
    for rel in relatorios:
        for nome, versao in _pacotes_vulneraveis(rel):
            cod = inverso.get(ct.H("P|" + nome))
            if not cod:
                continue
            if nome in esperado:
                if versao != esperado[nome]:
                    divergentes.add(nome)
                    continue
                variante_ok = True
            detectados.add(cod)
    return detectados, variante_ok, divergentes


# ----------------------------------------------------------------------------- Q00 threat model
ATORES = {"A%d" % i for i in range(1, 5)}
PROCESSOS = {"P%d" % i for i in range(1, 7)}
DEPOSITOS = {"D%d" % i for i in range(1, 7)}
FLUXOS = {"FL%02d" % i for i in range(1, 17)}
FLUXOS_LIMITE = FLUXOS - {"FL03", "FL06"}
PERMITIDO = {"ator": "SR", "processo": "STRIDE", "deposito": "TRID", "fluxo": "TID"}
GRUPOS = {"agente": ("habilidade", "motivo", "oportunidade", "tamanho"),
          "vulnerabilidade": ("descoberta", "exploracao", "conhecimento", "deteccao"),
          "impacto_tecnico": ("confidencialidade", "integridade", "disponibilidade", "rastreabilidade"),
          "impacto_negocio": ("financeiro", "reputacao", "conformidade", "privacidade")}
ORDEM_SEV = ["NOTA", "BAIXO", "MEDIO", "ALTO", "CRITICO"]
MATRIZ = {("BAIXO", "BAIXO"): "NOTA", ("MEDIO", "BAIXO"): "BAIXO", ("ALTO", "BAIXO"): "MEDIO",
          ("BAIXO", "MEDIO"): "BAIXO", ("MEDIO", "MEDIO"): "MEDIO", ("ALTO", "MEDIO"): "ALTO",
          ("BAIXO", "ALTO"): "MEDIO", ("MEDIO", "ALTO"): "ALTO", ("ALTO", "ALTO"): "CRITICO"}  # (prob, impacto)


def tipo_elemento(e):
    e = str(e).strip().upper()
    for conj, t in ((ATORES, "ator"), (PROCESSOS, "processo"), (DEPOSITOS, "deposito"), (FLUXOS, "fluxo")):
        if e in conj:
            return t
    return None


def letra_stride(s):
    s = sem_acento(s).lower().strip()
    for chave, letra in (("spoof", "S"), ("falsific", "S"), ("tamper", "T"), ("adulter", "T"), ("violac", "T"),
                         ("repud", "R"), ("information", "I"), ("disclos", "I"), ("divulg", "I"), ("vazament", "I"),
                         ("denial", "D"), ("negac", "D"), ("elevat", "E"), ("elevac", "E"), ("privil", "E")):
        if chave in s:
            return letra
    return s.upper() if s.upper() in list("STRIDE") and len(s) == 1 else None


def rotulo_nivel(x):
    return "BAIXO" if x < 3 else ("MEDIO" if x < 6 else "ALTO")


def norm_nivel(s):
    s = sem_acento(s).upper().strip()
    return {"LOW": "BAIXO", "MEDIUM": "MEDIO", "HIGH": "ALTO", "CRITICAL": "CRITICO", "NOTE": "NOTA",
            "BAIXA": "BAIXO", "MEDIA": "MEDIO", "ALTA": "ALTO", "CRITICA": "CRITICO"}.get(s, s)


def calcular_risco(a):
    """Recalcula o OWASP Risk Rating a partir dos 16 fatores. Devolve dict ou None."""
    fat = a.get("fatores")
    if not isinstance(fat, dict):
        return None
    medias = {}
    for grupo, campos in GRUPOS.items():
        g = fat.get(grupo)
        if not isinstance(g, dict):
            return None
        vals = []
        for c in campos:
            v = g.get(c)
            if isinstance(v, bool) or not isinstance(v, (int, float)) or v < 0 or v > 9 or int(v) != v:
                return None
            vals.append(int(v))
        medias[grupo] = sum(vals) / 4.0
    prob = (medias["agente"] + medias["vulnerabilidade"]) / 2.0
    imp = max(medias["impacto_tecnico"], medias["impacto_negocio"])
    np_, ni = rotulo_nivel(prob), rotulo_nivel(imp)
    return {"prob": prob, "imp": imp, "np": np_, "ni": ni, "sev": MATRIZ[(np_, ni)], "indice": prob * imp,
            "vetor": json.dumps(fat, sort_keys=True)}


def avaliar_ameacas(rm, base=GS):
    r = {"validas": 0, "categorias": 0, "elementos": 0, "limite": 0, "rm_ok": False,
         "calc_ok": 0, "vetores": 0, "sev_checks": 0, "existe": False, "calculos": {}}
    doc = ler_json(os.path.join(base, "threat-model", "ameacas.json"))
    if not isinstance(doc, dict) or not isinstance(doc.get("ameacas"), list):
        return r
    r["existe"] = True
    r["rm_ok"] = str(doc.get("rm", "")).strip() == str(rm)
    ids, titulos, cats, elems, vetores = set(), set(), set(), set(), set()
    validas = []
    for a in doc["ameacas"]:
        if not isinstance(a, dict):
            continue
        ident = str(a.get("id", "")).strip()
        elem = str(a.get("elemento", "")).strip().upper()
        tipo = tipo_elemento(elem)
        letra = letra_stride(a.get("stride", ""))
        titulo = " ".join(str(a.get("titulo", "")).lower().split())
        if (not ident or ident in ids or not tipo or not letra or letra not in PERMITIDO[tipo]
                or len(titulo) < 8 or titulo in titulos
                or len(str(a.get("descricao", "")).strip()) < 40 or len(str(a.get("mitigacao", "")).strip()) < 25):
            continue
        ids.add(ident)
        titulos.add(titulo)
        cats.add(letra)
        elems.add(elem)
        if elem in FLUXOS_LIMITE:
            r["limite"] += 1
        validas.append((ident, letra, a))
    r["validas"], r["categorias"], r["elementos"] = len(validas), len(cats), len(elems)

    for ident, letra, a in validas:
        c = calcular_risco(a)
        if not c:
            continue
        r["calculos"][ident] = dict(c, stride=letra)
        vetores.add(c["vetor"])
        try:
            certo = (abs(float(a.get("probabilidade")) - c["prob"]) <= 0.05
                     and abs(float(a.get("impacto")) - c["imp"]) <= 0.05
                     and norm_nivel(a.get("nivel_probabilidade", "")) == c["np"]
                     and norm_nivel(a.get("nivel_impacto", "")) == c["ni"]
                     and norm_nivel(a.get("severidade", "")) == c["sev"])
        except Exception:
            certo = False
        if certo:
            r["calc_ok"] += 1
    r["vetores"] = len(vetores)

    # 00.3 - analise de severidade consolidada (recalculada a partir do ameacas.json)
    sev = ler_json(os.path.join(base, "threat-model", "severidade.json"))
    calc = r["calculos"]
    if isinstance(sev, dict) and calc:
        ok = 0
        try:
            ok += int(sev.get("total")) == len(calc) and str(sev.get("rm", "")).strip() == str(rm)
        except Exception:
            pass
        esperado = collections.Counter(c["sev"] for c in calc.values())
        dado = {norm_nivel(k): v for k, v in (sev.get("por_severidade") or {}).items()} \
            if isinstance(sev.get("por_severidade"), dict) else {}
        ok += all(int(dado.get(k, 0) or 0) == esperado.get(k, 0) for k in ORDEM_SEV) and bool(dado)
        esp_s = collections.Counter(c["stride"] for c in calc.values())
        dado_s = collections.Counter()
        if isinstance(sev.get("por_stride"), dict):
            for k, v in sev["por_stride"].items():
                try:
                    dado_s[letra_stride(k)] += int(v)
                except Exception:
                    pass
        ok += bool(dado_s) and all(dado_s.get(k, 0) == esp_s.get(k, 0) for k in "STRIDE")
        indices = sorted((c["indice"] for c in calc.values()), reverse=True)
        try:
            ok_med = abs(float(sev.get("indice_medio")) - sum(indices) / len(indices)) <= 0.02
        except Exception:
            ok_med = False
        top = sev.get("top3") if isinstance(sev.get("top3"), list) else []
        try:
            ok_top = (len(top) == min(3, len(indices)) and len(set(map(str, top))) == len(top)
                      and all(abs(a - b) < 1e-6 for a, b in
                              zip(sorted((calc[str(t)]["indice"] for t in top), reverse=True), indices[:3])))
        except Exception:
            ok_top = False
        ok += ok_med and ok_top
        maior = max((c["sev"] for c in calc.values()), key=ORDEM_SEV.index)
        ok += norm_nivel(sev.get("severidade_ambiente", "")) == maior
        r["sev_checks"] = int(ok)
    return r


# ----------------------------------------------------------------------------- Q06 esteira
FASES = ["build", "sast", "segredos", "sca", "testes", "imagem", "dast", "deploy"]
GATES = ["sast", "segredos", "sca", "testes", "imagem", "dast"]
BYPASS = re.compile(r"\|\|\s*(true|:|exit\s+0|echo)\b|set\s+\+e|--exit-zero|--no-fail|--soft-fail", re.I)
SEGREDO_LITERAL = re.compile(r"AKIA[A-Z2-7]{16}|ghp_[A-Za-z0-9]{36}|xox[bap]-[0-9]{8,}|sk_live_[A-Za-z0-9]{16,}|"
                             r"glpat-[A-Za-z0-9_\-]{20}|-----BEGIN [A-Z ]*PRIVATE KEY")


def _texto_job(jid, job):
    partes = [str(jid), str(job.get("name", ""))]
    for s in job.get("steps") or []:
        if isinstance(s, dict):
            partes += [str(s.get("name", "")), str(s.get("uses", "")), str(s.get("run", "")),
                       json.dumps(s.get("with", {})), json.dumps(s.get("env", {}))]
    return "\n".join(partes).lower()


def _categorias(jid, job, t):
    c = set()
    trivy = "trivy" in t
    imagem_trivy = trivy and ("image-ref" in t or "trivy image" in t or re.search(r"scan-type\W+image", t))
    fs_trivy = trivy and ("trivy fs" in t or re.search(r"scan-type\W+(fs|filesystem|repo)", t))
    if re.search(r"zap-full-scan|action-full-scan|zap-api-scan|action-api-scan|zap\.sh.*-quickurl|ascan", t):
        c.add("dast")
    if imagem_trivy or ("grype" in t and "docker" in t) or "docker scout" in t:
        c.add("imagem")
    if fs_trivy or re.search(r"pip-audit|osv-scanner|dependency-check|safety (check|scan)|snyk test", t) \
            or ("grype" in t and "dir:" in t):
        c.add("sca")
    if re.search(r"gitleaks|trufflehog|detect-secrets", t):
        c.add("segredos")
    if re.search(r"semgrep|bandit", t):
        c.add("sast")
    if re.search(r"pytest|unittest|tox\b", t):
        c.add("testes")
    if re.search(r"docker build|build-push-action|pip install|python -m build|compileall", t):
        c.add("build")
    if re.search(r"deploy|release|entrega|publica", (str(jid) + " " + str(job.get("name", ""))).lower()) \
            or job.get("environment"):
        c.add("deploy")
    return c


def _atribuir(cats):
    """Associa cada fase a um job DISTINTO (maximo de fases cobertas)."""
    melhor = {}

    def rec(i, usado, atual):
        nonlocal melhor
        if len(atual) > len(melhor):
            melhor = dict(atual)
        if i == len(FASES) or len(atual) + (len(FASES) - i) <= len(melhor):
            return
        fase = FASES[i]
        for jid, c in cats.items():
            if fase in c and jid not in usado:
                atual[fase] = jid
                rec(i + 1, usado | {jid}, atual)
                del atual[fase]
        rec(i + 1, usado, atual)

    rec(0, frozenset(), {})
    return melhor


def _gate_efetivo(fase, job, t):
    if job.get("continue-on-error") in (True, "true"):
        return False
    for s in job.get("steps") or []:
        if isinstance(s, dict) and s.get("continue-on-error") in (True, "true"):
            return False
    if BYPASS.search(t):
        return False
    trivy_falha = bool(re.search(r"exit-code\W{1,6}1\b", t)) and bool(re.search(r"high|critical", t))
    if fase == "sast":
        return bool(re.search(r"semgrep ci|--error|semgrep-action", t)) or ("bandit" in t)
    if fase == "segredos":
        return not re.search(r"exit-code\W{1,6}0\b", t) and ("trufflehog" not in t or "--fail" in t)
    if fase == "sca":
        if "trivy" in t and not re.search(r"pip-audit|osv-scanner|safety|snyk", t):
            return trivy_falha
        if "grype" in t:
            return "fail-on" in t or "fail-build" in t
        if "dependency-check" in t:
            return "failoncvss" in t
        return True
    if fase == "imagem":
        return trivy_falha if "trivy" in t else ("fail-on" in t or "fail-build" in t or "exit-code" in t)
    if fase == "dast":
        if "zaproxy/action" in t:
            return bool(re.search(r"fail_action\W{1,6}true", t))
        return not re.search(r"\s-i(\s|$)", t)
    return True


def _git(args, cwd):
    try:
        return subprocess.run(["git", "-c", "safe.directory=*"] + args, cwd=cwd, stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL, timeout=60).stdout.decode(errors="replace")
    except Exception:
        return ""


def avaliar_esteira(rm, p, base=GS):
    r = {"existe": False, "repo": "", "repo_ok": False, "limpo": False, "nome_rm": False, "fases": {},
         "cadeia": False, "gates": {}, "endurecimento": {}, "arquivo": "", "motivo": ""}
    raiz = os.path.join(base, "esteira")
    arquivos = sorted(glob.glob(os.path.join(raiz, ".github", "workflows", "*.y*ml")))
    try:
        import yaml
    except Exception:
        r["motivo"] = "modulo python3-yaml ausente (apt install python3-yaml)"
        return r
    wf, texto = None, ""
    for arq in arquivos:
        try:
            with open(arq, encoding="utf-8") as f:
                bruto = f.read()
            d = yaml.safe_load(bruto)
        except Exception:
            continue
        if isinstance(d, dict) and isinstance(d.get("jobs"), dict) and (wf is None or len(d["jobs"]) > len(wf["jobs"])):
            wf, texto, r["arquivo"] = d, bruto, arq
    if wf is None:
        r["motivo"] = "nenhum workflow YAML valido em /opt/gs/esteira/.github/workflows"
        return r
    r["existe"] = True
    r["nome_rm"] = str(rm) in str(wf.get("name", ""))
    # so contam jobs executaveis de verdade: com runner e passos (uses/run) definidos
    jobs = {str(j): v for j, v in wf["jobs"].items()
            if isinstance(v, dict) and v.get("runs-on") and isinstance(v.get("steps"), list)
            and any(isinstance(s, dict) and (s.get("uses") or s.get("run")) for s in v["steps"])}

    # repositorio: GitHub + sem segredos na arvore e no historico
    r["repo"] = _git(["remote", "get-url", "origin"], raiz).strip()
    tem_commit = bool(_git(["rev-list", "-n", "1", "--all"], raiz).strip())
    r["repo_ok"] = tem_commit and "github.com" in r["repo"].lower()
    if tem_commit:
        historico = _git(["log", "--all", "-p", "--no-color"], raiz)
        rastreados = _git(["ls-files"], raiz).split("\n")
        vazou = any(v in historico for v in ct.segredos(rm).values()) or "PRIVATE KEY-----" in historico
        proibidos = [a for a in rastreados if os.path.basename(a) in (".env", "id_rsa") or a.endswith((".pem", ".key"))]
        r["limpo"] = not vazou and not proibidos
        r["repo_ok"] = r["repo_ok"] and os.path.relpath(r["arquivo"], raiz) in rastreados   # workflow versionado

    # fases em jobs distintos + encadeamento ate o deploy
    textos = {j: _texto_job(j, v) for j, v in jobs.items()}
    cats = {j: _categorias(j, jobs[j], textos[j]) for j in jobs}
    r["fases"] = _atribuir(cats)

    def fecho(j, visto=None):
        visto = visto or set()
        nd = jobs.get(j, {}).get("needs") or []
        for n in ([nd] if isinstance(nd, str) else nd):
            if n in jobs and n not in visto:
                visto.add(n)
                fecho(n, visto)
        return visto

    dep = r["fases"].get("deploy")
    if dep:
        antes = fecho(dep)
        r["cadeia"] = all(r["fases"].get(g) in antes for g in GATES)
        cond = str(jobs[dep].get("if", "")).lower()
        deploy_protegido = (bool(jobs[dep].get("environment")) and ("main" in cond or "master" in cond)
                            and "always()" not in cond and "failure()" not in cond)
    else:
        deploy_protegido = False
    for g in GATES:
        j = r["fases"].get(g)
        r["gates"][g] = bool(j) and _gate_efetivo(g, jobs[j], textos[j])

    # endurecimento da esteira
    perm = wf.get("permissions")
    perm_ok = (isinstance(perm, dict) and all(str(v).lower() in ("read", "none") for v in perm.values())) \
        or perm == "read-all" or perm == {} \
        or (perm is None and jobs and all(isinstance(v.get("permissions"), (dict, str)) for v in jobs.values()))
    if perm == "write-all" or any(v.get("permissions") == "write-all" for v in jobs.values()):
        perm_ok = False
    usos = [str(s.get("uses")) for v in jobs.values() for s in (v.get("steps") or [])
            if isinstance(s, dict) and s.get("uses")]
    fixos = bool(usos) and all(u.startswith(("./", "docker://")) or (
        "@" in u and u.rsplit("@", 1)[1].lower() not in ("main", "master", "latest", "head", "develop", "dev"))
        for u in usos)
    gat = wf.get("on", wf.get(True))
    nomes = set(gat) if isinstance(gat, (dict, list)) else {gat}
    evid = bool(re.search(r"upload-artifact|upload-sarif", texto))
    literal = bool(SEGREDO_LITERAL.search(texto)) or any(v in texto for v in ct.segredos(rm).values())
    r["endurecimento"] = {"permissoes": bool(perm_ok), "acoes_fixadas": fixos,
                          "gatilhos": {"push", "pull_request"} <= nomes, "evidencias": evid,
                          "deploy_protegido": deploy_protegido, "sem_segredo_literal": not literal}
    return r


# ----------------------------------------------------------------------------- correcao
def corrigir(rm, base=GS):
    """Executa toda a correcao. Devolve (pontos em centesimos por questao, linhas de saida, feedback, extras)."""
    gab = ler_json(os.path.join(AQUI, "gabarito.json"))
    p = ct.parametros(rm)
    rep = os.path.join(base, "reports")
    P = collections.OrderedDict((q, 0) for q in ("Q00", "Q02", "Q03", "Q04", "Q05", "Q06"))
    saida, feed, extras = [], [], {"repo": ""}

    def titulo(t):
        saida.append("\n" + t)
        feed.append("== " + t + " ==")

    def item(q, cod, pts, frac, texto, dica=""):
        ganho = int(round(pts * frac))
        P[q] += ganho
        marca = "[ OK ]" if frac >= 1 else ("[PARC]" if frac > 0 else "[FALTA]")
        saida.append("   %s %s %s  [%s de %s]" % (marca, cod, texto, fmt(ganho), fmt(pts)))
        feed.append("  %s %s %s%s" % ("[OK] " if frac >= 1 else "[X]  ", cod, texto,
                                      (" -> " + dica) if (dica and frac < 1) else ""))

    def cobertura(achados, ativos):
        n = len(set(achados) & set(ativos))
        return n, len(ativos), fator(n, len(ativos), gab)

    def pct(n, t):
        return "%d de %d (%d%%; minimo %d)" % (n, t, round(100.0 * n / t) if t else 0, minimo(t, gab["limiar"]))

    # ---------------- Q00
    titulo("Q00 - Modelagem de ameacas: STRIDE + OWASP Risk Rating (2,0)")
    a = avaliar_ameacas(rm, base)
    if not a["existe"]:
        item("Q00", "00.1", 80, 0, "threat-model/ameacas.json ausente ou invalido", "crie o arquivo no formato da prova")
        item("Q00", "00.2", 70, 0, "sem ameacas para avaliar o Risk Rating")
        item("Q00", "00.3", 50, 0, "sem base para a analise de severidade")
    else:
        completo = (a["validas"] >= 8 and a["categorias"] == 6 and a["elementos"] >= 6 and a["limite"] >= 2
                    and a["rm_ok"])
        parcial = a["validas"] >= 6 and a["categorias"] >= 4
        item("Q00", "00.1", 80, 1 if completo else (0.5 if parcial else 0),
             "STRIDE: %d ameacas validas, %d/6 categorias, %d elementos, %d em fluxos que cruzam limite, rm=%s"
             % (a["validas"], a["categorias"], a["elementos"], a["limite"], "ok" if a["rm_ok"] else "divergente"),
             "minimo: 8 ameacas validas, as 6 categorias, 6 elementos distintos, 2 em fluxos que cruzam limite de "
             "confianca, categoria compativel com o tipo do elemento e campo rm correto")
        cheio = a["calc_ok"] >= 8 and a["calc_ok"] >= 0.9 * max(a["validas"], 1) and a["vetores"] >= 4
        item("Q00", "00.2", 70, 1 if cheio else (0.5 if a["calc_ok"] >= 5 else 0),
             "Risk Rating: %d ameacas com os 16 fatores e calculo correto (%d vetores distintos)"
             % (a["calc_ok"], a["vetores"]),
             "confira medias de probabilidade/impacto, niveis e a matriz de severidade; varie os fatores por ameaca")
        item("Q00", "00.3", 50, 1 if a["sev_checks"] == 5 else (0.5 if a["sev_checks"] >= 3 else 0),
             "severidade.json: %d de 5 consolidacoes conferem com o ameacas.json" % a["sev_checks"],
             "recalcule total, por_severidade, por_stride, indice_medio/top3 e severidade_ambiente")

    # ---------------- Q02
    titulo("Q02 - Analise estatica: computador + SAST + segredos (2,0)")
    host = socket.gethostname()
    item("Q02", "02.a", 30, 1 if host == str(rm) else 0, "nome do computador '%s' (esperado %s)" % (host, rm),
         "altere o nome do computador para o seu RM")
    rel = ler_json(os.path.join(rep, "sast.json"))
    if rel is None:
        item("Q02", "02.b", 90, 0, "reports/sast.json ausente ou nao e JSON", "salve o relatorio do SAST em JSON")
    else:
        det, amb, tot = casar_sast(rel, gab, p)
        if not amb:
            item("Q02", "02.b", 90, 0, "sast.json nao pertence ao ambiente deste RM (%d achados ignorados)" % tot,
                 "gere o relatorio analisando o SEU /opt/gs/app completo")
        else:
            n, t, f = cobertura(det, gab["sast"]["ativos"])
            item("Q02", "02.b", 90, f, "SAST: %s vulnerabilidades do gabarito detectadas" % pct(n, t),
                 "amplie o conjunto de regras e analise todos os modulos da aplicacao")
    rel = ler_json(os.path.join(rep, "segredos.json"))
    if rel is None:
        item("Q02", "02.c", 80, 0, "reports/segredos.json ausente ou nao e JSON", "salve o relatorio de segredos em JSON")
    else:
        det, tot = casar_segredos(rel, p, base)
        n, t, f = cobertura(det, gab["segredos"]["ativos"])
        item("Q02", "02.c", 80, f, "Segredos: %s segredos do SEU ambiente encontrados" % pct(n, t),
             "o relatorio deve conter os valores (sem mascarar) e cobrir tambem o historico do repositorio")

    # ---------------- Q03
    titulo("Q03 - Conteiner: Dockerfile e imagem (1,3)")
    rel = ler_json(os.path.join(rep, "trivy-config.json"))
    if rel is None:
        item("Q03", "03.a", 60, 0, "reports/trivy-config.json ausente ou nao e JSON")
    else:
        det, tot = casar_trivy_config(rel, gab)
        n, t, f = cobertura(det, gab["trivy_config"]["ativos"])
        item("Q03", "03.a", 60, f, "Dockerfile: %s mas configuracoes do gabarito detectadas" % pct(n, t),
             "analise as configuracoes incorretas (misconfiguration) do Dockerfile, todas as severidades")
    rel = ler_json(os.path.join(rep, "trivy-image.json"))
    if rel is None:
        item("Q03", "03.b", 70, 0, "reports/trivy-image.json ausente ou nao e JSON")
    else:
        det, so, dono = casar_imagem(rel, gab, p)
        if not dono:
            item("Q03", "03.b", 70, 0, "a imagem analisada nao e a %s" % p["IMAGEM"],
                 "construa e analise a imagem com o nome/tag indicado em MEU_AMBIENTE.txt")
        else:
            n, t, f = cobertura(det, gab["imagem"]["ativos"])
            if so < gab["imagem"]["min_so"]:
                f = min(f, 0.5)
            item("Q03", "03.b", 70, f, "Imagem: %s bibliotecas vulneraveis; %d falhas HIGH/CRITICAL do SO (minimo %d)"
                 % (pct(n, t), so, gab["imagem"]["min_so"]), "inclua pacotes do sistema e das bibliotecas da aplicacao")

    # ---------------- Q04
    titulo("Q04 - Analise dinamica em modo ativo (1,5)")
    rel = ler_json(os.path.join(rep, "dast.json"))
    if rel is None:
        item("Q04", "04", 150, 0, "reports/dast.json ausente ou nao e JSON")
    else:
        det, porta_ok, tot = casar_dast(rel, gab, p)
        if not porta_ok:
            item("Q04", "04", 150, 0, "o relatorio nao e da aplicacao na porta %s" % p["PORTA"],
                 "execute a SUA aplicacao na porta indicada em MEU_AMBIENTE.txt e analise esse endereco")
        else:
            n, t, f = cobertura(det, gab["dast"]["ativos"])
            na = len(det & set(gab["dast"]["scan_ativo"]))
            if na < gab["dast"]["min_scan_ativo"]:
                f = min(f, 0.5) if na else 0.0
            item("Q04", "04", 150, f, "DAST: %s alertas do gabarito; %d de varredura ATIVA (minimo %d)"
                 % (pct(n, t), na, gab["dast"]["min_scan_ativo"]),
                 "use a varredura ativa completa, com a aplicacao no ar e todas as paginas exploradas")

    # ---------------- Q05
    titulo("Q05 - SCA: dependencias (1,2)")
    rels = [x for x in (ler_json(a_) for a_ in sorted(glob.glob(os.path.join(rep, "sca*.json")))) if x is not None]
    if not rels:
        item("Q05", "05", 120, 0, "reports/sca.json ausente ou nao e JSON")
    else:
        det, var_ok, div = casar_sca(rels, gab, p)
        if not var_ok:
            item("Q05", "05", 120, 0, "o relatorio nao cobre todos os manifestos do SEU projeto%s"
                 % (" (versoes divergentes: %s)" % ", ".join(sorted(div)) if div else ""),
                 "analise todos os arquivos de dependencias do seu /opt/gs/app")
        else:
            n, t, f = cobertura(det, gab["sca"]["ativos"])
            item("Q05", "05", 120, f, "SCA: %s dependencias vulneraveis identificadas" % pct(n, t),
                 "cubra todos os manifestos (aplicacao e worker)")

    # ---------------- Q06
    titulo("Q06 - Esteira CI/CD segura (2,0)")
    e = avaliar_esteira(rm, p, base)
    extras["repo"] = e["repo"]
    if not e["existe"]:
        item("Q06", "06", 200, 0, "esteira nao avaliada: %s" % e["motivo"],
             "crie o workflow em /opt/gs/esteira/.github/workflows/")
    else:
        na = sum([e["repo_ok"], e["limpo"], e["nome_rm"]])
        item("Q06", "06.a", 30, na / 3.0 if na == 3 else (0.5 if na == 2 else 0),
             "repositorio: GitHub=%s, sem segredos na arvore/historico=%s, RM no nome do workflow=%s"
             % tuple("sim" if x else "nao" for x in (e["repo_ok"], e["limpo"], e["nome_rm"])),
             "remoto no GitHub, repositorio sem segredos (inclusive no historico) e RM no nome do workflow")
        nf = len(e["fases"])
        item("Q06", "06.b", 60, (nf / 8.0) * (2 / 3.0) + (1 / 3.0 if e["cadeia"] else 0),
             "%d de 8 fases em jobs distintos; deploy condicionado a todos os gates=%s"
             % (nf, "sim" if e["cadeia"] else "nao"),
             "8 jobs (build, SAST, segredos, SCA, testes, imagem, DAST ativo, deploy) e deploy dependente de todos")
        ng = sum(e["gates"].values())
        item("Q06", "06.c", 60, ng / 6.0, "%d de 6 security gates efetivos (reprovam a esteira)" % ng,
             "gates sem bypass (continue-on-error, '|| true') e configurados para falhar em severidade alta")
        end = e["endurecimento"]
        ne = sum(1 for k in ("permissoes", "acoes_fixadas", "gatilhos", "evidencias", "deploy_protegido") if end[k])
        item("Q06", "06.d", 50, (ne / 5.0) if end["sem_segredo_literal"] else 0,
             "endurecimento: %d de 5 controles%s" % (ne, "" if end["sem_segredo_literal"] else " (SEGREDO no workflow!)"),
             "permissoes minimas, actions com versao fixa, gatilhos push+pull_request, upload de evidencias e "
             "deploy protegido (environment + somente branch principal)")
    return P, saida, feed, extras


def fmt(c):
    return "%d,%02d" % (c // 100, c % 100)


# ----------------------------------------------------------------------------- pacote + envio
def sha_arquivo(caminho):
    h = hashlib.sha256()
    with open(caminho, "rb") as f:
        for bloco in iter(lambda: f.read(1 << 20), b""):
            h.update(bloco)
    return h.hexdigest()


def empacotar(rm, nome, host, P, total, feedback_txt, base=GS):
    carimbo = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    nome_zip = "RM%s_%s_%s.zip" % (rm, re.sub(r"[^A-Za-z0-9_.-]", "_", host), carimbo)
    destino = os.path.join(AQUI, nome_zip)
    alvos = []
    for padrao in ("threat-model/ameacas.json", "threat-model/severidade.json", "reports/*.json",
                   "esteira/.github/workflows/*", "esteira/.gitignore", "MEU_AMBIENTE.txt"):
        alvos += sorted(glob.glob(os.path.join(base, padrao)))
    meta = {"rm": rm, "nome": nome, "computador": host, "gerado_em": carimbo, "nota": fmt(total),
            "pontos": {q: fmt(v) for q, v in P.items()}, "arquivos": {}}
    with zipfile.ZipFile(destino, "w", zipfile.ZIP_DEFLATED) as z:
        for a in alvos:
            if os.path.isfile(a) and os.path.getsize(a) <= 60 * 1024 * 1024:
                rel = os.path.relpath(a, base)
                z.write(a, rel)
                meta["arquivos"][rel] = {"sha256": sha_arquivo(a), "bytes": os.path.getsize(a),
                                         "modificado": datetime.datetime.fromtimestamp(os.path.getmtime(a)).isoformat()}
        z.writestr("esteira/git-log.txt", _git(["log", "--all", "--stat", "--date=iso"], os.path.join(base, "esteira")))
        z.writestr("feedback.txt", feedback_txt)
        z.writestr("meta.json", json.dumps(meta, indent=2, ensure_ascii=False))
    return destino, nome_zip


def impressao_digital(base, rm):
    """Hashes normalizados (sem o RM) para o professor detectar respostas identicas entre alunos."""
    d = {}
    for chave, padrao in (("ameacas", "threat-model/ameacas.json"), ("esteira", "esteira/.github/workflows/*.y*ml")):
        conteudo = ""
        for a in sorted(glob.glob(os.path.join(base, padrao))):
            try:
                conteudo += open(a, encoding="utf-8", errors="replace").read()
            except Exception:
                pass
        conteudo = re.sub(r"\s+", "", conteudo.replace(str(rm), "RM")).lower()
        d[chave] = hashlib.sha256(conteudo.encode()).hexdigest()[:20] if conteudo else ""
    return d


def enviar(url, carga):
    import urllib.request
    dados = json.dumps(carga).encode()
    try:
        req = urllib.request.Request(url, data=dados, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=180) as resp:
            return resp.read().decode(errors="replace")
    except Exception as e1:
        tmp = os.path.join("/tmp", "ct_envio_%d.json" % os.getpid())
        try:
            with open(tmp, "wb") as f:
                f.write(dados)
            return subprocess.run(["curl", "-fsS", "-L", "-m", "180", "-H", "Content-Type: application/json",
                                   "--data-binary", "@" + tmp, url], stdout=subprocess.PIPE,
                                  stderr=subprocess.DEVNULL).stdout.decode(errors="replace") or ("ERRO: %s" % e1)
        except Exception as e2:
            return "ERRO: %s / %s" % (e1, e2)
        finally:
            if os.path.exists(tmp):
                os.remove(tmp)


def ler_conf():
    conf = {"WEBAPP_URL": "", "TURMA": "", "AVALIACAO": "Global Solution - Citizen Tech Market (DevSecOps)"}
    try:
        for linha in open(os.path.join(AQUI, "prova.conf"), encoding="utf-8"):
            if "=" in linha and not linha.lstrip().startswith("#"):
                k, v = linha.split("=", 1)
                conf[k.strip()] = v.strip().strip('"').strip("'")
    except Exception:
        pass
    return conf


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if not args or not args[0].isdigit():
        sys.exit('Uso: sudo ./corrige.sh <RM> ["Nome Completo"]')
    rm = args[0]
    nome = args[1] if len(args) > 1 else ""
    if os.geteuid() != 0:
        sys.exit("Execute como root: sudo ./corrige.sh %s" % rm)
    amb = ler_json(os.path.join(GS, ".ambiente.json")) or {}
    if str(amb.get("rm", "")) != rm:
        sys.exit("O ambiente em /opt/gs foi preparado para o RM '%s', nao para %s. Use o SEU RM."
                 % (amb.get("rm", "nenhum"), rm))
    if not nome and sys.stdin.isatty():
        nome = input("Digite seu nome completo: ").strip()
    nome = nome or "N/A"
    host = socket.gethostname()
    conf = ler_conf()

    print("=" * 74)
    print(" GLOBAL SOLUTION - CITIZEN TECH MARKET | Corretor DevSecOps")
    print(" Aluno: %s   RM: %s   Computador: %s   %s" % (nome, rm, host, datetime.datetime.now().strftime("%d/%m/%Y %H:%M")))
    print("=" * 74)
    P, saida, feed, extras = corrigir(rm)
    print("\n".join(saida))
    total = sum(P.values())
    maximos = {"Q00": "2,00", "Q02": "2,00", "Q03": "1,30", "Q04": "1,50", "Q05": "1,20", "Q06": "2,00"}
    print("\n" + "=" * 74)
    for q, v in P.items():
        print("  %s ........: %s / %s" % (q, fmt(v), maximos[q]))
    print("  NOTA FINAL : %s / 10,00" % fmt(total))
    print("=" * 74)

    feedback_txt = ("GLOBAL SOLUTION - CITIZEN TECH MARKET (DevSecOps) | Feedback\nAluno: %s  RM: %s  Computador: %s\n"
                    "Nota: %s / 10,00\n%s\n%s\n%s\nLegenda: [OK] atendido | [X] pendente (a regra exige pelo menos 60%% "
                    "das vulnerabilidades do gabarito em cada analise).\n"
                    % (nome, rm, host, fmt(total), "-" * 70, "\n".join(feed), "-" * 70))
    with open(os.path.join(AQUI, "feedback_RM_%s.txt" % rm), "w", encoding="utf-8") as f:
        f.write(feedback_txt)
    caminho_zip, nome_zip = empacotar(rm, nome, host, P, total, feedback_txt)
    print("Feedback: feedback_RM_%s.txt | Copia das respostas: %s" % (rm, nome_zip))

    if "--local" in sys.argv:
        return
    if not conf["WEBAPP_URL"].startswith("http"):
        print("\nWEBAPP_URL nao configurada em prova.conf - nota e pacote NAO enviados (entregue o .zip ao professor).")
        return
    with open(caminho_zip, "rb") as f:
        b64 = base64.b64encode(f.read()).decode()
    pend = " | ".join(x.strip() for x in feed if x.strip().startswith("[X]"))
    carga = {"rm": rm, "nome": nome, "turma": conf["TURMA"], "avaliacao": conf["AVALIACAO"], "host": host,
             "nota": fmt(total), "detalhes": pend or "Sem pendencias", "repo": extras["repo"],
             "digitais": impressao_digital(GS, rm), "arquivo_nome": nome_zip, "arquivo_b64": b64}
    carga.update({q.lower(): fmt(v) for q, v in P.items()})
    print("\nEnviando nota e copia das respostas (%.1f MB)..." % (len(b64) / 1048576.0))
    resp = enviar(conf["WEBAPP_URL"], carga)
    if '"status":"ok"' in resp.replace(" ", ""):
        print("   Nota registrada e pacote salvo no Drive do professor.")
    else:
        print("   NAO confirmado. Resposta: %s" % resp[:200])
        print("   Entregue o arquivo %s diretamente ao professor." % nome_zip)


if __name__ == "__main__":
    main()
