"""
Pipeline de ingestao: cowrie.json -> PostgreSQL.

Le o log do honeypot (um JSON por linha), remonta as sessoes e grava nas
tabelas do schema. Funciona igual para log sintetico e para log real do
Cowrie - e exatamente esse o ponto de ter o gerador.

GARANTIAS DE PROJETO
    1. Idempotencia por arquivo. O SHA-256 do arquivo vai para
       `arquivo_processado`. Rodar duas vezes o mesmo arquivo nao faz nada.
    2. Idempotencia por linha. Todo INSERT usa ON CONFLICT sobre a chave
       natural. Mesmo com o arquivo crescendo (log rotativo), so entra o novo.
    3. Tudo em UMA transacao. Erro no meio = rollback completo. Nunca sobra
       meia sessao no banco.

USO
    python ingest.py ../dados/cowrie.json
    python ingest.py ../dados/cowrie.json --dry-run     # so parseia, nao grava
    python ingest.py ../dados/cowrie.json --forcar      # reprocessa arquivo ja visto

CONFIGURACAO
    Variavel de ambiente DATABASE_URL, ou o padrao abaixo (que bate com o
    docker-compose.yml do projeto).
"""

import argparse
import hashlib
import json
import os
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

DATABASE_URL_PADRAO = "postgresql://analista:trocar_em_producao@localhost:5432/honeypot"

# Quantas linhas por lote no executemany. Lote grande demais come memoria,
# pequeno demais desperdica ida e volta ate o banco.
TAMANHO_LOTE = 1000


# ===========================================================================
#  Parte 1 - Parsing (nao depende do banco; roda com --dry-run)
# ===========================================================================

def sha256_arquivo(caminho):
    """Hash do arquivo lido em blocos - nao carrega o arquivo inteiro na RAM."""
    h = hashlib.sha256()
    with open(caminho, "rb") as f:
        for bloco in iter(lambda: f.read(65536), b""):
            h.update(bloco)
    return h.hexdigest()


def ler_ts(texto):
    """
    ISO-8601 do Cowrie -> datetime com fuso.

    O Cowrie emite '2026-08-25T14:03:11.123456Z'. O sufixo Z e aceito
    nativamente pelo fromisoformat a partir do Python 3.11.
    """
    return datetime.fromisoformat(texto)


def parsear(caminho):
    """
    Le o log e remonta as sessoes.

    Retorna (sessoes, stats). Cada sessao e um dict pronto para virar linhas
    nas tabelas. Linha corrompida nao derruba a execucao - e contada e
    ignorada, que e o comportamento certo para log de producao.
    """
    sessoes = {}
    stats = {"linhas": 0, "erros": 0, "ignorados": 0,
             "tipos": defaultdict(int), "orfaos": 0}

    def nova_sessao(uid):
        return {
            "uid": uid, "ip": None, "pais": None, "protocolo": "ssh",
            "porta": 22, "cliente": None, "inicio": None, "fim": None,
            "autenticou": False,
            "tentativas": [], "comandos": [], "artefatos": [],
        }

    with open(caminho, encoding="utf-8") as f:
        for numero, linha in enumerate(f, start=1):
            linha = linha.strip()
            if not linha:
                continue
            stats["linhas"] += 1

            try:
                ev = json.loads(linha)
            except json.JSONDecodeError:
                stats["erros"] += 1
                continue

            tipo = ev.get("eventid")
            uid = ev.get("session")
            if not tipo or not uid:
                stats["erros"] += 1
                continue

            stats["tipos"][tipo] += 1
            s = sessoes.setdefault(uid, nova_sessao(uid))

            try:
                ts = ler_ts(ev["timestamp"])
            except (KeyError, ValueError):
                stats["erros"] += 1
                continue

            if tipo == "cowrie.session.connect":
                s["ip"] = ev.get("src_ip")
                s["inicio"] = ts
                s["protocolo"] = ev.get("protocol", "ssh")
                s["porta"] = ev.get("dst_port", 22)
                # Log real do Cowrie NAO traz pais - o enriquecimento por
                # geoIP roda depois. O gerador injeta para dar o que analisar.
                s["pais"] = ev.get("pais_simulado")

            elif tipo == "cowrie.client.version":
                s["cliente"] = ev.get("version")

            elif tipo in ("cowrie.login.failed", "cowrie.login.success"):
                sucesso = tipo.endswith("success")
                s["tentativas"].append((
                    ev.get("username", ""), ev.get("password", ""), sucesso, ts))
                if sucesso:
                    s["autenticou"] = True

            elif tipo == "cowrie.command.input":
                texto = ev.get("input", "")
                if texto:
                    # A ordem vem da posicao no log, nao de campo do evento.
                    s["comandos"].append((len(s["comandos"]) + 1, texto, ts))

            elif tipo == "cowrie.session.file_download":
                sha = (ev.get("shasum") or "").lower()
                # O CHECK do banco exige 64 hex. Filtrar aqui evita que uma
                # linha suja aborte a transacao inteira la na frente.
                if len(sha) == 64 and all(c in "0123456789abcdef" for c in sha):
                    s["artefatos"].append(
                        (ev.get("url"), sha, ev.get("size"), ts))
                else:
                    stats["ignorados"] += 1

            elif tipo == "cowrie.session.closed":
                s["fim"] = ts

            else:
                stats["ignorados"] += 1

    # Sessao sem evento de connect nao tem IP nem inicio - acontece quando o
    # log foi cortado no meio (rotacao). Descarta, mas conta.
    completas = {}
    for uid, s in sessoes.items():
        if s["ip"] and s["inicio"]:
            if s["fim"] and s["fim"] < s["inicio"]:
                s["fim"] = None          # respeita o CHECK sessao_fim_apos_inicio
            completas[uid] = s
        else:
            stats["orfaos"] += 1

    return completas, stats


# ===========================================================================
#  Parte 2 - Gravacao
# ===========================================================================

def gravar(conn, sessoes, caminho, hash_arq, stats):
    """
    Grava tudo em uma transacao, respeitando a ordem das dependencias:

        origem  ->  sessao  ->  tentativa / comando / artefato
        credencial  ->  tentativa

    A estrategia em toda etapa e a mesma: INSERT em lote com ON CONFLICT,
    depois um SELECT para montar o mapa chave-natural -> id. Assim funciona
    tanto para linha nova quanto para linha que ja existia de uma execucao
    anterior, sem precisar de RETURNING nem de logica condicional.
    """
    cur = conn.cursor()
    inseridos = defaultdict(int)

    # --- origem ------------------------------------------------------------
    # Agrega a janela de atividade por IP antes de gravar: um IP pode ter
    # varias sessoes no mesmo arquivo, e primeiro/ultimo visto sao o min/max.
    por_ip = {}
    for s in sessoes.values():
        fim = s["fim"] or s["inicio"]
        if s["ip"] in por_ip:
            atual = por_ip[s["ip"]]
            atual[1] = min(atual[1], s["inicio"])
            atual[2] = max(atual[2], fim)
        else:
            por_ip[s["ip"]] = [s["pais"], s["inicio"], fim]

    linhas_origem = [(ip, dados[0], dados[1], dados[2])
                     for ip, dados in por_ip.items()]

    # LEAST/GREATEST no UPDATE: se o IP ja existe de um arquivo anterior, a
    # janela so pode expandir, nunca encolher.
    cur.executemany("""
        INSERT INTO origem (ip, pais, primeiro_visto, ultimo_visto)
        VALUES (%s, %s, %s, %s)
        ON CONFLICT (ip) DO UPDATE SET
            primeiro_visto = LEAST(origem.primeiro_visto, EXCLUDED.primeiro_visto),
            ultimo_visto   = GREATEST(origem.ultimo_visto, EXCLUDED.ultimo_visto),
            pais           = COALESCE(origem.pais, EXCLUDED.pais)
    """, linhas_origem)
    inseridos["origem"] = len(linhas_origem)

    cur.execute("SELECT ip, id FROM origem WHERE ip = ANY(%s)",
                (list(por_ip.keys()),))
    mapa_origem = {str(ip): oid for ip, oid in cur.fetchall()}

    # --- credencial --------------------------------------------------------
    pares = {(u, p) for s in sessoes.values() for u, p, _, _ in s["tentativas"]}
    pares = {(u[:256], p[:256]) for u, p in pares if u}   # respeita os CHECKs

    cur.executemany("""
        INSERT INTO credencial (usuario, senha) VALUES (%s, %s)
        ON CONFLICT (usuario, senha) DO NOTHING
    """, list(pares))
    inseridos["credencial"] = len(pares)

    cur.execute("""
        SELECT usuario, senha, id FROM credencial
        WHERE (usuario, senha) IN (SELECT unnest(%s::text[]), unnest(%s::text[]))
    """, ([u for u, _ in pares], [p for _, p in pares]))
    mapa_cred = {(u, p): cid for u, p, cid in cur.fetchall()}

    # --- sessao ------------------------------------------------------------
    linhas_sessao = [
        (s["uid"], mapa_origem[s["ip"]], s["protocolo"], s["porta"],
         s["cliente"], s["inicio"], s["fim"], s["autenticou"])
        for s in sessoes.values()
    ]
    cur.executemany("""
        INSERT INTO sessao (sessao_uid, origem_id, protocolo, porta_destino,
                            cliente_versao, inicio, fim, autenticou)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (sessao_uid) DO NOTHING
    """, linhas_sessao)
    inseridos["sessao"] = len(linhas_sessao)

    cur.execute("SELECT sessao_uid, id FROM sessao WHERE sessao_uid = ANY(%s)",
                (list(sessoes.keys()),))
    mapa_sessao = dict(cur.fetchall())

    # --- tentativa ---------------------------------------------------------
    # ON CONFLICT sobre a chave natural (sessao, credencial, instante).
    #
    # A versao anterior deste arquivo nao tinha isso, apostando que o controle
    # por hash de arquivo bastaria. Nao bastava: o cowrie.json cresce, o hash
    # muda, as sessoes antigas voltam no parse e as tentativas delas eram
    # reinseridas. Medido: 5.916 -> 11.832 linhas ao reprocessar.
    linhas_tent = []
    for s in sessoes.values():
        sid = mapa_sessao[s["uid"]]
        for u, p, sucesso, ts in s["tentativas"]:
            chave = (u[:256], p[:256])
            if chave in mapa_cred:
                linhas_tent.append((sid, mapa_cred[chave], sucesso, ts))

    for i in range(0, len(linhas_tent), TAMANHO_LOTE):
        cur.executemany("""
            INSERT INTO tentativa (sessao_id, credencial_id, sucesso, ocorrido_em)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (sessao_id, credencial_id, ocorrido_em) DO NOTHING
        """, linhas_tent[i:i + TAMANHO_LOTE])
    inseridos["tentativa"] = len(linhas_tent)

    # --- comando -----------------------------------------------------------
    linhas_cmd = [
        (mapa_sessao[s["uid"]], ordem, texto, ts)
        for s in sessoes.values() for ordem, texto, ts in s["comandos"]
    ]
    for i in range(0, len(linhas_cmd), TAMANHO_LOTE):
        cur.executemany("""
            INSERT INTO comando (sessao_id, ordem, comando, ocorrido_em)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (sessao_id, ordem) DO NOTHING
        """, linhas_cmd[i:i + TAMANHO_LOTE])
    inseridos["comando"] = len(linhas_cmd)

    # --- artefato ----------------------------------------------------------
    linhas_art = [
        (mapa_sessao[s["uid"]], url, sha, tam, ts)
        for s in sessoes.values() for url, sha, tam, ts in s["artefatos"]
    ]
    if linhas_art:
        cur.executemany("""
            INSERT INTO artefato (sessao_id, url, sha256, tamanho_bytes, ocorrido_em)
            VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT (sessao_id, sha256, ocorrido_em) DO NOTHING
        """, linhas_art)
    inseridos["artefato"] = len(linhas_art)

    # --- registro do arquivo ----------------------------------------------
    cur.execute("""
        INSERT INTO arquivo_processado (nome_arquivo, sha256, linhas_lidas,
                                        linhas_com_erro)
        VALUES (%s, %s, %s, %s)
        ON CONFLICT (sha256) DO NOTHING
    """, (Path(caminho).name, hash_arq, stats["linhas"], stats["erros"]))

    return inseridos


def ja_processado(conn, hash_arq):
    cur = conn.cursor()
    cur.execute(
        "SELECT nome_arquivo, processado_em FROM arquivo_processado WHERE sha256 = %s",
        (hash_arq,))
    return cur.fetchone()


# ===========================================================================
#  Main
# ===========================================================================

def main():
    ap = argparse.ArgumentParser(description="Ingere log do Cowrie no PostgreSQL.")
    ap.add_argument("arquivo", help="caminho do cowrie.json")
    ap.add_argument("--dry-run", action="store_true",
                    help="so parseia e mostra estatisticas, nao toca no banco")
    ap.add_argument("--forcar", action="store_true",
                    help="reprocessa mesmo que o arquivo ja tenha sido ingerido")
    ap.add_argument("--db", default=os.environ.get("DATABASE_URL", DATABASE_URL_PADRAO),
                    help="connection string do PostgreSQL")
    args = ap.parse_args()

    caminho = Path(args.arquivo)
    if not caminho.exists():
        sys.exit(f"ERRO: arquivo nao encontrado: {caminho}")

    print(f"Lendo {caminho}...")
    hash_arq = sha256_arquivo(caminho)
    sessoes, stats = parsear(caminho)

    print(f"  linhas lidas .......... {stats['linhas']}")
    print(f"  linhas com erro ....... {stats['erros']}")
    print(f"  eventos ignorados ..... {stats['ignorados']}")
    print(f"  sessoes incompletas ... {stats['orfaos']}")
    print(f"  sessoes completas ..... {len(sessoes)}")
    print(f"  sha256 ................ {hash_arq[:16]}...")
    print()
    print("  Eventos por tipo:")
    for tipo, n in sorted(stats["tipos"].items(), key=lambda x: -x[1]):
        print(f"    {n:7d}  {tipo}")

    total_tent = sum(len(s["tentativas"]) for s in sessoes.values())
    total_cmd = sum(len(s["comandos"]) for s in sessoes.values())
    total_art = sum(len(s["artefatos"]) for s in sessoes.values())
    autent = sum(1 for s in sessoes.values() if s["autenticou"])
    print()
    print(f"  A gravar: {len(sessoes)} sessoes, {total_tent} tentativas, "
          f"{total_cmd} comandos, {total_art} artefatos")
    print(f"  Sessoes que autenticaram: {autent}")

    if args.dry_run:
        print("\n[--dry-run] nada foi gravado.")
        return

    try:
        import psycopg
    except ImportError:
        sys.exit("\nERRO: psycopg nao instalado.  ->  pip install -r requirements.txt")

    print(f"\nConectando ao banco...")
    with psycopg.connect(args.db) as conn:
        anterior = ja_processado(conn, hash_arq)
        if anterior and not args.forcar:
            nome, quando = anterior
            print(f"Arquivo ja ingerido em {quando:%d/%m/%Y %H:%M} (como {nome}).")
            print("Nada a fazer. Use --forcar para reprocessar.")
            return

        inseridos = gravar(conn, sessoes, caminho, hash_arq, stats)
        conn.commit()

    print("\nGravado:")
    for tabela in ("origem", "credencial", "sessao", "tentativa", "comando", "artefato"):
        print(f"  {tabela:12s} {inseridos[tabela]:7d}")
    print("\nOK - transacao confirmada.")


if __name__ == "__main__":
    main()
