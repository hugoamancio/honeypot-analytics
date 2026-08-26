"""
Motor de deteccao: roda as regras e grava alertas.

DESENHO
    Este arquivo nao contem UMA LINHA de logica de deteccao. Ele:

        1. le o catalogo em `regra_deteccao` (so as ativas);
        2. monta o nome da view a partir do codigo  (BRUTE_FORCE_SSH ->
           regra_brute_force_ssh);
        3. faz INSERT ... SELECT dessa view para `alerta`, com ON CONFLICT.

    Consequencia: criar regra nova = escrever uma view + inserir uma linha no
    catalogo. Nenhuma mudanca aqui. Desligar uma regra em producao = UPDATE
    regra_deteccao SET ativa = FALSE. Sem deploy.

    A deduplicacao NAO esta no Python. Ela e a constraint
    alerta_dedup UNIQUE (regra_id, origem_id, janela_inicio). Rodar de 5 em 5
    minutos num cron nao gera alerta repetido porque o banco recusa - nao
    porque este codigo lembrou de checar.

USO
    python detectar.py                  # roda todas as regras ativas
    python detectar.py --regra BRUTE_FORCE_SSH
    python detectar.py --listar         # mostra o catalogo e sai
    python detectar.py --dry-run        # conta o que dispararia, nao grava
"""

import argparse
import os
import sys

DATABASE_URL_PADRAO = "postgresql://analista:trocar_em_producao@localhost:5432/honeypot"


def nome_da_view(codigo):
    """BRUTE_FORCE_SSH -> regra_brute_force_ssh"""
    return "regra_" + codigo.lower()


def carregar_catalogo(cur, apenas=None):
    sql = """
        SELECT id, codigo, nome, severidade, mitre_tecnica, ativa
        FROM regra_deteccao
        {filtro}
        ORDER BY severidade DESC, codigo
    """
    if apenas:
        cur.execute(sql.format(filtro="WHERE codigo = %s"), (apenas,))
    else:
        cur.execute(sql.format(filtro="WHERE ativa = TRUE"))
    return cur.fetchall()


def view_existe(cur, view):
    cur.execute("SELECT to_regclass(%s) IS NOT NULL", (f"public.{view}",))
    return cur.fetchone()[0]


def executar(conn, regras, dry_run=False):
    cur = conn.cursor()
    resultados = []

    for regra_id, codigo, nome, sev, mitre, ativa in regras:
        view = nome_da_view(codigo)

        if not view_existe(cur, view):
            resultados.append((codigo, sev, mitre, None, None, "SEM VIEW"))
            continue

        # Quantas linhas a regra produz agora, no total.
        cur.execute(f"SELECT COUNT(*) FROM {view}")
        candidatos = cur.fetchone()[0]

        if dry_run:
            resultados.append((codigo, sev, mitre, candidatos, None, "dry-run"))
            continue

        # INSERT ... SELECT: os candidatos nunca sobem para o Python. Filtrar
        # milhares de linhas no banco e trazer so a contagem e a diferenca
        # entre uma query e um loop de round-trips.
        cur.execute(f"""
            INSERT INTO alerta (regra_id, origem_id, janela_inicio, janela_fim, evidencia)
            SELECT %s, origem_id, janela_inicio, janela_fim, evidencia
            FROM {view}
            ON CONFLICT (regra_id, origem_id, janela_inicio) DO NOTHING
        """, (regra_id,))
        novos = cur.rowcount

        resultados.append((codigo, sev, mitre, candidatos, novos,
                           "novos" if novos else "nada novo"))

    if not dry_run:
        conn.commit()
    return resultados


def main():
    ap = argparse.ArgumentParser(description="Roda as regras de deteccao.")
    ap.add_argument("--regra", help="rodar so esta regra (pelo codigo)")
    ap.add_argument("--listar", action="store_true", help="mostra o catalogo e sai")
    ap.add_argument("--dry-run", action="store_true",
                    help="conta o que dispararia, sem gravar alerta")
    ap.add_argument("--db", default=os.environ.get("DATABASE_URL", DATABASE_URL_PADRAO))
    args = ap.parse_args()

    try:
        import psycopg
    except ImportError:
        sys.exit("ERRO: psycopg nao instalado.  ->  pip install -r requirements.txt")

    with psycopg.connect(args.db) as conn:
        cur = conn.cursor()

        if args.listar:
            print(f"{'CODIGO':<26} {'MITRE':<11} {'SEVERIDADE':<10} ATIVA  VIEW")
            print("-" * 78)
            cur.execute("""SELECT id, codigo, nome, severidade, mitre_tecnica, ativa
                           FROM regra_deteccao ORDER BY severidade DESC, codigo""")
            for rid, cod, nome, sev, mitre, ativa in cur.fetchall():
                v = nome_da_view(cod)
                marca = "ok" if view_existe(cur, v) else "AUSENTE"
                print(f"{cod:<26} {mitre or '-':<11} {sev:<10} "
                      f"{'sim' if ativa else 'nao':<6} {marca}")
            return

        regras = carregar_catalogo(cur, args.regra)
        if not regras:
            sys.exit(f"Nenhuma regra encontrada" +
                     (f" com codigo {args.regra}" if args.regra else " ativa"))

        resultados = executar(conn, regras, args.dry_run)

    print(f"{'REGRA':<26} {'MITRE':<11} {'SEV':<8} {'CANDID':>7} {'NOVOS':>7}  STATUS")
    print("-" * 82)
    total_novos = 0
    for codigo, sev, mitre, cand, novos, status in resultados:
        total_novos += novos or 0
        print(f"{codigo:<26} {mitre or '-':<11} {sev:<8} "
              f"{'-' if cand is None else cand:>7} "
              f"{'-' if novos is None else novos:>7}  {status}")

    print()
    if args.dry_run:
        print("[--dry-run] nenhum alerta gravado.")
    else:
        print(f"{total_novos} alerta(s) novo(s) gravado(s).")
        print("Ver:  SELECT * FROM vw_alertas_abertos;")


if __name__ == "__main__":
    main()
