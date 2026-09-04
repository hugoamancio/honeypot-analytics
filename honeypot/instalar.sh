#!/usr/bin/env bash
# ============================================================================
#  Instala o Cowrie num Ubuntu 22.04 novo (testado em Oracle Cloud).
#
#  ESTE SCRIPT NAO MEXE NA PORTA 22.
#
#  Isso e deliberado. Mover o seu SSH e redirecionar a 22 para o honeypot sao
#  as duas operacoes que trancam voce para fora do servidor se algo der
#  errado. Elas ficam no DEPLOY.md, para serem feitas a mao, com uma segunda
#  sessao aberta como rede de seguranca.
#
#  USO
#      chmod +x instalar.sh
#      ./instalar.sh
#
#  Ao terminar, o Cowrie estara escutando em 2222 (SSH) e 2223 (Telnet),
#  ainda sem receber trafego da internet.
# ============================================================================

set -euo pipefail

COWRIE_DIR="$HOME/cowrie"
verde() { printf '\033[0;32m%s\033[0m\n' "$1"; }
aviso() { printf '\033[0;33m%s\033[0m\n' "$1"; }

# --- 0. Sanidade -----------------------------------------------------------
if [ "$(id -u)" -eq 0 ]; then
    echo "ERRO: nao rode como root. O Cowrie deve rodar como usuario comum -"
    echo "e o motivo inteiro de existir um honeypot e que ele pode ser"
    echo "comprometido. Rodando como root, o estrago seria total."
    exit 1
fi

verde "==> 1/6  Pacotes do sistema"
sudo apt-get update -qq
sudo apt-get install -y -qq \
    git python3-virtualenv python3-dev libssl-dev libffi-dev \
    build-essential libpython3-dev authbind jq

verde "==> 2/6  Baixando o Cowrie"
if [ -d "$COWRIE_DIR" ]; then
    aviso "    $COWRIE_DIR ja existe - pulando o clone"
else
    git clone --quiet https://github.com/cowrie/cowrie.git "$COWRIE_DIR"
fi
cd "$COWRIE_DIR"

verde "==> 3/6  Ambiente virtual e dependencias"
if [ ! -d "$COWRIE_DIR/cowrie-env" ]; then
    python3 -m virtualenv --quiet cowrie-env
fi
# shellcheck source=/dev/null
source cowrie-env/bin/activate
pip install --quiet --upgrade pip
pip install --quiet -r requirements.txt

# O Cowrie moderno se instala como PACOTE - o pyproject.toml declara
# `cowrie = "cowrie.scripts.cowrie:run"` em [project.scripts]. Sem este
# passo existem as dependencias mas nao o executavel, e o start falha com
# "bin/cowrie: No such file or directory" (o bin/cowrie das versoes antigas
# nao existe mais).
pip install --quiet -e .

verde "==> 4/6  Aplicando a configuracao do projeto"
CFG_ORIGEM="$(dirname "$(readlink -f "$0")")"
if [ -f "$CFG_ORIGEM/cowrie.cfg" ]; then
    cp "$CFG_ORIGEM/cowrie.cfg" "$COWRIE_DIR/etc/cowrie.cfg"
    verde "    cowrie.cfg aplicado (hostname, banner e ciphers customizados)"
else
    aviso "    cowrie.cfg nao encontrado ao lado do script - usando o padrao"
    cp etc/cowrie.cfg.dist etc/cowrie.cfg
fi

if [ -f "$CFG_ORIGEM/userdb.txt" ]; then
    cp "$CFG_ORIGEM/userdb.txt" "$COWRIE_DIR/etc/userdb.txt"
    verde "    userdb.txt aplicado (sem curinga - nao aceita qualquer senha)"
else
    aviso "    userdb.txt nao encontrado - copiando o exemplo"
    cp etc/userdb.example etc/userdb.txt
fi

verde "==> 5/6  Povoando o sistema de arquivos falso"
# Diretorio /home vazio e um dos sinais mais faceis de detectar. Alguns
# arquivos plausiveis bastam para o bot seguir o playbook em vez de sair.
#
# honeyfs/etc PRECISA estar nesta lista: o honeyfs que vem com o Cowrie
# chega vazio, entao nada abaixo dele existe antes de ser criado aqui.
# Faltava, e o script morria em "honeyfs/etc/motd: No such file or directory".
mkdir -p honeyfs/etc honeyfs/home/admin honeyfs/var/www/html honeyfs/opt

cat > honeyfs/etc/motd <<'MOTD'
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-105-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Mon Aug 26 03:14:07 UTC 2026

  System load:  0.08              Processes:             118
  Usage of /:   34.2% of 45.5GB   Users logged in:       0
  Memory usage: 41%               IPv4 address for ens3: 10.0.2.15
  Swap usage:   0%

0 updates can be applied immediately.

MOTD

echo "web-prod-02" > honeyfs/etc/hostname
printf 'server {\n    listen 80;\n    root /var/www/html;\n}\n' \
    > honeyfs/var/www/html/.nginx.conf.bak

verde "==> 6/7  Servico do systemd (sobrevive a reboot)"
# Sem isto o Cowrie morre no primeiro reinicio e o honeypot fica mudo sem
# ninguem perceber - foi exatamente o que aconteceu num teste real. Um sensor
# que so funciona ate a maquina reiniciar nao e um sensor.
sudo tee /etc/systemd/system/cowrie.service >/dev/null <<EOF
[Unit]
Description=Cowrie SSH/Telnet Honeypot
After=network-online.target
Wants=network-online.target

[Service]
Type=forking
User=$USER
Group=$USER
WorkingDirectory=$COWRIE_DIR
Environment=PATH=$COWRIE_DIR/cowrie-env/bin:/usr/local/bin:/usr/bin:/bin
ExecStart=$COWRIE_DIR/cowrie-env/bin/cowrie start
ExecStop=$COWRIE_DIR/cowrie-env/bin/cowrie stop
PIDFile=$COWRIE_DIR/var/run/cowrie.pid
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable cowrie >/dev/null 2>&1
verde "    cowrie.service criado e habilitado no boot"

verde "==> 7/7  Subindo o Cowrie"
# `cowrie` (do venv), nao `bin/cowrie`: o wrapper antigo foi removido do
# projeto e substituido pelo console script instalado no ambiente virtual.
cowrie stop >/dev/null 2>&1 || true
sudo systemctl restart cowrie
sleep 6

if cowrie status 2>&1 | grep -qi "running"; then
    verde ""
    verde "COWRIE NO AR"
    echo "  SSH falso ....... porta 2222"
    echo "  Telnet falso .... porta 2223"
    echo "  Log JSON ........ $COWRIE_DIR/var/log/cowrie/cowrie.json"
    echo "  Servico ......... systemctl status cowrie  (volta sozinho no boot)"
    echo ""
    aviso "AINDA NAO CHEGA TRAFEGO DA INTERNET."
    aviso "Falta liberar as portas e redirecionar a 22 - ver DEPLOY.md."
    aviso "Faca isso com DUAS sessoes SSH abertas. Serio."
else
    echo "ERRO: o Cowrie nao subiu. Veja o log:"
    echo "    tail -40 $COWRIE_DIR/var/log/cowrie/cowrie.log"
    tail -20 "$COWRIE_DIR/var/log/cowrie/cowrie.log" 2>/dev/null || true
    exit 1
fi
