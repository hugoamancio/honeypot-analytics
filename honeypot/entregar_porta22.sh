#!/usr/bin/env bash
# ============================================================================
#  Entrega a porta 22 ao honeypot.
#
#  SO RODE DEPOIS de conectar com sucesso em `ssh -p 2200`. Este script
#  remove a porta 22 do seu SSH; se a 2200 nao estiver funcionando, voce
#  perde o acesso e so volta pelo console web do provedor.
#
#  O script confere sozinho se a 2200 esta escutando e se recusa a
#  prosseguir caso nao esteja - mas essa checagem ve o servidor de dentro.
#  Firewall do provedor bloqueando a 2200 de fora ela nao detecta. Por isso
#  o teste externo continua sendo obrigatorio.
# ============================================================================

set -euo pipefail

PORTA_ADMIN=2200
verde() { printf '\033[0;32m%s\033[0m\n' "$1"; }
aviso() { printf '\033[0;33m%s\033[0m\n' "$1"; }
erro()  { printf '\033[0;31m%s\033[0m\n' "$1"; }

verde "==> 1/4  Conferindo que a porta de administracao responde"
if ! ss -tln | grep -qE ":${PORTA_ADMIN}\s"; then
    erro "A porta ${PORTA_ADMIN} nao esta escutando. ABORTANDO."
    erro "Rode mudar_porta_ssh.sh primeiro e teste a conexao de fora."
    exit 1
fi
verde "    ${PORTA_ADMIN} escutando"

verde "==> 2/4  Removendo a porta 22 do sshd"
sudo sed -i '/^Port 22$/d' /etc/ssh/sshd_config
if ! sudo sshd -t; then
    erro "Configuracao invalida - restaurando a linha e abortando"
    printf 'Port 22\n' | sudo tee -a /etc/ssh/sshd_config >/dev/null
    exit 1
fi
sudo systemctl restart ssh.service
sleep 2
verde "    sshd agora so escuta na ${PORTA_ADMIN}"

verde "==> 3/4  Redirecionando 22 -> Cowrie e 23 -> Cowrie"
# REDIRECT no PREROUTING: o pacote chega na 22, o kernel entrega na 2222.
# O atacante nunca sabe que houve tradução - do lado dele e a porta 22.
#
# -C testa se a regra ja existe; sem isso, rodar o script duas vezes
# empilharia regras duplicadas.
sudo iptables -t nat -C PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222 2>/dev/null \
  || sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
sudo iptables -t nat -C PREROUTING -p tcp --dport 23 -j REDIRECT --to-port 2223 2>/dev/null \
  || sudo iptables -t nat -A PREROUTING -p tcp --dport 23 -j REDIRECT --to-port 2223
verde "    regras de NAT aplicadas"

verde "==> 4/4  Tornando as regras permanentes"
# Sem isto as regras somem no proximo reboot e o honeypot para de receber
# trafego em silencio - a maquina fica no ar, o Cowrie rodando, e nada chega.
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq iptables-persistent >/dev/null 2>&1 || true
sudo netfilter-persistent save >/dev/null 2>&1 || sudo sh -c 'iptables-save > /etc/iptables/rules.v4'
verde "    regras salvas"

echo
verde "PRONTO."
echo "  Sua administracao ..... ssh -p ${PORTA_ADMIN}"
echo "  Porta 22 e 23 ......... pertencem ao honeypot"
echo
aviso "Conectar na 22 agora te leva ao sistema FALSO. Nao se assuste."
echo
echo "Acompanhe os primeiros ataques com:"
echo "  tail -f ~/cowrie/var/log/cowrie/cowrie.json"
