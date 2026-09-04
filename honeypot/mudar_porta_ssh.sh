#!/usr/bin/env bash
# ============================================================================
#  Move o SSH de administracao para a porta 2200, liberando a 22.
#
#  POR QUE ESTE SCRIPT EXISTE (aprendido quebrando um servidor de verdade)
#
#  A tentativa anterior editou o ssh.socket enquanto o ssh.service continuava
#  ativo. Os dois passaram a disputar a porta 22, o systemd tentou, falhou, e
#  derrubou o SSH inteiro - inclusive a porta 22 que estava funcionando. O
#  reboot nao resolveu: o conflito se repetia a cada boot.
#
#  A LICAO: no Ubuntu 24.04 existem DOIS mecanismos concorrentes de iniciar o
#  sshd. Voce escolhe um e desliga o outro. Mexer num sem desligar o outro e
#  o que quebra.
#
#  Aqui: desliga o socket, usa o service, porta no sshd_config. Caminho
#  classico e previsivel.
#
#  ORDEM DE SEGURANCA
#  O script deixa o SSH nas DUAS portas (22 e 2200) e NAO redireciona nada.
#  Confirme a 2200 de fora antes de rodar o entregar_porta22.sh.
# ============================================================================

set -euo pipefail

PORTA_ADMIN=2200
verde() { printf '\033[0;32m%s\033[0m\n' "$1"; }
aviso() { printf '\033[0;33m%s\033[0m\n' "$1"; }

verde "==> 1/4  Desligando a ativacao por socket"
# Este e o passo que faltava. Enquanto o ssh.socket existir ativo, ele disputa
# a porta com o ssh.service e o resultado e imprevisivel.
if systemctl is-active --quiet ssh.socket; then
    sudo systemctl disable --now ssh.socket
    verde "    ssh.socket desativado"
else
    verde "    ssh.socket ja estava inativo"
fi

# Remove qualquer drop-in de tentativa anterior.
sudo rm -rf /etc/systemd/system/ssh.socket.d
sudo systemctl daemon-reload

verde "==> 2/4  Configurando as portas no sshd_config"
# Limpa linhas Port anteriores e escreve as duas. Manter a 22 aqui e
# deliberado: e a rede de seguranca ate a 2200 ser confirmada.
sudo sed -i '/^[[:space:]]*Port[[:space:]]/d' /etc/ssh/sshd_config
sudo sed -i '/^#Port 22/d' /etc/ssh/sshd_config
printf 'Port 22\nPort %s\n' "$PORTA_ADMIN" | sudo tee -a /etc/ssh/sshd_config >/dev/null

verde "==> 3/4  Validando a sintaxe antes de reiniciar"
# sshd -t recusa configuracao invalida. Reiniciar sem validar e como
# recompilar sem checar erro: descobre-se quando ja nao da mais pra voltar.
if ! sudo sshd -t; then
    aviso "CONFIGURACAO INVALIDA - nada foi reiniciado, SSH atual intacto"
    exit 1
fi

verde "==> 4/4  Reiniciando o sshd"
sudo systemctl enable ssh.service >/dev/null 2>&1
sudo systemctl restart ssh.service
sleep 3

echo
echo "=== portas em que o SSH escuta ==="
ss -tln | grep -E ":(22|${PORTA_ADMIN})\s" || aviso "NENHUMA - algo deu errado"

echo
aviso "AGORA, DE FORA, TESTE:  ssh -i chave -p ${PORTA_ADMIN} sensor@IP"
aviso "So depois que ela responder, rode entregar_porta22.sh."
