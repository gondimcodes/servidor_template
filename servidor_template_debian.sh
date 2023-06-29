#!/usr/bin/env bash
# Script de preparacao de servidores Debian GNU/Linux para uso em producao
# ATENCAO! Esse script eh para ser usado em servidores recem instalados, que
# nao estejam ainda em producao pois serah re-configurado todo o ambiente.
# Eh uma contribuicao e nao me responsabilizo por quaisquer danos causados
# pelo uso desse script.
# Autor: Marcelo Gondim - gondim at gmail.com
# Data: 21/01/2023
# Versao: 1.4.1
#
# servidor_template.sh is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

# Variaveis de configuracao:
# E-mail para envio de logs do sistema via logwatch
EMAIL_LOGS=""
# E-mail para envio de avisos de upgrade do sistema via apticron
EMAIL_UPGRADES=""
# Definicao do hostname do servidor
HOSTNAME=""
# Se esse servidor nao for um servidor de correio mantenha o default MTA="N".
# Caso esse servidor vah se tornar um servidor de correio entao mude para MTA="S".
# Se nao sabe o que eh um servidor de correio ou MTA, deixe o defautl.
MTA="N"
# Com excecao da MSMTP_FROM, as variaveis MSMTP_* soh serao usadas se MTA="N"
MSMTP_FROM=""
MSMTP_HOST=""
MSMTP_USER=""
MSMTP_PASS=""

# Por padrao colocaremos o apparmor em complain mode. Caso queira manter o default em enforced mudar para APPARMOR="Y"
APPARMOR="N"
LANG="pt_BR.UTF-8"
LANGUAGE="pt_BR.UTF-8:pt:en"
DISTRO_NAME="`lsb_release -s -c`"
# Para listar os timezones disponiveis execute: timedatectl list-timezones
TIMEZONE="UTC"

# Coloque nessa lista usando espacos os IPs que o fail2ban nao podera bloquear.
# Adicione pelo menos o IP do servidor, IP do gateway, o seu DNS e o IP ou rede que voce
# usara para acessar esse servidor.
F2B_IGNOREIP="127.0.0.1 ::1"
# Tempo de banimento para o fail2ban
F2B_BANTIME="72h"
# Limite de tentativas antes do bloqueio
F2B_MAXRETRY="5"
# Notifica os contatos responsaveis dos IPs que foram banidos. Caso so queira bloquear, mude para N.
F2B_XARF="Y"

if [ "$EMAIL_LOGS" == "" -o "$EMAIL_UPGRADES" == "" ]; then
   echo -e "\nVariaveis de EMAIL vazias!"
   exit
fi

if [ "$MSMTP_FROM" == "" ]; then
   echo -e "\nVariavel MSMTP_FROM vazia!"
   exit
fi

if [ "$HOSTNAME" == "" ]; then
   echo -e "\nVariavel HOSTNAME vazia!"
   exit
fi

echo -e "Configurando repositorios APT em /etc/apt/sources.list..."
cat << EOF > /etc/apt/sources.list
deb http://security.debian.org/debian-security $DISTRO_NAME-security main contrib non-free
deb http://deb.debian.org/debian $DISTRO_NAME main non-free contrib
deb http://deb.debian.org/debian $DISTRO_NAME-updates main contrib non-free
deb http://deb.debian.org/debian $DISTRO_NAME-backports main contrib non-free
EOF

echo -e "Configurando /etc/hostname..."
echo "$HOSTNAME" > /etc/hostname
hostname -F /etc/hostname

echo -e "Configurando /etc/hosts..."
cat << EOF > /etc/hosts
127.0.0.1       localhost
127.0.1.1       $HOSTNAME

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
EOF

echo -e "Atualizando o sistema e instalando alguns pacotes uteis..."
apt-get update && apt-get -y full-upgrade && apt-get -y install neofetch net-tools nftables htop iotop sipcalc tcpdump vim-nox curl gnupg rsync wget host dnsutils mtr-tiny bmon sudo expect tmux whois ethtool dnstop apparmor-utils
echo "syntax on" > /root/.vimrc

echo -e "Adicionando algumas configuracoes em /etc/sysctl.d/local.conf..."
cat << EOF > /etc/sysctl.d/local.conf
net.core.rmem_max = 2147483647
net.core.wmem_max = 2147483647
net.ipv4.tcp_rmem = 4096 87380 2147483647
net.ipv4.tcp_wmem = 4096 65536 2147483647
net.netfilter.nf_conntrack_buckets = 512000
net.netfilter.nf_conntrack_max = 4096000
vm.swappiness=10
fs.inotify.max_user_watches=524288
EOF

echo nf_conntrack > /etc/modules
modprobe nf_conntrack
sysctl -p /etc/sysctl.d/local.conf

# Agradecimentos ao Kretcheu pelo script dele gerador de PS1: https://github.com/kretcheu/devel/blob/master/prompt
echo -e "Modificando o prompt (PS1) do bash..."
cat << EOF > /root/.bash_profile
PS1='\[\e[1;34m\]\342\224\214\342\224\200\[\e[1;34m\][\[\e[1;36m\]\u\[\e[1;33m\]@\[\e[1;37m\]\h\[\e[1;34m\]]\[\e[1;34m\]\342\224\200\[\e[1;34m\][\[\e[1;33m\]\w\[\e[1;34m\]]\[\e[1;34m\]\342\224\200[\[\e[1;37m\]\t\[\e[1;34m\]]\n\[\e[1;34m\]\342\224\224\342\224\200\342\224\200\342\225\274\[\e[1;32m\] # \[\e[0m\]'

alias l="ls -la --color=auto"
alias rm="rm -i"
alias mv="mv -i"
alias cp="cp -i"
EOF

if [ "$MTA" == "N" -o "$MTA" == "n" ]; then
   echo -e "Instalando sistema para envio de e-mails de notificacao..."
   apt-get -y install msmtp msmtp-mta bsd-mailx
   cat << EOF > /root/.msmtprc
# Set default values for all following accounts.
defaults
        port 587
        tls on
        tls_trust_file /etc/ssl/certs/ca-certificates.crt

account notificacoes
        protocol smtp
        host $MSMTP_HOST
        from $MSMTP_FROM
        auth login
        user $MSMTP_USER
        password $MSMTP_PASS

# Set a default account
account default : notificacoes
EOF
   echo -e "Enviando e-mail de teste..."
   echo "Teste de envio de e-mail!" | mailx -s $HOSTNAME $EMAIL_LOGS
fi

echo -e "Instalando apticron e logwatch..."
apt-get -y install apticron logwatch

cat << EOF > /etc/apticron/apticron.conf
EMAIL="$EMAIL_UPGRADES"
DIFF_ONLY="0"
LISTCHANGES_PROFILE=""
ALL_FQDNS="0"
SYSTEM=\$(/bin/hostname -f)
IPADDRESSNUM="1"
IPADDRESSES=""
NOTIFY_HOLDS="0"
NOTIFY_NEW="1"
NOTIFY_NO_UPDATES="0"
GPG_ENCRYPT="0"
EOF

cat << EOF > /etc/logwatch/conf/logwatch.conf
Output = mail
MailTo = $EMAIL_LOGS
MailFrom = $MSMTP_FROM
Detail = 5
EOF

echo -e "Instalando IRQBalance..."
apt-get -y install irqbalance
systemctl enable irqbalance

echo -e "Instalando o chrony para atualizacao de data e hora do sistema..."
apt-get -y install chrony

cat << EOF > /etc/chrony/chrony.conf
confdir /etc/chrony/conf.d
sourcedir /run/chrony-dhcp
sourcedir /etc/chrony/sources.d
keyfile /etc/chrony/chrony.keys
driftfile /var/lib/chrony/chrony.drift
ntsdumpdir /var/lib/chrony
logdir /var/log/chrony
maxupdateskew 100.0
rtcsync
makestep 1 3
leapsectz right/UTC
EOF

cat << EOF > /etc/chrony/sources.d/nic.sources
server a.st1.ntp.br iburst nts
server b.st1.ntp.br iburst nts
server c.st1.ntp.br iburst nts
server d.st1.ntp.br iburst nts
EOF

systemctl restart chronyd.service

echo -e "Instalando o iWatch para monitorar integridade do File System..."
apt-get -y install iwatch

cat << EOF > /etc/iwatch/iwatch.xml
<?xml version="1.0" ?>
<!DOCTYPE config SYSTEM "/etc/iwatch/iwatch.dtd" >

<config charset="utf-8">
  <guard email="$EMAIL_LOGS" name="iWatch"/>
  <watchlist>
    <title>Operating System</title>
    <contactpoint email="$EMAIL_LOGS" name="Administrator"/>
    <path type="single" syslog="off" alert="off" exec="(echo %e %f | mailx -s '$HOSTNAME %p' $EMAIL_LOGS)">/bin</path>
    <path type="single" syslog="off" alert="off" exec="(echo %e %f | mailx -s '$HOSTNAME %p' $EMAIL_LOGS)">/sbin</path>
    <path type="recursive" syslog="off" alert="off" exec="(echo %e %f | mailx -s '$HOSTNAME %p' $EMAIL_LOGS)">/lib</path>
    <path type="single" syslog="off" alert="off" exec="(echo %e %f | mailx -s '$HOSTNAME %p' $EMAIL_LOGS)">/var/spool/cron/crontabs/root</path>
  </watchlist>
</config>
EOF

chattr -i /var/spool/cron/crontabs/root
cat << EOF > /var/spool/cron/crontabs/root
# Edit this file to introduce tasks to be run by cron.
#
# Each task to run has to be defined through a single line
# indicating with different fields when the task will be run
# and what command to run for the task
#
# To define the time you can provide concrete values for
# minute (m), hour (h), day of month (dom), month (mon),
# and day of week (dow) or use '*' in these fields (for 'any').
#
# Notice that tasks will be started based on the cron's system
# daemon's notion of time and timezones.
#
# Output of the crontab jobs (including errors) is sent through
# email to the user the crontab file belongs to (unless redirected).
#
# For example, you can run a backup of all your user accounts
# at 5 a.m every week with:
# 0 5 * * 1 tar -zcf /var/backups/home.tgz /home/
#
# For more information see the manual pages of crontab(5) and cron(8)
#
# m h  dom mon dow   command
MAILTO=""
*/1 * * * * (systemctl status iwatch;if [ \$? -ne 0 ]; then echo "iWatch Parou. Verifique!" | mailx -s '$HOSTNAME iWatch' $EMAIL_LOGS; fi)
EOF
crontab -u root /var/spool/cron/crontabs/root
chattr +i /var/spool/cron/crontabs/root
systemctl restart iwatch.service

echo -e "Instalando o fail2ban..."
apt-get -y install fail2ban bind9-utils

if [ "$F2B_XARF" == "Y" ]; then
   cat << EOF > /etc/fail2ban/jail.local
[DEFAULT]
ignoreip = $F2B_IGNOREIP
bantime  = $F2B_BANTIME
findtime  = 1m
maxretry = $F2B_MAXRETRY
banaction = route
banaction_allports = route
sender = $MSMTP_FROM
mta = sendmail
action = %(action_xarf)s

[sshd]
enabled = true
EOF
else
   cat << EOF > /etc/fail2ban/jail.local
[DEFAULT]
ignoreip = $F2B_IGNOREIP
bantime  = $F2B_BANTIME
findtime  = 1m
maxretry = $F2B_MAXRETRY
banaction = route
banaction_allports = route
sender = $MSMTP_FROM
mta = sendmail
action = %(action_)s

[sshd]
enabled = true
EOF
fi

cat << EOF > /etc/fail2ban/action.d/route.local
# Fail2Ban configuration file
#
# Author: Michael Gebetsroither
#
# This is for blocking whole hosts through blackhole routes.
#
# PRO:
#   - Works on all kernel versions and as no compatibility problems (back to debian lenny and WAY further).
#   - It's FAST for very large numbers of blocked ips.
#   - It's FAST because it Blocks traffic before it enters common iptables chains used for filtering.
#   - It's per host, ideal as action against ssh password bruteforcing to block further attack attempts.
#   - No additional software required beside iproute/iproute2
#
# CON:
#   - Blocking is per IP and NOT per service, but ideal as action against ssh password bruteforcing hosts

[Definition]
actionban   = ip route add <blocktype> <ip>
actionunban = ip route del <blocktype> <ip>
actioncheck =
actionstart =
actionstop =

[Init]

# Option:  blocktype
# Note:    Type can be blackhole, unreachable and prohibit. Unreachable and prohibit correspond to the ICMP reject messages.
# Values:  STRING
blocktype = blackhole
EOF

systemctl enable fail2ban.service
systemctl restart fail2ban.service

if [ "$APPARMOR" == "N" -o "$APPARMOR" == "n" ]; then
   echo -e "Colocando o APPARMOR em complain mode..."
   aa-complain /etc/apparmor.d/*
fi

echo -e "Setando timezone para $TIMEZONE..."
timedatectl set-timezone "$TIMEZONE"

echo -e "Definindo o locales do sistema..."
localectl set-locale LANG=$LANG LANGUAGE=$LANGUAGE

echo -e "\nServidor configurado. Reinicie o sistema para validar!"
