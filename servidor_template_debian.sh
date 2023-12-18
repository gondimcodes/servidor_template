#!/usr/bin/env bash
# Script de preparacao de servidores Debian GNU/Linux para uso em producao
# ATENCAO! Esse script eh para ser usado em servidores recem instalados, que
# nao estejam ainda em producao pois serah re-configurado todo o ambiente.
# Eh uma contribuicao e nao me responsabilizo por quaisquer danos causados
# pelo uso desse script.
# Autor: Marcelo Gondim - gondim at gmail.com
# Data: 21/01/2023
# Versao: 2.0
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

# A variavel mitigations do kernel, mitiga as vulnerabilidades dos processadores. Se você tem um ambiente bare metal ou virtualizado e sob controle, pode
# manter como "off" para ganhar performance em detrimento a seguranca. Caso contrario altere o valor para: "auto"
MITIGATIONS="off"

LANG="pt_BR.UTF-8"
LANGUAGE="pt_BR.UTF-8:pt:en"
DISTRO_NAME="`lsb_release -s -c`"
# Para listar os timezones disponiveis execute: timedatectl list-timezones
TIMEZONE="UTC"

# Habilita fail2ban?
F2B_ENABLE="Y"
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
if [ "$DISTRO_NAME" == "bookworm" ]; then
    cat << EOF > /etc/apt/sources.list
deb http://security.debian.org/debian-security $DISTRO_NAME-security main contrib non-free non-free-firmware
deb http://deb.debian.org/debian $DISTRO_NAME main contrib non-free non-free-firmware
deb http://deb.debian.org/debian $DISTRO_NAME-updates main contrib non-free non-free-firmware
deb http://deb.debian.org/debian $DISTRO_NAME-backports main contrib non-free non-free-firmware
EOF
else
    cat << EOF > /etc/apt/sources.list
deb http://security.debian.org/debian-security $DISTRO_NAME-security main contrib non-free
deb http://deb.debian.org/debian $DISTRO_NAME main non-free contrib
deb http://deb.debian.org/debian $DISTRO_NAME-updates main contrib non-free
deb http://deb.debian.org/debian $DISTRO_NAME-backports main contrib non-free
EOF
fi

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
apt-get update && apt-get -y full-upgrade && apt-get -y install neofetch net-tools nftables htop iotop sipcalc tcpdump vim-nox curl gnupg rsync wget host dnsutils mtr-tiny bmon sudo expect tmux whois ethtool dnstop apparmor-utils openssl openssh-client openssh-server iproute2 nmap ncdu bind9utils conntrack psmisc uuid uuid-runtime fping zstd 
echo "syntax on" > /root/.vimrc

# Agradecimento a Patrick Brandao pelos tunings http://patrickbrandao.com/
echo -e "Adicionando algumas configuracoes em /etc/sysctl.d/..."
cat << EOF > /etc/sysctl.d/051-net-core.conf
net.core.rmem_default=31457280
net.core.wmem_default=31457280
net.core.rmem_max=134217728
net.core.wmem_max=134217728
net.core.netdev_max_backlog=250000
net.core.optmem_max=33554432
net.core.default_qdisc=fq
net.core.somaxconn=4096
EOF
 
cat << EOF > /etc/sysctl.d/052-net-tcp-ipv4.conf
net.ipv4.tcp_sack=1
net.ipv4.tcp_timestamps=1
net.ipv4.tcp_low_latency=1
net.ipv4.tcp_max_syn_backlog=8192
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.ipv4.tcp_mem = 6672016 6682016 7185248
net.ipv4.tcp_congestion_control=htcp
net.ipv4.tcp_mtu_probing=1
net.ipv4.tcp_moderate_rcvbuf=1
net.ipv4.tcp_no_metrics_save=1
EOF
 
cat << EOF > /etc/sysctl.d/056-port-range-ipv4.conf
net.ipv4.ip_local_port_range=1024 65535
EOF
 
cat << EOF > /etc/sysctl.d/062-default-ttl-ipv4.conf
net.ipv4.ip_default_ttl=128
EOF
 
cat << EOF > /etc/sysctl.d/063-neigh-ipv4.conf
net.ipv4.neigh.default.gc_interval = 30
net.ipv4.neigh.default.gc_stale_time = 60
net.ipv4.neigh.default.gc_thresh1 = 4096
net.ipv4.neigh.default.gc_thresh2 = 8192
net.ipv4.neigh.default.gc_thresh3 = 12288
 
net.ipv4.ipfrag_high_thresh=4194304
net.ipv4.ipfrag_low_thresh=3145728
net.ipv4.ipfrag_max_dist=64
net.ipv4.ipfrag_secret_interval=0
net.ipv4.ipfrag_time=30
EOF
 
cat << EOF > /etc/sysctl.d/064-neigh-ipv6.conf
net.ipv6.neigh.default.gc_interval = 30
net.ipv6.neigh.default.gc_stale_time = 60
net.ipv6.neigh.default.gc_thresh1 = 4096
net.ipv6.neigh.default.gc_thresh2 = 8192
net.ipv6.neigh.default.gc_thresh3 = 12288
 
net.ipv6.ip6frag_high_thresh=4194304
net.ipv6.ip6frag_low_thresh=3145728
net.ipv6.ip6frag_secret_interval=0
net.ipv6.ip6frag_time=60
EOF
 
cat << EOF > /etc/sysctl.d/065-default-foward-ipv4.conf
net.ipv4.conf.default.forwarding=1
EOF
 
cat << EOF > /etc/sysctl.d/066-default-foward-ipv6.conf
net.ipv6.conf.default.forwarding=1
EOF
 
cat << EOF > /etc/sysctl.d/067-all-foward-ipv4.conf
net.ipv4.conf.all.forwarding=1
EOF
 
cat << EOF > /etc/sysctl.d/068-all-foward-ipv6.conf
net.ipv6.conf.all.forwarding=1
EOF
 
cat << EOF > /etc/sysctl.d/069-ipv4-forward.conf
net.ipv4.ip_forward=1
EOF
 
cat << EOF > /etc/sysctl.d/072-fs-options.conf
fs.file-max = 3263776
fs.aio-max-nr=3263776
fs.mount-max=1048576
fs.mqueue.msg_max=128
fs.mqueue.msgsize_max=131072
fs.mqueue.queues_max=4096
fs.pipe-max-size=8388608
EOF
 
cat << EOF > /etc/sysctl.d/073-swappiness.conf 
vm.swappiness=1
EOF
 
cat << EOF > /etc/sysctl.d/074-vfs-cache-pressure.conf
vm.vfs_cache_pressure=50
EOF
 
cat << EOF > /etc/sysctl.d/081-kernel-panic.conf
kernel.panic=3
EOF
 
cat << EOF > /etc/sysctl.d/082-kernel-threads.conf
kernel.threads-max=1031306
EOF
 
cat << EOF > /etc/sysctl.d/083-kernel-pid.conf
kernel.pid_max=262144
EOF
 
cat << EOF > /etc/sysctl.d/084-kernel-msgmax.conf
kernel.msgmax=327680
EOF
 
cat << EOF > /etc/sysctl.d/085-kernel-msgmnb.conf
kernel.msgmnb=655360
EOF
 
cat << EOF > /etc/sysctl.d/086-kernel-msgmni.conf
kernel.msgmni=32768
EOF
 
cat << EOF > /etc/sysctl.d/087-kernel-free-min-kb.conf
vm.min_free_kbytes = 32768
EOF

cat << EOF > /etc/sysctl.d/090-netfilter-max.conf
net.nf_conntrack_max=8000000
EOF

cat << EOF > /etc/sysctl.d/091-netfilter-generic.conf
net.netfilter.nf_conntrack_buckets=262144
net.netfilter.nf_conntrack_checksum=1
net.netfilter.nf_conntrack_events=1
net.netfilter.nf_conntrack_expect_max=1024
net.netfilter.nf_conntrack_timestamp=0
EOF

cat << EOF > /etc/sysctl.d/093-netfilter-icmp.conf
net.netfilter.nf_conntrack_icmp_timeout=30
net.netfilter.nf_conntrack_icmpv6_timeout=30
EOF

cat << EOF > /etc/sysctl.d/094-netfilter-tcp.conf
net.netfilter.nf_conntrack_tcp_be_liberal=0
net.netfilter.nf_conntrack_tcp_loose=1
net.netfilter.nf_conntrack_tcp_max_retrans=3
net.netfilter.nf_conntrack_tcp_timeout_close=10
net.netfilter.nf_conntrack_tcp_timeout_close_wait=10
net.netfilter.nf_conntrack_tcp_timeout_established=600
net.netfilter.nf_conntrack_tcp_timeout_fin_wait=10
net.netfilter.nf_conntrack_tcp_timeout_last_ack=10
net.netfilter.nf_conntrack_tcp_timeout_max_retrans=60
net.netfilter.nf_conntrack_tcp_timeout_syn_recv=5
net.netfilter.nf_conntrack_tcp_timeout_syn_sent=5
net.netfilter.nf_conntrack_tcp_timeout_time_wait=30
net.netfilter.nf_conntrack_tcp_timeout_unacknowledged=300
EOF

cat << EOF > /etc/sysctl.d/095-netfilter-udp.conf
net.netfilter.nf_conntrack_udp_timeout=30
net.netfilter.nf_conntrack_udp_timeout_stream=180
EOF

cat << EOF > /etc/sysctl.d/096-netfilter-sctp.conf
net.netfilter.nf_conntrack_sctp_timeout_closed=10
net.netfilter.nf_conntrack_sctp_timeout_cookie_echoed=3
net.netfilter.nf_conntrack_sctp_timeout_cookie_wait=3
net.netfilter.nf_conntrack_sctp_timeout_established=432000
net.netfilter.nf_conntrack_sctp_timeout_heartbeat_acked=210
net.netfilter.nf_conntrack_sctp_timeout_heartbeat_sent=30
net.netfilter.nf_conntrack_sctp_timeout_shutdown_ack_sent=3
net.netfilter.nf_conntrack_sctp_timeout_shutdown_recd=0
net.netfilter.nf_conntrack_sctp_timeout_shutdown_sent=0
EOF

cat << EOF > /etc/sysctl.d/097-netfilter-dccp.conf
net.netfilter.nf_conntrack_dccp_loose=1
net.netfilter.nf_conntrack_dccp_timeout_closereq=64
net.netfilter.nf_conntrack_dccp_timeout_closing=64
net.netfilter.nf_conntrack_dccp_timeout_open=43200
net.netfilter.nf_conntrack_dccp_timeout_partopen=480
net.netfilter.nf_conntrack_dccp_timeout_request=240
net.netfilter.nf_conntrack_dccp_timeout_respond=480
net.netfilter.nf_conntrack_dccp_timeout_timewait=240
EOF

cat << EOF > /etc/sysctl.d/099-netfilter-ipv6.conf
net.netfilter.nf_conntrack_frag6_high_thresh=4194304
net.netfilter.nf_conntrack_frag6_low_thresh=3145728
net.netfilter.nf_conntrack_frag6_timeout=60
EOF

cat << EOF > /etc/sysctl.d/100-fs-inotify.conf
fs.inotify.max_user_watches=524288
EOF

echo nf_conntrack > /etc/modules-load.d/conntrack.conf
modprobe nf_conntrack
sysctl --system

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

if [ "$F2B_ENABLE" == "Y" -o "$F2B_ENABLE" == "y" ]; then
   echo -e "Instalando o fail2ban..."
   apt-get -y install fail2ban bind9-utils

   if [ "$F2B_XARF" == "Y" -o "$F2B_XARF" == "y" ]; then
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

fi

if [ "$APPARMOR" == "N" -o "$APPARMOR" == "n" ]; then
   echo -e "Removendo o APPARMOR..."
   mkdir -p /etc/default/grub.d
   cat << EOF > /etc/default/grub.d/apparmor.cfg
GRUB_CMDLINE_LINUX_DEFAULT="\$GRUB_CMDLINE_LINUX_DEFAULT mitigations=$MITIGATIONS apparmor=0"
EOF
   update-grub
fi

echo -e "Setando timezone para $TIMEZONE..."
timedatectl set-timezone "$TIMEZONE"

echo -e "Definindo o locales do sistema..."
localectl set-locale LANG=$LANG LANGUAGE=$LANGUAGE

echo -e "\nServidor configurado. Reinicie o sistema para validar!"
