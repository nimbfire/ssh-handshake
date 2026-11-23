#!/bin/sh
set -e
# Chaves de host geradas no primeiro start do container (só para teste).
ssh-keygen -A >/dev/null
rsyslogd
[ -f /var/log/auth.log ] || install -o syslog -g adm -m 0640 /dev/null /var/log/auth.log
exec /usr/sbin/sshd -D -e
