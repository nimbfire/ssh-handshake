# Cliente Linux para testar o servidor.
FROM ubuntu:24.04
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-client sshpass rsync netcat-openbsd \
 && rm -rf /var/lib/apt/lists/*
# Não guarda/valida host key: o servidor de teste é recriado com frequência.
RUN printf 'Host server\n  StrictHostKeyChecking no\n  UserKnownHostsFile /dev/null\n  LogLevel ERROR\n' > /etc/ssh/ssh_config.d/test.conf
CMD ["sleep", "infinity"]
