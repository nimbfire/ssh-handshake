# Servidor SSH de TESTE com ssh-handshake. Não use em produção: senhas fixas.
FROM golang:1.24-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -trimpath -o /out/ssh-handshake ./cmd/ssh-handshake

FROM ubuntu:24.04
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-server rsyslog \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /run/sshd \
 && sed -i '/imklog/s/^/#/' /etc/rsyslog.conf

COPY --from=build /out/ssh-handshake /usr/local/bin/ssh-handshake
COPY docker/server/sshd_config /etc/ssh/sshd_config
COPY docker/server/entrypoint.sh /entrypoint.sh

# Usuários de teste (senha = nome do usuário):
#   alice -> modo home, cria o handshake no primeiro login
#   bob   -> modo system, handshake instalado pelo root
#   carol -> fora do grupo, sem handshake (para comparar)
RUN groupadd ssh-handshake \
 && for u in alice bob carol; do useradd -m -s /bin/bash "$u" && echo "$u:$u" | chpasswd; done \
 && usermod -aG ssh-handshake alice \
 && usermod -aG ssh-handshake bob \
 && chmod 0755 /usr/local/bin/ssh-handshake /entrypoint.sh

EXPOSE 22
ENTRYPOINT ["/entrypoint.sh"]
