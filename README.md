# ssh-handshake

Uma camada extra de autenticação para sessões SSH, escrita em Go.

Depois que o `sshd` autentica o usuário normalmente (chave, senha, MFA etc.), e **antes** de liberar o shell ou o comando pedido, o `ssh-handshake` roda e exige um segundo segredo interativo: o *handshake*. Se o handshake falhar, a conexão é encerrada.

```
cliente ──ssh──▶ sshd (chave/senha OK) ──ForceCommand──▶ ssh-handshake login
                                                              │
                                     ok ◀─────────────────────┤──────────▶ falha
                                     │                                     │
                      exec $SHELL / SSH_ORIGINAL_COMMAND           log + espera + desconecta
```

## Sumário

- [Como funciona o handshake de movimentos de mão](#como-funciona-o-handshake-de-movimentos-de-mão)
- [Instalação](#instalação)
- [Configuração do sshd](#configuração-do-sshd)
- [Modos de armazenamento: `system` x `home`](#modos-de-armazenamento-system-x-home)
- [Criando handshakes (enrollment)](#criando-handshakes-enrollment)
- [Referência de comandos](#referência-de-comandos)
- [Modelo de segurança e riscos conhecidos](#modelo-de-segurança-e-riscos-conhecidos)
- [Logs e fail2ban](#logs-e-fail2ban)
- [Formato do arquivo de handshake](#formato-do-arquivo-de-handshake)
- [Criando novos validadores](#criando-novos-validadores)
- [Desenvolvimento](#desenvolvimento)

## Como funciona o handshake de movimentos de mão

O validador padrão (`handmove`) é um sistema de perguntas e respostas. Existem 9 movimentos de mão:

| # | Movimento |
|---|-----------|
| 0 | Mão aberta (palma para frente) |
| 1 | Punho fechado |
| 2 | Polegar para cima |
| 3 | Polegar para baixo |
| 4 | Sinal de V (paz) |
| 5 | Indicador apontando |
| 6 | Sinal de OK |
| 7 | Chifres (indicador e mindinho) |
| 8 | Mão em concha |

**Na criação (enrollment):**

1. O servidor sorteia, com `crypto/rand`, uma sequência fixa de *N* movimentos dele (as "deixas"). O padrão é *N* = 10 e o mínimo é 8.
2. Para cada deixa, o usuário escolhe com qual movimento responde. Esse é o segredo.
3. O usuário repete a sequência inteira para confirmar. As opções aparecem embaralhadas de novo.
4. O sistema rejeita sequências com menos de 3 respostas diferentes.
5. As deixas ficam salvas em texto claro. As respostas são salvas só como hash Argon2id.

**No login:**

```
== ssh-handshake ==

[1/10] Meu movimento: Sinal de OK
  1) Polegar para baixo
  2) Mão em concha
  3) Punho fechado
  4) Sinal de V (paz)
  5) Mão aberta (palma para frente)
  6) Chifres (indicador e mindinho)
  7) Indicador apontando
  8) Polegar para cima
  9) Sinal de OK
Sua resposta (1-9):
```

- As deixas aparecem sempre na mesma ordem.
- As 9 opções são **embaralhadas a cada pergunta e a cada login**. O usuário digita de 1 a 9, mas o que entra no hash é *qual movimento* foi escolhido, não o dígito. Assim, quem grava as teclas ou olha a tela vê números que mudam a cada sessão.
- As 9 opções aparecem sempre, então observar vários logins não reduz o conjunto de candidatos.
- A entrada não ecoa no terminal.
- Não há feedback por pergunta: o servidor monta a resposta completa e só no final compara o hash, em tempo constante. Um erro na pergunta 2 só aparece depois da pergunta 10.

## Instalação

Requer Go ≥ 1.23.

```sh
git clone https://github.com/nimbfire/ssh-handshake
cd ssh-handshake
make test
sudo make install          # instala /usr/local/bin/ssh-handshake (root:root 0755)
```

O binário precisa pertencer ao root e não pode ser gravável por usuários comuns, porque é ele que decide quem passa.

> Compile com cgo habilitado (o padrão do `make build`) se os usuários vierem de LDAP/SSSD. A implementação pura em Go de `os/user` só lê `/etc/passwd`.

## Configuração do sshd

Crie o grupo dos usuários protegidos:

```sh
sudo groupadd ssh-handshake
sudo usermod -aG ssh-handshake alice
```

Copie [`examples/sshd_config.d-ssh-handshake.conf`](examples/sshd_config.d-ssh-handshake.conf) para `/etc/ssh/sshd_config.d/ssh-handshake.conf` (ou cole no fim do `sshd_config`):

```sshconfig
Match Group ssh-handshake
    ForceCommand /usr/local/bin/ssh-handshake login --store system
    AllowTcpForwarding no
    AllowStreamLocalForwarding no
    PermitTunnel no
    X11Forwarding no
    AllowAgentForwarding no
    PermitUserRC no
```

Valide e recarregue a configuração **mantendo uma sessão root aberta** para não ficar trancado do lado de fora:

```sh
sudo sshd -t && sudo systemctl reload ssh   # ou sshd, conforme a distro
```

### Por que cada linha é obrigatória

| Diretiva | Sem ela… |
|----------|----------|
| `ForceCommand` | O handshake não roda. O `ForceCommand` vem do `sshd_config` (root) e sobrepõe o comando pedido pelo cliente, o subsistema sftp e o `command=` do `authorized_keys`. **Não use `~/.ssh/rc`**: esse arquivo é do usuário e não consegue bloquear o shell. |
| `AllowTcpForwarding no`, `AllowStreamLocalForwarding no`, `PermitTunnel no` | `ssh -N -L/-R/-D` abre túneis **sem executar nenhum comando**, então o handshake nunca roda. |
| `X11Forwarding no`, `AllowAgentForwarding no` | Esses canais podem ser usados antes ou fora da sessão interativa. |
| `PermitUserRC no` | O `~/.ssh/rc` roda **antes** do ForceCommand, com código controlado pelo usuário. |
| `PermitUserEnvironment no` (padrão) | O cliente poderia trocar `SHELL` e outras variáveis usadas depois do handshake. |

### O que acontece com cada tipo de acesso

| Acesso | Resultado |
|--------|-----------|
| `ssh host` | handshake, depois shell de login |
| `ssh -t host cmd` / `ssh host cmd` | handshake (prompts em stderr), depois `$SHELL -c "cmd"` |
| `sftp`, `scp`, `rsync`, `git push/pull` | **negado na hora**: são protocolos de máquina e não conseguem responder ao handshake |
| `ssh -N -L …` | túnel recusado pelo sshd (com a configuração acima) |
| Ctrl+C durante o handshake | sessão encerrada |
| Ctrl+Z durante o handshake | ignorado |
| Sem resposta | sessão encerrada após `--timeout` (padrão: 3 min) |

Se você precisa de sftp/scp/git para um usuário protegido, use outra conta, fora do grupo e com permissões mínimas, para isso. Liberar esses protocolos sem handshake abriria um bypass.

## Modos de armazenamento: `system` x `home`

| | `--store system` (**recomendado**) | `--store home` |
|---|---|---|
| Local | `/var/lib/ssh-handshake/<user>` | `~/.ssh/ssh-handshake` |
| Dono / permissão | `root:<grupo do user>` `0640`, diretório `root` `0755` | `user` `0600` |
| Quem pode alterar | só root | o próprio usuário e **qualquer processo rodando como ele** |
| Criação no 1º login | não (enrollment pelo admin) | opcional, com `--allow-self-enroll` |
| Outros usuários leem o hash? | não | não |

No modo `home`, o usuário é dono de `~/.ssh` e pode apagar ou trocar o arquivo mesmo que ele seja de outro dono. Se o arquivo for **apagado** e `--allow-self-enroll` estiver ativo, o próximo login cria um handshake novo. Uma webapp comprometida rodando como o usuário, ou alguém com acesso temporário, consegue então "resetar" o handshake. O modo `system` elimina isso.

Nos dois modos, o programa **falha fechado**:

- recusa symlinks, arquivos ou diretórios graváveis por grupo/outros, donos inesperados, JSON inválido e registros de outro usuário;
- nesses casos **nunca** oferece criar um handshake novo: só um arquivo inexistente leva ao enrollment.

## Criando handshakes (enrollment)

### Modo `system`: o usuário gera, o admin instala (o admin não fica sabendo o segredo)

1. O usuário roda o binário em **qualquer máquina**, inclusive a própria, e gera o registro:

   ```sh
   ssh-handshake enroll -u alice --print > alice.json
   ```

   O JSON contém só as deixas e o hash Argon2id. Mesmo assim, trate o arquivo como sensível (veja *ataque offline* abaixo) e envie por um canal confiável.

2. O admin instala no servidor:

   ```sh
   sudo ssh-handshake install -u alice alice.json
   ```

Se preferir, o admin pode criar junto com o usuário, direto no servidor: `sudo ssh-handshake enroll -u alice --store system`.

Para resetar, o admin roda `sudo rm /var/lib/ssh-handshake/alice` e repete o processo. Enquanto não houver arquivo, a alice fica **sem acesso**.

### Modo `home`

- **Criação no primeiro login (TOFU):** use `login --store home --allow-self-enroll`. Na primeira conexão sem arquivo, o usuário cria o handshake e entra.
- **Pelo próprio usuário:** `ssh-handshake enroll`. Se já existir um handshake, ele precisa ser respondido antes de ser trocado.
- **Pelo admin:** `sudo ssh-handshake enroll -u alice --store home`.

> ⚠️ Com `--allow-self-enroll`, quem conectar primeiro define o handshake. Se a chave ou senha da conta vazar antes do dono criar o handshake, o atacante cria o dele. Só habilite isso numa janela controlada, ou faça o enrollment antes de adicionar o usuário ao grupo.

## Referência de comandos

```
ssh-handshake login    [flags]           ForceCommand do sshd: valida e faz exec do shell
ssh-handshake enroll   [flags]           cria/troca o handshake
ssh-handshake install  -u USER ARQUIVO   (root) instala um registro gerado com enroll --print
ssh-handshake verify   [flags]           testa o handshake sem abrir shell
ssh-handshake validators                 lista os validadores disponíveis
ssh-handshake version
```

| Flag | Comandos | Padrão | Descrição |
|------|----------|--------|-----------|
| `--store home\|system` | todos | `home` (`install`: `system`) | backend de armazenamento |
| `--store-dir DIR` | todos | `/var/lib/ssh-handshake` | diretório do store `system` |
| `--timeout D` | login, enroll, verify | `3m` | tempo máximo de interação |
| `--length N` | enroll, login (TOFU) | `10` | número de passos (8–32) |
| `--validator NOME` | enroll, login (TOFU) | `handmove` | tipo de handshake para novos registros |
| `--allow-self-enroll` | login | desligado | permite criar no 1º login (só `home`) |
| `--fail-delay D` | login | `3s` | espera antes de desconectar após falha |
| `-u USER` | enroll, install | usuário atual | usuário alvo |
| `--print` | enroll | — | imprime o registro em stdout em vez de salvar |

Códigos de saída: `0` sucesso; `1` negado ou erro; `2` uso incorreto. Em `login`, o sucesso não retorna: o processo vira o shell via `exec`.

## Modelo de segurança e riscos conhecidos

**O que o ssh-handshake protege:** o uso de credenciais SSH roubadas (chave privada, senha) por quem não conhece o handshake.

**O que ele não protege:**

- Um atacante que já executa código **no servidor** como o usuário (no modo `home`, ele pode resetar o handshake) ou como root.
- Sessões já abertas, ou um cliente comprometido que sequestra uma sessão autenticada (por exemplo, multiplexação com `ControlMaster` do lado do cliente).
- Outros serviços do servidor (web, banco etc.).

### Espaço de chaves e ataque offline

Cada resposta tem 9 possibilidades, ou ~3,17 bits:

| Passos | Combinações | Busca completa a ~0,1 s de CPU por tentativa (1 núcleo) |
|-------:|------------:|------------------------------------:|
| 6 | 531 mil | ~15 horas |
| 8 (mínimo) | 43 milhões | ~50 dias |
| 10 (padrão) | 3,5 bilhões | ~11 anos |
| 12 | 282 bilhões | ~900 anos |

Os valores foram medidos com `go test -bench . ./internal/kdf/`: ~60 ms por verificação usando 2 threads. Um atacante com *k* núcleos divide esses tempos por *k*: com 100 núcleos, 10 passos caem para ~40 dias. Por isso o arquivo de hash precisa ficar protegido.

Com um hash rápido (SHA-256), mesmo 12 passos cairiam em segundos numa GPU. Por isso:

- **Argon2id** com 64 MiB, 3 passadas, 2 threads e salt aleatório de 16 bytes. Os parâmetros ficam no arquivo, e o verificador rejeita parâmetros abaixo de um piso (19 MiB) ou acima de um teto (1 GiB), para impedir downgrade e DoS.
- O hash é **vinculado** ao usuário, ao validador e às deixas. Mudar qualquer um desses invalida o registro.
- O hash ainda é a parte mais sensível: **quem lê o arquivo pode montar um ataque offline**. No modo `system`, só root e o próprio usuário leem o arquivo. Use 10 passos ou mais.

### Ataque online

- Uma tentativa por conexão, sem feedback por passo.
- `--fail-delay` atrasa cada falha.
- Cada falha gera log em syslog (`auth`) com o IP. Use [fail2ban](#logs-e-fail2ban).
- O `MaxStartups` e o `LoginGraceTime` do sshd limitam conexões em paralelo.

### Outros cuidados

- **Keylogger e shoulder surfing:** os dígitos digitados mudam a cada login porque as opções são embaralhadas. Quem filma a tela inteira em um login, porém, vê os movimentos escolhidos. É um segredo de conhecimento, como uma senha.
- **Root:** root pode tudo. Se a conta root usar SSH, coloque-a no grupo também, ou desabilite `PermitRootLogin`.
- **Console ou outro acesso:** o handshake só vale para SSH. Login local, painel do provedor etc. não passam por ele.

## Logs e fail2ban

Os eventos vão para o syslog com a facility `auth` e a tag `ssh-handshake`:

```
ssh-handshake[1234]: accepted user=alice from=203.0.113.7 port=51022 validator=handmove
ssh-handshake[1240]: denied user=alice from=198.51.100.9 port=40112 reason="wrong answer"
ssh-handshake[1250]: denied user=alice from=198.51.100.9 port=40118 reason="non-interactive protocol" command="internal-sftp"
ssh-handshake[1300]: installed handshake user=alice validator=handmove
```

Para usar com fail2ban, copie `examples/fail2ban/filter.d-ssh-handshake.conf` e `examples/fail2ban/jail.d-ssh-handshake.conf` para `/etc/fail2ban/` e rode `sudo systemctl reload fail2ban`.

## Formato do arquivo de handshake

```json
{
  "version": 1,
  "user": "alice",
  "validator": "handmove",
  "params": { "cues": [6, 2, 0, 8, 1, 1, 4, 7, 3, 5] },
  "kdf": {
    "alg": "argon2id",
    "time": 3,
    "memory_kib": 65536,
    "threads": 2,
    "salt": "base64…",
    "hash": "base64…"
  },
  "created_at": "2026-11-23T20:48:00Z"
}
```

O hash é `Argon2id(len(ad) ‖ ad ‖ len(segredo) ‖ segredo, salt)`, onde:

- `ad = "ssh-handshake/v1\0" ‖ user ‖ "\0" ‖ validator ‖ "\0" ‖ params (JSON compactado)`;
- para o `handmove`, o segredo é a sequência de índices dos movimentos escolhidos.

**Nunca reordene o catálogo `handmove.Movements`**: os índices fazem parte do formato.

## Criando novos validadores

Cada validador implementa a interface `validator.Validator` (`internal/validator/validator.go`):

```go
type Validator interface {
    Name() string
    Description() string
    Enroll(t terminal.Terminal, rnd io.Reader, opts EnrollOptions) (params json.RawMessage, secret []byte, err error)
    Challenge(t terminal.Terminal, rnd io.Reader, params json.RawMessage) (secret []byte, err error)
}
```

O validador cuida **só da conversa** com o usuário:

- devolve os parâmetros públicos, que ficam salvos em claro, e os bytes do segredo;
- não deve dar feedback de acerto ou erro por etapa;
- não calcula hash nem compara nada: Argon2id, vínculo com o usuário, comparação em tempo constante e armazenamento ficam centralizados em `internal/app`, `internal/kdf` e `internal/store`.

Para adicionar um validador:

1. Crie `internal/validator/<nome>/` com um tipo que implemente a interface.
2. Registre o validador em `init()` com `validator.Register(...)`.
3. Importe o pacote em `cmd/ssh-handshake/main.go`, como já é feito com `handmove`.
4. Garanta que o espaço de chaves seja ≥ ~2³⁰ e escreva testes usando `internal/testutil`.

Exemplos de ideias: sequência de cores ou formas, padrão em grade 3×3 ou TOTP.

## Desenvolvimento

```sh
make test     # go vet + testes unitários
make build
```

Estrutura:

```
cmd/ssh-handshake/        CLI (flags, sinais, timeout, exec)
internal/app/             fluxos login / enroll / verify (testáveis)
internal/kdf/             Argon2id + limites de parâmetros
internal/store/           backends home e system, checagens de dono/permissão
internal/validator/       interface + registro de validadores
internal/validator/handmove/  validador de movimentos de mão
internal/terminal/        I/O com o usuário (sem eco em TTY, prompts em stderr)
internal/session/         exec do shell / SSH_ORIGINAL_COMMAND
internal/audit/           logs em syslog
examples/                 sshd_config e fail2ban
```

Os testes cobrem:

- enrollment, confirmação e login;
- rejeição de respostas erradas, arquivos corrompidos, symlinks, permissões frouxas e registros de outro usuário;
- downgrade de parâmetros do KDF;
- detecção de protocolos não interativos.

Além disso, o fluxo foi validado de ponta a ponta contra um OpenSSH real:

- enrollment no 1º login, shell e comando remoto;
- resposta errada, que desconecta sem executar o comando;
- port forwarding recusado;
- sftp e scp negados;
- Ctrl+C desconecta e Ctrl+Z é ignorado;
- modo `system` com `enroll --print` + `install`, com o usuário sem permissão para alterar o próprio registro.
