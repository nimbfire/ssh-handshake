// Command ssh-handshake is an extra, interactive authentication step that
// runs after sshd has authenticated a user, through sshd's ForceCommand.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"os/user"
	"strconv"
	"syscall"
	"time"

	"github.com/nimbfire/ssh-handshake/internal/app"
	"github.com/nimbfire/ssh-handshake/internal/audit"
	"github.com/nimbfire/ssh-handshake/internal/session"
	"github.com/nimbfire/ssh-handshake/internal/store"
	"github.com/nimbfire/ssh-handshake/internal/terminal"
	"github.com/nimbfire/ssh-handshake/internal/validator"
	"github.com/nimbfire/ssh-handshake/internal/validator/handmove"
	"github.com/nimbfire/ssh-handshake/internal/validator/handseq"
)

var version = "dev"

const usage = `ssh-handshake - camada extra de autenticação para sessões SSH

Uso:
  ssh-handshake login    [flags]         (ForceCommand do sshd) valida e abre o shell
  ssh-handshake enroll   [flags]         cria ou troca o handshake
  ssh-handshake install  -u USER ARQUIVO (root) instala um handshake gerado com enroll --print
  ssh-handshake verify   [flags]         testa o handshake sem abrir shell
  ssh-handshake validators               lista os tipos de handshake
  ssh-handshake version

Use "ssh-handshake <comando> -h" para ver as flags.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "login":
		err = runLogin(args)
	case "enroll":
		err = runEnroll(args)
	case "install":
		err = runInstall(args)
	case "verify":
		err = runVerify(args)
	case "validators":
		for _, n := range validator.Names() {
			v, _ := validator.Get(n)
			fmt.Printf("%-10s %s\n", n, v.Description())
		}
	case "version":
		fmt.Println(version)
	case "-h", "--help", "help":
		fmt.Print(usage)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "ssh-handshake: %v\n", err)
		os.Exit(1)
	}
}

// common holds flags shared by subcommands.
type common struct {
	storeKind string
	storeDir  string
	length    int
	minLength int
	validator string
	timeout   time.Duration
}

func (c *common) register(fs *flag.FlagSet) {
	fs.StringVar(&c.storeKind, "store", "home", `onde fica o hash: "home" (~/.ssh/ssh-handshake) ou "system" (root-owned)`)
	fs.StringVar(&c.storeDir, "store-dir", store.DefaultSystemDir, "diretório do store system")
	fs.IntVar(&c.length, "length", handmove.DefaultLength, "número de passos ao criar um handshake handmove")
	fs.IntVar(&c.minLength, "min-length", handseq.MinLength, "mínimo de mãos ao criar um handshake handseq")
	fs.StringVar(&c.validator, "validator", handseq.Name, "tipo de handshake ao criar um novo")
	fs.BoolFunc("fixed-order", "handseq: cada mão tem sempre o mesmo número, em todo login", func(string) error {
		handseq.FixedOrder = true
		return nil
	})
	fs.DurationVar(&c.timeout, "timeout", 3*time.Minute, "tempo máximo da interação")
	fs.BoolFunc("no-emoji", "não mostra emojis das mãos (terminais sem suporte)", func(string) error {
		handmove.ShowEmoji = false
		return nil
	})
}

func (c *common) store() (store.Store, error) {
	switch c.storeKind {
	case "home":
		return store.Home{}, nil
	case "system":
		return store.System{Dir: c.storeDir}, nil
	}
	return nil, fmt.Errorf("--store inválido %q (use home ou system)", c.storeKind)
}

func (c *common) config(log audit.Logger) (app.Config, error) {
	st, err := c.store()
	if err != nil {
		return app.Config{}, err
	}
	if c.minLength < handseq.MinLength || c.minLength > handseq.MaxLength {
		return app.Config{}, fmt.Errorf("--min-length deve estar entre %d e %d", handseq.MinLength, handseq.MaxLength)
	}
	if c.length < handmove.MinLength || c.length > handmove.MaxLength {
		return app.Config{}, fmt.Errorf("--length deve estar entre %d e %d", handmove.MinLength, handmove.MaxLength)
	}
	if _, err := validator.Get(c.validator); err != nil {
		return app.Config{}, err
	}
	return app.Config{Store: st, Validator: c.validator, Length: c.length, MinLength: c.minLength, Log: log}, nil
}

func runLogin(args []string) error {
	fs := flag.NewFlagSet("login", flag.ExitOnError)
	var c common
	c.register(fs)
	selfEnroll := fs.Bool("allow-self-enroll", false, "permite criar o handshake no primeiro login (TOFU; só com --store home)")
	failDelay := fs.Duration("fail-delay", 3*time.Second, "espera antes de desconectar após falha")
	_ = fs.Parse(args)

	guard(c.timeout)
	log := audit.NewSyslog()
	cfg, err := c.config(log)
	if err != nil {
		return err
	}
	if *selfEnroll && !cfg.Store.SelfWritable() {
		return errors.New("--allow-self-enroll só funciona com --store home")
	}
	cfg.AllowSelfEnroll = *selfEnroll
	cfg.FailDelay = *failDelay

	acct, err := currentAccount()
	if err != nil {
		return err
	}
	if cmd := os.Getenv("SSH_ORIGINAL_COMMAND"); app.IsFileTransfer(cmd) {
		log.Warn(fmt.Sprintf("denied user=%s %s reason=\"non-interactive protocol\" command=%q", acct.Name, audit.Remote(), cmd))
		return fmt.Errorf("%w: %q não é interativo e não pode responder ao handshake", app.ErrDenied, cmd)
	}
	if err := app.Login(cfg, acct, terminal.NewStd()); err != nil {
		return err
	}
	return session.Exec()
}

func runVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	var c common
	c.register(fs)
	_ = fs.Parse(args)
	guard(c.timeout)
	cfg, err := c.config(audit.Nop{})
	if err != nil {
		return err
	}
	acct, err := currentAccount()
	if err != nil {
		return err
	}
	rec, err := cfg.Store.Load(acct)
	if err != nil {
		return err
	}
	ok, err := app.Verify(cfg, rec, terminal.NewStd())
	if err != nil {
		return err
	}
	if !ok {
		return app.ErrDenied
	}
	fmt.Fprintln(os.Stderr, "Handshake ok.")
	return nil
}

func runEnroll(args []string) error {
	fs := flag.NewFlagSet("enroll", flag.ExitOnError)
	var c common
	c.register(fs)
	userName := fs.String("u", "", "usuário alvo (padrão: o usuário atual; outro usuário exige root ou --print)")
	printOnly := fs.Bool("print", false, "não salva: imprime o registro JSON em stdout (para enviar ao admin e usar com install)")
	_ = fs.Parse(args)
	guard(c.timeout)

	log := audit.NewSyslog()
	cfg, err := c.config(log)
	if err != nil {
		return err
	}
	acct, err := resolveAccount(*userName, *printOnly)
	if err != nil {
		return err
	}
	t := terminal.NewStd()

	if *printOnly {
		rec, err := app.NewRecord(cfg, acct, t)
		if err != nil {
			return err
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(rec)
	}

	// A non-root user replacing an existing handshake must prove the
	// current one first, so a hijacked shell cannot silently rotate it.
	if os.Geteuid() != 0 {
		if !cfg.Store.SelfWritable() {
			return errors.New("o store system só pode ser alterado pelo root; use enroll --print e peça ao admin para rodar install")
		}
		rec, err := cfg.Store.Load(acct)
		switch {
		case err == nil:
			t.Printf("Primeiro confirme o handshake atual.\n")
			ok, err := app.Verify(cfg, rec, t)
			if err != nil {
				return err
			}
			if !ok {
				log.Warn(fmt.Sprintf("re-enroll denied user=%s %s", acct.Name, audit.Remote()))
				return app.ErrDenied
			}
		case errors.Is(err, store.ErrNotFound):
		default:
			return err
		}
	}
	if err := app.Enroll(cfg, acct, t); err != nil {
		return err
	}
	p, _ := cfg.Store.Path(acct)
	log.Info(fmt.Sprintf("enrolled user=%s by_uid=%d validator=%s", acct.Name, os.Geteuid(), cfg.Validator))
	fmt.Fprintf(os.Stderr, "Handshake salvo em %s\n", p)
	return nil
}

func runInstall(args []string) error {
	fs := flag.NewFlagSet("install", flag.ExitOnError)
	var c common
	c.register(fs)
	userName := fs.String("u", "", "usuário dono do handshake (obrigatório)")
	c.storeKind = "system"
	_ = fs.Parse(args)
	if *userName == "" || fs.NArg() != 1 {
		return errors.New("uso: ssh-handshake install -u USER [--store system|home] ARQUIVO|-")
	}
	if os.Geteuid() != 0 {
		return errors.New("install precisa rodar como root")
	}
	st, err := c.store()
	if err != nil {
		return err
	}
	acct, err := lookupAccount(*userName)
	if err != nil {
		return err
	}
	var r io.Reader = os.Stdin
	if fs.Arg(0) != "-" {
		f, err := os.Open(fs.Arg(0))
		if err != nil {
			return err
		}
		defer f.Close()
		r = f
	}
	data, err := io.ReadAll(io.LimitReader(r, 64<<10))
	if err != nil {
		return err
	}
	rec, err := store.Decode(data, acct)
	if err != nil {
		return err
	}
	if _, err := validator.Get(rec.Validator); err != nil {
		return err
	}
	if err := st.Save(acct, rec); err != nil {
		return err
	}
	audit.NewSyslog().Info(fmt.Sprintf("installed handshake user=%s validator=%s", acct.Name, rec.Validator))
	p, _ := st.Path(acct)
	fmt.Fprintf(os.Stderr, "Handshake instalado em %s\n", p)
	return nil
}

// guard enforces the interaction timeout and keeps job-control signals from
// suspending the process mid-handshake. SIGINT/SIGTERM/SIGHUP keep their
// default action (terminate), which fails closed. Handlers installed with
// signal.Notify are reset by exec, so the shell starts with defaults.
func guard(timeout time.Duration) {
	ch := make(chan os.Signal, 4)
	signal.Notify(ch, syscall.SIGTSTP, syscall.SIGTTIN, syscall.SIGTTOU, syscall.SIGQUIT)
	go func() {
		for range ch {
		}
	}()
	if timeout > 0 {
		time.AfterFunc(timeout, func() {
			terminal.Restore()
			fmt.Fprintln(os.Stderr, "\nTempo esgotado. Desconectando.")
			os.Exit(1)
		})
	}
}

func resolveAccount(name string, printOnly bool) (store.Account, error) {
	cur, err := currentAccount()
	if err != nil {
		return store.Account{}, err
	}
	if name == "" || name == cur.Name {
		return cur, nil
	}
	if printOnly {
		// The user does not need to exist here: the record is generated on
		// any machine and installed on the server by root.
		return store.Account{Name: name}, nil
	}
	if os.Geteuid() != 0 {
		return store.Account{}, errors.New("enroll para outro usuário exige root (ou use --print)")
	}
	return lookupAccount(name)
}

func currentAccount() (store.Account, error) {
	u, err := user.LookupId(strconv.Itoa(os.Getuid()))
	if err != nil {
		return store.Account{}, err
	}
	return toAccount(u)
}

func lookupAccount(name string) (store.Account, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return store.Account{}, err
	}
	return toAccount(u)
}

func toAccount(u *user.User) (store.Account, error) {
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return store.Account{}, err
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return store.Account{}, err
	}
	return store.Account{Name: u.Username, UID: uid, GID: gid, Home: u.HomeDir}, nil
}
