package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/arunsworld/nursery"
	"github.com/gliderlabs/ssh"
	"github.com/urfave/cli/v2"
)

func main() {
	conf := config{}

	app := &cli.App{
		Name: "ssh-server",
		Flags: []cli.Flag{
			&cli.IntFlag{
				Name:        "port",
				Value:       2222,
				EnvVars:     []string{"SSH_PORT"},
				Destination: &conf.port,
			},
			&cli.StringFlag{
				Name:        "users",
				Aliases:     []string{"u"},
				EnvVars:     []string{"SSH_USERS"},
				Destination: &conf.usersFile,
			},
			&cli.BoolFlag{
				Name:        "allowsession",
				Value:       false,
				Aliases:     []string{"s"},
				EnvVars:     []string{"SSH_ALLOW_SESSION"},
				Destination: &conf.allowSession,
			},
			&cli.BoolFlag{
				Name:        "disallowPwdAuth",
				Aliases:     []string{"w"},
				EnvVars:     []string{"SSH_DISALLOW_PWD_AUTH"},
				Destination: &conf.disallowPwdAuth,
			},
			&cli.BoolFlag{
				Name:        "disallowPubKeyAuth",
				Aliases:     []string{"k"},
				EnvVars:     []string{"SSH_DISALLOW_PUBKEY_AUTH"},
				Destination: &conf.disallowPubKeyAuth,
			},
			&cli.BoolFlag{
				Name:        "allowPortForward",
				Aliases:     []string{"p"},
				EnvVars:     []string{"SSH_ALLOW_PORT_FWD"},
				Destination: &conf.allowPortForward,
			},
			&cli.BoolFlag{
				Name:        "allowReverseForward",
				Aliases:     []string{"r"},
				EnvVars:     []string{"SSH_ALLOW_REVERSE_PORT_FWD"},
				Destination: &conf.allowReverseForward,
			},
		},
		Action: func(cCtx *cli.Context) error {
			authUsers, err := newUsersFromConfig(conf.usersFile)
			if err != nil {
				return fmt.Errorf("error opening users file: %s: %v", conf.usersFile, err)
			}
			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer cancel()

			return run(ctx, authUsers, conf)
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
	log.Println("server stopped...")
}

func run(ctx context.Context, authUsers *auth, conf config) error {

	server := ssh.Server{
		Addr: fmt.Sprintf(":%d", conf.port),
	}

	if conf.allowSession {
		server.Handler = func(s ssh.Session) {
			sessionCtx := s.Context()
			log.Printf("Session handler started: user: %s. environ: %v. session: %s. commands: %s", s.User(), s.Environ(), sessionCtx.SessionID(), s.Command())
			if len(s.Command()) == 1 && s.Command()[0] == "sleep" {
				io.WriteString(s, "SESSION STARTED... BLOCKING...\n")
				select {
				case <-sessionCtx.Done():
				case <-ctx.Done():
					io.WriteString(s, "server shutting down\n")
				}
			} else {
				io.WriteString(s, "SESSION DISALLOWED...\n")
			}
			log.Printf("Session handler ended: user: %s. environ: %v. session: %s", s.User(), s.Environ(), s.Context().SessionID())
		}
	} else {
		server.Handler = func(s ssh.Session) {
			io.WriteString(s, "SESSION DISALLOWED\n")
		}
	}

	if !conf.disallowPwdAuth {
		server.PasswordHandler = func(ctx ssh.Context, password string) bool {
			result := authUsers.authenticateWithPwd(ctx.User(), password)
			log.Printf("Password Handler: user: %s. session: %s. local: %s. remote: %s. allowed: %v", ctx.User(), ctx.SessionID(), ctx.LocalAddr(), ctx.RemoteAddr(), result)
			return result
		}
	}

	if !conf.disallowPubKeyAuth {
		server.PublicKeyHandler = func(ctx ssh.Context, key ssh.PublicKey) bool {
			result := authUsers.authenticateWithPubKey(ctx.User(), key)
			log.Printf("Publickey handler: user: %s. key: %s. allowed: %v", ctx.User(), key.Type(), result)
			return result
		}
	}

	if conf.allowPortForward {
		server.LocalPortForwardingCallback = ssh.LocalPortForwardingCallback(func(ctx ssh.Context, dhost string, dport uint32) bool {
			switch ctx.User() {
			case "abarua":
				log.Println("Accepted forward", dhost, dport)
				return true
			default:
				log.Println("Denied forward (bad user)", dhost, dport)
				return false
			}
		})
		server.ChannelHandlers = map[string]ssh.ChannelHandler{
			"direct-tcpip": ssh.DirectTCPIPHandler,
			"session":      ssh.DefaultSessionHandler,
		}
	}

	if conf.allowReverseForward {
		forwardHandler := &ssh.ForwardedTCPHandler{}
		server.RequestHandlers = map[string]ssh.RequestHandler{
			"tcpip-forward":        forwardHandler.HandleSSHRequest,
			"cancel-tcpip-forward": forwardHandler.HandleSSHRequest,
		}
		server.ReversePortForwardingCallback = ssh.ReversePortForwardingCallback(func(ctx ssh.Context, host string, port uint32) bool {
			switch ctx.User() {
			case "abarua":
				log.Println("attempt to bind", host, port, "granted")
				return true
			default:
				log.Println("attempt to bind", host, port, "denied (bad user)")
				return false
			}
		})
	}

	log.Printf("starting ssh server on port %d...", conf.port)

	return nursery.RunConcurrently(
		func(_ context.Context, errCh chan error) {
			if err := server.ListenAndServe(); err != nil {
				select {
				case <-ctx.Done():
					return
				default:
					errCh <- err
				}
			}
		},
		func(lctx context.Context, _ chan error) {
			select {
			case <-ctx.Done():
				log.Println("shutting down server gracefully...")
				timedCtx, timedCtxCancel := context.WithTimeout(context.Background(), time.Second*5)
				defer timedCtxCancel()
				if err := server.Shutdown(timedCtx); err != nil {
					log.Println("error gracefully shutting down ssh server...")
				}
			case <-lctx.Done():
				log.Println("server stopped unexpectedly")
				return
			}
		},
	)
}
