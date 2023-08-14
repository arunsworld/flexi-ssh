package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/arunsworld/nursery"
	"github.com/gliderlabs/ssh"
	probing "github.com/prometheus-community/pro-bing"
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
		server.Handler = sessionHandler
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

func sessionHandler(s ssh.Session) {
	sessionCtx := s.Context()
	log.Printf("Session handler started: user: %s. environ: %v. session: %s. commands: %s", s.User(), s.Environ(), sessionCtx.SessionID(), s.Command())

	var sessionErr error

	defer func() {
		log.Printf("Session handler ended: user: %s. environ: %v. session: %s. error: %v", s.User(), s.Environ(), s.Context().SessionID(), sessionErr)
	}()

	var cmd *exec.Cmd
	inputCommand := s.Command()
	switch {
	case len(inputCommand) == 0:
		cmd = exec.CommandContext(sessionCtx, "sh")
	case len(inputCommand) == 1:
		cmd = exec.CommandContext(sessionCtx, inputCommand[0])
	case inputCommand[0] == "ping":
		if err := doPing(s, inputCommand[1]); err != nil {
			fmt.Fprintf(s, "ERROR executing ping: %v", err)
		}
		return
	default:
		cmd = exec.CommandContext(sessionCtx, inputCommand[0], inputCommand[1:]...)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		sessionErr = err
		fmt.Fprintf(s, "ERROR executing command connecting to pipe: %v", err)
		return
	}
	if err := cmd.Start(); err != nil {
		sessionErr = err
		fmt.Fprintf(s, "ERROR executing command: %v", err)
		return
	}
	if _, err := io.Copy(s, stdout); err != nil {
		sessionErr = err
		fmt.Fprintf(s, "ERROR executing command - copy error: %v", err)
		return
	}
	if err := cmd.Wait(); err != nil {
		sessionErr = err
		fmt.Fprintf(s, "ERROR executing command - on wait: %v", err)
		return
	}
}

func doPing(s ssh.Session, target string) error {
	pinger, err := probing.NewPinger(target)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(s.Context())
	defer cancel()
	go func() {
		<-ctx.Done()
		pinger.Stop()
	}()
	pinger.Count = 3
	pinger.OnRecv = func(pkt *probing.Packet) {
		fmt.Fprintf(s, "%d bytes from %s: icmp_seq=%d time=%v\n",
			pkt.Nbytes, pkt.IPAddr, pkt.Seq, pkt.Rtt)
	}
	pinger.OnDuplicateRecv = func(pkt *probing.Packet) {
		fmt.Fprintf(s, "%d bytes from %s: icmp_seq=%d time=%v ttl=%v (DUP!)\n",
			pkt.Nbytes, pkt.IPAddr, pkt.Seq, pkt.Rtt, pkt.TTL)
	}
	pinger.OnFinish = func(stats *probing.Statistics) {
		fmt.Fprintf(s, "\n--- %s ping statistics ---\n", stats.Addr)
		fmt.Fprintf(s, "%d packets transmitted, %d packets received, %v%% packet loss\n",
			stats.PacketsSent, stats.PacketsRecv, stats.PacketLoss)
		fmt.Fprintf(s, "round-trip min/avg/max/stddev = %v/%v/%v/%v\n",
			stats.MinRtt, stats.AvgRtt, stats.MaxRtt, stats.StdDevRtt)
	}
	fmt.Fprintf(s, "PING %s (%s):\n", pinger.Addr(), pinger.IPAddr())
	if err := pinger.Run(); err != nil {
		return err
	}
	return nil
}
