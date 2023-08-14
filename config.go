package main

type config struct {
	port                int
	usersFile           string
	allowSession        bool
	disallowPwdAuth     bool
	disallowPubKeyAuth  bool
	allowPortForward    bool
	allowReverseForward bool
}
