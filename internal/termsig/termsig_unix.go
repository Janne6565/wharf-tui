//go:build !windows

package termsig

import (
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/term"
)

func ignoreQuit() func() {
	signal.Ignore(syscall.SIGQUIT)
	return func() { signal.Reset(syscall.SIGQUIT) }
}

func watchResize(fd int, onResize func(cols, rows int)) func() {
	winch := make(chan os.Signal, 1)
	signal.Notify(winch, syscall.SIGWINCH)
	stop := make(chan struct{})

	go func() {
		for {
			select {
			case <-stop:
				return
			case <-winch:
				if cols, rows, err := term.GetSize(fd); err == nil {
					onResize(cols, rows)
				}
			}
		}
	}()

	return func() {
		signal.Stop(winch)
		close(stop)
	}
}
