// Package browser opens a URL in the user's default browser.
package browser

import (
	"os/exec"
	"runtime"
)

// Open launches the platform's default browser on url. It returns as soon as the
// helper process is started — it does not wait for the browser to render, so a
// nil error means "handed off", not "the page loaded".
func Open(url string) error {
	var cmd string
	var args []string
	switch runtime.GOOS {
	case "darwin":
		cmd = "open"
	case "windows":
		cmd, args = "rundll32", []string{"url.dll,FileProtocolHandler"}
	default:
		cmd = "xdg-open"
	}
	return exec.Command(cmd, append(args, url)...).Start()
}
