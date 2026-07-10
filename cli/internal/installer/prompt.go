package installer

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"github.com/codebooker/vulna/cli/internal/config"
)

// Interactive gathers the limited set of installer choices from the user. Only
// these fields are ever prompted for (roadmap: keep the interactive surface
// small). Defaults come from o; the user presses Enter to accept them.
func Interactive(in io.Reader, out io.Writer, o config.Options) (config.Options, error) {
	r := bufio.NewReader(in)
	ask := func(label, def string) string {
		if def != "" {
			fmt.Fprintf(out, "%s [%s]: ", label, def)
		} else {
			fmt.Fprintf(out, "%s: ", label)
		}
		line, _ := r.ReadString('\n')
		line = strings.TrimSpace(line)
		if line == "" {
			return def
		}
		return line
	}

	o.InstallDir = ask("Installation directory", o.InstallDir)
	o.DataDir = ask("Data directory", o.DataDir)

	mode := ask("Access mode (localhost/lan/public)", string(o.AccessMode))
	o.AccessMode = config.AccessMode(strings.ToLower(mode))

	if o.AccessMode == config.AccessLAN || o.AccessMode == config.AccessPublic {
		o.URL = ask("Hostname or URL", o.URL)
	}
	if o.AccessMode == config.AccessPublic {
		o.ACMEEmail = ask("Email for automatic TLS (Let's Encrypt)", o.ACMEEmail)
	}

	o.AdminEmail = ask("Administrator email", o.AdminEmail)

	upd := ask("Enable update checks? (yes/no)", boolWord(o.UpdateChecks))
	o.UpdateChecks = isYes(upd)

	return o, nil
}

func boolWord(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func isYes(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "y", "yes", "true", "on", "1":
		return true
	default:
		return false
	}
}
