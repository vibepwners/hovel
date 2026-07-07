package daemonlocal

import "log"

func logDaemonLocalError(action string, err error) {
	if err != nil {
		log.Printf("hovel daemon local adapter: %s: %v", action, err)
	}
}
