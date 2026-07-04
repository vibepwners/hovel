package daemonmanager

import "log"

func logDaemonManagerError(action string, err error) {
	if err != nil {
		log.Printf("hovel daemon manager: %s: %v", action, err)
	}
}
