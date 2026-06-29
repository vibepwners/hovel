package commands

import "log"

func logCommandError(action string, err error) {
	if err != nil {
		log.Printf("hovel command: %s: %v", action, err)
	}
}
