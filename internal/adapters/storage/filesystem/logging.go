package filesystem

import "log"

func logFilesystemError(action string, err error) {
	if err != nil {
		log.Printf("hovel filesystem storage: %s: %v", action, err)
	}
}
