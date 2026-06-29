package services

import "log"

func logServiceError(action string, err error) {
	if err != nil {
		log.Printf("app service: %s: %v", action, err)
	}
}
