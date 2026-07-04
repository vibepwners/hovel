package operatorsession

import "log"

func logSessionError(action string, err error) {
	if err != nil {
		log.Printf("operator session: %s: %v", action, err)
	}
}
