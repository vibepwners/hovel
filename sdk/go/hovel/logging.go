package hovel

import "log"

func logSDKError(action string, err error) {
	if err != nil {
		log.Printf("hovel sdk: %s: %v", action, err)
	}
}
