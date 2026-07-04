package mcpadapter

import "log"

func logMCPError(action string, err error) {
	if err != nil {
		log.Printf("hovel mcp adapter: %s: %v", action, err)
	}
}
