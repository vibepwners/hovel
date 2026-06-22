package main

import "github.com/Vibe-Pwners/hovel/sdk/go/hovel"

func main() {
	hovel.Serve(newProvider())
}
