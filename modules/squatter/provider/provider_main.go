//go:build hovel_squatter_provider

package main

import "github.com/vibepwners/hovel/sdk/go/hovel"

func main() {
	hovel.Serve(newProvider())
}
