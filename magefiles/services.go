package main

import (
	"github.com/magefile/mage/sh"
)

func RunAuth() {
	sh.RunV("go", "run", "./cmd/mem-auth")
}

func RunBank() {
	sh.RunV("go", "run", "./cmd/mem-bank")
}

func RunOhttpRelay() {
	sh.RunV("go", "run", "./cmd/ohttp-relay")
}

func RunGateway() {
	sh.RunV("go", "run", "./cmd/mem-gateway")
}

func RunRouter() {
	sh.RunV("go", "run", "./cmd/mem-router")
}

func RunCredithole() {
	sh.RunV("go", "run", "./cmd/mem-credithole")
}

func RunClient() {
	sh.RunV("go", "run", "./cmd/test-client")
}
