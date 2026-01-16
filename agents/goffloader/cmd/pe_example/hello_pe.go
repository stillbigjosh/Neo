package main

import (
	_ "embed"
	"fmt"

	"agents/goffloader/src/pe"
)

// code for this is in hello.c
//
//go:embed hello.exe
var helloBytes []byte

func main() {
	output, err := pe.RunExecutable(helloBytes, []string{"Arg1", "Arg2", "Arg3"})
	if err != nil {
		panic(err)
	}
	fmt.Printf("Output captured is: %s\n", output)
}
