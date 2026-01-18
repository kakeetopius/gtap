package main

import (
	"errors"
	_ "fmt"
	"os"

	"github.com/kakeetopius/gtap/internal/argparser"
	"github.com/kakeetopius/gtap/internal/util"
)

func main() {
	_, err := argparser.ParseArgs(os.Args)
	if err != nil {
		if !errors.Is(err, argparser.ErrHelp) {
			util.PrintError(err)
		}
	}
}
