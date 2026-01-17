package main

import (
	"errors"
	_ "fmt"
	"os"

	"github.com/kakeetopius/gosnooper/internal/argparser"
	"github.com/kakeetopius/gosnooper/internal/util"
)

func main() {
	_, err := argparser.ParseArgs(os.Args)
	if err != nil {
		if errors.Is(err, argparser.ErrHelp) {
			return
		}
		util.PrintError(err)
	}
}
