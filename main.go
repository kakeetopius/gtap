package main

import (
	"errors"
	"os"

	"github.com/kakeetopius/gtap/internal/argparser"
	"github.com/kakeetopius/gtap/internal/pcap"
	"github.com/kakeetopius/gtap/internal/util"
)

func main() {
	opts, err := argparser.ParseArgs(os.Args)
	if err != nil {
		if !errors.Is(err, argparser.ErrHelp) {
			util.PrintError(err)
		}
		return
	}
	err = pcap.StartCapture(opts)
	if err != nil {
		util.PrintError(err)
	}
}
