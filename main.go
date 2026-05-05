package main

import (
	"errors"
	"os"

	"github.com/kakeetopius/gtap/internal/argparser"
	"github.com/kakeetopius/gtap/internal/pcap"
	"github.com/kakeetopius/gtap/internal/tui"
	"github.com/kakeetopius/gtap/internal/util"
)

func main() {
	opts, err := argparser.ParseArgs(os.Args)
	checkErr(err)

	err = pcap.StartCapture(opts)
	checkErr(err)
}

func checkErr(err error) {
	if err != nil {
		returnCode := 0
		if !errors.Is(err, argparser.ErrHelp) && !errors.Is(err, tui.ErrUserQuit) {
			// no need to print to error message for the above
			util.PrintError(err)
			returnCode = -1
		}
		os.Exit(returnCode)
	}
}
