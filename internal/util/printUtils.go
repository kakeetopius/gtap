// Package util provides different utilities utilised throught the project.
package util

import (
	"fmt"
	"os"

	"github.com/pterm/pterm"
)

type printableTypes interface {
	string | ~int | ~uint8 | ~uint16
}

func PrintError(err error) {
	errorStr := pterm.Error.Sprintf("%v\n", err)
	fmt.Fprintf(os.Stderr, "%v", errorStr)
}

func PrintProtocolHeader(headerName string) {
	headerStyle := pterm.NewStyle(pterm.FgYellow)
	headerStyle.Printf("###[ %v ]###\n", headerName)
}

func PrintProtocolField[T printableTypes](fieldname string, value T) {
	fieldStyle := pterm.NewStyle(pterm.Bold)
	valueStyle := pterm.NewStyle(pterm.FgDefault)

	fieldStyle.Printf("  %v", fieldname)
	if len(fieldname) < 6 {
		fmt.Printf("\t\t= ")
	} else {
		fmt.Printf("\t= ")
	}
	valueStyle.Printf("%v\n", value)
}
