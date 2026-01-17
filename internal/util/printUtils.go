// Package util provides different utilities utilised throught the project.
package util

import (
	"github.com/pterm/pterm"
)

func PrintError(err error) {
	pterm.Error.Printf("%v\n", err)
}
