package util

import (
	"fmt"
)

type numTypes interface {
	int | ~uint8 | ~uint16 | ~uint32
}

func NumtoHexStr[T numTypes](num T) string {
	return fmt.Sprintf("%0#x", num)
}

func NumtoBinStr[T numTypes](num T) string {
	return fmt.Sprintf("%0#b", num)
}
