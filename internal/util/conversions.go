package util

import (
	"encoding/binary"
	"fmt"
)

type numTypes interface {
	int | ~uint8 | ~uint16 | ~uint32
}

func Ntohs[T numTypes](num T) int {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], uint32(num))
	return int(binary.LittleEndian.Uint32(b[:]))
}

func NumtoHexStr[T numTypes](num T) string {
	return fmt.Sprintf("%0#x", num)
}

func NumtoBinStr[T numTypes](num T) string {
	return fmt.Sprintf("%0#b", num)
}
