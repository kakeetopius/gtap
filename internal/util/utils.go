package util

import (
	"encoding/binary"
	"strconv"
)

func Ntohs(num int) int {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], uint32(num))
	return int(binary.LittleEndian.Uint32(b[:]))
}

func NumTostr(num int) string {
	return string(strconv.Itoa(num))
}

// func Numtohex
// func NumtoBin
