package util

import (
	"encoding/binary"
	"strconv"
)

func Htons(num int) int {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], uint32(num))
	return int(binary.BigEndian.Uint32(b[:]))
}

func Htonstr(num int) string {
	return string(strconv.Itoa(num))
}
