package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
)

func parseFlowFileLength(in *bufio.Reader) (i int64, err error) {
	ni, _ := in.Peek(2)
	var pk []byte
	if string(ni) != "Ni" {
		return 0, fmt.Errorf("Unrecognized flowfile start bytes, %q", ni)
	}

	i = 11
	pk, err = in.Peek(int(i))
	if err != nil {
		return
	}
	for j := 0; j < int(pk[7])<<9+int(pk[8])<<1; j++ {
		i += int64(pk[i-2])<<8 + int64(pk[i-1]) + 2
		pk, err = in.Peek(int(i))
		if err != nil {
			return
		}
	}

	pk, err = in.Peek(int(i + 6))
	if err != nil {
		return
	}

	i += int64(binary.BigEndian.Uint64(pk[i-8:]))
	return
}
