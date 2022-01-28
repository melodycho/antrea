package bpf

import (
	"fmt"
	"net"
	"testing"
)

func TestBytesToString(t *testing.T) {
	// after:
	// bpftool map dump id 30
	// key: 27 6c db c0  value: 01 00 00 00
	// Found 1 element

	// 1000 1000 0001 0011 == 88 13 == 5000
	// (16+3)*256 + (128+8) = 4864+136 = 5000
	// bpftool map dump id 248
	// key: 06 00 88 13  value: 01
	// Found 1 element
	ip := net.ParseIP("39.108.219.192")
	result, err := IPToHexString(ip)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(result)

	port := 5000
	result1, err := IntToHex(uint32(port))
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(result1)

	proto := 6
	result2, err := IntToHex(uint32(proto))
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(result2)

	res := ProtoPortToHexString(6, 5000)
	fmt.Println(res)

	// res1, _ := hexStringsToBytes([]string{"0x01"})
	// fmt.Println(res1)
}
