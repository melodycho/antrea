// Copyright 2022 Antrea Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package bpf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/big"
	"net"
)

const (
	ObjectDir      = "/usr/lib/antrea/bpf"
	RuntimeProgDir = "/var/run/antrea/bpf/prog"
)

// // hexStringsToBytes takes a string slice containing bpf data represented as
// // bpftool hex and returns a slice of bytes containing that data.
// func hexStringsToBytes(hexStrings []string) ([]byte, error) {
// 	var hex []byte
// 	for _, b := range hexStrings {
// 		h, err := hexToByte(b)
// 		if err != nil {
// 			return nil, err
// 		}
// 		hex = append(hex, byte(h))
// 	}
// 	return hex, nil
// }
//
// func hexToByte(hexString string) (byte, error) {
// 	hex := strings.TrimPrefix(hexString, "0x")
// 	proto64, err := strconv.ParseUint(hex, 16, 8)
// 	if err != nil {
// 		return 0, err
// 	}
// 	return byte(proto64), nil
// }

func IP4toInt(IPv4Address net.IP) int64 {
	IPv4Int := big.NewInt(0)
	IPv4Int.SetBytes(IPv4Address.To4())
	return IPv4Int.Int64()
}

func IntToHex(port uint32) (string, error) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, port)

	if err != nil {
		fmt.Println("Unable to write to buffer:", err)
		return "", err
	}

	// present in hexadecimal format
	result := fmt.Sprintf("%x", buf.Bytes())
	return result, nil
}

func ProtoPortToHexString(proto, port int32) string {
	prot, _ := IntToHex(uint32(proto))
	por, _ := IntToHex(uint32(port))
	return fmt.Sprintf("%s %s %s %s", prot[:2], prot[2:4], por[:2], por[2:4])

}

func IPToHexString(ip net.IP) (string, error) {
	// hex := strings.TrimPrefix(hexString, "0x")
	// proto64, err := strconv.ParseUint(hex, 16, 8)
	// if err != nil {
	// 	return 0, err
	// }
	// return byte(proto64), nil
	ipv4Decimal := IP4toInt(ip)

	ipHexString, _ := IntToHex(uint32(ipv4Decimal))
	return fmt.Sprintf("%s %s %s %s", ipHexString[:2], ipHexString[2:4], ipHexString[4:6], ipHexString[6:8]), nil
}
