// Copyright 2021 Antrea Authors
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

package ndp

import (
	"fmt"
	"net"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv6"
)

const (
	// Option Length, 8-bit unsigned integer. The length of the option (including the type and length fields) in units of 8 octets.
	// The value 0 is invalid. Nodes MUST silently discard an ND packet that contains an option with length zero.
	// https://datatracker.ietf.org/doc/html/rfc4861
	ndpOptionLen = 1

	// ndpOptionType
	// 	Option Name                             Type
	//
	// Source Link-Layer Address                    1
	// Target Link-Layer Address                    2
	// Prefix Information                           3
	// Redirected Header                            4
	// MTU                                          5
	ndpOptionType = 2

	// Minimum byte length values for each type of valid Message.
	naLen = 20

	// expected IPv6 hop limit, hop limit is always 255 for all NDP messages, RFC 4861.
	hopLimit = 255
)

func checkIPv6(ip net.IP) error {
	if ip.To16() == nil || ip.To4() != nil {
		return fmt.Errorf("invalid IPv6 address: %s", ip.String())
	}
	return nil
}

// NeighborAdvertisement1 sends an NDP Neighbor Advertisement over interface 'iface' from 'srcIP'.
func NeighborAdvertisement(srcIP net.IP, iface *net.Interface) error {
	if err := checkIPv6(srcIP); err != nil {
		return err
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return fmt.Errorf("interface address error: %v", err)
	}

	ipAddr := &net.IPAddr{}

	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}

		if err := checkIPv6(ipn.IP); err != nil {
			continue
		}

		if ipn.IP.IsLinkLocalUnicast() {
			ipAddr = &net.IPAddr{
				IP:   ipn.IP,
				Zone: iface.Name,
			}
			break
		}
	}

	ic, err := icmp.ListenPacket("ip6:ipv6-icmp", ipAddr.String())
	if err != nil {
		return fmt.Errorf("listen icmp error: %v", err)
	}

	pc := ic.IPv6PacketConn()
	if err := pc.SetHopLimit(hopLimit); err != nil {
		return fmt.Errorf("ipv6 conn set hop limit error: %v", err)
	}
	if err := pc.SetMulticastHopLimit(hopLimit); err != nil {
		return fmt.Errorf("ipv6 conn set multicast hoplimit error: %v", err)
	}

	// Calculate and place ICMPv6 checksum at correct offset in all messages.
	const chkOff = 2
	if err := pc.SetChecksum(true, chkOff); err != nil {
		return fmt.Errorf("ipv6 conn set checksum error: %v", err)
	}

	defer pc.Close()
	mb, err := newNDPNeighborAdvertisementMessage(srcIP, iface.HardwareAddr)
	if err != nil {
		return fmt.Errorf("new NDP Neighbor Advertisement Message error: %v", err)
	}

	cm := &ipv6.ControlMessage{
		HopLimit: hopLimit,
		Src:      ipAddr.IP,
		IfIndex:  iface.Index,
	}
	dstAddr := &net.IPAddr{
		IP:   net.IPv6linklocalallnodes,
		Zone: iface.Name,
	}
	if _, err = pc.WriteTo(mb, cm, dstAddr); err != nil {
		return fmt.Errorf("writing a payload of the IPv6 datagram error: %v", err)
	}
	return nil
}

func newNDPNeighborAdvertisementMessage(targetAddress net.IP, hwa net.HardwareAddr) ([]byte, error) {
	naMsgBytes := make([]byte, naLen)
	naMsgBytes[0] |= 1 << 5
	copy(naMsgBytes[4:], targetAddress)

	marshall := func() ([]byte, error) {
		if 1+1+len(hwa) != int(ndpOptionLen*8) {
			return nil, fmt.Errorf("hardwareAddr length error: %s", hwa)
		}
		b := make([]byte, ndpOptionLen*8)
		b[0] = ndpOptionType
		b[1] = ndpOptionLen
		copy(b[2:], hwa)
		return b, nil
	}

	optionsBytes, err := marshall()
	if err != nil {
		return nil, err
	}
	naMsgBytes = append(naMsgBytes, optionsBytes...)

	im := icmp.Message{
		// ICMPType = 136, Neighbor Advertisement
		Type: ipv6.ICMPTypeNeighborAdvertisement,
		// Always zero.
		Code: 0,
		// The ICMP checksum. Calculated by caller or OS.
		Checksum: 0,
		Body: &icmp.RawBody{
			Data: naMsgBytes,
		},
	}
	return im.Marshal(nil)
}
