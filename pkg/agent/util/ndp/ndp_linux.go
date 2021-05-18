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

	"github.com/mdlayher/ndp"
)

func NeighborAdvertisement(srcIP net.IP, iface *net.Interface) error {
	if err := checkIPv6(srcIP); err != nil {
		return err
	}

	dst := net.IPv6linklocalallnodes
	conn, _, err := ndp.Listen(iface, ndp.LinkLocal)
	if err != nil {
		return fmt.Errorf("creating NDP conn for %q error: %v", iface.Name, err)
	}

	msg := &ndp.NeighborAdvertisement{
		Solicited:     false,
		Override:      true,
		TargetAddress: srcIP,
		Options: []ndp.Option{
			&ndp.LinkLayerAddress{
				Direction: ndp.Target,
				Addr:      iface.HardwareAddr,
			},
		},
	}
	return conn.WriteTo(msg, nil, dst)
}

func checkIPv6(ip net.IP) error {
	if ip.To16() == nil || ip.To4() != nil {
		return fmt.Errorf("invalid IPv6 address: %s", ip.String())
	}
	return nil
}
