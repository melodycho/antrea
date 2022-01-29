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
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"

	"k8s.io/klog/v2"
)

func CreateQDisc(ifName string) error {
	// tc qdisc add dev eth0 clsact
	return nil
}

func ShowClassifier(ifName string) error {
	var cmd *exec.Cmd
	// tc qdisc show dev eth0
	cmd = exec.Command("tc", "qdisc", "show", "dev", ifName)
	if output, err := cmd.CombinedOutput(); err != nil {
		klog.ErrorS(err, "ifName", ifName, "cmd", cmd.String(), "output", string(output), "err", err)
	}
	return nil
}

func AttachClassifier(ifName string) error {
	var cmd *exec.Cmd
	// tc qdisc add dev eth0 clsact
	cmd = exec.Command("tc", "qdisc", "add", "dev", ifName, "clsact")
	if output, err := cmd.CombinedOutput(); err != nil {
		klog.ErrorS(err, "ifName", ifName, "cmd", cmd.String(), "output", string(output))
		if err := ShowClassifier(ifName); err != nil {
			return err
		}
	}
	return nil
}

func AttachBPFProg(secName, ifName, hook string, isIngress bool) error {
	// secName, ifName, hook string, isIngress bool
	direction := "ingress"
	if !isIngress {
		direction = "egress"
	}
	var cmd *exec.Cmd
	// tc filter add dev eth0 egress bps da obj debug_drop_tcp.o sec tc
	cmd = exec.Command("tc", "filter", "add", "dev", ifName, direction, "bpf", "da", "obj",
		fmt.Sprintf("/usr/sbin/%s", hook), "sec", secName)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("error attaching BPF prog %s, cmd %s, output: %s: %v", ifName, cmd.String(), string(output), err)
	}
	return nil
}

type bpftoolMapMeta struct {
	ID         int    `json:"id"`
	Name       string `json:"name"`
	MaxEntries int    `json:"max_entries"`
}

func ListBPFMaps() (maps []bpftoolMapMeta, err error) {
	cmd := exec.Command("bpftool", "map", "list", "-j")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("bpftool map error: %v", err)
	}
	klog.V(2).InfoS("Got map metadata", "maps", string(out))

	err = json.Unmarshal(out, &maps)
	if err != nil {
		return nil, fmt.Errorf("bpftool map return bad json: %v", err)
	}

	return maps, nil
}

func PinBPFMap(m bpftoolMapMeta, filename string) error {
	mapID := strconv.Itoa(m.ID)
	cmd := exec.Command("bpftool", "map", "pin", "id", mapID, filename)
	return cmd.Run()
}
