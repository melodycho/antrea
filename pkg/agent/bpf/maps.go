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
	"fmt"
	"os/exec"
	"strconv"
)

type MapFD uint32

type Maper interface {
	GetName() string
	// EnsureExists opens the map, creating and pinning it if needed.
	EnsureExists() error
	// Open opens the map, returns error if it does not exist.
	Open() error
	// MapFD gets the file descriptor of the map, only valid after calling EnsureExists().
	MapFD() MapFD
	// Path returns the path that the map is (to be) pinned to.
	Path() string

	Update(k, v []byte) error
	Get(k []byte) ([]byte, error)
	Delete(k []byte) error
}

type Map struct {
	Filename   string
	Type       string
	ID         int
	KeySize    int
	ValueSize  int
	MaxEntries int
	Name       string
	Flags      int
	Version    int
}

func (m *Map) EnsureKey(key string) error {
	var cmd *exec.Cmd
	// bpftool map update id 296  key hex 06 00 88 13 value hex 01
	mapID := strconv.Itoa(m.ID)
	cmd = exec.Command("bpftool", "map", "add", "update", "id", mapID, "key", key, "value", "hex", "01")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("error add map key %s: %v", key, err)
	}
	return nil
}

func (m *Map) create() error {
	return nil
}

func (m *Map) delete() error {
	return nil
}
