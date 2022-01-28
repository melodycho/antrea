package networkpolicy

import (
	"k8s.io/apimachinery/pkg/util/sets"

	"antrea.io/antrea/pkg/agent/bpf"
)

const (
	ipMap        = "ip"
	protoPortMap = "proto_port"
)

func initBPFProg(infName string) (mapIDs map[string]*bpf.Map, err error) {
	// if err := bpf.CreateQDisc(infName); err != nil {
	// 	klog.ErrorS(err, "CreateQDisc error")
	// 	return err
	// }
	oldMaps, err := bpf.ListBPFMaps()
	if err != nil {
		return nil, err
	}
	mapSet := sets.Int{}
	for _, m := range oldMaps {
		mapSet.Insert(m.ID)
	}
	if err := bpf.AttachBPFProg(infName); err != nil {
		return nil, err
	}
	newMaps, err := bpf.ListBPFMaps()
	if err != nil {
		return nil, err
	}
	mapIDs = make(map[string]*bpf.Map, 2)
	for _, m := range newMaps {
		if mapSet.Has(m.ID) {
			continue
		}
		if m.MaxEntries == 100000 {
			mapIDs[ipMap] = &bpf.Map{ID: m.ID, MaxEntries: m.MaxEntries, Name: m.Name}
		}
		if m.MaxEntries == 65535 {
			mapIDs[protoPortMap] = &bpf.Map{ID: m.ID, MaxEntries: m.MaxEntries, Name: m.Name}
		}
	}
	return
}
