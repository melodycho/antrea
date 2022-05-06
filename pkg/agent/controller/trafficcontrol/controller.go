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

package trafficcontrol

import (
	"crypto/sha1" // #nosec G505: not used for security purposes
	"encoding/hex"
	"fmt"
	"net"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	coreinformers "k8s.io/client-go/informers/core/v1"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/interfacestore"
	"antrea.io/antrea/pkg/agent/openflow"
	"antrea.io/antrea/pkg/apis/crd/v1alpha2"
	trafficControlinformers "antrea.io/antrea/pkg/client/informers/externalversions/crd/v1alpha2"
	trafficControllisters "antrea.io/antrea/pkg/client/listers/crd/v1alpha2"
	"antrea.io/antrea/pkg/ovs/ovsconfig"
)

const (
	controllerName = "TrafficControlController"
	// Default number of workers processing a TrafficControl change.
	defaultWorkers = 4
	// Disable resyncing.
	resyncPeriod time.Duration = 0

	// Default VXLAN tunnel destination port.
	defaultVXLANTunnelDestinationPort = int32(4789)
	// Default Geneve tunnel destination port.
	defaultGENEVETunnelDestinationPort = int32(6081)

	portNamePrefixVXLAN  = "vxlan"
	portNamePrefixGENEVE = "geneve"
	portNamePrefixGRE    = "gre"
	portNamePrefixERSPAN = "erspan"
)

// tcState keeps the actual state of a TrafficControl that has been realized.
type tcState struct {
	// The Pods affected by a TrafficControl.
	pods sets.String
	// The target port of a TrafficControl.
	targetPort uint32
	// The return port of a TrafficControl. Note that, it's only for the TrafficControl whose action is redirect.
	returnPort uint32
	// The rule to filter affected Pods by a
	appliedTo v1alpha2.AppliedTo
}

type Controller struct {
	ofClient openflow.Client

	ovsBridgeClient    ovsconfig.OVSBridgeClient
	ovsPortUpdateMutex sync.Mutex

	interfaceStore interfacestore.InterfaceStore

	podInformer cache.SharedIndexInformer
	podLister   corelisters.PodLister

	namespaceInformer coreinformers.NamespaceInformer
	namespaceLister   corelisters.NamespaceLister

	tcStates      map[string]*tcState
	tcStatesMutex sync.RWMutex

	trafficControlInformer cache.SharedIndexInformer
	// trafficControlLister
	trafficControlLister trafficControllisters.TrafficControlLister
	// trafficControlListerSynced is a function which returns true if the TrafficControl shared informer has been synced at least once.
	trafficControlListerSynced cache.InformerSynced

	// queue maintains the TrafficControlGroup objects that need to be synced.
	queue workqueue.RateLimitingInterface
}

func NewTrafficControlController(ofClient openflow.Client,
	interfaceStore interfacestore.InterfaceStore,
	ovsBridgeClient ovsconfig.OVSBridgeClient,
	tcInformer trafficControlinformers.TrafficControlInformer,
	podInformer cache.SharedIndexInformer,
	namespaceInformer coreinformers.NamespaceInformer) *Controller {
	c := &Controller{
		ofClient:                   ofClient,
		ovsBridgeClient:            ovsBridgeClient,
		interfaceStore:             interfaceStore,
		trafficControlInformer:     tcInformer.Informer(),
		trafficControlLister:       tcInformer.Lister(),
		trafficControlListerSynced: tcInformer.Informer().HasSynced,
		podInformer:                podInformer,
		podLister:                  corelisters.NewPodLister(podInformer.GetIndexer()),
		namespaceInformer:          namespaceInformer,
		namespaceLister:            namespaceInformer.Lister(),
		tcStates:                   map[string]*tcState{},
		queue:                      workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(5*time.Second, 300*time.Second), "trafficControl"),
	}
	c.trafficControlInformer.AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    c.addTC,
			UpdateFunc: c.updateTC,
			DeleteFunc: c.deleteTC,
		},
		resyncPeriod,
	)
	c.podInformer.AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    c.addPod,
			UpdateFunc: c.updatePod,
			DeleteFunc: c.deletePod,
		},
		resyncPeriod,
	)
	return c
}

func (c *Controller) matchPod(pod *v1.Pod, to *v1alpha2.AppliedTo) (match bool) {
	if to.NamespaceSelector != nil {
		namespace, _ := c.namespaceLister.Get(pod.Namespace)
		nsSelector, _ := metav1.LabelSelectorAsSelector(to.NamespaceSelector)
		if !nsSelector.Matches(labels.Set(namespace.GetLabels())) {
			return
		}
	}

	podSelector, _ := metav1.LabelSelectorAsSelector(to.PodSelector)
	if !podSelector.Matches(labels.Set(pod.Labels)) {
		return
	}
	return true
}

func (c *Controller) filterAffectedTCsByPod(pod *v1.Pod) sets.String {
	c.tcStatesMutex.RLock()
	defer c.tcStatesMutex.RUnlock()
	affectedTCs := sets.NewString()
	for tcName, tcState := range c.tcStates {
		if c.matchPod(pod, &tcState.appliedTo) {
			affectedTCs.Insert(tcName)
		}
	}
	return affectedTCs
}

func (c *Controller) addPod(obj interface{}) {
	pod := obj.(*v1.Pod)
	klog.InfoS("Processing local Pod ADD event", "Namespace", pod.Namespace, "Pod", pod.Name, "labels", pod.Labels)
	affectedTCs := c.filterAffectedTCsByPod(pod)
	for tc := range affectedTCs {
		c.queue.Add(tc)
	}
}

func (c *Controller) updatePod(oldObj interface{}, obj interface{}) {
	oldPod := oldObj.(*v1.Pod)
	pod := obj.(*v1.Pod)
	klog.InfoS("Processing Pod UPDATE event", "Namespace", pod.Namespace, "Pod", pod.Name, "labels", pod.Labels)
	if !reflect.DeepEqual(pod.GetLabels(), oldPod.GetLabels()) {
		oldPodAffectedTCs := c.filterAffectedTCsByPod(oldPod)
		newPodAffectedTCs := c.filterAffectedTCsByPod(pod)
		for tc := range oldPodAffectedTCs.Difference(newPodAffectedTCs) {
			c.queue.Add(tc)
		}
		for tc := range newPodAffectedTCs.Difference(oldPodAffectedTCs) {
			c.queue.Add(tc)
		}
	}
}

func (c *Controller) deletePod(obj interface{}) {
	pod := obj.(*v1.Pod)
	klog.InfoS("Processing Pod DELETE event", "Namespace", pod.Namespace, "Pod", pod.Name, "labels", pod.Labels)
	affectedTCs := c.filterAffectedTCsByPod(pod)
	for tc := range affectedTCs {
		c.queue.Add(tc)
	}
}

func (c *Controller) addTC(obj interface{}) {
	tc := obj.(*v1alpha2.TrafficControl)
	klog.InfoS("Processing TrafficControl ADD event", "trafficControl", tc.Name, "appliedTo", tc.Spec.AppliedTo)
	c.queue.Add(tc.Name)
}

func (c *Controller) updateTC(oldObj interface{}, obj interface{}) {
	oldTC := oldObj.(*v1alpha2.TrafficControl)
	tc := obj.(*v1alpha2.TrafficControl)
	klog.InfoS("Processing TrafficControl UPDATE event", "trafficControl", tc.Name, "appliedTo", tc.Spec.AppliedTo)
	if tc.Generation != oldTC.Generation {
		c.queue.Add(tc.Name)
	}
}

func (c *Controller) deleteTC(obj interface{}) {
	tc := obj.(*v1alpha2.TrafficControl)
	klog.InfoS("Processing TrafficControl DELETE event", "trafficControl", tc.Name, "appliedTo", tc.Spec.AppliedTo)
	c.queue.Add(tc.Name)
}

func (c *Controller) Run(stopCh <-chan struct{}) {
	defer c.queue.ShutDown()

	klog.InfoS("Starting", "controllerName", controllerName)
	defer klog.InfoS("Shutting down", "controllerName", controllerName)

	if !cache.WaitForNamedCacheSync(controllerName, stopCh, c.trafficControlListerSynced, c.podInformer.HasSynced, c.podInformer.HasSynced) {
		return
	}

	for i := 0; i < defaultWorkers; i++ {
		go wait.Until(c.worker, time.Second, stopCh)
	}

	<-stopCh
}

func (c *Controller) worker() {
	for c.processNextWorkItem() {
	}
}

func (c *Controller) processNextWorkItem() bool {
	obj, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(obj)

	if key, ok := obj.(string); !ok {
		// As the item in the work queue is actually invalid, we call Forget here else we'd
		// go into a loop of attempting to process a work item that is invalid.
		// This should not happen.
		c.queue.Forget(obj)
		klog.Errorf("Expected string in work queue but got %#v", obj)
		return true
	} else if err := c.syncTrafficControl(key); err == nil {
		// If no error occurs we Forget this item, so it does not get queued again until
		// another change happens.
		c.queue.Forget(key)
	} else {
		// Put the item back on the work queue to handle any transient errors.
		c.queue.AddRateLimited(key)
		klog.ErrorS(err, "Syncing TrafficControl failed, requeue", "TrafficControl", key)
	}
	return true
}

func (c *Controller) createTcState(tc *v1alpha2.TrafficControl) *tcState {
	c.tcStatesMutex.Lock()
	defer c.tcStatesMutex.Unlock()
	state := &tcState{
		pods:      sets.NewString(),
		appliedTo: tc.Spec.AppliedTo,
	}
	c.tcStates[tc.Name] = state
	return state
}

func (c *Controller) getTcState(name string) (*tcState, bool) {
	c.tcStatesMutex.RLock()
	defer c.tcStatesMutex.RUnlock()
	state, exists := c.tcStates[name]
	return state, exists
}

func (c *Controller) deleteTcState(name string) {
	c.tcStatesMutex.Lock()
	defer c.tcStatesMutex.Unlock()
	delete(c.tcStates, name)
	return
}

func (c *Controller) filterPods(appliedTo *v1alpha2.AppliedTo) ([]*v1.Pod, error) {
	if appliedTo == nil {
		return c.podLister.List(labels.Everything())
	}
	var podSelector, nsSelector labels.Selector
	var err error

	if appliedTo.PodSelector == nil {
		podSelector = labels.Everything()
	} else {
		if podSelector, err = metav1.LabelSelectorAsSelector(appliedTo.PodSelector); err != nil {
			return nil, err
		}
	}

	if appliedTo.NamespaceSelector != nil {
		var namespaces []*v1.Namespace
		if nsSelector, err = metav1.LabelSelectorAsSelector(appliedTo.NamespaceSelector); err != nil {
			return nil, err
		}
		if namespaces, err = c.namespaceLister.List(nsSelector); err != nil {
			return nil, err
		}
		var allPods []*v1.Pod
		for _, ns := range namespaces {
			pods, err := c.podLister.Pods(ns.Name).List(podSelector)
			if err != nil {
				return nil, err
			}
			allPods = append(allPods, pods...)
		}
		return allPods, nil
	}
	return c.podLister.List(podSelector)
}

func genPortNameUDPTunnel(tunnel *v1alpha2.UDPTunnel) string {
	hash := sha1.New() // #nosec G401: not used for security purposes
	hash.Write(net.ParseIP(tunnel.RemoteIP))
	if tunnel.DestinationPort != nil {
		hash.Write([]byte(strconv.Itoa(int(*tunnel.DestinationPort))))
	}
	if tunnel.VNI != nil {
		hash.Write([]byte(strconv.Itoa(int(*tunnel.VNI))))
	}
	return hex.EncodeToString(hash.Sum(nil))[:6]
}

func genPortNameGRETunnel(tunnel *v1alpha2.GRETunnel) string {
	hash := sha1.New() // #nosec G401: not used for security purposes
	hash.Write(net.ParseIP(tunnel.RemoteIP))
	if tunnel.Key != nil {
		hash.Write([]byte(strconv.Itoa(int(*tunnel.Key))))
	}
	return hex.EncodeToString(hash.Sum(nil))[:6]
}

func genPortNameERSPANTunnel(tunnel *v1alpha2.ERSPANTunnel) string {
	hash := sha1.New() // #nosec G401: not used for security purposes
	hash.Write(net.ParseIP(tunnel.RemoteIP))
	if tunnel.SessionID != nil {
		hash.Write([]byte(strconv.Itoa(int(*tunnel.SessionID))))
	}
	if tunnel.Index != nil {
		hash.Write([]byte(strconv.Itoa(int(*tunnel.Index))))
	}
	if tunnel.Dir != nil {
		hash.Write([]byte(strconv.Itoa(int(*tunnel.Dir))))
	}
	if tunnel.HardwareID != nil {
		hash.Write([]byte(strconv.Itoa(int(*tunnel.HardwareID))))
	}
	return hex.EncodeToString(hash.Sum(nil))[:6]
}

func (c *Controller) getDevicePort(device *v1alpha2.TrafficControlPort) (ofPort uint32, err error) {
	if device == nil {
		return 0, fmt.Errorf("device is invalid")
	}
	var ofPortTmp int32
	createUDPTunnel := func(tunnelType ovsconfig.TunnelType, portName, remoteIP string, dstPort int32) error {
		externalIDs := map[string]interface{}{
			interfacestore.AntreaInterfaceTypeKey: interfacestore.AntreaTunnel,
		}
		if dstPort != 0 {
			externalIDs["dst_port"] = strconv.Itoa(int(dstPort))
		}
		c.ovsPortUpdateMutex.Lock()
		defer c.ovsPortUpdateMutex.Unlock()
		portUUID, err := c.ovsBridgeClient.CreateTunnelPortExt(
			portName, tunnelType, 0, false, "", remoteIP, "", externalIDs)
		if err != nil {
			return err
		}
		ofPortTmp, err = c.ovsBridgeClient.GetOFPort(portName, false)
		if err != nil {
			return err
		}
		itf := interfacestore.NewTunnelInterface(portName, tunnelType, nil, false)
		itf.OVSPortConfig = &interfacestore.OVSPortConfig{PortUUID: portUUID, OFPort: ofPortTmp}
		c.interfaceStore.AddInterface(itf)
		ofPort = uint32(ofPortTmp)
		return nil
	}
	switch {
	case device.OVSInternal != nil:
		if ofPort, err := c.ovsBridgeClient.GetOFPort(device.OVSInternal.Name, false); err == nil {
			return uint32(ofPort), nil
		}
		externalIDs := map[string]interface{}{
			interfacestore.AntreaInterfaceTypeKey: interfacestore.AntreaUnset,
		}
		c.ovsPortUpdateMutex.Lock()
		defer c.ovsPortUpdateMutex.Unlock()
		portUUID, err := c.ovsBridgeClient.CreateInternalPort(device.OVSInternal.Name, 0, externalIDs)
		if err != nil {
			return 0, err
		}
		defer func() {
			if err != nil {
				_ = c.ovsBridgeClient.DeletePort(portUUID)
			}
		}()
		ofPortTmp, err = c.ovsBridgeClient.GetOFPort(device.OVSInternal.Name, false)
		if err != nil {
			return 0, err
		}
		intf := interfacestore.NewGatewayInterface(device.OVSInternal.Name)
		intf.OVSPortConfig = &interfacestore.OVSPortConfig{PortUUID: portUUID, OFPort: ofPortTmp}
		c.interfaceStore.AddInterface(intf)
		ofPort = uint32(ofPortTmp)
		klog.V(2).InfoS("Created internal port", "portUUID", portUUID)
	case device.Device != nil:
		itf, ok := c.interfaceStore.GetInterfaceByName(device.Device.Name)
		if ok {
			return uint32(itf.OFPort), nil
		}
		externalIDs := map[string]interface{}{
			interfacestore.AntreaInterfaceTypeKey: interfacestore.AntreaUnset,
		}
		c.ovsPortUpdateMutex.Lock()
		defer c.ovsPortUpdateMutex.Unlock()
		portUUID, err := c.ovsBridgeClient.CreatePort(device.Device.Name, device.Device.Name, externalIDs)
		if err != nil {
			return 0, err
		}
		defer func() {
			if err != nil {
				_ = c.ovsBridgeClient.DeletePort(portUUID)
			}
		}()
		ofPortTmp, err = c.ovsBridgeClient.GetOFPort(device.Device.Name, false)
		if err != nil {
			return 0, err
		}
		newItf := interfacestore.NewUplinkInterface(device.Device.Name)
		newItf.OVSPortConfig = &interfacestore.OVSPortConfig{PortUUID: portUUID, OFPort: ofPortTmp}
		c.interfaceStore.AddInterface(newItf)
		ofPort = uint32(ofPortTmp)
		klog.V(2).InfoS("Created device", "portUUID", portUUID)
	case device.VXLAN != nil:
		dstPort := defaultVXLANTunnelDestinationPort
		if device.VXLAN.DestinationPort == nil {
			device.VXLAN.DestinationPort = &dstPort
		}
		portName := strings.Join([]string{portNamePrefixVXLAN, genPortNameUDPTunnel(device.VXLAN)}, "-")
		if err := createUDPTunnel(ovsconfig.VXLANTunnel, portName, device.VXLAN.RemoteIP, *device.VXLAN.DestinationPort); err != nil {
			return 0, err
		}
		klog.V(2).InfoS("Created VXLANTunnel port", "config", device.VXLAN)
	case device.GENEVE != nil:
		deviceConfig := device.GENEVE
		dstPort := defaultGENEVETunnelDestinationPort
		if deviceConfig.DestinationPort == nil {
			deviceConfig.DestinationPort = &dstPort
		}
		portName := strings.Join([]string{portNamePrefixGENEVE, genPortNameUDPTunnel(deviceConfig)}, "-")
		if err := createUDPTunnel(ovsconfig.GeneveTunnel, portName, deviceConfig.RemoteIP, *deviceConfig.DestinationPort); err != nil {
			return 0, err
		}
		klog.V(2).InfoS("Created Geneve Tunnel port", "config", deviceConfig)
	case device.GRE != nil:
		portName := strings.Join([]string{portNamePrefixGRE, genPortNameGRETunnel(device.GRE)}, "-")
		if err := createUDPTunnel(ovsconfig.GRETunnel, portName, device.GRE.RemoteIP, 0); err != nil {
			return 0, err
		}
		klog.V(2).InfoS("Created GRETunnel port", "config", device.GRE)
	case device.ERSPAN != nil:
		// ERSPAN version I and version II over IPv4 GRE and IPv6 GRE tunnel are supported. See ovs-fields(7) for matching and setting ERSPAN fields.
		// $ ovs-vsctl add-br br0
		// $ #For ERSPAN type 2 (version I)
		// $ ovs-vsctl add-port br0 at_erspan0 -- \
		//        set int at_erspan0 type=erspan options:key=1 \
		//        options:remote_ip=172.31.1.1 \
		//        options:erspan_ver=1 options:erspan_idx=1

		// $ #For ERSPAN type 3 (version II)
		// $ ovs-vsctl add-port br0 at_erspan0 -- \
		//        set int at_erspan0 type=erspan options:key=1 \
		//        options:remote_ip=172.31.1.1 \
		//        options:erspan_ver=2 options:erspan_dir=1 \
		//        options:erspan_hwid=4

		config := device.ERSPAN
		remoteIP := config.RemoteIP
		version := config.Version
		index := config.Index
		dir := config.Dir
		hardwareID := config.HardwareID

		portName := strings.Join([]string{portNamePrefixERSPAN, genPortNameERSPANTunnel(device.ERSPAN)}, "-")

		externalIDs := map[string]interface{}{
			interfacestore.AntreaInterfaceTypeKey: interfacestore.AntreaUnset,
			"erspan_ver":                          strconv.Itoa(int(version)),
			"key":                                 strconv.Itoa(1),
		}
		if version == 1 {
			if index != nil {
				externalIDs["erspan_idx"] = strconv.Itoa(int(*index))
			}
		} else if version == 2 {
			externalIDs["erspan_dir"] = strconv.Itoa(int(*dir))
			externalIDs["erspan_hwid"] = strconv.Itoa(int(*hardwareID))
		}
		c.ovsPortUpdateMutex.Lock()
		defer c.ovsPortUpdateMutex.Unlock()
		portUUID, err := c.ovsBridgeClient.CreateTunnelPortExt(portName,
			ovsconfig.ERSpanTunnel, 0, false, "", remoteIP, "", externalIDs)
		if err != nil {
			return 0, err
		}
		ofPortTmp, err = c.ovsBridgeClient.GetOFPort(portName, false)
		if err != nil {
			return 0, err
		}
		itf := interfacestore.NewTunnelInterface(portName, ovsconfig.ERSpanTunnel, nil, false)
		itf.OVSPortConfig = &interfacestore.OVSPortConfig{PortUUID: portUUID, OFPort: ofPortTmp}
		c.interfaceStore.AddInterface(itf)
		ofPort = uint32(ofPortTmp)

		klog.V(2).InfoS("Created ERSPAN port", "remoteIP", remoteIP, "version", version, "index", index,
			"dir", dir, "hardwareID", hardwareID)
	}
	return
}

func (c *Controller) syncTrafficControl(tcName string) (err error) {
	startTime := time.Now()
	defer func() {
		klog.V(4).InfoS("Finished syncing TrafficControl", "TrafficControl", tcName, "durationTime", time.Since(startTime))
	}()

	tc, err := c.trafficControlLister.Get(tcName)
	if err != nil {
		if apierrors.IsNotFound(err) {
			tcState, exist := c.getTcState(tcName)
			if !exist {
				return nil
			}
			if err := c.uninstallTrafficControl(tcName, tcState); err != nil {
				return err
			}
			return nil
		}
		return err
	}

	tcState, exist := c.getTcState(tcName)

	if !exist {
		tcState = c.createTcState(tc)
		var returnPort, targetPort uint32
		// ReturnPort should only be set for Redirect action.The validation webhook checked it.
		if tc.Spec.ReturnPort != nil {
			if returnPort, err = c.getDevicePort(tc.Spec.ReturnPort); err != nil {
				return err
			}
			if err := c.ofClient.InstallTrafficControlReturnPortFlow(returnPort); err != nil {
				return err
			}
		}
		if targetPort, err = c.getDevicePort(&tc.Spec.TargetPort); err != nil {
			return err
		}

		tcState.targetPort = targetPort
		tcState.returnPort = returnPort
	}
	var pods []*v1.Pod
	if pods, err = c.filterPods(&tc.Spec.AppliedTo); err != nil {
		return err
	}
	klog.V(4).InfoS("Filtering Pods", "localPodsNum", len(pods), "appliedTo", tc.Spec.AppliedTo)
	if len(pods) == 0 {
		return nil
	}

	var podOfPorts []uint32
	for _, pod := range pods {
		// TrafficControl does not support HostNetwork Pods. Ignore Pod if it's HostNetwork Pod.
		if pod.Spec.HostNetwork {
			continue
		}
		podItem := strings.Join([]string{pod.Namespace, pod.Name}, "/")
		tcState.pods.Insert(podItem)
		podInterfaces := c.interfaceStore.GetContainerInterfacesByPod(pod.Name, pod.Namespace)
		if len(podInterfaces) == 0 {
			klog.InfoS("Container interfaces not found", "Namespace", pod.Namespace, "Pod", pod.Name)
			continue
		}
		ofPort := podInterfaces[0].OFPort
		podOfPorts = append(podOfPorts, uint32(ofPort))
	}

	if err := c.ofClient.InstallTrafficControlMarkFlows(tc.Name, podOfPorts, tcState.targetPort, tc.Spec.Direction, tc.Spec.Action); err != nil {
		return err
	}

	return nil
}

func (c *Controller) uninstallTrafficControl(tcName string, ts *tcState) error {
	if err := c.ofClient.UninstallTrafficControlMarkFlows(tcName); err != nil {
		return err
	}

	if ts.returnPort != 0 {
		if err := c.ofClient.UninstallTrafficControlReturnPortFlow(ts.returnPort); err != nil {
			return err
		}
	}

	c.deleteTcState(tcName)
	return nil
}
