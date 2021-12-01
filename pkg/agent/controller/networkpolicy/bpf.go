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

package networkpolicy

import (
	"reflect"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	coreinformers "k8s.io/client-go/informers/core/v1"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"
)

const (
	controllerName               = "BPF-Controller"
	resyncPeriod   time.Duration = 0
)

type BPFController struct {
	// Name of local Node.
	nodeName string

	nodeInformer     coreinformers.NodeInformer
	nodeLister       corelisters.NodeLister
	nodeListerSynced cache.InformerSynced

	queue workqueue.RateLimitingInterface

	// ruleCache provides the desired state of NetworkPolicy rules.
	ruleCache *ruleCache
}

func NewBPFController(
	nodeName string,
	nodeInformer coreinformers.NodeInformer,
) (*BPFController, error) {
	c := &BPFController{
		nodeName:         nodeName,
		nodeInformer:     nodeInformer,
		nodeLister:       nodeInformer.Lister(),
		nodeListerSynced: nodeInformer.Informer().HasSynced,
		queue:            workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), "BPF"),
	}

	nodeInformer.Informer().AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    c.handleCreateNode,
			UpdateFunc: c.handleUpdateNode,
			DeleteFunc: c.handleDeleteNode,
		},
		resyncPeriod,
	)
	return c, nil
}

func (c *BPFController) handleCreateNode(obj interface{}) {
	node := obj.(*corev1.Node)
	//
	klog.V(2).InfoS("Processed Node CREATE event", "nodeName", node.Name)
}

func (c *BPFController) handleDeleteNode(obj interface{}) {
	node, ok := obj.(*corev1.Node)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			klog.ErrorS(nil, "Processing Node DELETE event error", "obj", obj)
			return
		}
		node, ok = tombstone.Obj.(*corev1.Node)
		if !ok {
			klog.ErrorS(nil, "Processing Node DELETE event error", "obj", tombstone.Obj)
			return
		}
	}
	//
	klog.V(2).InfoS("Processed Node DELETE event", "nodeName", node.Name, "affectedExternalIPPoolNum")
}

func (c *BPFController) handleUpdateNode(oldObj, newObj interface{}) {
	node := newObj.(*corev1.Node)
	oldNode := oldObj.(*corev1.Node)
	if reflect.DeepEqual(node.GetLabels(), oldNode.GetLabels()) {
		klog.V(2).InfoS("Processing Node UPDATE event, labels not changed", "nodeName", node.Name)
		return
	}
	//
	klog.V(2).InfoS("Processed Node UPDATE event", "nodeName", node.Name)
}

func (c *BPFController) Run(stopCh <-chan struct{}) {
	defer c.queue.ShutDown()

	klog.InfoS("Starting", "controllerName", controllerName)
	defer klog.InfoS("Shutting down", "controllerName", controllerName)

	if !cache.WaitForNamedCacheSync(controllerName, stopCh, c.nodeListerSynced) {
		return
	}

	for i := 0; i < defaultWorkers; i++ {
		go wait.Until(c.worker, time.Second, stopCh)
	}

}

func (c *BPFController) worker() {
	for c.processNextWorkItem() {
	}
}

func (c *BPFController) processNextWorkItem() bool {
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
	} else if err := c.syncRule(key); err == nil {
		// If no error occurs we Forget this item so it does not get queued again until
		// another change happens.
		c.queue.Forget(key)
	} else {
		// Put the item back on the work queue to handle any transient errors.
		c.queue.AddRateLimited(key)
		klog.ErrorS(err, "Syncing consistentHash by ExternalIPPool failed, requeue", "ExternalIPPool", key)
	}
	return true
}

func (c BPFController) syncRule(key string) error {
	klog.InfoS("sync rule", "rule key", key)
	// rule := ruleCache.GetCompletedRule()
	return nil
}
