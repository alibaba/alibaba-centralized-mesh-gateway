// Copyright (c) 2022, Alibaba Group。
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

package controller

import (
	"cannalcontroller/pkg/coredns"
	"cannalcontroller/pkg/tools"
	"context"
	"fmt"
	"github.com/golang/glog"
	"istio.io/client-go/pkg/apis/networking/v1alpha3"
	versionedclient "istio.io/client-go/pkg/clientset/versioned"
	netinformer "istio.io/client-go/pkg/informers/externalversions/networking/v1alpha3"
	lister "istio.io/client-go/pkg/listers/networking/v1alpha3"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"time"
)

var (
	rewritePrefix = "rewrite name "
	rewriteSuffix = ".svc.cluster.local"
)

type Controller struct {
	kubeclientset        kubernetes.Interface
	vsclientset          versionedclient.Interface
	workqueue            workqueue.RateLimitingInterface
	virtualserviceLister lister.VirtualServiceLister
	virtualserviceSynced cache.InformerSynced
	gatewayLister        lister.GatewayLister
	gatewaySynced        cache.InformerSynced
	canalServiceName     string
	canalNamespace       string
	gatewayName          string
}

type OperationType uint8

const (
	Update OperationType = 0
	Add    OperationType = 1
	Delete OperationType = 2
)

type ItemValue struct {
	key           string
	operationType OperationType
	value         *v1alpha3.VirtualService
	oldValue      *v1alpha3.VirtualService
}

func (c *Controller) enqueueVSForDelete(obj interface{}) {
	deleteObj := obj.(*v1alpha3.VirtualService)
	glog.Info(deleteObj)
	var key string
	var err error
	key, err = cache.DeletionHandlingMetaNamespaceKeyFunc(obj)
	if err != nil {
		runtime.HandleError(err)
		return
	}
	c.workqueue.AddRateLimited(ItemValue{key: key, value: deleteObj, operationType: Delete})
}

func (c *Controller) enqueueVSForAdd(obj interface{}) {
	addObj := obj.(*v1alpha3.VirtualService)
	var key string
	var err error
	if key, err = cache.MetaNamespaceKeyFunc(obj); err != nil {
		runtime.HandleError(err)
		return
	}
	c.workqueue.AddRateLimited(ItemValue{key: key, value: addObj, operationType: Add})
}

func (c *Controller) enqueueVSForUpdate(old interface{}, new interface{}) {
	oldObj := old.(*v1alpha3.VirtualService)
	newObj := new.(*v1alpha3.VirtualService)
	var key string
	var err error
	if key, err = cache.MetaNamespaceKeyFunc(newObj); err != nil {
		runtime.HandleError(err)
		return
	}
	c.workqueue.AddRateLimited(ItemValue{key: key, value: newObj, oldValue: oldObj, operationType: Update})
}

func NewController(virtualServiceInformer netinformer.VirtualServiceInformer, gatewayInformer netinformer.GatewayInformer, kubeclientset kubernetes.Interface,
	vsclientset versionedclient.Interface) *Controller {
	controller := &Controller{
		kubeclientset:        kubeclientset,
		vsclientset:          vsclientset,
		virtualserviceLister: virtualServiceInformer.Lister(),
		workqueue:            workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "Networks"),
		virtualserviceSynced: virtualServiceInformer.Informer().HasSynced,
		gatewayLister:        gatewayInformer.Lister(),
		gatewaySynced:        gatewayInformer.Informer().HasSynced,
		canalNamespace:       "istio-system",
		canalServiceName:     "canal",
	}

	glog.Info("Setting up event handlers")
	virtualServiceInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: controller.enqueueVSForAdd,
		UpdateFunc: func(old, new interface{}) {
			oldVS := old.(*v1alpha3.VirtualService)
			newVS := new.(*v1alpha3.VirtualService)
			if oldVS.ResourceVersion == newVS.ResourceVersion {
				return
			}
			controller.enqueueVSForUpdate(old, new)
		},
		DeleteFunc: controller.enqueueVSForDelete,
	})
	return controller
}

func (c *Controller) processNextWorkItem() bool {
	obj, shutdown := c.workqueue.Get()

	if shutdown {
		return false
	}
	err := func(obj interface{}) error {
		defer c.workqueue.Done(obj)
		var item ItemValue
		var ok bool
		if item, ok = obj.(ItemValue); !ok {
			// As the item in the workqueue is actually invalid, we call
			// Forget here else we'd go into a loop of attempting to
			// process a work item that is invalid.
			c.workqueue.Forget(obj)
			runtime.HandleError(fmt.Errorf("expected string in workqueue but got %#v", obj))
			return nil
		}
		if err := c.syncHandler(item); err != nil {
			return fmt.Errorf("error syncing '%s': %s", item.key, err.Error())
		}
		c.workqueue.Forget(obj)
		glog.Infof("Successfully synced '%s'", item.key)
		return nil
	}(obj)

	if err != nil {
		runtime.HandleError(err)
		return true
	}

	return true
}

func (c *Controller) runWorker() {
	for c.processNextWorkItem() {
	}
}

func (c *Controller) findCanalGateWay() string {
	glog.Info("start find and verify gateway")
	gateways, err := c.gatewayLister.List(labels.NewSelector())
	if err != nil {
		panic(err.Error())
	}
	glog.Infof("V1alpha3 gateways num is %d", len(gateways))
	if len(gateways) > 1 {
		panic("gateways num is not 1")
	}

	if gateways[0].Spec.Selector["app"] != "canal-gateway" || gateways[0].Namespace != "istio-system" {
		panic("gateways not belong to Canal")
	}
	glog.Info("gatewayName is ", gateways[0].Name)
	return gateways[0].Name
}

func (c *Controller) Run(threadiness int, stopCh <-chan struct{}) error {
	defer runtime.HandleCrash()
	defer c.workqueue.ShutDown()

	// Start the informer factories to begin populating the informer caches
	glog.Info("Starting Canal control loop")

	// Wait for the caches to be synced before starting workers
	glog.Info("Waiting for informer caches to sync")
	if ok := cache.WaitForCacheSync(stopCh, c.virtualserviceSynced, c.gatewaySynced); !ok {
		return fmt.Errorf("failed to wait for caches to sync")
	}

	c.gatewayName = c.findCanalGateWay()

	glog.Infof("CanalServiceName: %s, CanalNamespace: %s, GatewayName: %s", c.canalServiceName, c.canalNamespace, c.gatewayName)

	glog.Info("Starting workers")
	// Launch two workers to process Network resources
	for i := 0; i < threadiness; i++ {
		go wait.Until(c.runWorker, time.Second, stopCh)
	}

	glog.Info("Started workers")
	<-stopCh
	glog.Info("Shutting down workers")

	return nil
}

func (c *Controller) syncHandler(item ItemValue) error {
	namespace, name, err := cache.SplitMetaNamespaceKey(item.key)
	if err != nil {
		runtime.HandleError(fmt.Errorf("invalid resource key: %s", item.key))
		return nil
	}
	vs, err := c.virtualserviceLister.VirtualServices(namespace).Get(name)
	switch item.operationType {
	case Add:
		glog.Infof("[CoreDnsMap] Try to add VirtualService: %#v ...", vs)
		if err != nil {
			glog.Errorf("%s is err", err)
			return nil
		}
		c.addVirtualService(vs)
	case Update:
		glog.Infof("[CoreDnsMap] Try to update VirtualService: %#v ...", vs)
		if err != nil {
			glog.Errorf("%s is err", err)
			return nil
		}
		if item.oldValue == nil || item.value == nil {
			glog.Errorf("update %s is nil", item.key)
			return nil
		}
		glog.Info("first delete old vs")
		c.deleteVirtualService(item.oldValue)
		glog.Info("second add new vs")
		c.addVirtualService(item.value)
	case Delete:
		glog.Infof("[CoreDnsMap] Try to delete VirtualService: %#v ...", vs)
		if err != nil {
			if errors.IsNotFound(err) {
				glog.Warningf("VirtualService: %s/%s does not exist in local cache, will delete it from CoreDnsMap ...",
					namespace, name)
				if item.value == nil {
					glog.Fatalf("VirtualService: %s is not exist value", item.key)
					runtime.HandleError(fmt.Errorf("%s %s is not exist value", namespace, name))
				}
				glog.Infof("[CoreDnsMap] Deleting VirtualService: %s/%s ...", namespace, name)
				c.deleteVirtualService(item.value)
				return nil
			}
			runtime.HandleError(fmt.Errorf("failed to list virtualservice by: %s/%s", namespace, name))
			return err
		}
	default:
		return nil
	}
	return nil
}

func (c *Controller) buildCanalDnsName() (canalDnsName string) {
	return c.canalServiceName + "." + c.canalNamespace + rewriteSuffix
}

func (c *Controller) deleteVirtualService(vs *v1alpha3.VirtualService) {
	glog.Info("delete event")
	var needDeleteBlock []string
	relateServices := make(map[string][]string)
	canalNameFull := c.buildCanalDnsName()
	if tools.FilterVirtualService(vs, c.canalNamespace, c.gatewayName) {
		for _, http := range vs.Spec.GetHttp() {
			for _, ds := range http.Route {
				relateServices[vs.Namespace] = append(relateServices[vs.Namespace], ds.Destination.Host)
			}
		}
	}
	for k, v := range relateServices {
		var serviceFullName string
		var deleteLine string
		for _, service := range v {
			if !tools.IsDnsFullName(service) {
				serviceFullName = service + "." + k + rewriteSuffix
			} else {
				serviceFullName = service
			}
			num := coredns.Del(serviceFullName)
			if num == 0 {
				deleteLine = rewritePrefix + serviceFullName + " " + canalNameFull
				if !tools.HaveString(deleteLine, needDeleteBlock) {
					needDeleteBlock = append(needDeleteBlock, deleteLine)
				}
			}
		}
	}
	configMaps, err := c.kubeclientset.CoreV1().ConfigMaps("kube-system").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		panic(err)
	}
	for _, configmap := range configMaps.Items {
		if configmap.Name == "coredns" {
			newConfigMap, err := coredns.BuildNewConfigMapForDelete(configmap, needDeleteBlock)
			if err != nil {
				//coredns.RollBackConfigMapData(clientSet, configmap)
				glog.Fatalf("Error content is empty after build: %s", err)
			} else {
				coredns.UpdateConfigMap(c.kubeclientset, newConfigMap, configmap)
			}
		}
	}
}

func (c *Controller) addVirtualService(vs *v1alpha3.VirtualService) {
	glog.Info("add event")
	var needAddBlock []string
	relateServices := make(map[string][]string)
	canalNameFull := c.buildCanalDnsName()
	if tools.FilterVirtualService(vs, c.canalNamespace, c.gatewayName) {
		for _, http := range vs.Spec.GetHttp() {
			for _, ds := range http.Route {
				relateServices[vs.Namespace] = append(relateServices[vs.Namespace], ds.Destination.Host)
			}
		}
	}
	for k, v := range relateServices {
		var serviceFullName string
		var rewriteLine string
		for _, service := range v {
			if !tools.IsDnsFullName(service) {
				serviceFullName = service + "." + k + rewriteSuffix
			} else {
				serviceFullName = service
			}
			num := coredns.Put(serviceFullName)
			if num == 1 {
				rewriteLine = rewritePrefix + serviceFullName + " " + canalNameFull
				if !tools.HaveString(rewriteLine, needAddBlock) {
					needAddBlock = append(needAddBlock, rewriteLine)
				}
			}
		}
	}
	glog.Infof("addBlock is : %v", needAddBlock)
	configMaps, err := c.kubeclientset.CoreV1().ConfigMaps("kube-system").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		panic(err)
	}
	for _, configmap := range configMaps.Items {
		if configmap.Name == "coredns" {
			newConfigMap, err := coredns.BuildNewConfigMapForAdd(configmap, needAddBlock)
			if err != nil {
				//coredns.RollBackConfigMapData(clientSet, configmap)
				glog.Fatalf("Error content is empty after build: %s", err)
			} else {
				coredns.UpdateConfigMap(c.kubeclientset, newConfigMap, configmap)
			}
		}
	}
}
