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

package main

import (
	"cannalcontroller/pkg/controller"
	"cannalcontroller/pkg/coredns"
	"cannalcontroller/pkg/signal"
	"flag"
	"github.com/golang/glog"
	versionedclient "istio.io/client-go/pkg/clientset/versioned"
	"istio.io/client-go/pkg/informers/externalversions"
	"k8s.io/client-go/kubernetes"
	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"time"
)

var (
	masterURL  string
	kubeConfig string
)

func main() {
	flag.Parse()

	stopCh := signal.SetupSignalHandler()
	var cfg *restclient.Config
	var err error
	if kubeConfig != "" {
		cfg, err = clientcmd.BuildConfigFromFlags(masterURL, kubeConfig)
		if err != nil {
			glog.Fatalf("Error building kubeConfig: %s", err.Error())
		}
	} else {
		cfg, err = restclient.InClusterConfig()
		if err != nil {
			panic(err.Error())
		}
	}

	clientSet, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		glog.Fatalf("Error building kubernetes clientSet: %s", err.Error())
	}

	client, err := versionedclient.NewForConfig(cfg)
	if err != nil {
		glog.Fatalf("Failed to create istio client: %s", err)
	}

	factory := externalversions.NewSharedInformerFactory(client, time.Second*30)
	virtualServiceInformer := factory.Networking().V1alpha3().VirtualServices()
	gatewaysInformer := factory.Networking().V1alpha3().Gateways()

	canalController := controller.NewController(virtualServiceInformer, gatewaysInformer, clientSet, client)

	factory.Start(stopCh)
	coredns.StartDebugServer()

	if err = canalController.Run(1, stopCh); err != nil {
		glog.Fatalf("Error running controller: %s", err.Error())
	}
}

func init() {
	flag.StringVar(&kubeConfig, "kubeConfig", "", "Path to a kubeConfig. Only required if out-of-cluster.")
	flag.StringVar(&masterURL, "master", "", "The address of the Kubernetes API server. Overrides any value in kubeConfig. Only required if out-of-cluster.")
}
