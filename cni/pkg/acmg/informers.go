// Copyright Istio Authors
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

package acmg

import (
	"fmt"
	"istio.io/istio/pilot/pkg/acmg/acmgpod"
	"istio.io/istio/pkg/config/constants"
	"istio.io/istio/pkg/kube/controllers"
	"istio.io/istio/pkg/kube/kclient"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	klabels "k8s.io/apimachinery/pkg/labels"
)

var ErrLegacyLabel = "Namespace %s has sidecar label istio-injection or istio.io/rev " +
	"enabled while also setting acmg mode. This is not supported and the namespace will " +
	"be ignored from the acmg mesh."

func (s *Server) setupHandlers() {
	s.queue = controllers.NewQueue("acmg",
		controllers.WithGenericReconciler(s.Reconcile),
		controllers.WithMaxAttempts(5),
	)

	// We only need to handle pods on our node
	s.pods = kclient.NewFiltered[*corev1.Pod](s.kubeClient, kclient.Filter{FieldSelector: "spec.nodeName=" + NodeName})
	s.pods.AddEventHandler(controllers.FromEventHandler(func(o controllers.Event) {
		s.queue.Add(o)
	}))

	// Namespaces could be anything though, so we watch all of those
	s.namespaces = kclient.New[*corev1.Namespace](s.kubeClient)
	s.namespaces.AddEventHandler(controllers.ObjectHandler(s.EnqueueNamespace))
	log.Infof("acmg handlers init ok!")
}

func (s *Server) Run(stop <-chan struct{}) {
	go s.queue.Run(stop)
	<-stop
}

func (s *Server) ReconcileNamespaces() {
	for _, ns := range s.namespaces.List(metav1.NamespaceAll, klabels.Everything()) {
		s.EnqueueNamespace(ns)
	}
}

// EnqueueNamespace takes a Namespace and enqueues all Pod objects that make need an update
func (s *Server) EnqueueNamespace(o controllers.Object) {
	namespace := o.GetName()
	matchAcmg := o.GetLabels()[constants.DataplaneMode] == constants.DataplaneModeAcmg
	if matchAcmg {
		log.Infof("Namespace %s is enabled in acmg mesh", namespace)
		for _, pod := range s.pods.List(namespace, klabels.Everything()) {
			log.Infof("Add namespace %s %v to queue", namespace, pod.Name)
			s.queue.Add(controllers.Event{
				New:   pod,
				Old:   pod,
				Event: controllers.EventUpdate,
			})
		}
	} else {
		log.Infof("Namespace %s is disabled from acmg mesh", namespace)
		for _, pod := range s.pods.List(namespace, klabels.Everything()) {
			s.queue.Add(controllers.Event{
				New:   pod,
				Event: controllers.EventDelete,
			})
		}
	}
}

func (s *Server) Reconcile(input any) error {
	event := input.(controllers.Event)
	log := log.WithLabels("type", event.Event)
	pod := event.Latest().(*corev1.Pod)
	log.Infof("Reconcile Pod %v %v", pod.Namespace, pod.Name)
	if nodeProxyPod(pod) {
		return s.ReconcileNodeProxy()
	}
	switch event.Event {
	case controllers.EventAdd:
	case controllers.EventUpdate:
		// For update, we just need to handle opt outs
		newPod := event.New.(*corev1.Pod)
		oldPod := event.Old.(*corev1.Pod)
		ns := s.namespaces.Get(newPod.Namespace, "")
		if ns == nil {
			return fmt.Errorf("failed to find namespace %v", ns)
		}
		wasEnabled := oldPod.Annotations[constants.AcmgRedirection] == constants.AcmgRedirectionEnabled
		nowEnabled := acmgpod.PodNodeProxyEnabled(ns, newPod)
		log.Infof("Pod %v %v wasEnabled: %v nowEnabled: %v", pod.Namespace, pod.Name, wasEnabled, nowEnabled)
		if wasEnabled && !nowEnabled {
			log.Debugf("Pod %s no longer matches, removing from mesh", newPod.Name)
			s.DelPodFromMesh(newPod)
		}

		if !wasEnabled && nowEnabled {
			log.Debugf("Pod %s now matches, adding to mesh", newPod.Name)
			s.AddPodToMesh(pod)
		}
	case controllers.EventDelete:
		if s.redirectMode == IptablesMode && IsPodInIpset(pod) {
			log.Infof("Pod %s/%s is now stopped... cleaning up.", pod.Namespace, pod.Name)
			s.DelPodFromMesh(pod)
		} else if s.redirectMode == EbpfMode {
			log.Debugf("Pod %s/%s is now stopped or opt out... cleaning up.", pod.Namespace, pod.Name)
			s.DelPodFromMesh(pod)
		}
		return nil
	}
	return nil
}

func nodeProxyPod(pod *corev1.Pod) bool {
	return pod.GetLabels()["app"] == "nodeproxy"
}
