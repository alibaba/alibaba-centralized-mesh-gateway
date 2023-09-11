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

package acmgpod

import (
	"istio.io/api/annotation"
	"istio.io/istio/pilot/pkg/acmg"
	"istio.io/istio/pkg/config/constants"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	"istio.io/api/label"
	"istio.io/pkg/log"
)

func WorkloadFromPod(pod *corev1.Pod) acmg.Workload {
	var containers, ips []string
	for _, container := range pod.Spec.Containers {
		containers = append(containers, container.Name)
	}
	for _, ip := range pod.Status.PodIPs {
		ips = append(ips, ip.IP)
	}

	var controllerName, controllerKind string
	for _, ref := range pod.GetOwnerReferences() {
		if ref.Controller != nil && *ref.Controller {
			controllerName, controllerKind = ref.Name, ref.Kind
			break
		}
	}

	return acmg.Workload{
		UID:               string(pod.UID),
		Name:              pod.Name,
		Namespace:         pod.Namespace,
		Labels:            pod.Labels, // TODO copy?
		ServiceAccount:    pod.Spec.ServiceAccountName,
		NodeName:          pod.Spec.NodeName,
		HostNetwork:       pod.Spec.HostNetwork,
		PodIP:             pod.Status.PodIP,
		PodIPs:            ips,
		CreationTimestamp: pod.CreationTimestamp.Time,
		WorkloadMetadata: acmg.WorkloadMetadata{
			GenerateName:   pod.GenerateName,
			Containers:     containers,
			ControllerName: controllerName,
			ControllerKind: controllerKind,
		},
	}
}

// PodNodeProxyEnabled determines if a pod is eligible for ztunnel redirection
func PodNodeProxyEnabled(namespace *corev1.Namespace, pod *corev1.Pod) bool {
	if namespace.GetLabels()[constants.DataplaneMode] != constants.DataplaneModeAcmg {
		// Namespace does not have ambient mode enabled
		return false
	}
	if podHasSidecar(pod) {
		// Ztunnel and sidecar for a single pod is currently not supported; opt out.
		return false
	}
	if pod.Annotations[constants.AcmgRedirection] == constants.AcmgRedirectionDisabled {
		// Pod explicitly asked to not have redirection enabled
		return false
	}
	return true
}

func podHasSidecar(pod *corev1.Pod) bool {
	if _, f := pod.Annotations[annotation.SidecarStatus.Name]; f {
		return true
	}
	return false
}

var LegacyLabelSelector = []*metav1.LabelSelector{
	{
		MatchExpressions: []metav1.LabelSelectorRequirement{
			{
				Key:      "istio-injection",
				Operator: metav1.LabelSelectorOpIn,
				Values: []string{
					"enabled",
				},
			},
		},
	},
	{
		MatchExpressions: []metav1.LabelSelectorRequirement{
			{
				Key:      label.IoIstioRev.Name,
				Operator: metav1.LabelSelectorOpExists,
			},
		},
	},
}

var LegacySelectors = ConvertDisabledSelectors(LegacyLabelSelector)

func ConvertDisabledSelectors(selectors []*metav1.LabelSelector) []labels.Selector {
	res := make([]labels.Selector, 0, len(selectors))
	for _, k := range selectors {
		s, err := metav1.LabelSelectorAsSelector(k)
		if err != nil {
			log.Errorf("failed to convert label selector: %v", err)
			continue
		}
		res = append(res, s)
	}
	return res
}
