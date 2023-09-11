package controller

import (
	"context"
	"fmt"
	"istio.io/istio/pilot/pkg/acmg"
	v1 "k8s.io/api/core/v1"
	klabels "k8s.io/apimachinery/pkg/labels"
	listerv1 "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"istio.io/api/label"
	"istio.io/istio/pilot/pkg/features"
	kubelib "istio.io/istio/pkg/kube"
	"istio.io/istio/pkg/kube/controllers"
	"istio.io/istio/pkg/kube/inject"
	"istio.io/istio/pkg/util/sets"
	"istio.io/pkg/env"
)

var autoLabel = env.RegisterBoolVar("ACMG_AUTO_LABEL", false, "").Get()

type AutoLabel struct {
	labeledNamespace []string
	podQueue         *controllers.Queue
	podLister        listerv1.PodLister
	client           kubelib.Client
}

func NewAutoLabel() *AutoLabel {
	return &AutoLabel{
		labeledNamespace: make([]string, 0),
	}
}

func (a *AutoLabel) nsOnAcmg(ns string) bool {
	if ns == "" {
		return false
	}
	for _, labelledNs := range a.labeledNamespace {
		if labelledNs == ns {
			return true
		}
	}
	return false
}

func (a *AutoLabel) initAutoLabel(opts *Options) {
	if !autoLabel && !opts.forceAutoLabel {
		return
	}
	log.Infof("Starting acmg mesh auto-labeler")

	if _, err := opts.Client.KubeInformer().Core().V1().Namespaces().Informer().AddEventHandler(a.labeledNamespaceInformer()); err != nil {
		log.Errorf("initAcmgAutoLabel failed %v", err)
		return
	}

	podQueue := controllers.NewQueue("acmg pod label controller",
		controllers.WithReconciler(a.acmgPodLabelPatcher(opts.Client)),
		controllers.WithMaxAttempts(5),
	)
	a.podQueue = &podQueue
	a.client = opts.Client
	a.podLister = opts.Client.KubeInformer().Core().V1().Pods().Lister()

	ignored := sets.New(append(strings.Split(features.AcmgAutoLabelIgnore, ","), opts.SystemNamespace)...)
	workloadHandler := controllers.FilteredObjectHandler(podQueue.AddObject, a.acmgPodLabelFilter(ignored))
	if _, err := opts.Client.KubeInformer().Core().V1().Pods().Informer().AddEventHandler(workloadHandler); err != nil {
		log.Errorf("initAcmgAutoLabel failed %v", err)
		return
	}
	go a.podQueue.Run(opts.Stop)
}

var labelPatch = []byte(fmt.Sprintf(
	`[{"op":"add","path":"/metadata/labels/%s","value":"%s" }]`,
	acmg.LabelType,
	acmg.TypeWorkload,
))

func (a *AutoLabel) addPodToQueue(ns *v1.Namespace) {
	a.labeledNamespace = append(a.labeledNamespace, ns.Name)
	pods, err := a.podLister.Pods(ns.Name).List(klabels.Everything())
	if err != nil {
		log.Errorf("Failed to list namespaces %v pods %v", ns, err)
		return
	}
	for _, pod := range pods {
		a.podQueue.Add(types.NamespacedName{
			Namespace: pod.GetNamespace(),
			Name:      pod.GetName(),
		})
	}
}

func checkNamespaceLabel(ns *v1.Namespace) bool {
	if labelValue, labelled := ns.GetLabels()["istio.io/dataplane-mode"]; labelled && labelValue == "acmg" {
		return true
	}
	return false
}

func (a *AutoLabel) labeledNamespaceInformer() *cache.ResourceEventHandlerFuncs {
	return &cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj any) {
			ns := obj.(*v1.Namespace)
			if checkNamespaceLabel(ns) {
				a.addPodToQueue(ns)
			}
		},
		UpdateFunc: func(oldObj, newObj any) {
			oldNs := oldObj.(*v1.Namespace)
			newNs := newObj.(*v1.Namespace)

			if checkNamespaceLabel(newNs) && !checkNamespaceLabel(oldNs) {
				a.addPodToQueue(newNs)
			}
			log.Infof("")
		},
		DeleteFunc: func(obj any) {
			return
		},
	}
}

func (a *AutoLabel) acmgPodLabelFilter(ignoredNamespaces sets.String) func(o controllers.Object) bool {
	return func(o controllers.Object) bool {
		_, alreadyLabelled := o.GetLabels()[acmg.LabelType]
		ignored := inject.IgnoredNamespaces.Contains(o.GetNamespace()) || ignoredNamespaces.Contains(o.GetNamespace())
		_, injected := o.GetLabels()[label.SecurityTlsMode.Name]
		return !alreadyLabelled && !ignored && !injected && a.nsOnAcmg(o.GetNamespace())
	}
}

func (a *AutoLabel) acmgPodLabelPatcher(client kubelib.Client) func(types.NamespacedName) error {
	return func(key types.NamespacedName) error {
		_, err := client.Kube().CoreV1().
			Pods(key.Namespace).
			Patch(
				context.Background(),
				key.Name,
				types.JSONPatchType,
				labelPatch, metav1.PatchOptions{},
			)
		return err
	}
}
