package controller

import (
	"context"
	"istio.io/istio/pilot/pkg/acmg"
	"istio.io/istio/pilot/pkg/acmg/acmgpod"
	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pkg/kube/controllers"
	kubeErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	v1 "k8s.io/client-go/kubernetes/typed/core/v1"
)

type workloadCache struct {
	xds     model.XDSUpdater
	indexes map[acmg.NodeType]*acmg.WorkloadIndex
	pods    func(namespace string) v1.PodInterface
}

func initWorkloadCache(opts *Options) *workloadCache {
	wc := &workloadCache{
		xds:  opts.xds,
		pods: opts.Client.Kube().CoreV1().Pods,
		// 3 types of things here: ztunnels, waypoint proxies, and Workloads.
		// While we don't have to look up all of these by the same keys, the indexes should be pretty cheap.
		indexes: map[acmg.NodeType]*acmg.WorkloadIndex{
			acmg.TypeNodeProxy: acmg.NewWorkloadIndex(),
			acmg.TypeCoreProxy: acmg.NewWorkloadIndex(),
			acmg.TypeWorkload:  acmg.NewWorkloadIndex(),
			acmg.TypeNone:      acmg.NewWorkloadIndex(),
		},
	}
	queue := controllers.NewQueue("acmg workload cache",
		controllers.WithReconciler(wc.Reconcile),
		controllers.WithMaxAttempts(5),
	)
	proxyHandler := controllers.FilteredObjectHandler(queue.AddObject, func(o controllers.Object) bool {
		_, hasType := o.GetLabels()[acmg.LabelType]
		return hasType
	})

	if _, err := opts.Client.KubeInformer().Core().V1().Pods().Informer().AddEventHandler(proxyHandler); err != nil {
		log.Errorf("initWorkloadCache failed %v", err)
		return nil
	}

	go queue.Run(opts.Stop)
	return wc
}

func (wc *workloadCache) Reconcile(key types.NamespacedName) error {
	ctx := context.Background()
	// TODO use lister
	pod, err := wc.pods(key.Namespace).Get(ctx, key.Name, metav1.GetOptions{})
	if kubeErrors.IsNotFound(err) {
		wc.removeFromAll(key)
		wc.xds.ConfigUpdate(&model.PushRequest{
			// TODO scope our updates
			Full:   true,
			Reason: []model.TriggerReason{model.AcmgUpdate},
		})
		return nil
	} else if err != nil {
		return err
	}

	w := acmgpod.WorkloadFromPod(pod)
	index, ok := wc.indexes[pod.Labels[acmg.LabelType]]
	if ok && wc.validate(w) {
		// known type, cache it
		index.Insert(w)
	} else {
		// if this Pod went from valid -> empty/invalid we need to remove it from every index
		wc.removeFromAll(key)
	}
	wc.xds.ConfigUpdate(&model.PushRequest{
		// TODO scope our updates
		Full:   true,
		Reason: []model.TriggerReason{model.AcmgUpdate},
	})
	return nil
}

func (wc *workloadCache) validate(w acmg.Workload) bool {
	// TODO also check readiness; also requirements may differ by ambient-type
	return w.PodIP != ""
}

func (wc *workloadCache) removeFromAll(key types.NamespacedName) {
	for _, index := range wc.indexes {
		index.Remove(key)
	}
}

func (wc *workloadCache) AcmgWorkloads() acmg.Indexes {
	return acmg.Indexes{
		Workloads: wc.indexes[acmg.TypeWorkload].Copy(),
		None:      wc.indexes[acmg.TypeNone].Copy(),
		CoreProxy: wc.indexes[acmg.TypeCoreProxy].Copy(),
		NodeProxy: wc.indexes[acmg.TypeNodeProxy].Copy(),
	}
}
