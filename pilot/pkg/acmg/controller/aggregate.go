package controller

import (
	"istio.io/istio/pilot/pkg/acmg"
	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pkg/cluster"
	kubelib "istio.io/istio/pkg/kube"
	"istio.io/istio/pkg/kube/inject"
	"istio.io/istio/pkg/kube/multicluster"
	istiolog "istio.io/pkg/log"
	"sync"
)

var log = istiolog.RegisterScope("acmg", "acmg mesh controllers")

type Options struct {
	xds       model.XDSUpdater
	Client    kubelib.Client
	Stop      <-chan struct{}
	ClusterID cluster.ID

	SystemNamespace string

	LocalCluster  bool
	WebhookConfig func() inject.WebhookConfig

	forceAutoLabel bool
}

func NewAggregate(
	systemNamespace string,
	localCluster cluster.ID,
	webhookConfig func() inject.WebhookConfig,
	xdsUpdater model.XDSUpdater,
	forceAutoLabel bool,
) *Aggregate {
	return &Aggregate{
		localCluster: localCluster,
		baseOpts: Options{
			SystemNamespace: systemNamespace,
			WebhookConfig:   webhookConfig,
			xds:             xdsUpdater,
			forceAutoLabel:  forceAutoLabel,
		},

		clusters: make(map[cluster.ID]*acmgController),
	}
}

type Aggregate struct {
	localCluster cluster.ID
	baseOpts     Options

	mu       sync.RWMutex
	clusters map[cluster.ID]*acmgController
}

func (a *Aggregate) AcmgWorkloads() acmg.Indexes {
	out := acmg.Indexes{
		Workloads: acmg.NewWorkloadIndex(),
		CoreProxy: acmg.NewWorkloadIndex(),
		NodeProxy: acmg.NewWorkloadIndex(),
		None:      acmg.NewWorkloadIndex(),
	}
	if a == nil {
		return out
	}

	// consistent ordering should be handled somewhere (config gen, workload index), but not in the cluster iteration
	a.mu.RLock()
	defer a.mu.RUnlock()
	for _, c := range a.clusters {
		ci := c.workloads.AcmgWorkloads()
		ci.Workloads.MergeInto(out.Workloads)
		ci.None.MergeInto(out.None)
		ci.NodeProxy.MergeInto(out.NodeProxy)
		ci.CoreProxy.MergeInto(out.CoreProxy)
	}
	return out
}

func (a *Aggregate) ClusterAdded(cluster *multicluster.Cluster, stop <-chan struct{}) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	return a.clusterAdded(cluster, stop)
}

func (a *Aggregate) clusterAdded(cluster *multicluster.Cluster, stop <-chan struct{}) error {
	log.Infof("starting acmg controller for %s", cluster.ID)
	opts := a.baseOpts

	opts.Client = cluster.Client
	opts.Stop = stop
	opts.ClusterID = cluster.ID

	// don't modify remote clusters, just find their waypoint proxies and Pods
	opts.LocalCluster = a.localCluster == cluster.ID

	a.clusters[cluster.ID] = initForCluster(&opts)
	return nil
}

func initForCluster(opts *Options) *acmgController {
	if opts.LocalCluster {
		autoLabelServer := NewAutoLabel()
		// TODO handle istiodless remote clusters
		autoLabelServer.initAutoLabel(opts)
	}
	return &acmgController{
		workloads: initWorkloadCache(opts),
	}
}

func (a *Aggregate) ClusterUpdated(cluster *multicluster.Cluster, stop <-chan struct{}) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.clusterDeleted(cluster.ID); err != nil {
		return err
	}
	return a.clusterAdded(cluster, stop)
}

func (a *Aggregate) ClusterDeleted(clusterID cluster.ID) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.clusterDeleted(clusterID)
}

func (a *Aggregate) clusterDeleted(clusterID cluster.ID) error {
	delete(a.clusters, clusterID)
	return nil
}

type acmgController struct {
	workloads *workloadCache
}
