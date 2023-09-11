package acmg

import (
	"istio.io/istio/pkg/spiffe"
	"k8s.io/apimachinery/pkg/types"
	"sync"
	"time"
)

type NodeType = string

const (
	LabelStatus = "istio.io/acmg-status"
	TypeEnabled = "enabled"
	// LabelType == "workload" -> intercept into ztunnel
	// TODO this could be an annotation – eventually move it into api repo
	LabelType = "acmg-type"

	TypeWorkload  NodeType = "workload"
	TypeNone      NodeType = "none"
	TypeNodeProxy NodeType = "nodeproxy"
	TypeCoreProxy NodeType = "coreproxy"
)

type WorkloadMetadata struct {
	Containers     []string
	GenerateName   string
	ControllerName string
	ControllerKind string
}

type Workload struct {
	UID       string
	Name      string
	Namespace string
	Labels    map[string]string

	ServiceAccount string
	NodeName       string
	PodIP          string
	PodIPs         []string
	HostNetwork    bool

	WorkloadMetadata

	CreationTimestamp time.Time
}

// AcmgCache holds Indexes of client workloads, waypoint proxies, and ztunnels
type AcmgCache interface {
	AcmgWorkloads() Indexes
}

type Indexes struct {
	Workloads *WorkloadIndex `json:"workloads"`
	None      *WorkloadIndex `json:"none"`
	CoreProxy *WorkloadIndex `json:"coreproxy"`
	NodeProxy *WorkloadIndex `json:"nodeproxy"`
}

// Identity generates SecureNamingSAN but for Workload instead of Pod
func (w Workload) Identity() string {
	return spiffe.MustGenSpiffeURI(w.Namespace, w.ServiceAccount)
}

type WorkloadIndex struct {
	sync.RWMutex

	ByNamespacedName  map[types.NamespacedName]Workload
	ByNode            map[string][]Workload
	ByIdentity        map[string][]Workload
	ByNodeAndIdentity map[string]map[string][]Workload
	ByIP              map[string]Workload

	// we cache this so we can cleanup the other indexes on removal without searching
	details map[types.NamespacedName]subindexDetails
}

func NewWorkloadIndex() *WorkloadIndex {
	// TODO take opts that disable individual indexes if needed
	return &WorkloadIndex{
		ByNamespacedName:  map[types.NamespacedName]Workload{},
		ByNode:            map[string][]Workload{},
		ByIdentity:        map[string][]Workload{},
		ByNodeAndIdentity: map[string]map[string][]Workload{},
		ByIP:              map[string]Workload{},

		details: map[types.NamespacedName]subindexDetails{},
	}
}

type subindexDetails struct {
	sa, node, ip string
}

func (wi *WorkloadIndex) NodeLocal(node string) []Workload {
	if node == "" {
		return wi.All()
	}
	return wi.ByNode[node]
}

func (wi *WorkloadIndex) All() []Workload {
	var out []Workload
	for _, workload := range wi.ByNamespacedName {
		out = append(out, workload)
	}
	return out
}

func (wi *WorkloadIndex) Insert(workload Workload) {
	wi.Lock()
	defer wi.Unlock()
	node, sa := workload.NodeName, workload.Identity()
	ip := workload.PodIP // TODO eventually support multi-IP
	namespacedName := types.NamespacedName{Name: workload.Name, Namespace: workload.Namespace}

	// TODO if we start indexing by a mutable key, call Remove here

	wi.ByNamespacedName[namespacedName] = workload
	wi.details[namespacedName] = subindexDetails{node: node, sa: sa, ip: ip}
	if node != "" {
		wi.ByNode[node] = append(wi.ByNode[node], workload)
	}
	if sa != "" {
		wi.ByIdentity[sa] = append(wi.ByIdentity[sa], workload)
	}
	if node != "" && sa != "" {
		if wi.ByNodeAndIdentity[node] == nil {
			wi.ByNodeAndIdentity[node] = map[string][]Workload{}
		}
		if sa != "" {
			wi.ByNodeAndIdentity[node][sa] = append(wi.ByNodeAndIdentity[node][sa], workload)
		}
	}
	if ip != "" {
		wi.ByIP[ip] = workload
	}
}

func (wi *WorkloadIndex) MergeInto(other *WorkloadIndex) *WorkloadIndex {
	wi.RLock()
	defer wi.RUnlock()
	for _, v := range wi.ByNamespacedName {
		other.Insert(v)
	}
	return other
}

func (wi *WorkloadIndex) Remove(namespacedName types.NamespacedName) {
	wi.Lock()
	defer wi.Unlock()
	details, ok := wi.details[namespacedName]
	if !ok {
		return
	}
	node, sa, ip := details.node, details.sa, details.ip
	delete(wi.ByNamespacedName, namespacedName)
	delete(wi.details, namespacedName)
	delete(wi.ByNode, node)
	delete(wi.ByNode, sa)
	delete(wi.ByIP, ip)
	if bySA, ok := wi.ByNodeAndIdentity[node]; ok {
		delete(bySA, sa)
	}
	if len(wi.ByNodeAndIdentity[node]) == 0 {
		delete(wi.ByNodeAndIdentity, node)
	}
}

func (wi *WorkloadIndex) Copy() *WorkloadIndex {
	return wi.MergeInto(NewWorkloadIndex())
}
