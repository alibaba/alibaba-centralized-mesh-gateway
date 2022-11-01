package server

import (
	"context"
	"fmt"
	"istio.io/client-go/pkg/apis/networking/v1alpha3"
	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"strings"
)

import "istio.io/pkg/log"

type CoreDnsBuilder struct {
	kubeClient  kubernetes.Interface
	gatewayData GatewayData
	content     string
	deepNum     int
}

func filterVirtualService(virtualService *v1alpha3.VirtualService, gatewayNamespace string, gatewayName string) bool {
	if virtualService.Namespace != gatewayNamespace {
		return false
	}
	for i := 0; i < len(virtualService.Spec.Gateways); i++ {
		if virtualService.Spec.Gateways[i] == gatewayName {
			return true
		}
	}
	return false
}

func isDnsFullName(service string) bool {
	return strings.Contains(service, ".svc.cluster.local")
}

func haveString(target string, list []string) bool {
	for _, ele := range list {
		if ele == target {
			return true
		}
	}
	return false
}

func cleanString(target string) (ret string) {
	ret = strings.TrimLeft(target, " ")
	ret = strings.TrimLeft(ret, "\n")
	ret = strings.TrimLeft(ret, "\t")

	ret = strings.TrimRight(ret, " ")
	ret = strings.TrimRight(ret, "\n")
	ret = strings.TrimRight(ret, "\t")
	return ret
}

func (b *CoreDnsBuilder) insertBlock(block []string) {
	for _, line := range block {
		b.content += "    " + line + "\n"
	}
}

func (b *CoreDnsBuilder) processLineForAdd(line string, block []string) {
	b.content += line + "\n"
	var haveFlag = false
	if strings.Contains(line, "{") {
		b.deepNum++
		haveFlag = true
	}
	if strings.Contains(line, "}") {
		b.deepNum--
	}
	if b.deepNum == 1 && haveFlag {
		b.insertBlock(block)
	}
	if b.deepNum < 0 {
		log.Errorf("Error deepNum is %d : %s\n", b.deepNum, line)
		return
	}
}

func (b *CoreDnsBuilder) processLineForDelete(line string, deleteBlock []string) {
	if !haveString(cleanString(line), deleteBlock) {
		b.content += line + "\n"
		return
	}
}

func (b *CoreDnsBuilder) buildNewConfigMapForAdd(oldConfigMap *v1.ConfigMap, insertBlock []string) (newConfigMap *v1.ConfigMap, err error) {
	if len(insertBlock) == 0 {
		log.Warn("insertBlock is empty")
		return
	}
	oldConfigMap.DeepCopyInto(newConfigMap)
	for k, v := range oldConfigMap.Data {
		if k == "Corefile" {
			lines := strings.Split(v, "\n")
			for i := 0; i < len(lines); i++ {
				b.processLineForAdd(lines[i], insertBlock)
			}
		}
	}

	if b.content == "" {
		log.Errorf("Error Content is empty after build: %s", b.content)
		return newConfigMap, fmt.Errorf("add coredns content is empty")
	}
	newConfigMap.Data["Corefile"] = b.content
	b.content = ""
	return newConfigMap, nil
}

func (b *CoreDnsBuilder) buildNewConfigMapForDelete(oldConfigMap *v1.ConfigMap, deleteBlock []string) (newConfigMap *v1.ConfigMap, err error) {
	if len(deleteBlock) == 0 {
		log.Warn("deleteBlock is empty")
		return
	}
	oldConfigMap.DeepCopyInto(newConfigMap)
	if len(deleteBlock) != 0 {
		for k, v := range oldConfigMap.Data {
			if k == "Corefile" {
				lines := strings.Split(v, "\n")
				for i := 0; i < len(lines); i++ {
					b.processLineForDelete(lines[i], deleteBlock)
				}
			}
		}
	}
	if b.content == "" {
		log.Errorf("Error content is empty after build: %s", b.content)
		return newConfigMap, fmt.Errorf("delete coredns content is empty")
	}
	newConfigMap.Data["Corefile"] = b.content
	b.content = ""
	return newConfigMap, nil
}

func (b *CoreDnsBuilder) rollBackConfigMapData(newConfigMap *v1.ConfigMap, maxRetry int) error {
	var err error
	for i := 0; i < maxRetry; i++ {
		_, err = b.kubeClient.CoreV1().ConfigMaps("kube-system").Update(context.TODO(), newConfigMap, metav1.UpdateOptions{})
		if err != nil {
			log.Errorf("rollBackConfigMapData error %s", err)
			continue
		}
		break
	}
	return err
}

func (b *CoreDnsBuilder) updateConfigMap(newConfigMap *v1.ConfigMap, oldConfigMap *v1.ConfigMap) error {
	_, err := b.kubeClient.CoreV1().ConfigMaps("kube-system").Update(context.TODO(), newConfigMap, metav1.UpdateOptions{})
	if err != nil {
		log.Errorf("updateConfigMap error %s", err)
		err = b.rollBackConfigMapData(oldConfigMap, 3)
		return fmt.Errorf("update coredns configMap error")
	}
	return nil
}

func (b *CoreDnsBuilder) AddVSToCoreDns(vs *v1alpha3.VirtualService) error {
	log.Debugf("add virtualservice to coredns configmap")
	var needAddBlock []string
	relatedServices := make(map[string][]string)
	if filterVirtualService(vs, b.gatewayData.gatewayNamespace, b.gatewayData.istioGatewayName) {
		for _, http := range vs.Spec.GetHttp() {
			for _, ds := range http.Route {
				relatedServices[vs.Namespace] = append(relatedServices[vs.Namespace], ds.Destination.Host)
			}
		}
	}
	for k, v := range relatedServices {
		var serviceFullName string
		var rewriteLine string
		for _, service := range v {
			if !isDnsFullName(service) {
				serviceFullName = service + "." + k + ".svc.cluster.local"
			} else {
				serviceFullName = service
			}
			num := Put(serviceFullName)
			if num == 1 {
				rewriteLine = "rewrite name " + serviceFullName + " " + b.gatewayData.gatewayDns
				if !haveString(rewriteLine, needAddBlock) {
					needAddBlock = append(needAddBlock, rewriteLine)
				}
			}
		}
	}
	log.Infof("addBlock is : %v", needAddBlock)
	if len(needAddBlock) != 0 {
		configMap, err := b.kubeClient.CoreV1().ConfigMaps("kube-system").Get(context.TODO(), "coredns", metav1.GetOptions{})
		if err != nil {
			log.Errorf("get core dns configmap failed %s", err)
			return fmt.Errorf("get core dns configmap failed")
		}
		newConfigMap, err := b.buildNewConfigMapForAdd(configMap, needAddBlock)
		if err != nil {
			log.Errorf("Error content is empty after build: %s", err)
			return err
		} else {
			return b.updateConfigMap(newConfigMap, configMap)
		}
	}
	return nil
}

func (b *CoreDnsBuilder) deleteVSFromCoreDns(vs *v1alpha3.VirtualService) error {
	log.Debugf("delete virtualservice from coredns configmap")
	var needDeleteBlock []string
	relateServices := make(map[string][]string)
	if filterVirtualService(vs, b.gatewayData.gatewayNamespace, b.gatewayData.istioGatewayName) {
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
			if !isDnsFullName(service) {
				serviceFullName = service + "." + k + ".svc.cluster.local"
			} else {
				serviceFullName = service
			}
			num := Del(serviceFullName)
			if num == 0 {
				deleteLine = "rewrite name " + serviceFullName + " " + b.gatewayData.gatewayDns
				if !haveString(deleteLine, needDeleteBlock) {
					needDeleteBlock = append(needDeleteBlock, deleteLine)
				}
			}
		}
	}
	if len(needDeleteBlock) != 0 {
		configMap, err := b.kubeClient.CoreV1().ConfigMaps("kube-system").Get(context.TODO(), "coredns", metav1.GetOptions{})
		if err != nil {
			log.Errorf("get core dns configmap failed %s", err)
			return fmt.Errorf("get core dns configmap failed")
		}
		newConfigMap, err := b.buildNewConfigMapForDelete(configMap, needDeleteBlock)
		if err != nil {
			log.Errorf("Error content is empty after build: %s", err)
			return err
		} else {
			return b.updateConfigMap(newConfigMap, configMap)
		}
	}
	return nil
}
