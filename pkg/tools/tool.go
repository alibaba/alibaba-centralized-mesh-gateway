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

package tools

import (
	"gopkg.in/mgo.v2/bson"
	"istio.io/client-go/pkg/apis/networking/v1alpha3"
	"strings"
)

func HaveString(target string, list []string) bool {
	for _, ele := range list {
		if ele == target {
			//glog.Infof("ele: %s, target: %s", ele, target)
			return true
		}
	}
	return false
}

func CleanString(target string) (ret string) {
	ret = strings.TrimLeft(target, " ")
	ret = strings.TrimLeft(ret, "\n")
	ret = strings.TrimLeft(ret, "\t")

	ret = strings.TrimRight(ret, " ")
	ret = strings.TrimRight(ret, "\n")
	ret = strings.TrimRight(ret, "\t")
	return ret
}

func IsDnsFullName(service string) bool {
	return strings.Contains(service, ".svc.cluster.local")
}

func DeepCopy(value interface{}) interface{} {
	if valueMap, ok := value.(map[string]interface{}); ok {
		newMap := make(map[string]interface{})
		for k, v := range valueMap {
			newMap[k] = DeepCopy(v)
		}

		return newMap
	} else if valueSlice, ok := value.([]interface{}); ok {
		newSlice := make([]interface{}, len(valueSlice))
		for k, v := range valueSlice {
			newSlice[k] = DeepCopy(v)
		}

		return newSlice
	} else if valueMap, ok := value.(bson.M); ok {
		newMap := make(bson.M)
		for k, v := range valueMap {
			newMap[k] = DeepCopy(v)
		}
	}
	return value
}

func FilterVirtualService(virtualService *v1alpha3.VirtualService, ns string, name string) bool {
	if virtualService.Namespace != ns {
		return false
	}
	for i := 0; i < len(virtualService.Spec.Gateways); i++ {
		if virtualService.Spec.Gateways[i] == name {
			return true
		}
	}
	return false
}
