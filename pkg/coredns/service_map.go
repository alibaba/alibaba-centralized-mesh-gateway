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

package coredns

import (
	"cannalcontroller/pkg/tools"
	"fmt"
	"github.com/golang/glog"
	"k8s.io/apimachinery/pkg/util/runtime"
)

var (
	serviceMap = make(map[string]uint32)
)

func Put(service string) uint32 {
	if !tools.IsDnsFullName(service) {
		glog.Errorf("Put %s is not full dns name", service)
		runtime.HandleError(fmt.Errorf("put %s is not correct fmt", service))
	}
	serviceMap[service] = serviceMap[service] + 1
	return serviceMap[service]
}

func Del(service string) uint32 {
	if !tools.IsDnsFullName(service) {
		glog.Errorf("Del %s is not full dns name", service)
		runtime.HandleError(fmt.Errorf("del %s is not correct fmt", service))
	}
	serviceMap[service] = serviceMap[service] - 1
	if serviceMap[service] == 0 {
		delete(serviceMap, service)
		return 0
	}
	return serviceMap[service]
}

func Get() map[string]uint32 {
	return tools.DeepCopy(serviceMap).(map[string]uint32)
}
