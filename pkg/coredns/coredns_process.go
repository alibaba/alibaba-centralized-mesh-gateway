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
	"context"
	"errors"
	"github.com/golang/glog"
	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"strings"
)

var (
	content string
	deepNum int
)

func insertBlock(block []string) {
	for _, line := range block {
		content += "    " + line + "\n"
	}
}

func processLineForAdd(line string, block []string) {
	content += line + "\n"
	var haveFlag = false
	if strings.Contains(line, "{") {
		deepNum++
		haveFlag = true
	}
	if strings.Contains(line, "}") {
		deepNum--
	}
	if deepNum == 1 && haveFlag {
		insertBlock(block)
	}
	if deepNum < 0 {
		glog.Fatalf("Error deepNum is %d : %s\n", deepNum, line)
		return
	}
}

func processLineForDelete(line string, deleteBlock []string) {
	if !tools.HaveString(tools.CleanString(line), deleteBlock) {
		content += line + "\n"
		return
	}
}

func BuildNewConfigMapForAdd(oldConfigMap v1.ConfigMap, insertBlock []string) (newConfigMap v1.ConfigMap, err error) {
	if len(insertBlock) == 0 {
		glog.Warning("insertBlock is empty")
		return
	}
	oldConfigMap.DeepCopyInto(&newConfigMap)
	for k, v := range oldConfigMap.Data {
		if k == "Corefile" {
			lines := strings.Split(v, "\n")
			for i := 0; i < len(lines); i++ {
				processLineForAdd(lines[i], insertBlock)
			}
		}
	}

	if content == "" {
		glog.Fatalf("Error content is empty after build: %s", content)
		return newConfigMap, errors.New("content is empty")
	}
	newConfigMap.Data["Corefile"] = content
	content = ""
	return newConfigMap, nil
}

func BuildNewConfigMapForDelete(oldConfigMap v1.ConfigMap, deleteBlock []string) (newConfigMap v1.ConfigMap, err error) {
	if len(deleteBlock) == 0 {
		glog.Warning("deleteBlock is empty")
		return
	}
	oldConfigMap.DeepCopyInto(&newConfigMap)
	if len(deleteBlock) != 0 {
		for k, v := range oldConfigMap.Data {
			if k == "Corefile" {
				lines := strings.Split(v, "\n")
				for i := 0; i < len(lines); i++ {
					processLineForDelete(lines[i], deleteBlock)
				}
			}
		}
	}
	if content == "" {
		glog.Fatalf("Error content is empty after build: %s", content)
		return newConfigMap, errors.New("content is empty")
	}
	newConfigMap.Data["Corefile"] = content
	content = ""
	return newConfigMap, nil
}

func rollBackConfigMapData(clientSet kubernetes.Interface, oldConfigMap v1.ConfigMap) {
	return
}

func UpdateConfigMap(clientSet kubernetes.Interface, newConfigMap v1.ConfigMap, oldConfigMap v1.ConfigMap) {
	_, err := clientSet.CoreV1().ConfigMaps("kube-system").Update(context.TODO(), &newConfigMap, metav1.UpdateOptions{})
	if err != nil {
		rollBackConfigMapData(clientSet, oldConfigMap)
	}
}
