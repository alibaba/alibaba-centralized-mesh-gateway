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
	"fmt"
	"github.com/golang/glog"
	"net/http"
	"strconv"
)

func printMap(w http.ResponseWriter, r *http.Request) {
	mapInfo := Get()
	for k, v := range mapInfo {
		lineSvc := k + "->" + strconv.Itoa(int(v)) + "\n"
		_, err := fmt.Fprintf(w, lineSvc)
		if err != nil {
			return
		}
	}
}

func run() error {
	http.HandleFunc("/configMap", printMap)
	err := http.ListenAndServe(":2323", nil)
	if err != nil {
		glog.Fatal("ListenAndServe: ", err)
	}
	return err
}

func StartDebugServer() {
	glog.Info("Start debug server")
	go func() {
		err := run()
		if err != nil {
			panic(err)
		}
	}()
}
