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

//go:build integ
// +build integ

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

package nullvm

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/util/rand"

	"istio.io/istio/pkg/test"
	"istio.io/istio/pkg/test/framework"
	"istio.io/istio/pkg/test/framework/components/echo"
	"istio.io/istio/pkg/test/util/retry"
	common "istio.io/istio/tests/integration/telemetry/stats/prometheus"
)

func TestAccessLogs(t *testing.T) {
	framework.NewTest(t).
		Features("observability.telemetry.logging").
		Run(func(t framework.TestContext) {
			t.NewSubTest("enabled").Run(func(t framework.TestContext) {
				applyTelemetryResource(t, true)
				runAccessLogsTests(t, true)
				deleteTelemetryResource(t, true)
			})
			t.NewSubTest("disabled").Run(func(t framework.TestContext) {
				applyTelemetryResource(t, false)
				runAccessLogsTests(t, false)
				deleteTelemetryResource(t, false)
			})
		})
}

func TestAccessLogsDefaultProvider(t *testing.T) {
	framework.NewTest(t).
		Features("observability.telemetry.logging.defaultprovider").
		Run(func(t framework.TestContext) {
			t.NewSubTest("disabled").Run(func(t framework.TestContext) {
				cfg := `
accessLogFile: ""
`
				ist := *(common.GetIstioInstance())
				ist.PatchMeshConfigOrFail(t, t, cfg)
				runAccessLogsTests(t, false)
			})
			t.NewSubTest("enabled").Run(func(t framework.TestContext) {
				cfg := `
accessLogFile: ""
defaultProviders:
  accessLogging:
  - envoy
`
				ist := *(common.GetIstioInstance())
				ist.PatchMeshConfigOrFail(t, t, cfg)
				runAccessLogsTests(t, true)
			})
		})
}

func applyTelemetryResource(t framework.TestContext, enableLogs bool) {
	config := fmt.Sprintf(`apiVersion: telemetry.istio.io/v1alpha1
kind: Telemetry
metadata:
  name: logs
spec:
  accessLogging:
  - providers:
    - name: envoy
    disabled: %v
`, !enableLogs)
	t.ConfigIstio().YAML(common.GetAppNamespace().Name(), config).ApplyOrFail(t)
}

func deleteTelemetryResource(t framework.TestContext, enableLogs bool) {
	config := fmt.Sprintf(`apiVersion: telemetry.istio.io/v1alpha1
kind: Telemetry
metadata:
  name: logs
spec:
  accessLogging:
  - disabled: %v
`, enableLogs)
	t.ConfigIstio().YAML(common.GetAppNamespace().Name(), config).DeleteOrFail(t)
}

func runAccessLogsTests(t framework.TestContext, expectLogs bool) {
	testID := rand.String(16)
	to := common.GetTarget()
	if expectLogs {
		// For positive test, we use the same ID and repeatedly send requests and check the count
		// Retry a bit to get the logs. There is some delay before they are output(MeshConfig will not take effect immediately),
		// so they may not be immediately ready. If not ready, we retry sending a call again.
		err := retry.UntilSuccess(func() error {
			common.GetClientInstances()[0].CallOrFail(t, echo.CallOptions{
				To: to,
				Port: echo.Port{
					Name: "http",
				},
				HTTP: echo.HTTP{
					Path: "/" + testID,
				},
			})
			count := logCount(t, to, testID)
			if count > 0 != expectLogs {
				return fmt.Errorf("expected logs '%v', got %v", expectLogs, count)
			}
			return nil
		}, retry.Timeout(time.Second*10))
		if err != nil {
			t.Fatalf("expected logs but got nil, err: %v", err)
		}
	} else {
		// For negative case, we retry with a new ID each time. This ensures that a previous failure
		// (due to hitting old code path with logs still enabled) doesn't stop us from succeeding later
		// once we stop logging.
		retry.UntilSuccessOrFail(t, func() error {
			testID := rand.String(16)
			common.GetClientInstances()[0].CallOrFail(t, echo.CallOptions{
				To: to,
				Port: echo.Port{
					Name: "http",
				},
				HTTP: echo.HTTP{
					Path: "/" + testID,
				},
			})
			// This is a negative test; there isn't much we can do other than wait a few seconds and ensure we didn't emit logs
			// Logs should flush every 1s, so 2s should be plenty of time for logs to be emitted
			time.Sleep(time.Second * 2)
			count := logCount(t, common.GetTarget(), testID)
			if count > 0 != expectLogs {
				return fmt.Errorf("expected logs '%v', got %v", expectLogs, count)
			}
			return nil
		})
	}
}

func logCount(t test.Failer, to echo.Target, testID string) float64 {
	counts := map[string]float64{}
	for _, w := range to.WorkloadsOrFail(t) {
		var logs string
		l, err := w.Sidecar().Logs()
		if err != nil {
			t.Fatalf("failed getting logs: %v", err)
		}
		logs += l
		if c := float64(strings.Count(logs, testID)); c > 0 {
			counts[w.Cluster().Name()] = c
		}
	}
	var total float64
	for _, c := range counts {
		total += c
	}
	return total
}
