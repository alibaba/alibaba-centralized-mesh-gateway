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

// Tool to generate pilot/pkg/config/kube/crdclient/types.gen.go
// Example run command:
// REPO_ROOT=`pwd` go generate ./pilot/pkg/config/kube/crdclient/...
package main

import (
	"bytes"
	"flag"
	"fmt"
	"go/format"
	"log"
	"os"
	"path"
	"strings"
	"text/template"

	"istio.io/istio/pkg/config"
	"istio.io/istio/pkg/config/schema/collection"
	"istio.io/istio/pkg/config/schema/collections"
	"istio.io/istio/pkg/test/env"
)

// ConfigData is data struct to feed to types.go template.
type ConfigData struct {
	Namespaced      bool
	VariableName    string
	APIImport       string
	ClientImport    string
	ClientGroupPath string
	ClientTypePath  string
	Kind            string
	StatusAPIImport string
	StatusKind      string

	Gvk config.GroupVersionKind

	// Support gateway-api, which require a custom client and the Spec suffix
	Client string

	ClientType string

	Readonly bool
	NoSpec   bool
	TypeName string

	// MultiVersion indicates this type supports multiple different versions in the cluster.
	MultiVersion bool
	// PreferredClientImport, only present if MultiVersion, indicates the ClientImport of the preferred version.
	PreferredClientImport string
	// Versions, only present if MultiVersion, indicates all possible ClientImports.
	Versions []string
}

var (
	GatewayAPITypes = collections.PilotGatewayAPI.Remove(collections.Pilot.All()...)
	NonIstioTypes   = collections.All.Remove(collections.Pilot.All()...)
)

// MakeConfigData prepare data for code generation for the given schema.
func MakeConfigData(schema collection.Schema) []ConfigData {
	res := []ConfigData{}
	_, gatewayAPI := GatewayAPITypes.Find(schema.Name().String())
	primary := schema.Resource().GroupVersionKind()
	gvks := []config.GroupVersionKind{primary}
	if gatewayAPI {
		gvks = schema.Resource().GroupVersionAliasKinds()
	}
	for _, gvk := range gvks {
		out := ConfigData{
			Namespaced:      !schema.Resource().IsClusterScoped(),
			VariableName:    schema.VariableName(),
			APIImport:       apiImport[schema.Resource().ProtoPackage()],
			ClientImport:    clientGoImport[schema.Resource().ProtoPackage()],
			ClientGroupPath: clientGoAccessPath[gvk.GroupVersion()],
			ClientTypePath:  clientGoTypePath[schema.Resource().Plural()],
			Kind:            schema.Resource().Kind(),
			Gvk:             gvk,
			// MultiVersion relies on not only having two versions present, but those being typecast-able to one another.
			// If we wanted to support, for example, Istio dual version types, we would need more robust (and expensive) conversion logic.
			// However, there are no plans to remove Istio alpha types.
			MultiVersion:    gatewayAPI && len(schema.Resource().GroupVersionAliasKinds()) > 1,
			TypeName:        strings.ReplaceAll(strings.ReplaceAll(gvk.String(), "/", "_"), ".", "_"),
			Client:          "ic",
			StatusAPIImport: apiImport[schema.Resource().StatusPackage()],
			StatusKind:      schema.Resource().StatusKind(),
		}
		if out.MultiVersion {
			// If we are a MultiVersion we need some extra info to handle the type casts
			out.PreferredClientImport = strings.ReplaceAll(out.ClientImport, primary.Version, gvk.Version)
			for _, v := range schema.Resource().GroupVersionAliasKinds() {
				out.Versions = append(out.Versions, strings.ReplaceAll(out.ClientImport, primary.Version, v.Version))
			}
		}
		out.ClientType = out.Kind
		if _, f := GatewayAPITypes.Find(schema.Name().String()); f {
			out.Client = "sc"
			out.ClientType += "Spec"
		} else if _, f := NonIstioTypes.Find(schema.Name().String()); f {
			out.ClientType += "Spec"
			out.Readonly = true
		}
		if o, f := clientGoTypeOverrides[out.Kind]; f {
			out.ClientType = o
		}
		if _, f := noSpec[schema.Resource().Plural()]; f {
			out.NoSpec = true
		}
		log.Printf("Generating Istio type %s for %s/%s CRD\n", out.VariableName, out.APIImport, out.Kind)
		if out.ClientGroupPath == "" || out.ClientTypePath == "" || out.ClientImport == "" {
			log.Fatalf("invalid config %+v", out)
		}
		res = append(res, out)
	}
	return res
}

var (
	// Mapping from istio/api path import to api import path
	apiImport = map[string]string{
		"istio.io/api/networking/v1alpha3":                         "networkingv1alpha3",
		"istio.io/api/networking/v1beta1":                          "networkingv1beta1",
		"istio.io/api/security/v1beta1":                            "securityv1beta1",
		"istio.io/api/telemetry/v1alpha1":                          "telemetryv1alpha1",
		"sigs.k8s.io/gateway-api/apis/v1alpha2":                    "gatewayv1alpha2",
		"sigs.k8s.io/gateway-api/apis/v1beta1":                     "gatewayv1beta1",
		"istio.io/api/meta/v1alpha1":                               "metav1alpha1",
		"istio.io/api/extensions/v1alpha1":                         "extensionsv1alpha1",
		"k8s.io/api/admissionregistration/v1":                      "admissionregistrationv1",
		"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1": "apiextensionsv1",
		"k8s.io/api/apps/v1":                                       "appsv1",
		"k8s.io/api/core/v1":                                       "corev1",
		"k8s.io/api/extensions/v1beta1":                            "extensionsv1beta1",
	}
	// Mapping from istio/api path import to client go import path
	clientGoImport = map[string]string{
		"istio.io/api/networking/v1alpha3":                         "clientnetworkingv1alpha3",
		"istio.io/api/networking/v1beta1":                          "clientnetworkingv1beta1",
		"istio.io/api/security/v1beta1":                            "clientsecurityv1beta1",
		"istio.io/api/telemetry/v1alpha1":                          "clienttelemetryv1alpha1",
		"sigs.k8s.io/gateway-api/apis/v1alpha2":                    "gatewayv1alpha2",
		"sigs.k8s.io/gateway-api/apis/v1beta1":                     "gatewayv1beta1",
		"istio.io/api/extensions/v1alpha1":                         "clientextensionsv1alpha1",
		"k8s.io/api/admissionregistration/v1":                      "admissionregistrationv1",
		"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1": "apiextensionsv1",
		"k8s.io/api/apps/v1":                                       "appsv1",
		"k8s.io/api/core/v1":                                       "corev1",
		"k8s.io/api/extensions/v1beta1":                            "extensionsv1beta1",
	}
	// Translates an api import path to the top level path in client-go
	clientGoAccessPath = map[string]string{
		"networking.istio.io/v1alpha3":       "NetworkingV1alpha3",
		"networking.istio.io/v1beta1":        "NetworkingV1beta1",
		"security.istio.io/v1beta1":          "SecurityV1beta1",
		"telemetry.istio.io/v1alpha1":        "TelemetryV1alpha1",
		"extensions.istio.io/v1alpha1":       "ExtensionsV1alpha1",
		"gateway.networking.k8s.io/v1alpha2": "GatewayV1alpha2",
		"gateway.networking.k8s.io/v1beta1":  "GatewayV1beta1",
		"admissionregistration.k8s.io/v1":    "admissionregistrationv1",
		"apiextensions.k8s.io/v1":            "apiextensionsv1",
		"apps/v1":                            "appsv1",
		"v1":                                 "corev1",
		"extensions/v1beta1":                 "extensionsv1beta1",
	}
	// Translates a plural type name to the type path in client-go
	// TODO: can we automatically derive this? I don't think we can, its internal to the kubegen
	clientGoTypePath = map[string]string{
		"destinationrules":              "DestinationRules",
		"envoyfilters":                  "EnvoyFilters",
		"gateways":                      "Gateways",
		"serviceentries":                "ServiceEntries",
		"sidecars":                      "Sidecars",
		"proxyconfigs":                  "ProxyConfigs",
		"virtualservices":               "VirtualServices",
		"workloadentries":               "WorkloadEntries",
		"workloadgroups":                "WorkloadGroups",
		"authorizationpolicies":         "AuthorizationPolicies",
		"peerauthentications":           "PeerAuthentications",
		"requestauthentications":        "RequestAuthentications",
		"gatewayclasses":                "GatewayClasses",
		"httproutes":                    "HTTPRoutes",
		"tcproutes":                     "TCPRoutes",
		"tlsroutes":                     "TLSRoutes",
		"referencepolicies":             "ReferencePolicies",
		"referencegrants":               "ReferenceGrants",
		"telemetries":                   "Telemetries",
		"wasmplugins":                   "WasmPlugins",
		"mutatingwebhookconfigurations": "MutatingWebhookConfigurations",
		"customresourcedefinitions":     "CustomResourceDefinitions",
		"deployments":                   "Deployments",
		"configmaps":                    "ConfigMaps",
		"pods":                          "Pods",
		"services":                      "Services",
		"namespaces":                    "Namespaces",
		"endpoints":                     "Endpoints",
		"nodes":                         "Nodes",
		"secrets":                       "Secrets",
		"ingresses":                     "Ingresses",
	}
	clientGoTypeOverrides = map[string]string{
		"ReferencePolicy": "ReferenceGrantSpec",
	}

	noSpec = map[string]struct{}{
		"secrets":                       {},
		"endpoints":                     {},
		"configmaps":                    {},
		"mutatingwebhookconfigurations": {},
	}
)

func main() {
	templateFile := flag.String("template", path.Join(env.IstioSrc, "pilot/pkg/config/kube/crdclient/gen/types.go.tmpl"), "Template file")
	outputFile := flag.String("output", "", "Output file. Leave blank to go to stdout")
	flag.Parse()

	tmpl := template.Must(template.ParseFiles(*templateFile))

	// Prepare to generate types for mock schema and all Istio schemas
	typeList := []ConfigData{}
	for _, s := range collections.PilotGatewayAPI.Union(collections.Kube).All() {
		c := MakeConfigData(s)
		typeList = append(typeList, c...)
	}
	var buffer bytes.Buffer
	if err := tmpl.Execute(&buffer, typeList); err != nil {
		log.Fatal(fmt.Errorf("template: %v", err))
	}

	// Format source code.
	out, err := format.Source(buffer.Bytes())
	if err != nil {
		log.Fatal(err)
	}
	// Output
	if outputFile == nil || *outputFile == "" {
		fmt.Println(string(out))
	} else if err := os.WriteFile(*outputFile, out, 0o644); err != nil {
		panic(err)
	}
}
