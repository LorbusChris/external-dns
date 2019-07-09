/*
Copyright 2017 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package source

import (
	"testing"
	"fmt"
	istionetworking "istio.io/api/networking/v1alpha3"
	istiomodel "istio.io/istio/pilot/pkg/model"

	"github.com/kubernetes-incubator/external-dns/endpoint"

	"strconv"
	"sync"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// This is a compile-time validation that gatewaySource is a Source.
var _ Source = &gatewaySource{}

var gatewayType = istiomodel.Gateway.Type

type GatewaySuite struct {
	suite.Suite
	source     Source
	lbServices []*v1.Service
	config     istiomodel.Config
}

func (suite *GatewaySuite) SetupTest() {
	fakeKubernetesClient := fake.NewSimpleClientset()
	fakeIstioClient := NewFakeConfigStore()
	var err error

	suite.lbServices = []*v1.Service{
		(fakeIngressGatewayService{
			ips:       []string{"8.8.8.8"},
			hostnames: []string{"v1"},
			namespace: "istio-system",
			name:      "istio-gateway1",
			selector:  map[string]string{
				"istio": "ingressgateway",
			},
		}).Service(),
		(fakeIngressGatewayService{
			ips:       []string{"1.1.1.1"},
			hostnames: []string{"v42"},
			namespace: "istio-other",
			name:      "istio-gateway2",
			selector:  map[string]string{
				"istio-other": "istio-gateway2",
			},
		}).Service(),
		(fakeIngressGatewayService{
			hostnames: []string{"lb.com"},
			namespace: "istio-yetanother",
			name:      "istio-gateway3",
			selector:  map[string]string{
				"foo": "bar",
			},
		}).Service(),
		(fakeIngressGatewayService{
			ips: []string{"1.2.3.4"},
			namespace: "foobar",
			name:      "istio-gateway4",
			selector:  map[string]string{
				"bar": "baz",
			},
		}).Service(),
	}

	for _, loadBalancer := range suite.lbServices {
		_, err = fakeKubernetesClient.CoreV1().Services(loadBalancer.Namespace).Create(loadBalancer)
		suite.NoError(err, "should succeed")
	}

	suite.source, err = NewIstioGatewaySource(
		fakeKubernetesClient,
		fakeIstioClient,
		"default",
		"",
		"{{.Name}}",
		false,
		false,
	)
	suite.NoError(err, "should initialize gateway source")

	suite.config = (fakeGatewayConfig{
		name:      "foo-gateway-with-targets",
		namespace: "default",
		dnsnames:  [][]string{{"foo"}},
		selector:  map[string]string{
			"istio": "ingressgateway",
			"istio-other": "istio-gateway2",
			"foo": "bar",
			"bar": "baz",
		},
	}).Config()
	_, err = fakeIstioClient.Create(suite.config)
	suite.NoError(err, "should succeed")
}

func (suite *GatewaySuite) TestResourceLabelIsSet() {
	endpoints, _ := suite.source.Endpoints()
	for _, ep := range endpoints {
		suite.Equal("gateway/default/foo-gateway-with-targets", ep.Labels[endpoint.ResourceLabelKey], "should set correct resource label")
	}
}

func TestGateway(t *testing.T) {
	suite.Run(t, new(GatewaySuite))
	t.Run("endpointsFromGatewayConfig", testEndpointsFromGatewayConfig)
	// t.Run("Endpoints", testGatewayEndpoints)
}

func TestNewIstioGatewaySource(t *testing.T) {
	for _, ti := range []struct {
		title                    string
		annotationFilter         string
		fqdnTemplate             string
		combineFQDNAndAnnotation bool
		expectError              bool
	}{
		{
			title:        "invalid template",
			expectError:  true,
			fqdnTemplate: "{{.Name",
		},
		{
			title:       "valid empty template",
			expectError: false,
		},
		{
			title:        "valid template",
			expectError:  false,
			fqdnTemplate: "{{.Name}}-{{.Namespace}}.ext-dns.test.com",
		},
		{
			title:        "valid template",
			expectError:  false,
			fqdnTemplate: "{{.Name}}-{{.Namespace}}.ext-dns.test.com, {{.Name}}-{{.Namespace}}.ext-dna.test.com",
		},
		{
			title:                    "valid template",
			expectError:              false,
			fqdnTemplate:             "{{.Name}}-{{.Namespace}}.ext-dns.test.com, {{.Name}}-{{.Namespace}}.ext-dna.test.com",
			combineFQDNAndAnnotation: true,
		},
		{
			title:            "non-empty annotation filter label",
			expectError:      false,
			annotationFilter: "kubernetes.io/gateway.class=nginx",
		},
	} {
		t.Run(ti.title, func(t *testing.T) {
			_, err := NewIstioGatewaySource(
				fake.NewSimpleClientset(),
				NewFakeConfigStore(),
				"",
				ti.annotationFilter,
				ti.fqdnTemplate,
				ti.combineFQDNAndAnnotation,
				false,
			)
			if ti.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func testEndpointsFromGatewayConfig(t *testing.T) {
	for _, ti := range []struct {
		title      string
		config     fakeGatewayConfig
		expected   []*endpoint.Endpoint
	}{
		{
			title: "one rule.host one lb.hostname",
			config: fakeGatewayConfig{
				dnsnames: [][]string{
					{"foo.bar"}, // Kubernetes requires removal of trailing dot
				},
				selector: map[string]string{
					"foo": "bar",
				},
			},
			expected: []*endpoint.Endpoint{
				{
					DNSName: "foo.bar",
					Targets: endpoint.Targets{"lb.com"},
				},
			},
		},
		{
			title: "one rule.host one lb.IP",
			config: fakeGatewayConfig{
				dnsnames: [][]string{
					{"foo.bar"},
				},
				selector: map[string]string{
					"bar": "baz",
				},
			},
			expected: []*endpoint.Endpoint{
				{
					DNSName: "foo.bar",
					Targets: endpoint.Targets{"1.2.3.4"},
				},
			},
		},
		{
			title: "one rule.host two lb.IP and two lb.Hostname",
			config: fakeGatewayConfig{
				dnsnames: [][]string{
					{"foo.bar"},
				},
				selector: map[string]string{
					"istio": "ingressgateway",
					"istio-other": "istio-gateway2",
				},
			},
			expected: []*endpoint.Endpoint{
				{
					DNSName: "foo.bar",
					Targets: endpoint.Targets{"v1", "1.1.1.1", "v42", "8.8.8.8"},
				},
			},
		},
		{
			title: "no rule.host",
			config: fakeGatewayConfig{
				dnsnames: [][]string{},
				selector: map[string]string{
					"baz": "istio-gateway1",
				},
			},
			expected: []*endpoint.Endpoint{},
		},
		{
			title: "one empty rule.host",
			config: fakeGatewayConfig{
				dnsnames: [][]string{
					{""},
				},
				selector: map[string]string{
					"baz": "istio-gateway1",
				},
			},
			expected: []*endpoint.Endpoint{},
		},
		{
			title:      "nonexistent loadbalancer targets",
			config: fakeGatewayConfig{
				dnsnames: [][]string{
					{""},
				},
				selector: map[string]string{},
			},
			expected: []*endpoint.Endpoint{},
		},
	} {
		t.Run(ti.title, func(t *testing.T) {
			if source, err := newTestGatewaySource(); err != nil {
				fmt.Printf("source: %v", source)
				require.NoError(t, err)
			} else if endpoints, err := source.endpointsFromGatewayConfig(ti.config.Config()); err != nil {
				fmt.Printf("elif: %v", endpoints)
				require.NoError(t, err)
			} else {
				fmt.Printf("else: %v", endpoints)
				validateEndpoints(t, endpoints, ti.expected)
			}
		})
	}
}

// gateway specific helper functions
func newTestGatewaySource() (*gatewaySource, error) {
	fakeKubernetesClient := fake.NewSimpleClientset()
	fakeIstioClient := NewFakeConfigStore()

	src, err := NewIstioGatewaySource(
		fakeKubernetesClient,
		fakeIstioClient,
		"default",
		"",
		"{{.Name}}",
		false,
		false,
	)
	if err != nil {
		return nil, err
	}

	gwsrc, ok := src.(*gatewaySource)
	if !ok {
		return nil, errors.New("underlying source type was not gateway")
	}

	return gwsrc, nil
}

type fakeIngressGatewayService struct {
	ips       []string
	hostnames []string
	namespace string
	name      string
	selector map[string]string
}

func (ig fakeIngressGatewayService) Service() *v1.Service {
	svc := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ig.namespace,
			Name:      ig.name,
		},
		Status: v1.ServiceStatus{
			LoadBalancer: v1.LoadBalancerStatus{
				Ingress: []v1.LoadBalancerIngress{},
			},
		},
		Spec: v1.ServiceSpec{
			Selector: map[string]string{},
		},
	}

	for _, ip := range ig.ips {
		svc.Status.LoadBalancer.Ingress = append(svc.Status.LoadBalancer.Ingress, v1.LoadBalancerIngress{
			IP: ip,
		})
	}
	for _, hostname := range ig.hostnames {
		svc.Status.LoadBalancer.Ingress = append(svc.Status.LoadBalancer.Ingress, v1.LoadBalancerIngress{
			Hostname: hostname,
		})
	}
	for key, selection := range ig.selector {
		svc.Spec.Selector[key] = selection
	}

	return svc
}

type fakeGatewayConfig struct {
	namespace   string
	name        string
	annotations map[string]string
	dnsnames    [][]string
	selector	map[string]string
}

func (c fakeGatewayConfig) Config() istiomodel.Config {
	gw := &istionetworking.Gateway{
		Selector: map[string]string{},
		Servers: []*istionetworking.Server{},
	}

	for _, dnsnames := range c.dnsnames {
		gw.Servers = append(gw.Servers, &istionetworking.Server{
			Hosts: dnsnames,
		})
	}

	for key, value := range c.selector {
		gw.Selector[key] = value
	}
	
	
	config := istiomodel.Config{
		ConfigMeta: istiomodel.ConfigMeta{
			Namespace:   c.namespace,
			Name:        c.name,
			Type:        gatewayType,
			Annotations: c.annotations,
		},
		Spec: gw,
	}

	return config
}

type fakeConfigStore struct {
	descriptor istiomodel.ConfigDescriptor
	configs    []*istiomodel.Config
	sync.RWMutex
}

func NewFakeConfigStore() istiomodel.ConfigStore {
	return &fakeConfigStore{
		descriptor: istiomodel.ConfigDescriptor{
			istiomodel.Gateway,
		},
		configs: make([]*istiomodel.Config, 0),
	}
}

func (f *fakeConfigStore) ConfigDescriptor() istiomodel.ConfigDescriptor {
	return f.descriptor
}

func (f *fakeConfigStore) Get(typ, name, namespace string) (config *istiomodel.Config, exists bool) {
	exists = false
	
	f.RLock()
	defer f.RUnlock()

	if cfg, _ := f.get(typ, name, namespace); cfg != nil {
		config = cfg
		exists = true
	}

	return
}

func (f *fakeConfigStore) get(typ, name, namespace string) (*istiomodel.Config, int) {
	for idx, cfg := range f.configs {
		if cfg.Type == typ && cfg.Name == name && cfg.Namespace == namespace {
			return cfg, idx
		}
	}

	return nil, -1
}

func (f *fakeConfigStore) List(typ, namespace string) (configs []istiomodel.Config, err error) {
	f.RLock()
	defer f.RUnlock()

	if namespace == "" {
		for _, cfg := range f.configs {
			configs = append(configs, *cfg)
		}
	} else {
		for _, cfg := range f.configs {
			if cfg.Type == typ && cfg.Namespace == namespace {
				configs = append(configs, *cfg)
			}
		}
	}

	return
}

func (f *fakeConfigStore) Create(config istiomodel.Config) (revision string, err error) {
	f.Lock()
	defer f.Unlock()

	if cfg, _ := f.get(config.Type, config.Name, config.Namespace); cfg != nil {
		err = errors.New("config already exists")
	} else {
		revision = "0"
		cfg := &config
		cfg.ResourceVersion = revision
		f.configs = append(f.configs, cfg)
	}

	return
}

func (f *fakeConfigStore) Update(config istiomodel.Config) (newRevision string, err error) {
	f.Lock()
	defer f.Unlock()

	if oldCfg, idx := f.get(config.Type, config.Name, config.Namespace); oldCfg == nil {
		err = errors.New("config does not exist")
	} else if oldRevision, e := strconv.Atoi(oldCfg.ResourceVersion); e != nil {
		err = e
	} else {
		newRevision = strconv.Itoa(oldRevision + 1)
		cfg := &config
		cfg.ResourceVersion = newRevision
		f.configs[idx] = cfg
	}

	return
}

func (f *fakeConfigStore) Delete(typ, name, namespace string) error {
	f.Lock()
	defer f.Unlock()

	_, idx := f.get(typ, name, namespace)
	if idx < 0 {
		return errors.New("config does not exist")
	}

	copy(f.configs[idx:], f.configs[idx+1:])
	f.configs[len(f.configs)-1] = nil
	f.configs = f.configs[:len(f.configs)-1]

	return nil
}
