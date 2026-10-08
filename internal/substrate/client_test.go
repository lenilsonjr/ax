// Copyright 2026 Google LLC
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

package substrate

import (
	"testing"

	"github.com/agent-substrate/substrate/pkg/proto/ateapipb"
	"github.com/google/ax/pkg/apis/v1alpha1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

func TestBuildEgressRules(t *testing.T) {
	inject := []*v1alpha1.HeaderInjection{{
		Header:        "authorization",
		Prefix:        "Bearer ",
		CredentialUri: "ate-secret://k8s.io/default/ns/tok/token",
	}}
	injectRule := &ateapipb.EgressRule{Hostnames: &ateapipb.HostnameRule{
		Patterns: []string{"api.anthropic.com"},
		Effects: &ateapipb.EgressRuleEffects{InjectStaticHeaders: []*ateapipb.CredentialHeaderInjection{{
			Header:        "authorization",
			Prefix:        "Bearer ",
			CredentialUri: "ate-secret://k8s.io/default/ns/tok/token",
		}}},
	}}

	tests := []struct {
		name    string
		hosts   []*v1alpha1.HostRule
		want    []*ateapipb.EgressRule
		wantErr bool
	}{
		{
			name:  "hostnames and cidrs",
			hosts: []*v1alpha1.HostRule{{Host: "github.com"}, {Host: "10.0.0.0/8"}},
			want: []*ateapipb.EgressRule{
				{Hostnames: &ateapipb.HostnameRule{Patterns: []string{"github.com"}}},
				{Cidrs: &ateapipb.CIDRRule{Cidrs: []string{"10.0.0.0/8"}}},
			},
		},
		{
			name:  "injecting host gets its own rule first",
			hosts: []*v1alpha1.HostRule{{Host: "github.com"}, {Host: "api.anthropic.com", Inject: inject}},
			want: []*ateapipb.EgressRule{
				injectRule,
				{Hostnames: &ateapipb.HostnameRule{Patterns: []string{"github.com"}}},
			},
		},
		{
			name:  "injecting host precedes allow-all",
			hosts: []*v1alpha1.HostRule{{Host: "*"}, {Host: "api.anthropic.com", Inject: inject}},
			want:  []*ateapipb.EgressRule{injectRule, {All: &emptypb.Empty{}}},
		},
		{
			name:    "inject on a cidr is rejected",
			hosts:   []*v1alpha1.HostRule{{Host: "10.0.0.0/8", Inject: inject}},
			wantErr: true,
		},
		{
			name:    "inject on wildcard-all is rejected",
			hosts:   []*v1alpha1.HostRule{{Host: "*", Inject: inject}},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := buildEgressRules(&v1alpha1.EgressAllowlist{Hosts: tt.hosts})
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("got %d rules, want %d: %v", len(got), len(tt.want), got)
			}
			for i := range got {
				if !proto.Equal(got[i], tt.want[i]) {
					t.Errorf("rule %d = %v, want %v", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestWithEgressTrustBundle(t *testing.T) {
	tmpl := BuildActorTemplate("default", "t", "img@sha256:0", nil, nil, "gs://b/")
	WithEgressTrustBundle(tmpl, "")
	if len(tmpl.Volumes) != 1 {
		t.Fatalf("empty bundle changed volumes: %d", len(tmpl.Volumes))
	}

	WithEgressTrustBundle(tmpl, "egress-mitm.ate.dev")
	if len(tmpl.Volumes) != 2 {
		t.Fatalf("volumes = %d, want 2", len(tmpl.Volumes))
	}
	tb := tmpl.Volumes[1].GetSystemInfo().GetDataSources()[0].GetTrustBundle()
	if tb.GetName() != "egress-mitm.ate.dev" || tb.GetPath() != "trust-bundle.pem" {
		t.Errorf("trust bundle = %v", tb)
	}
	ctr := tmpl.Containers[0]
	mounted := false
	for _, m := range ctr.VolumeMounts {
		if m.Name == "egress-trust" && m.MountPath == EgressTrustBundleDir {
			mounted = true
		}
	}
	if !mounted {
		t.Errorf("bundle not mounted at %s: %v", EgressTrustBundleDir, ctr.VolumeMounts)
	}
	env := map[string]string{}
	for _, e := range ctr.Env {
		env[e.Name] = e.Value
	}
	for _, k := range []string{"SSL_CERT_FILE", "NODE_EXTRA_CA_CERTS", "REQUESTS_CA_BUNDLE", "GIT_SSL_CAINFO"} {
		if env[k] != EgressTrustBundleDir+"/trust-bundle.pem" {
			t.Errorf("%s = %q", k, env[k])
		}
	}
	// SSL_CERT_DIR must stay unset: pointed at a directory holding only this
	// bundle it strips the public roots, so every unrelated host stops
	// validating.
	if v, ok := env["SSL_CERT_DIR"]; ok {
		t.Errorf("SSL_CERT_DIR must not be projected, got %q", v)
	}
}
