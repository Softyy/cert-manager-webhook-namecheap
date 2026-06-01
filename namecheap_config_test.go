package main

import (
	"strings"
	"testing"

	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
)

func TestLoadNamecheapConfigRequiresConfig(t *testing.T) {
	_, err := loadNamecheapConfig(nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if err.Error() != "solver config is required" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadNamecheapConfigSchemaValidation(t *testing.T) {
	invalidConfigs := []string{
		`{"apiKeySecretRef":{"name":"api","key":"key"}}`,
		`{"apiUser":"user","clientIP":"1.2.3.4","apiKeySecretRef":{"name":"api","key":"key"}}`,
		`{"apiUserSecretRef":{"name":"user"},"username":"name","clientIP":"1.2.3.4","apiKeySecretRef":{"name":"api","key":"key"}}`,
		`{"apiUser":"user","usernameSecretRef":{"name":"name"},"clientIP":"1.2.3.4","apiKeySecretRef":{"name":"api","key":"key"}}`,
	}
	for _, raw := range invalidConfigs {
		cfgJSON := &extapi.JSON{Raw: []byte(raw)}
		_, err := loadNamecheapConfig(cfgJSON)
		if err == nil {
			t.Fatalf("expected error for config %s", raw)
		}
		if !strings.Contains(err.Error(), "invalid solver config") {
			t.Fatalf("unexpected error for config %s: %v", raw, err)
		}
	}
}

func TestLoadNamecheapConfigDefaultsTTL(t *testing.T) {
	cfgJSON := &extapi.JSON{Raw: []byte(`{
		"apiUser": "user",
		"username": "name",
		"clientIP": "1.2.3.4",
		"apiKeySecretRef": {"name": "api", "key": "key"}
	}`)}
	cfg, err := loadNamecheapConfig(cfgJSON)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.TTL != defaultRecordTTL {
		t.Fatalf("expected ttl %d, got %d", defaultRecordTTL, cfg.TTL)
	}
}

func TestLoadNamecheapConfigInvalidTTL(t *testing.T) {
	cfgJSON := &extapi.JSON{Raw: []byte(`{
		"apiUser": "user",
		"username": "name",
		"clientIP": "1.2.3.4",
		"ttl": 1,
		"apiKeySecretRef": {"name": "api", "key": "key"}
	}`)}
	_, err := loadNamecheapConfig(cfgJSON)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "ttl must be between") {
		t.Fatalf("unexpected error: %v", err)
	}
}
