package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/google/jsonschema-go/jsonschema"
	"github.com/namecheap/go-namecheap-sdk/v2/namecheap"
	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const (
	namecheapSolverName = "namecheap"
	defaultRecordTTL    = 60
)

type namecheapSolver struct {
	client kubernetes.Interface
}

type namecheapDNSProviderConfig struct {
	APIUser        string                   `json:"apiUser"`
	APIUserSecret  cmmeta.SecretKeySelector `json:"apiUserSecretRef"`
	APIKeySecret   cmmeta.SecretKeySelector `json:"apiKeySecretRef"`
	Username       string                   `json:"username"`
	UsernameSecret cmmeta.SecretKeySelector `json:"usernameSecretRef"`
	ClientIP       string                   `json:"clientIP"`
	UseSandbox     bool                     `json:"useSandbox"`
	TTL            int                      `json:"ttl"`
}

//go:embed schema/namecheap-config.schema.json
var namecheapConfigSchemaJSON []byte

var namecheapConfigSchema = mustResolveNamecheapConfigSchema()

func mustResolveNamecheapConfigSchema() *jsonschema.Resolved {
	var schema jsonschema.Schema
	if err := json.Unmarshal(namecheapConfigSchemaJSON, &schema); err != nil {
		panic(fmt.Sprintf("invalid namecheap config schema: %v", err))
	}
	resolved, err := schema.Resolve(nil)
	if err != nil {
		panic(fmt.Sprintf("failed to resolve namecheap config schema: %v", err))
	}
	return resolved
}

func (c *namecheapSolver) Name() string {
	return namecheapSolverName
}

func (c *namecheapSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := loadNamecheapConfig(ch.Config)
	if err != nil {
		return err
	}

	client, err := c.buildClient(ch, cfg)
	if err != nil {
		return err
	}

	return upsertTXTRecord(client, ch.ResolvedZone, ch.ResolvedFQDN, ch.Key, cfg.TTL)
}

func (c *namecheapSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := loadNamecheapConfig(ch.Config)
	if err != nil {
		return err
	}

	client, err := c.buildClient(ch, cfg)
	if err != nil {
		return err
	}

	return deleteTXTRecord(client, ch.ResolvedZone, ch.ResolvedFQDN, ch.Key)
}

func (c *namecheapSolver) Initialize(kubeClientConfig *rest.Config, _ <-chan struct{}) error {
	cl, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return err
	}

	c.client = cl
	return nil
}

func loadNamecheapConfig(cfgJSON *extapi.JSON) (namecheapDNSProviderConfig, error) {
	cfg := namecheapDNSProviderConfig{}
	if cfgJSON == nil {
		return cfg, errors.New("solver config is required")
	}
	var raw any
	if err := json.Unmarshal(cfgJSON.Raw, &raw); err != nil {
		return cfg, fmt.Errorf("error decoding solver config: %w", err)
	}
	if err := namecheapConfigSchema.Validate(raw); err != nil {
		return cfg, fmt.Errorf("invalid solver config: %w", err)
	}
	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("error decoding solver config: %w", err)
	}
	if cfg.TTL == 0 {
		cfg.TTL = defaultRecordTTL
	}
	if cfg.TTL < namecheap.MinTTL || cfg.TTL > namecheap.MaxTTL {
		return cfg, fmt.Errorf("ttl must be between %d and %d", namecheap.MinTTL, namecheap.MaxTTL)
	}
	return cfg, nil
}

func (c *namecheapSolver) buildClient(ch *v1alpha1.ChallengeRequest, cfg namecheapDNSProviderConfig) (*namecheap.Client, error) {
	if c.client == nil {
		return nil, errors.New("kubernetes client not initialized")
	}

	ns := ch.ResourceNamespace
	secretCache := map[string]map[string][]byte{}
	getSecretValue := func(ref cmmeta.SecretKeySelector, description string) (string, error) {
		secretData, ok := secretCache[ref.Name]
		if !ok {
			secret, err := c.client.CoreV1().Secrets(ns).Get(context.Background(), ref.Name, metav1.GetOptions{})
			if err != nil {
				return "", fmt.Errorf("failed to read %s secret %s/%s: %w", description, ns, ref.Name, err)
			}
			secretData = secret.Data
			secretCache[ref.Name] = secretData
		}
		valueBytes, ok := secretData[ref.Key]
		if !ok {
			return "", fmt.Errorf("%s secret missing key %q", description, ref.Key)
		}
		value := strings.TrimSpace(string(valueBytes))
		if value == "" {
			return "", fmt.Errorf("%s is empty", description)
		}
		return value, nil
	}

	apiKey, err := getSecretValue(cfg.APIKeySecret, "api key")
	if err != nil {
		return nil, err
	}

	apiUser := strings.TrimSpace(cfg.APIUser)
	if cfg.APIUserSecret.Name != "" {
		apiUser, err = getSecretValue(cfg.APIUserSecret, "api user")
		if err != nil {
			return nil, err
		}
	}

	username := strings.TrimSpace(cfg.Username)
	if cfg.UsernameSecret.Name != "" {
		username, err = getSecretValue(cfg.UsernameSecret, "username")
		if err != nil {
			return nil, err
		}
	}

	client := namecheap.NewClient(&namecheap.ClientOptions{
		UserName:   username,
		ApiUser:    apiUser,
		ApiKey:     apiKey,
		ClientIp:   cfg.ClientIP,
		UseSandbox: cfg.UseSandbox,
	})

	return client, nil
}

func upsertTXTRecord(client *namecheap.Client, zone string, fqdn string, value string, ttl int) error {
	records, emailType, err := getHostRecords(client, zone)
	if err != nil {
		return err
	}

	hostName := namecheapHostName(zone, fqdn)
	for i, record := range records {
		if record.RecordType == nil || record.HostName == nil {
			continue
		}
		if *record.RecordType != namecheap.RecordTypeTXT {
			continue
		}
		if *record.HostName != hostName {
			continue
		}
		if record.Address != nil && *record.Address == value {
			if record.TTL == nil || *record.TTL != ttl {
				records[i].TTL = namecheap.Int(ttl)
			}
			return setHostRecords(client, zone, records, emailType)
		}
	}

	records = append(records, namecheap.DomainsDNSHostRecord{
		HostName:   namecheap.String(hostName),
		RecordType: namecheap.String(namecheap.RecordTypeTXT),
		Address:    namecheap.String(value),
		TTL:        namecheap.Int(ttl),
	})

	return setHostRecords(client, zone, records, emailType)
}

func deleteTXTRecord(client *namecheap.Client, zone string, fqdn string, value string) error {
	records, emailType, err := getHostRecords(client, zone)
	if err != nil {
		return err
	}

	hostName := namecheapHostName(zone, fqdn)
	filtered := records[:0]
	for _, record := range records {
		if record.RecordType == nil || record.HostName == nil {
			filtered = append(filtered, record)
			continue
		}
		if *record.RecordType != namecheap.RecordTypeTXT || *record.HostName != hostName {
			filtered = append(filtered, record)
			continue
		}
		if record.Address == nil || *record.Address != value {
			filtered = append(filtered, record)
			continue
		}
	}

	if len(filtered) == len(records) {
		return nil
	}

	return setHostRecords(client, zone, filtered, emailType)
}

func getHostRecords(client *namecheap.Client, zone string) ([]namecheap.DomainsDNSHostRecord, *string, error) {
	resp, err := client.DomainsDNS.GetHosts(trimDot(zone))
	if err != nil {
		return nil, nil, err
	}
	if resp == nil || resp.DomainDNSGetHostsResult == nil {
		return nil, nil, errors.New("namecheap response missing host records")
	}
	result := resp.DomainDNSGetHostsResult
	if result.Hosts == nil {
		return []namecheap.DomainsDNSHostRecord{}, result.EmailType, nil
	}

	records := make([]namecheap.DomainsDNSHostRecord, 0, len(*result.Hosts))
	for _, host := range *result.Hosts {
		records = append(records, namecheap.DomainsDNSHostRecord{
			HostName:   host.Name,
			RecordType: host.Type,
			Address:    host.Address,
			TTL:        host.TTL,
			MXPref:     mxPrefFromInt(host.MXPref),
		})
	}

	return records, result.EmailType, nil
}

func setHostRecords(client *namecheap.Client, zone string, records []namecheap.DomainsDNSHostRecord, emailType *string) error {
	args := &namecheap.DomainsDNSSetHostsArgs{
		Domain:  namecheap.String(trimDot(zone)),
		Records: &records,
	}
	if emailType != nil && *emailType != "" {
		args.EmailType = namecheap.String(*emailType)
	}

	_, err := client.DomainsDNS.SetHosts(args)
	if err != nil {
		return err
	}
	return nil
}

func namecheapHostName(zone string, fqdn string) string {
	zone = ensureTrailingDot(zone)
	fqdn = ensureTrailingDot(fqdn)
	if !strings.HasSuffix(fqdn, zone) {
		return fqdn
	}
	rel := strings.TrimSuffix(fqdn, zone)
	rel = strings.TrimSuffix(rel, ".")
	if rel == "" {
		return "@"
	}
	return rel
}

func ensureTrailingDot(value string) string {
	if value == "" {
		return value
	}
	if strings.HasSuffix(value, ".") {
		return value
	}
	return value + "."
}

func trimDot(value string) string {
	return strings.TrimSuffix(value, ".")
}

func mxPrefFromInt(value *int) *uint8 {
	if value == nil {
		return nil
	}
	if *value < 0 {
		return namecheap.UInt8(0)
	}
	if *value > 255 {
		return namecheap.UInt8(255)
	}
	return namecheap.UInt8(uint8(*value))
}
