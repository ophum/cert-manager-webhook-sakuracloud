package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"

	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
	"github.com/sacloud/iaas-api-go"
	"github.com/sacloud/iaas-api-go/types"
	"github.com/sacloud/iaas-service-go/dns"
)

var GroupName = os.Getenv("GROUP_NAME")

func main() {
	if GroupName == "" {
		panic("GROUP_NAME must be specified")
	}

	// This will register our custom DNS provider with the webhook serving
	// library, making it available as an API under the provided GroupName.
	// You can register multiple DNS provider implementations with a single
	// webhook, where the Name() method will be used to disambiguate between
	// the different implementations.
	cmd.RunWebhookServer(GroupName,
		&sakuraCloudDNSProviderSolver{},
	)
}

// sakuraCloudDNSProviderSolver implements the provider-specific logic needed to
// 'present' an ACME challenge TXT record for your own DNS provider.
// To do so, it must implement the `github.com/cert-manager/cert-manager/pkg/acme/webhook.Solver`
// interface.
type sakuraCloudDNSProviderSolver struct {
	// If a Kubernetes 'clientset' is needed, you must:
	// 1. uncomment the additional `client` field in this structure below
	// 2. uncomment the "k8s.io/client-go/kubernetes" import at the top of the file
	// 3. uncomment the relevant code in the Initialize method below
	// 4. ensure your webhook's service account has the required RBAC role
	//    assigned to it for interacting with the Kubernetes APIs you need.
	client kubernetes.Interface
}

// sakuraCloudDNSProviderConfig is a structure that is used to decode into when
// solving a DNS01 challenge.
// This information is provided by cert-manager, and may be a reference to
// additional configuration that's needed to solve the challenge for this
// particular certificate or issuer.
// This typically includes references to Secret resources containing DNS
// provider credentials, in cases where a 'multi-tenant' DNS solver is being
// created.
// If you do *not* require per-issuer or per-certificate configuration to be
// provided to your webhook, you can skip decoding altogether in favour of
// using CLI flags or similar to provide configuration.
// You should not include sensitive information here. If credentials need to
// be used by your provider here, you should reference a Kubernetes Secret
// resource and fetch these credentials using a Kubernetes clientset.
type sakuraCloudDNSProviderConfig struct {
	// Change the two fields below according to the format of the configuration
	// to be decoded.
	// These fields will be set by users in the
	// `issuer.spec.acme.dns01.providers.webhook.config` field.

	//Email           string `json:"email"`
	//APIKeySecretRef v1alpha1.SecretKeySelector `json:"apiKeySecretRef"`
	ZoneID               int64                    `json:"zoneID"`
	AccessTokenRef       cmmeta.SecretKeySelector `json:"accessTokenRef"`
	AccessTokenSecretRef cmmeta.SecretKeySelector `json:"accessTokenSecretRef"`
}

func (c *sakuraCloudDNSProviderSolver) newClient(cfg *sakuraCloudDNSProviderConfig, ch *v1alpha1.ChallengeRequest) (*dns.Service, error) {
	accessToken, err := c.getSecretString(&cfg.AccessTokenRef, ch.ResourceNamespace)
	if err != nil {
		return nil, err
	}
	accessTokenSecret, err := c.getSecretString(&cfg.AccessTokenSecretRef, ch.ResourceNamespace)
	if err != nil {
		return nil, err
	}

	return dns.New(
		iaas.NewClient(accessToken, accessTokenSecret),
	), nil
}

// Name is used as the name for this DNS solver when referencing it on the ACME
// Issuer resource.
// This should be unique **within the group name**, i.e. you can have two
// solvers configured with the same Name() **so long as they do not co-exist
// within a single webhook deployment**.
// For example, `cloudflare` may be used as the name of a solver.
func (c *sakuraCloudDNSProviderSolver) Name() string {
	return "sakuracloud-dns-solver"
}

// Present is responsible for actually presenting the DNS record with the
// DNS provider.
// This method should tolerate being called multiple times with the same value.
// cert-manager itself will later perform a self check to ensure that the
// solver has correctly configured the DNS provider.
func (c *sakuraCloudDNSProviderSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return err
	}

	client, err := c.newClient(&cfg, ch)
	if err != nil {
		return err
	}
	zone, err := client.Read(&dns.ReadRequest{
		ID: types.Int64ID(cfg.ZoneID),
	})
	if err != nil {
		return err
	}

	entry, err := c.getEntry(ch, zone)
	if err != nil {
		return err
	}
	klog.V(6).Infof("present for entry=%s, zone=%s", entry, zone.Name)

	records := zone.GetRecords()
	isExists := false
	for _, record := range records {
		if record.Name == entry && record.Type == types.DNSRecordTypes.TXT {
			record.RData = ch.Key
			isExists = true
			break
		}
	}
	if !isExists {
		records.Add(&iaas.DNSRecord{
			Name:  entry,
			Type:  types.DNSRecordTypes.TXT,
			RData: ch.Key,
			TTL:   60,
		})
	}
	_, err = client.Update(&dns.UpdateRequest{
		ID:           zone.ID,
		Records:      records,
		SettingsHash: zone.SettingsHash,
	})
	return err
}

func (c *sakuraCloudDNSProviderSolver) getEntry(ch *v1alpha1.ChallengeRequest, zone *iaas.DNS) (string, error) {
	zoneName := zone.Name
	if zoneName[len(zoneName)-1] != '.' {
		zoneName += "."
	}
	if !strings.HasSuffix(ch.ResolvedZone, zoneName) {
		return "", fmt.Errorf("invalid zone, resolvedZone: %s, zoneName: %s", ch.ResolvedZone, zoneName)
	}

	entry, ok := strings.CutSuffix(ch.ResolvedFQDN, "."+zoneName)
	if !ok {
		return "", fmt.Errorf("invalid fqdn, resolvedFQDN: %s, zoneName: %s", ch.ResolvedFQDN, zoneName)
	}
	return entry, nil
}

func (c *sakuraCloudDNSProviderSolver) getSecretString(ref *cmmeta.SecretKeySelector, ns string) (string, error) {
	secret, err := c.client.CoreV1().Secrets(ns).Get(context.TODO(), ref.Name, v1.GetOptions{})
	if err != nil {
		return "", err
	}

	if accessToken, ok := secret.Data[ref.Key]; ok {
		return string(accessToken), nil
	}
	return "", errors.New("accessToken not found")
}

// CleanUp should delete the relevant TXT record from the DNS provider console.
// If multiple TXT records exist with the same record name (e.g.
// _acme-challenge.example.com) then **only** the record with the same `key`
// value provided on the ChallengeRequest should be cleaned up.
// This is in order to facilitate multiple DNS validations for the same domain
// concurrently.
func (c *sakuraCloudDNSProviderSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return err
	}

	client, err := c.newClient(&cfg, ch)
	if err != nil {
		return err
	}
	zone, err := client.Read(&dns.ReadRequest{
		ID: types.Int64ID(cfg.ZoneID),
	})
	if err != nil {
		return err
	}

	entry, err := c.getEntry(ch, zone)
	if err != nil {
		return err
	}

	records := zone.GetRecords()
	isExists := false
	records = slices.DeleteFunc(records, func(d *iaas.DNSRecord) bool {
		if d.Name == entry && d.Type == types.DNSRecordTypes.TXT {
			isExists = true
			return true
		}
		return false
	})
	if isExists {
		klog.V(6).Infof("cleanup for entry=%s, zone=%s", entry, zone.Name)
		_, err = client.Update(&dns.UpdateRequest{
			ID:           zone.ID,
			Records:      records,
			SettingsHash: zone.SettingsHash,
		})
		return err
	}
	return nil
}

// Initialize will be called when the webhook first starts.
// This method can be used to instantiate the webhook, i.e. initialising
// connections or warming up caches.
// Typically, the kubeClientConfig parameter is used to build a Kubernetes
// client that can be used to fetch resources from the Kubernetes API, e.g.
// Secret resources containing credentials used to authenticate with DNS
// provider accounts.
// The stopCh can be used to handle early termination of the webhook, in cases
// where a SIGTERM or similar signal is sent to the webhook process.
func (c *sakuraCloudDNSProviderSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	cl, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return err
	}

	c.client = cl
	return nil
}

// loadConfig is a small helper function that decodes JSON configuration into
// the typed config struct.
func loadConfig(cfgJSON *extapi.JSON) (sakuraCloudDNSProviderConfig, error) {
	cfg := sakuraCloudDNSProviderConfig{}
	// handle the 'base case' where no configuration has been provided
	if cfgJSON == nil {
		return cfg, nil
	}
	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("error decoding solver config: %v", err)
	}

	return cfg, nil
}
