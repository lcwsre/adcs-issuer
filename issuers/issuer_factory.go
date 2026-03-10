package issuers

import (
	"context"
	"crypto/x509"
	"fmt"
	"strings"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"

	"github.com/lcwsre/adcs-issuer/adcs"
	api "github.com/lcwsre/adcs-issuer/api/v1"
)

const (
	defaultStatusCheckInterval = "6h"
	defaultRetryInterval       = "1h"
)

type IssuerFactory struct {
	client.Client
	Log                      logr.Logger
	ClusterResourceNamespace string
}

func (f *IssuerFactory) GetIssuer(ctx context.Context, ref cmmeta.ObjectReference, namespace string) (*Issuer, error) {
	key := client.ObjectKey{Namespace: namespace, Name: ref.Name}

	switch strings.ToLower(ref.Kind) {
	case "adcsissuer":
		return f.getAdcsIssuer(ctx, key)
	case "clusteradcsissuer":
		return f.getClusterAdcsIssuer(ctx, key)
	}
	return nil, fmt.Errorf("Unsupported issuer kind %s.", ref.Kind)
}

// Get AdcsIssuer object from K8s and create Issuer
func (f *IssuerFactory) getAdcsIssuer(ctx context.Context, key client.ObjectKey) (*Issuer, error) {
	log := f.Log.WithValues("AdcsIssuer", key)

	issuer := new(api.AdcsIssuer)
	if err := f.Client.Get(ctx, key, issuer); err != nil {
		return nil, err
	}
	// TODO: add checking issuer status

	username, password, realm, err := f.getUserPassword(ctx, issuer.Spec.CredentialsRef.Name, issuer.Namespace, issuer.Spec.AuthMode)
	if err != nil {
		return nil, err
	}

	var caCertPool *x509.CertPool
	certs := issuer.Spec.CABundle
	if len(certs) > 0 {
		caCertPool = x509.NewCertPool()
		ok := caCertPool.AppendCertsFromPEM(certs)
		if !ok {
			return nil, fmt.Errorf("error loading ADCS CA bundle")
		}
		log.Info("Using custom CA bundle for ADCS connection")
	} else {
		// Use system CA pool for public CAs (e.g., GoDaddy, DigiCert)
		caCertPool, err = x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("failed to load system CA pool: %w", err)
		}
		log.Info("No CA bundle provided, using system CA pool")
	}

	authMode := strings.ToLower(strings.TrimSpace(issuer.Spec.AuthMode))
	if authMode == "" {
		authMode = "basic"
	}
	log.Info("Using authentication mode", "authMode", authMode)

	var certServ adcs.AdcsCertsrv
	switch authMode {
	case "kerberos":
		certServ, err = adcs.NewKerberosCertsrv(issuer.Spec.URL, username, realm, password, caCertPool, false)
	default:
		// "basic" is the default authentication mode
		certServ, err = adcs.NewBasicCertsrv(issuer.Spec.URL, username, password, caCertPool, false)
	}
	if err != nil {
		return nil, err
	}

	statusCheckInterval := getInterval(
		issuer.Spec.StatusCheckInterval,
		defaultStatusCheckInterval,
		log.WithValues("interval", "statusCheckInterval"))
	retryInterval := getInterval(
		issuer.Spec.RetryInterval,
		defaultRetryInterval,
		log.WithValues("interval", "retryInterval"))
	return &Issuer{
		f.Client,
		certServ,
		retryInterval,
		statusCheckInterval,
	}, nil
}

// Get ClusterAdcsIssuer object from K8s and create Issuer
func (f *IssuerFactory) getClusterAdcsIssuer(ctx context.Context, key client.ObjectKey) (*Issuer, error) {
	log := f.Log.WithValues("ClusterAdcsIssuer", key)
	key.Namespace = ""

	issuer := new(api.ClusterAdcsIssuer)
	if err := f.Client.Get(ctx, key, issuer); err != nil {
		return nil, err
	}
	// TODO: add checking issuer status

	username, password, realm, err := f.getUserPassword(ctx, issuer.Spec.CredentialsRef.Name, f.ClusterResourceNamespace, issuer.Spec.AuthMode)
	if err != nil {
		return nil, err
	}

	var caCertPool *x509.CertPool
	certs := issuer.Spec.CABundle
	if len(certs) > 0 {
		caCertPool = x509.NewCertPool()
		ok := caCertPool.AppendCertsFromPEM(certs)
		if !ok {
			return nil, fmt.Errorf("error loading ADCS CA bundle")
		}
		log.Info("Using custom CA bundle for ADCS connection")
	} else {
		// Use system CA pool for public CAs (e.g., GoDaddy, DigiCert)
		caCertPool, err = x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("failed to load system CA pool: %w", err)
		}
		log.Info("No CA bundle provided, using system CA pool")
	}

	authMode := strings.ToLower(strings.TrimSpace(issuer.Spec.AuthMode))
	if authMode == "" {
		authMode = "basic"
	}
	log.Info("Using authentication mode", "authMode", authMode)

	var certServ adcs.AdcsCertsrv
	switch authMode {
	case "kerberos":
		certServ, err = adcs.NewKerberosCertsrv(issuer.Spec.URL, username, realm, password, caCertPool, false)
	default:
		// "basic" is the default authentication mode
		certServ, err = adcs.NewBasicCertsrv(issuer.Spec.URL, username, password, caCertPool, false)
	}
	if err != nil {
		return nil, err
	}

	statusCheckInterval := getInterval(
		issuer.Spec.StatusCheckInterval,
		defaultStatusCheckInterval,
		log.WithValues("interval", "statusCheckInterval"))
	retryInterval := getInterval(
		issuer.Spec.RetryInterval,
		defaultRetryInterval,
		log.WithValues("interval", "retryInterval"))
	return &Issuer{
		f.Client,
		certServ,
		retryInterval,
		statusCheckInterval,
	}, nil
}

func getInterval(specValue string, def string, log logr.Logger) time.Duration {
	interval, _ := time.ParseDuration(def)
	if specValue != "" {
		i, err := time.ParseDuration(specValue)
		if err != nil {
			log.Error(err, "Cannot parse interval. Using default.")
		} else {
			interval = i
		}
	} else {
		log.Info("Using default")
	}
	return interval
}

// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch

func (f *IssuerFactory) getUserPassword(ctx context.Context, secretName string, namespace string, authMode string) (string, string, string, error) {
	secret := new(corev1.Secret)
	if err := f.Client.Get(ctx, client.ObjectKey{Namespace: namespace, Name: secretName}, secret); err != nil {
		return "", "", "", err
	}
	if _, ok := secret.Data["username"]; !ok {
		return "", "", "", fmt.Errorf("User name not set in secret")
	}
	if _, ok := secret.Data["password"]; !ok {
		return "", "", "", fmt.Errorf("Password not set in secret")
	}

	// Kerberos requires a realm field in the secret
	var realm string
	if strings.ToLower(strings.TrimSpace(authMode)) == "kerberos" {
		if _, ok := secret.Data["realm"]; !ok {
			return "", "", "", fmt.Errorf("realm not set in secret (required for Kerberos auth)")
		}
		realm = string(secret.Data["realm"])
	}

	return string(secret.Data["username"]), string(secret.Data["password"]), realm, nil
}
