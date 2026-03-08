package issuers

import (
	"context"
	"fmt"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/lcwsre/adcs-issuer/adcs"
	api "github.com/lcwsre/adcs-issuer/api/v1"
)

const (
	// Default ADCS certificate template used when no annotation is specified.
	defaultCertTemplate = "BasicSSLWebServer"
)

type Issuer struct {
	client.Client
	certServ            adcs.AdcsCertsrv
	RetryInterval       time.Duration
	StatusCheckInterval time.Duration
}

// Go to ADCS for a certificate. If current status is 'Pending' then
// check for existing request. Otherwise ask for new.
// The current status is set in the passed request.
// If status is 'Ready' the returns include certificate and CA cert respectively.
func (i *Issuer) Issue(ctx context.Context, ar *api.AdcsRequest) ([]byte, []byte, error) {
	var adcsResponseStatus adcs.AdcsResponseStatus
	var desc string
	var id string
	var err error
	if ar.Status.State != api.Unknown {
		// Pending and Ready both need to check with ADCS to get/re-get the cert.
		// Ready re-fetches to handle cases where the cert wasn't saved to CertificateRequest
		// (e.g. due to conflict errors). Rejected/Errored are truly final.
		if ar.Status.State == api.Pending || ar.Status.State == api.Ready {
			if ar.Status.Id == "" {
				return nil, nil, fmt.Errorf("ADCS ID not set.")
			}
			adcsResponseStatus, desc, id, err = i.certServ.GetExistingCertificate(ar.Status.Id)
		} else {
			// Rejected or Errored - nothing to do
			return nil, nil, nil
		}
	} else {
		// New request
		// Use template from AdcsRequest spec annotation, fallback to default
		template := ar.Spec.CertTemplate
		if template == "" {
			template = defaultCertTemplate
		}
		adcsResponseStatus, desc, id, err = i.certServ.RequestCertificate(string(ar.Spec.CSRPEM), template)
	}
	if err != nil {
		// This is a local error
		return nil, nil, err
	}

	var cert []byte
	switch adcsResponseStatus {
	case adcs.Pending:
		// It must be checked again later
		ar.Status.State = api.Pending
		ar.Status.Id = id
		ar.Status.Reason = desc
	case adcs.Ready:
		// Certificate obtained successfully
		ar.Status.State = api.Ready
		ar.Status.Id = id
		ar.Status.Reason = ""
		cert = []byte(desc)
	case adcs.Rejected:
		// Certificate request rejected by ADCS
		ar.Status.State = api.Rejected
		ar.Status.Id = id
		ar.Status.Reason = desc
	case adcs.Errored:
		// Unknown problem occured on ADCS
		ar.Status.State = api.Errored
		ar.Status.Id = id
		ar.Status.Reason = desc
	}

	ca, err := i.certServ.GetCaCertificate()
	if err != nil {
		return nil, nil, err
	}

	return cert, []byte(ca), nil

}
