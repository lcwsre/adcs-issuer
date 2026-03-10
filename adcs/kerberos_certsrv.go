package adcs

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net/http"
	neturl "net/url"
	"regexp"
	"strings"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/spnego"
)

// KerberosCertsrv implements AdcsCertsrv using Kerberos (SPNEGO) authentication.
type KerberosCertsrv struct {
	url        string
	krbClient  *client.Client
	httpClient *spnego.Client
}

// NewKerberosCertsrv creates a new ADCS client using Kerberos (SPNEGO) authentication.
// It requires a valid /etc/krb5.conf file in the container.
// The credentials secret must include a "realm" field (e.g., "EXAMPLE.COM").
func NewKerberosCertsrv(url, username, realm, password string, caCertPool *x509.CertPool, verify bool) (AdcsCertsrv, error) {
	// Load krb5.conf
	krb5ConfPath := "/etc/krb5.conf"
	log.Printf("Loading Kerberos config from %s", krb5ConfPath)
	krb5Conf, err := config.Load(krb5ConfPath)
	if err != nil {
		log.Printf("ERROR: Failed to load krb5 config: %s", err.Error())
		return nil, fmt.Errorf("failed to load krb5 config: %w", err)
	}

	// Create Kerberos client with username/password
	log.Printf("Authenticating with Kerberos as %s@%s", username, realm)
	krbClient := client.NewWithPassword(username, realm, password, krb5Conf,
		client.DisablePAFXFAST(true))

	if err := krbClient.Login(); err != nil {
		log.Printf("ERROR: Kerberos login failed: %s", err.Error())
		return nil, fmt.Errorf("kerberos login failed: %w", err)
	}
	log.Println("Kerberos authentication successful")

	// Set up TLS
	caPool := caCertPool
	if caPool == nil {
		caPool, err = x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("failed to load system cert pool: %w", err)
		}
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: false,
			MinVersion:         tls.VersionTLS12,
			RootCAs:            caPool,
		},
	}

	httpClient := &http.Client{Transport: transport}
	spnegoClient := spnego.NewClient(krbClient, httpClient, "")

	// Ensure URL does not have trailing slash
	url = strings.TrimRight(url, "/")

	c := &KerberosCertsrv{
		url:        url,
		krbClient:  krbClient,
		httpClient: spnegoClient,
	}

	if verify {
		success, err := c.verifyKerberos()
		if !success {
			return nil, err
		}
	}

	log.Println("Kerberos ADCS client initialized successfully")
	return c, nil
}

// verifyKerberos checks connectivity to the ADCS server using Kerberos auth.
func (s *KerberosCertsrv) verifyKerberos() (bool, error) {
	log.Printf("Kerberos verification for URL %s", s.url)
	req, err := http.NewRequest("GET", s.url, nil)
	if err != nil {
		return false, err
	}

	res, err := s.httpClient.Do(req)
	if err != nil {
		log.Printf("ERROR: ADCS server error: %s", err.Error())
		return false, err
	}
	defer res.Body.Close()
	// Drain body to allow connection reuse
	_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, maxResponseSize))
	log.Printf("Kerberos verification successful (res = %s)", res.Status)
	return true, nil
}

// GetExistingCertificate retrieves a previously requested certificate from ADCS.
func (s *KerberosCertsrv) GetExistingCertificate(id string) (AdcsResponseStatus, string, string, error) {
	var certStatus AdcsResponseStatus = Unknown

	url := fmt.Sprintf("%s/%s?ReqID=%s&ENC=b64", s.url, certnew_cer, id)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-agent", "Mozilla")
	res, err := s.httpClient.Do(req)
	if err != nil {
		log.Printf("ERROR: ADCS Certserv error: %s", err.Error())
		return certStatus, "", id, err
	}
	defer res.Body.Close()

	if res.StatusCode == http.StatusOK {
		switch ct := strings.Split(res.Header.Get("Content-Type"), ";"); ct[0] {
		case ct_html:
			body, err := io.ReadAll(io.LimitReader(res.Body, maxResponseSize))
			if err != nil {
				log.Printf("ERROR: Cannot read ADCS Certserv response: %s", err.Error())
				return certStatus, "", id, err
			}
			bodyString := string(body)
			dispositionMessage := "unknown"
			exp := regexp.MustCompile(`Disposition message:[^\t]+\t\t([^\r\n]+)`)
			found := exp.FindStringSubmatch(bodyString)
			if len(found) > 1 {
				dispositionMessage = found[1]
				expPending := regexp.MustCompile(`.*Taken Under Submission*.`)
				expRejected := regexp.MustCompile(`.*Denied by*.`)
				switch true {
				case expPending.MatchString(bodyString):
					certStatus = Pending
				case expRejected.MatchString(bodyString):
					certStatus = Rejected
				default:
					certStatus = Errored
				}
			} else {
				disp := bodyString
				if len(found) == 1 {
					disp = found[0]
				}
				err = fmt.Errorf("Disposition message unknown: %s", disp)
				log.Printf("ERROR: %s", err.Error())
			}

			lastStatusMessage := ""
			exp = regexp.MustCompile(`LastStatus:[^\t]+\t\t([^\r\n]+)`)
			found = exp.FindStringSubmatch(bodyString)
			if len(found) > 1 {
				lastStatusMessage = " " + found[1]
			} else {
				log.Println("WARNING: Last status unknown.")
			}
			return certStatus, dispositionMessage + lastStatusMessage, id, err

		case ct_pkix:
			cert, err := io.ReadAll(io.LimitReader(res.Body, maxResponseSize))
			if err != nil {
				log.Printf("ERROR: Cannot read ADCS Certserv response: %s", err.Error())
				return certStatus, "", id, err
			}
			return Ready, string(cert), id, nil
		default:
			err = fmt.Errorf("Unexpected content type %s:", ct)
			log.Printf("ERROR: %s", err.Error())
			return certStatus, "", id, err
		}
	}
	return certStatus, "", id, fmt.Errorf("ADCS Certsrv response status %s", res.Status)
}

// RequestCertificate submits a new certificate signing request to ADCS.
func (s *KerberosCertsrv) RequestCertificate(csr string, template string) (AdcsResponseStatus, string, string, error) {
	var certStatus AdcsResponseStatus = Unknown

	url := fmt.Sprintf("%s/%s", s.url, certfnsh)
	params := neturl.Values{
		"Mode":                {"newreq"},
		"CertRequest":         {csr},
		"CertAttrib":          {"CertificateTemplate:" + template},
		"FriendlyType":        {"Saved-Request Certificate"},
		"TargetStoreFlags":    {"0"},
		"SaveCert":            {"yes"},
		"CertificateTemplate": {template},
	}
	req, err := http.NewRequest("POST", url, bytes.NewBufferString(params.Encode()))
	if err != nil {
		log.Printf("ERROR: Cannot create request: %s", err.Error())
		return certStatus, "", "", err
	}
	req.Header.Set("User-agent", "Mozilla")
	req.Header.Set("Content-type", ct_urlenc)

	log.Printf("Sending Kerberos request to: %s", url)

	res, err := s.httpClient.Do(req)
	if err != nil {
		log.Printf("ERROR: ADCS Certserv error: %s", err.Error())
		return certStatus, "", "", err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, maxResponseSize))
	if res.Header.Get("Content-type") == ct_pkix {
		return Ready, string(body), "none", nil
	}

	if err != nil {
		log.Printf("ERROR: Cannot read ADCS Certserv response: %s", err.Error())
		return certStatus, "", "", err
	}

	bodyString := string(body)
	log.Printf("Response body length: %d", len(bodyString))

	exp := regexp.MustCompile(`certnew.cer\?ReqID=([0-9]+)&`)
	found := exp.FindStringSubmatch(bodyString)
	certId := ""
	if len(found) > 1 {
		certId = found[1]
	} else {
		exp = regexp.MustCompile(`Your Request Id is ([0-9]+).`)
		found = exp.FindStringSubmatch(bodyString)
		if len(found) > 1 {
			certId = found[1]
		} else {
			errorString := ""
			exp = regexp.MustCompile(`The disposition message is "([^"]+)`)
			found = exp.FindStringSubmatch(bodyString)
			if len(found) > 1 {
				errorString = found[1]
			} else {
				errorString = "Unknown error occured"
				log.Printf("ERROR: %s", bodyString)
			}
			log.Printf("ERROR: Couldn't obtain new certificate ID")
			return certStatus, "", "", fmt.Errorf("%s", errorString)
		}
	}

	return s.GetExistingCertificate(certId)
}

func (s *KerberosCertsrv) obtainCaCertificate(certPage string, expectedContentType string) (string, error) {
	// Check for newest renewal number
	url := fmt.Sprintf("%s/%s", s.url, certcarc)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-agent", "Mozilla")
	res1, err := s.httpClient.Do(req)
	if err != nil {
		log.Printf("ERROR: ADCS Certserv error: %s", err.Error())
		return "", err
	}
	defer res1.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res1.Body, maxResponseSize))
	if err != nil {
		log.Printf("ERROR: Cannot read ADCS Certserv response: %s", err.Error())
		return "", err
	}

	renewal := "0"
	exp := regexp.MustCompile(`var nRenewals=([0-9]+);`)
	found := exp.FindStringSubmatch(string(body))
	if len(found) > 1 {
		renewal = found[1]
	} else {
		log.Println("WARNING: Renewal not found. Using '0'.")
	}

	// Get CA cert (newest renewal number)
	url = fmt.Sprintf("%s/%s?ReqID=CACert&ENC=b64&Renewal=%s", s.url, certPage, renewal)
	req, _ = http.NewRequest("GET", url, nil)
	req.Header.Set("User-agent", "Mozilla")
	res2, err := s.httpClient.Do(req)
	if err != nil {
		log.Printf("ERROR: ADCS Certserv error: %s", err.Error())
		return "", err
	}
	defer res2.Body.Close()

	if res2.StatusCode == http.StatusOK {
		ct := res2.Header.Get("Content-Type")
		if expectedContentType != ct {
			err = fmt.Errorf("Unexpected content type %s:", ct)
			log.Printf("ERROR: %s", err.Error())
			return "", err
		}
		body, err := io.ReadAll(io.LimitReader(res2.Body, maxResponseSize))
		if err != nil {
			log.Printf("ERROR: Cannot read ADCS Certserv response: %s", err.Error())
			return "", err
		}
		return string(body), nil
	}
	return "", fmt.Errorf("ADCS Certsrv response status %s", res2.Status)
}

// GetCaCertificate retrieves the CA certificate from ADCS in X.509 PEM format.
func (s *KerberosCertsrv) GetCaCertificate() (string, error) {
	log.Printf("Getting CA from ADCS Certsrv %s (Kerberos)", s.url)
	return s.obtainCaCertificate(certnew_cer, ct_pkix)
}

// GetCaCertificateChain retrieves the CA certificate chain from ADCS in PKCS#7 format.
func (s *KerberosCertsrv) GetCaCertificateChain() (string, error) {
	log.Printf("Getting CA Chain from ADCS Certsrv %s (Kerberos)", s.url)
	return s.obtainCaCertificate(certnew_p7b, ct_pkcs7)
}
