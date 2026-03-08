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
	"time"

	"github.com/Azure/go-ntlmssp"
)

// maxResponseSize limits the size of HTTP response bodies to prevent memory exhaustion (10 MB).
const maxResponseSize = 10 * 1024 * 1024

type NtlmCertsrv struct {
	url        string
	username   string
	password   string
	httpClient *http.Client
}

const (
	certnew_cer = "certnew.cer"
	certnew_p7b = "certnew.p7b"
	certcarc    = "certcarc.asp"
	certfnsh    = "certfnsh.asp"

	ct_pkix   = "application/pkix-cert"
	ct_pkcs7  = "application/x-pkcs7-certificates"
	ct_html   = "text/html"
	ct_urlenc = "application/x-www-form-urlencoded"
)

func NewNtlmCertsrv(url string, username string, password string, caCertPool *x509.CertPool, verify bool, authMode string) (AdcsCertsrv, error) {
	var client *http.Client
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: false,
			MinVersion:         tls.VersionTLS12,
			RootCAs:            caCertPool,
		},
	}

	if username != "" && password != "" {
		if authMode == "basic" {
			// Use plain HTTP Basic Authentication (no NTLM)
			// Requires Basic Auth to be enabled on IIS/ADCS certsrv
			client = &http.Client{
				Timeout:   30 * time.Second,
				Transport: transport,
				// Preserve Authorization header on same-host redirects (e.g. /certsrv -> /certsrv/)
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					if len(via) >= 10 {
						return fmt.Errorf("stopped after 10 redirects")
					}
					if len(via) > 0 {
						req.SetBasicAuth(username, password)
					}
					return nil
				},
			}
			log.Println("Using Basic Authentication mode")
		} else {
			// Set up NTLM authentication (default)
			client = &http.Client{
				Timeout: 30 * time.Second,
				Transport: ntlmssp.Negotiator{
					RoundTripper: transport,
				},
			}
			log.Println("Using NTLM Authentication mode")
		}
	} else {
		// Plain client with no auth
		client = &http.Client{
			Timeout:   30 * time.Second,
			Transport: transport,
		}
		log.Println("WARNING: No credentials provided, not using authentication")
	}

	// Ensure URL does not have trailing slash (sub-paths are built with Sprintf("%s/resource", url))
	url = strings.TrimRight(url, "/")

	c := &NtlmCertsrv{
		url:        url,
		username:   username,
		password:   password,
		httpClient: client,
	}
	if verify {
		success, err := c.verifyNtlm()
		if !success {
			return nil, err
		}
	}
	return c, nil
}

// Check if NTLM authentication is working for current credentials and URL
func (s *NtlmCertsrv) verifyNtlm() (bool, error) {
	log.Printf("NTLM verification for URL %s", s.url)
	req, _ := http.NewRequest("GET", s.url, nil)
	req.SetBasicAuth(s.username, s.password)
	res, err := s.httpClient.Do(req)
	if err != nil {
		log.Printf("ERROR: ADCS server error: %s", err.Error())
		return false, err
	}
	defer res.Body.Close()
	// Drain and discard the body to allow connection reuse
	_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, maxResponseSize))
	log.Printf("NTLM verification successful (res = %s)", res.Status)
	return true, nil
}

/*
 * Returns:
 * - Certificate response status
 * - Certificate (if status is Ready) or status description (if status is not Ready)
 * - ADCS Request ID
 * - Error
 */
func (s *NtlmCertsrv) GetExistingCertificate(id string) (AdcsResponseStatus, string, string, error) {
	var certStatus AdcsResponseStatus = Unknown

	url := fmt.Sprintf("%s/%s?ReqID=%s&ENC=b64", s.url, certnew_cer, id)
	req, _ := http.NewRequest("GET", url, nil)
	req.SetBasicAuth(s.username, s.password)
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
			// Denied or pending
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
				// If the response page is not formatted as we expect it
				// we just log the entire page
				disp := bodyString
				if len(found) == 1 {
					// Or at least the 'Disposition message' section
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
			// Certificate
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

/*
 * Returns:
 * - Certificate response status
 * - Certificate (if status is Ready) or status description (if status is not Ready)
 * - ADCS Request ID (if known)
 * - Error
 */
func (s *NtlmCertsrv) RequestCertificate(csr string, template string) (AdcsResponseStatus, string, string, error) {
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
	req.SetBasicAuth(s.username, s.password)
	req.Header.Set("User-agent", "Mozilla")
	req.Header.Set("Content-type", ct_urlenc)

	log.Printf("Sending request to: %s", url)

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

func (s *NtlmCertsrv) obtainCaCertificate(certPage string, expectedContentType string) (string, error) {

	// Check for newest renewal number
	url := fmt.Sprintf("%s/%s", s.url, certcarc)
	req, _ := http.NewRequest("GET", url, nil)
	req.SetBasicAuth(s.username, s.password)
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
	req.SetBasicAuth(s.username, s.password)
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
func (s *NtlmCertsrv) GetCaCertificate() (string, error) {
	log.Printf("Getting CA from ADCS Certsrv %s", s.url)
	return s.obtainCaCertificate(certnew_cer, ct_pkix)
}
func (s *NtlmCertsrv) GetCaCertificateChain() (string, error) {
	log.Printf("Getting CA Chain from ADCS Certsrv %s", s.url)
	return s.obtainCaCertificate(certnew_p7b, ct_pkcs7)
}
