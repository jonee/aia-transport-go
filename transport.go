package aia

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io/ioutil"
	"net"
	"net/http"
	"runtime"
	"time"
)

// NewTransport returns a http.Transport that supports AIA (Authority Information Access) resolution
// for incomplete certificate chains.
func NewTransport() (*http.Transport, error) {

	// Support windows.
	if runtime.GOOS == "windows" {
		return &http.Transport{}, nil
	}

	rootCAs, err := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}

	return NewTransportWithCustomTLSClientConfig(&tls.Config{RootCAs: rootCAs})
}

// Allow custom TLSClientConfig parameter which could have custom RootCAs
func NewTransportWithCustomTLSClientConfig(TLSClientConfig *tls.Config) (*http.Transport, error) {
	// Support windows.
	if runtime.GOOS == "windows" {
		return &http.Transport{TLSClientConfig: TLSClientConfig}, nil
	}

	return &http.Transport{
		TLSClientConfig: TLSClientConfig,
		DialTLS: func(network, addr string) (net.Conn, error) {
			conn, err := tls.Dial(network, addr, &tls.Config{
				InsecureSkipVerify: true,
				RootCAs:            TLSClientConfig.RootCAs,
				VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
					serverName, _, err := net.SplitHostPort(addr)
					if err != nil {
						return err
					}
					return VerifyPeerCerts(TLSClientConfig.RootCAs, serverName, rawCerts)
				},
			})
			if err != nil {
				return conn, err
			}
			return conn, nil
		},
	}, nil

}

func VerifyPeerCerts(rootCAs *x509.CertPool, serverName string, rawCerts [][]byte) error {
	certs := make([]*x509.Certificate, len(rawCerts))
	for i, asn1Data := range rawCerts {
		cert, err := x509.ParseCertificate(asn1Data)
		if err != nil {
			return errors.New("failed to parse certificate from server: " + err.Error())
		}
		certs[i] = cert
	}

	opts := &x509.VerifyOptions{
		Roots:         rootCAs,
		CurrentTime:   time.Now(),
		DNSName:       serverName,
		Intermediates: x509.NewCertPool(),
	}
	for _, cert := range certs[1:] {
		opts.Intermediates.AddCert(cert)
	}

	_, err := certs[0].Verify(*opts)
	if err != nil {
		if _, ok := err.(x509.UnknownAuthorityError); ok {
			if len(certs[0].IssuingCertificateURL) >= 1 && certs[0].IssuingCertificateURL[0] != "" {
				err1 := VerifyIncompleteChain(certs[0].IssuingCertificateURL[0], certs[0], opts)
				if err1 != nil {
					return err // return original x509.UnknownAuthorityError
				} 
				return nil
			}
		}
		return err
	}
	return nil
}

func VerifyIncompleteChain(issuingCertificateURL string, baseCert *x509.Certificate, opts *x509.VerifyOptions) error {
	issuer, err := GetCert(issuingCertificateURL)
	if err != nil {
		return err
	}
	opts.Intermediates.AddCert(issuer)
	_, err = baseCert.Verify(*opts)
	if err != nil {
		if _, ok := err.(x509.UnknownAuthorityError); ok {
			if len(issuer.IssuingCertificateURL) >= 1 && issuer.IssuingCertificateURL[0] != "" {
				return VerifyIncompleteChain(issuer.IssuingCertificateURL[0], baseCert, opts)
			}
		}
		return err
	}
	return nil
}

func GetCert(url string) (*x509.Certificate, error) {
	resp, err := http.Get(url)
	if resp != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		return nil, err
	}

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(data)
}
