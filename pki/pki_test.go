package pki

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"
)

func TestCA(t *testing.T) {

	DefaultProvince = []string{"CO"}
	DefaultLocality = []string{"Denver"}

	// Create a root CA.
	root := New(IsCA, Subject(pkix.Name{
		CommonName: "root.myorg.com",
	}))

	// Create an intermediate CA under the root.
	intermediate := root.Issue(IsCA, Subject(pkix.Name{
		CommonName: "intermediate.myorg.com",
	}))

	// Create a leaf certificate under the intermediate.
	leaf := intermediate.Issue(Subject(pkix.Name{
		CommonName: "leaf.myorg.com",
	}))

	Intermediate := x509.NewCertPool()
	Intermediate.AddCert(intermediate.Certificate)

	roots := x509.NewCertPool()
	roots.AddCert(root.Certificate)

	Opts := x509.VerifyOptions{
		Intermediates: Intermediate,
		Roots:         roots,
		CurrentTime:   time.Now(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	_, err := leaf.Certificate.Verify(Opts)

	if err != nil {
		t.Error(err)
	}

}
