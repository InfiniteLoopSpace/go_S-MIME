//Package pki can create ca's intermediates and certificates
package pki

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math"
	"math/big"
	"os/exec"
	"time"
)

type configuration struct {
	subject               *pkix.Name
	issuer                *Identity
	nextSN                *int64
	signatureAlgrotim     x509.SignatureAlgorithm
	priv                  *crypto.Signer
	isCA                  bool
	notBefore             *time.Time
	notAfter              *time.Time
	issuingCertificateURL []string
	ocspServer            []string
}

func (c *configuration) generate() *Identity {
	templ := &x509.Certificate{
		Subject:               c.getSubject(),
		SignatureAlgorithm:    c.signatureAlgrotim,
		IsCA:                  c.isCA,
		BasicConstraintsValid: true,
		NotAfter:              c.getNotAfter(),
		NotBefore:             c.getNotBefore(),
		IssuingCertificateURL: c.issuingCertificateURL,
		OCSPServer:            c.ocspServer,
	}

	var (
		parent   *x509.Certificate
		thisPriv = c.getPrivateKey()
		priv     crypto.Signer
	)

	if c.issuer != nil {
		parent = c.issuer.Certificate
		templ.SerialNumber = big.NewInt(c.issuer.IncrementSN())
		priv = c.issuer.PrivateKey
	} else {
		parent = templ
		templ.SerialNumber = randSN()
		priv = thisPriv
	}

	der, err := x509.CreateCertificate(rand.Reader, templ, parent, thisPriv.Public(), priv)
	if err != nil {
		panic(err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}

	return &Identity{
		Certificate: cert,
		PrivateKey:  thisPriv,
		Issuer:      c.issuer,
		NextSN:      c.getNextSN(),
	}
}

var (
	// DefaultCountry is the default subject Country.
	DefaultCountry = []string{"US"}

	// DefaultProvince is the default subject Province.
	DefaultProvince = []string{"CA"}

	// DefaultLocality is the default subject Locality.
	DefaultLocality = []string{"San Francisco"}

	// DefaultStreetAddress is the default subject StreetAddress.
	DefaultStreetAddress = []string(nil)

	// DefaultPostalCode is the default subject PostalCode.
	DefaultPostalCode = []string(nil)

	// DefaultCommonName is the default subject CommonName.
	DefaultCommonName = "fakeca"

	cnCounter int64
)

func (c *configuration) getSubject() pkix.Name {
	if c.subject != nil {
		return *c.subject
	}

	var cn string
	if cnCounter == 0 {
		cn = DefaultCommonName
	} else {
		cn = fmt.Sprintf("%s #%d", DefaultCommonName, cnCounter)
	}
	cnCounter++

	return pkix.Name{
		Country:       DefaultCountry,
		Province:      DefaultProvince,
		Locality:      DefaultLocality,
		StreetAddress: DefaultStreetAddress,
		PostalCode:    DefaultPostalCode,
		CommonName:    cn,
	}
}

func (c *configuration) getNextSN() int64 {
	if c.nextSN == nil {
		sn := randSN().Int64()
		c.nextSN = &sn
	}

	return *c.nextSN
}

func randSN() *big.Int {
	i, err := rand.Int(rand.Reader, big.NewInt(int64(math.MaxInt64)))
	if err != nil {
		panic(err)
	}

	return i
}

func (c *configuration) getPrivateKey() crypto.Signer {
	if c.priv == nil {
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}

		signer := crypto.Signer(priv)

		c.priv = &signer
	}

	return *c.priv
}

func (c *configuration) getNotBefore() time.Time {
	if c.notBefore == nil {
		return time.Unix(0, 0)
	}

	return *c.notBefore
}

func (c *configuration) getNotAfter() time.Time {
	if c.notAfter == nil {
		return time.Now().Add(time.Hour * 24 * 365 * 10)
	}

	return *c.notAfter
}

// Option is an option that can be passed to New().
type Option option
type option func(c *configuration)

// Subject is an Option that sets a identity's subject field.
func Subject(value pkix.Name) Option {
	return func(c *configuration) {
		c.subject = &value
	}
}

// NextSerialNumber is an Option that determines the SN of the next issued
// certificate.
func NextSerialNumber(value int64) Option {
	return func(c *configuration) {
		c.nextSN = &value
	}
}

// PrivateKey is an Option for setting the identity's private key.
func PrivateKey(value crypto.Signer) Option {
	return func(c *configuration) {
		c.priv = &value
	}
}

// SignatureAlgorithm is an Option for setting the signature algorithm.
func SignatureAlgorithm(value x509.SignatureAlgorithm) Option {
	return func(c *configuration) {
		c.signatureAlgrotim = value
	}
}

// Issuer is an Option for setting the identity's issuer.
func Issuer(value *Identity) Option {
	return func(c *configuration) {
		c.issuer = value
	}
}

// NotBefore is an Option for setting the identity's certificate's NotBefore.
func NotBefore(value time.Time) Option {
	return func(c *configuration) {
		c.notBefore = &value
	}
}

// NotAfter is an Option for setting the identity's certificate's NotAfter.
func NotAfter(value time.Time) Option {
	return func(c *configuration) {
		c.notAfter = &value
	}
}

// IssuingCertificateURL is an Option for setting the identity's certificate's
// IssuingCertificateURL.
func IssuingCertificateURL(value ...string) Option {
	return func(c *configuration) {
		c.issuingCertificateURL = append(c.issuingCertificateURL, value...)
	}
}

// OCSPServer is an Option for setting the identity's certificate's OCSPServer.
func OCSPServer(value ...string) Option {
	return func(c *configuration) {
		c.ocspServer = append(c.ocspServer, value...)
	}
}

// IsCA is an Option for making an identity a certificate authority.
var IsCA Option = func(c *configuration) {
	c.isCA = true
}

// Identity is a certificate and private key.
type Identity struct {
	Issuer      *Identity
	PrivateKey  crypto.Signer
	Certificate *x509.Certificate
	NextSN      int64
}

// New creates a new CA.
func New(opts ...Option) *Identity {
	c := &configuration{}

	for _, opt := range opts {
		option(opt)(c)
	}

	return c.generate()
}

// Issue issues a new Identity with this one as its parent.
func (id *Identity) Issue(opts ...Option) *Identity {
	opts = append(opts, Issuer(id))
	return New(opts...)
}

// PFX wraps the certificate and private key in an encrypted PKCS#12 packet. The
// provided password must be alphanumeric.
func (id *Identity) PFX(password string) []byte {
	return toPFX(id.Certificate, id.PrivateKey, password)
}

// Chain builds a slice of *x509.Certificate from this CA and its issuers.
func (id *Identity) Chain() []*x509.Certificate {
	chain := []*x509.Certificate{}
	for this := id; this != nil; this = this.Issuer {
		chain = append(chain, this.Certificate)
	}

	return chain
}

// ChainPool builds an *x509.CertPool from this CA and its issuers.
func (id *Identity) ChainPool() *x509.CertPool {
	chain := x509.NewCertPool()
	for this := id; this != nil; this = this.Issuer {
		chain.AddCert(this.Certificate)
	}

	return chain
}

// IncrementSN returns the next serial number.
func (id *Identity) IncrementSN() int64 {
	defer func() {
		id.NextSN++
	}()

	return id.NextSN
}

func toPFX(cert *x509.Certificate, priv interface{}, password string) []byte {
	// only allow alphanumeric passwords
	for _, c := range password {
		switch {
		case c >= 'a' && c <= 'z':
		case c >= 'A' && c <= 'Z':
		case c >= '0' && c <= '9':
		default:
			panic("password must be alphanumeric")
		}
	}

	passout := fmt.Sprintf("pass:%s", password)
	cmd := exec.Command("openssl", "pkcs12", "-export", "-passout", passout)

	cmd.Stdin = bytes.NewReader(append(append(toPKCS8(priv), '\n'), toPEM(cert)...))

	out := new(bytes.Buffer)
	cmd.Stdout = out

	if err := cmd.Run(); err != nil {
		panic(err)
	}

	return out.Bytes()
}

func toPEM(cert *x509.Certificate) []byte {
	buf := new(bytes.Buffer)
	if err := pem.Encode(buf, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
		panic(err)
	}

	return buf.Bytes()
}

func toDER(priv interface{}) []byte {
	var (
		der []byte
		err error
	)
	switch p := priv.(type) {
	case *rsa.PrivateKey:
		der = x509.MarshalPKCS1PrivateKey(p)
	case *ecdsa.PrivateKey:
		der, err = x509.MarshalECPrivateKey(p)
	default:
		err = errors.New("unknown key type")
	}
	if err != nil {
		panic(err)
	}

	return der
}

func toPKCS8(priv interface{}) []byte {
	cmd := exec.Command("openssl", "pkcs8", "-topk8", "-nocrypt", "-inform", "DER")

	cmd.Stdin = bytes.NewReader(toDER(priv))

	out := new(bytes.Buffer)
	cmd.Stdout = out

	if err := cmd.Run(); err != nil {
		panic(err)
	}

	return out.Bytes()
}
