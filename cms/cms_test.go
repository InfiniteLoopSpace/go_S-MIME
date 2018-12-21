package cms

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"strings"
	"testing"

	openssl "github.com/InfiniteLoopSpace/go_S-MIME/openssl"
	pki "github.com/InfiniteLoopSpace/go_S-MIME/pki"
)

var (
	root = pki.New(pki.IsCA, pki.Subject(pkix.Name{
		CommonName: "root.example.com",
	}))

	intermediate = root.Issue(pki.IsCA, pki.Subject(pkix.Name{
		CommonName: "intermediate.example.com",
	}))

	leaf = intermediate.Issue(pki.Subject(pkix.Name{
		CommonName: "leaf.example.com",
	}))

	leafPSS = intermediate.Issue(pki.Subject(pkix.Name{
		CommonName: "leaf.example.com",
	}), pki.SignatureAlgorithm(x509.SHA256WithRSAPSS))

	ecKey, _ = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)

	leafECC = intermediate.Issue(pki.Subject(pkix.Name{
		CommonName: "leaf.example.com",
	}), pki.PrivateKey(ecKey))

	keyPairRSA = tls.Certificate{
		Certificate: [][]byte{leaf.Certificate.Raw, intermediate.Certificate.Raw, root.Certificate.Raw},
		PrivateKey:  leaf.PrivateKey.(crypto.PrivateKey),
		Leaf:        leaf.Certificate,
	}

	keyPairRSAPSS = tls.Certificate{
		Certificate: [][]byte{leafPSS.Certificate.Raw, intermediate.Certificate.Raw, root.Certificate.Raw},
		PrivateKey:  leafPSS.PrivateKey.(crypto.PrivateKey),
		Leaf:        leafPSS.Certificate,
	}

	keyPairECC = tls.Certificate{
		Certificate: [][]byte{leafECC.Certificate.Raw, intermediate.Certificate.Raw, root.Certificate.Raw},
		PrivateKey:  leafECC.PrivateKey.(crypto.PrivateKey),
		Leaf:        leafECC.Certificate,
	}

	keypair tls.Certificate

	skipOpenssl = false

	opensslSignOpts = []string{"-outform", "DER"}

	opensslEncOpts = []string{"-outform", "DER"}
)

func TestMain(m *testing.M) {
	// Test RSA
	keypair = keyPairRSA

	version, err := openssl.Openssl(nil, "version")
	if err != nil {
		skipOpenssl = true
	}

	m.Run()

	// Test RSA PSS OAEP
	keypair = keyPairRSAPSS

	if strings.HasPrefix(string(version), "OpenSSL 1.1") {
		openssl.SMIME = "cms"
	} else {
		skipOpenssl = true
	}

	opensslSignOpts = append(opensslSignOpts, "-keyopt", "rsa_padding_mode:pss")
	opensslEncOpts = append(opensslEncOpts, "-keyopt", "rsa_padding_mode:oaep")

	m.Run()
	opensslSignOpts = []string{"-outform", "DER"}
	opensslEncOpts = []string{"-outform", "DER"}

	// Test ECDDSA
	keypair = keyPairECC

	m.Run()
}

func TestAuthEnrypt(t *testing.T) {

	cms, err := New(keypair)
	if err != nil {
		t.Error(err)
	}

	plaintext := []byte("Hallo Welt!")

	ciphertext, err := cms.AuthEncrypt(plaintext, []*x509.Certificate{keypair.Leaf})
	if err != nil {
		t.Error(err)
	}

	plain, err := cms.AuthDecrypt(ciphertext)
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(plaintext, plain) {
		t.Fatal("Encryption and decryption are not inverse")
	}
}

func TestEnryptDecrypt(t *testing.T) {

	cms, err := New(keypair)
	if err != nil {
		t.Error(err)
	}

	plaintext := []byte("Hallo Welt!")

	ciphertext, err := cms.Encrypt(plaintext, []*x509.Certificate{keypair.Leaf})
	if err != nil {
		t.Error(err)
	}

	plain, err := cms.Decrypt(ciphertext)
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(plaintext, plain) {
		t.Fatal("Encryption and decryption are not inverse")
	}

}

func TestSignVerify(t *testing.T) {

	cms, err := New(keypair)
	if err != nil {
		t.Error(err)
	}

	cms.roots.AddCert(root.Certificate)

	msg := []byte("Hallo Welt!")

	der, err := cms.Sign(msg)
	if err != nil {
		t.Error(err)
	}

	_, err = cms.Verify(der)
	if err != nil {
		t.Error(err)
	}
}

func TestEncryptOpenSSL(t *testing.T) {

	if skipOpenssl {
		return
	}

	message := []byte("Hallo Welt!")

	der, err := openssl.Encrypt(message, keypair.Leaf, opensslEncOpts...)
	if err != nil {
		t.Error(err)
	}

	cms, err := New(keypair)
	plain, err := cms.Decrypt(der)
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(message, plain) {
		t.Fatal("Encryption and decryption are not inverse")
	}

}

func TestDecryptOpenSSL(t *testing.T) {

	if skipOpenssl {
		return
	}

	message := []byte("Hallo Welt!")

	cms, _ := New()
	ciphertext, err := cms.Encrypt(message, []*x509.Certificate{keypair.Leaf})
	if err != nil {
		t.Error(err)
	}

	plain, err := openssl.Decrypt(ciphertext, keypair.PrivateKey, "-inform", "DER")
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(message, plain) {
		t.Fatal("Encryption and decryption are not inverse")
	}

}

func TestSignOpenSSL(t *testing.T) {

	if skipOpenssl {
		return
	}

	message := []byte("Hallo Welt")

	sig, err := openssl.SignDetached(message, keypair.Leaf, keypair.PrivateKey, []*x509.Certificate{intermediate.Certificate}, opensslSignOpts...)
	if err != nil {
		t.Error(err)
	}

	cms, err := New()
	if err != nil {
		t.Error(err)
	}
	cms.roots.AddCert(root.Certificate)

	_, err = cms.Verify(sig)
	if err != nil {
		t.Error(err)
	}
}

func TestVerifyOpenSSL(t *testing.T) {

	if skipOpenssl {
		return
	}

	cms, err := New(keypair)
	if err != nil {
		t.Error(err)
	}

	cms.TimeStamp = true

	cms.roots.AddCert(root.Certificate)

	msg := []byte("Hallo Welt!")

	der, err := cms.Sign(msg)
	if err != nil {
		t.Error(err)
	}

	sig, err := openssl.Verify(der, root.Certificate, "-inform", "DER")
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(msg, sig) {
		t.Fatal("Signed message and message do not agree!")
	}
}
