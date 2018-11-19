package cms

import (
	"bytes"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"log"
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

	keyPair = tls.Certificate{
		Certificate: [][]byte{leaf.Certificate.Raw, intermediate.Certificate.Raw, root.Certificate.Raw},
		PrivateKey:  leaf.PrivateKey.(crypto.PrivateKey),
	}
)

func TestAuthEnrypt(t *testing.T) {

	cms, err := New(keyPair)
	if err != nil {
		t.Error(err)
	}

	plaintext := []byte("Hallo Welt!")

	ciphertext, err := cms.AuthEncrypt(plaintext, []*x509.Certificate{leaf.Certificate})
	if err != nil {
		t.Error(err)
	}

	plain, err := cms.AuthDecrypt(ciphertext)
	if err != nil {
		log.Fatal(err)
	}

	if !bytes.Equal(plaintext, plain) {
		t.Fatal("Encryption and decryption are not inverse")
	}
}

func TestEnryptDecrypt(t *testing.T) {

	cms, err := New(keyPair)
	if err != nil {
		t.Error(err)
	}

	plaintext := []byte("Hallo Welt!")

	ciphertext, err := cms.Encrypt(plaintext, []*x509.Certificate{leaf.Certificate})
	if err != nil {
		t.Error(err)
	}

	plain, err := cms.Decrypt(ciphertext)
	if err != nil {
		log.Fatal(err)
	}

	if !bytes.Equal(plaintext, plain) {
		t.Fatal("Encryption and decryption are not inverse")
	}
}

func TestSignVerify(t *testing.T) {
	cms, err := New(keyPair)
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
	message := []byte("Hallo Welt!")

	der, err := openssl.Encrypt(message, leaf.Certificate, "-outform", "DER")
	if err != nil {
		t.Error(err)
	}

	cms, err := New(keyPair)
	plain, err := cms.Decrypt(der)
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(message, plain) {
		t.Fatal("Encryption and decryption are not inverse")
	}
}

func TestDecryptOpenSSL(t *testing.T) {
	message := []byte("Hallo Welt!")

	cms, _ := New()
	ciphertext, err := cms.Encrypt(message, []*x509.Certificate{leaf.Certificate})
	if err != nil {
		t.Error(err)
	}

	plain, err := openssl.Decrypt(ciphertext, leaf.PrivateKey, "-inform", "DER")
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(message, plain) {
		t.Fatal("Encryption and decryption are not inverse")
	}
}

func TestSignOpenSSL(t *testing.T) {
	message := []byte("Hallo Welt")

	sig, err := openssl.SignDetached(message, leaf.Certificate, leaf.PrivateKey, []*x509.Certificate{intermediate.Certificate}, "-outform", "DER")
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
	cms, err := New(keyPair)
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
