package smime

import (
	"bytes"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log"
	"testing"

	"github.com/InfiniteLoopSpace/go_S-MIME/openssl"
	"github.com/InfiniteLoopSpace/go_S-MIME/pki"
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

func TestEnryptDecrypt(t *testing.T) {

	SMIME, err := New(keyPair)
	if err != nil {
		t.Error(err)
	}

	plaintext := []byte(msg)

	ciphertext, err := SMIME.Encrypt(plaintext, []*x509.Certificate{leaf.Certificate})
	if err != nil {
		t.Error(err)
	}
	fmt.Printf("%s\n", ciphertext)

	plain, err := SMIME.Decrypt(ciphertext)
	if err != nil {
		log.Fatal(err)
	}

	if !bytes.Equal(plaintext, plain) {
		t.Fatal("Encryption and decryption are not inverse")
	}
}

func TestSignVerify(t *testing.T) {
	SMIME, err := New(keyPair)
	if err != nil {
		t.Error(err)
	}

	SMIME.CMS.Opts.Roots.AddCert(root.Certificate)

	msg := []byte(msg)

	der, err := SMIME.Sign(msg)
	if err != nil {
		t.Error(err)
	}

	_, err = SMIME.Verify(der)
	if err != nil {
		t.Error(err)
	}
}

func TestEncryptOpenSSL(t *testing.T) {
	message := []byte("Hallo Welt!")

	der, err := openssl.Encrypt(message, leaf.Certificate)
	if err != nil {
		t.Error(err)
	}

	SMIME, err := New(keyPair)
	plain, err := SMIME.Decrypt(der)
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(message, plain) {
		t.Fatal("Encryption and decryption are not inverse")
	}
}

func TestDecryptOpenSSL(t *testing.T) {
	message := []byte(msg)

	SMIME, _ := New()
	ciphertext, err := SMIME.Encrypt(message, []*x509.Certificate{leaf.Certificate})
	if err != nil {
		t.Error(err)
	}

	plain, err := openssl.Decrypt(ciphertext, leaf.PrivateKey)
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(message, plain) {
		t.Fatal("Encryption and decryption are not inverse")
	}
}

func TestSignOpenSSL(t *testing.T) {
	message := []byte(msg)

	sig, err := openssl.Sign(message, leaf.Certificate, leaf.PrivateKey, []*x509.Certificate{intermediate.Certificate})
	if err != nil {
		t.Error(err)
	}

	SMIME, err := New()
	if err != nil {
		t.Error(err)
	}
	SMIME.CMS.Opts.Roots.AddCert(root.Certificate)

	_, err = SMIME.Verify(sig)
	if err != nil {
		t.Error(err)
	}
}

func TestVerifyOpenSSL(t *testing.T) {
	SMIME, err := New(keyPair)
	if err != nil {
		t.Error(err)
	}

	SMIME.CMS.Opts.Roots.AddCert(root.Certificate)

	msg := []byte(msg)

	der, err := SMIME.Sign(msg)
	if err != nil {
		t.Error(err)
	}

	sig, err := openssl.Verify(der, root.Certificate)
	if err != nil {
		t.Error(err)
	}

	if !bytes.Contains(msg, bytes.Replace(sig, []byte("\r"), nil, -1)) {
		t.Fatal("Signed message and message do not agree!")
	}
}

func TestDecrypt(t *testing.T) {
	cert, err := tls.X509KeyPair([]byte(bobCert), []byte(bobRSAkey))
	if err != nil {
		t.Error(err)
	}

	SMIME, err := New(cert)
	if err != nil {
		t.Error(err)
	}

	plain, err := SMIME.Decrypt([]byte(msg))
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(plain, []byte("This is some sample content.")) {
		t.Fatal("Decrypted plaintext is not correct.")
	}
}

var msg = `MIME-Version: 1.0
Message-Id: <00103112005203.00349@amyemily.ig.com>
Date: Tue, 31 Oct 2000 12:00:52 -0600 (Central Standard Time)
From: User1
To: User2
Subject: Example 5.3
Content-Type: application/pkcs7-mime;
        name=smime.p7m;
        smime-type=enveloped-data
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename=smime.p7m

MIIBHgYJKoZIhvcNAQcDoIIBDzCCAQsCAQAxgcAwgb0CAQAwJjASMRAwDgYDVQQDEwdDYXJ
sUlNBAhBGNGvHgABWvBHTbi7NXXHQMA0GCSqGSIb3DQEBAQUABIGAC3EN5nGIiJi2lsGPcP
2iJ97a4e8kbKQz36zg6Z2i0yx6zYC4mZ7mX7FBs3IWg+f6KgCLx3M1eCbWx8+MDFbbpXadC
DgO8/nUkUNYeNxJtuzubGgzoyEd8Ch4H/dd9gdzTd+taTEgS0ipdSJuNnkVY4/M652jKKHR
LFf02hosdR8wQwYJKoZIhvcNAQcBMBQGCCqGSIb3DQMHBAgtaMXpRwZRNYAgDsiSf8Z9P43
LrY4OxUk660cu1lXeCSFOSOpOJ7FuVyU=`

var bobCert = `-----BEGIN CERTIFICATE-----
MIICJzCCAZCgAwIBAgIQRjRrx4AAVrwR024uzV1x0DANBgkqhkiG9w0BAQUFADASMRAwDg
YDVQQDEwdDYXJsUlNBMB4XDTk5MDkxOTAxMDkwMloXDTM5MTIzMTIzNTk1OVowETEPMA0G
A1UEAxMGQm9iUlNBMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCp4WeYPznVX/Kgk0
FepnmJhcg1XZqRW/sdAdoZcCYXD72lItA1hW16mGYUQVzPt7cIOwnJkbgZaTdt+WUee9mp
MySjfzu7r0YBhjY0MssHA1lS/IWLMQS4zBgIFEjmTxz7XWDE4FwfU9N/U9hpAfEF+Hpw0b
6Dxl84zxwsqmqn6wIDAQABo38wfTAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIFIDAf
BgNVHSMEGDAWgBTp4JAnrHggeprTTPJCN04irp44uzAdBgNVHQ4EFgQU6PS4Z9izlqQq8x
GqKdOVWoYWtCQwHQYDVR0RBBYwFIESQm9iUlNBQGV4YW1wbGUuY29tMA0GCSqGSIb3DQEB
BQUAA4GBAHuOZsXxED8QIEyIcat7QGshM/pKld6dDltrlCEFwPLhfirNnJOIh/uLt359QW
Hh5NZt+eIEVWFFvGQnRMChvVl52R1kPCHWRbBdaDOS6qzxV+WBfZjmNZGjOd539OgcOync
f1EHl/M28FAK3Zvetl44ESv7V+qJba3JiNiPzyvT
-----END CERTIFICATE-----`

var bobRSAkey = `-----BEGIN PRIVATE KEY-----
MIIChQIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAKnhZ5g/OdVf8qCTQV6meY
mFyDVdmpFb+x0B2hlwJhcPvaUi0DWFbXqYZhRBXM+3twg7CcmRuBlpN235ZR572akzJKN/
O7uvRgGGNjQyywcDWVL8hYsxBLjMGAgUSOZPHPtdYMTgXB9T039T2GkB8QX4enDRvoPGXz
jPHCyqaqfrAgMBAAECgYBnzUhMmg2PmMIbZf8ig5xt8KYGHbztpwOIlPIcaw+LNd4Ogngw
y+e6alatd8brUXlweQqg9P5F4Kmy9Bnah5jWMIR05PxZbMHGd9ypkdB8MKCixQheIXFD/A
0HPfD6bRSeTmPwF1h5HEuYHD09sBvf+iU7o8AsmAX2EAnYh9sDGQJBANDDIsbeopkYdo+N
vKZ11mY/1I1FUox29XLE6/BGmvE+XKpVC5va3Wtt+Pw7PAhDk7Vb/s7q/WiEI2Kv8zHCue
UCQQDQUfweIrdb7bWOAcjXq/JY1PeClPNTqBlFy2bKKBlf4hAr84/sajB0+E0R9KfEILVH
IdxJAfkKICnwJAiEYH2PAkA0umTJSChXdNdVUN5qSO8bKlocSHseIVnDYDubl6nA7xhmqU
5iUjiEzuUJiEiUacUgFJlaV/4jbOSnI3vQgLeFAkEAni+zN5r7CwZdV+EJBqRd2ZCWBgVf
JAZAcpw6iIWchw+dYhKIFmioNRobQ+g4wJhprwMKSDIETukPj3d9NDAlBwJAVxhn1grSta
vCunrnVNqcBU+B1O8BiR4yPWnLMcRSyFRVJQA7HCp8JlDV6abXd8vPFfXuC9WN7rOvTKF8
Y0ZB9qANMAsGA1UdDzEEAwIAEA==
-----END PRIVATE KEY-----`
