//Package openssl shells out openssl for testing
package openssl

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
)

//Encrypt a message with openssl
func Encrypt(in []byte, cert *x509.Certificate) (der []byte, err error) {

	tmp, err := ioutil.TempFile("", "example")
	defer os.Remove(tmp.Name())

	pem.Encode(tmp, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})

	der, err = openssl(in, "smime", "-outform", "DER", "-encrypt", "-aes128", tmp.Name())

	return
}

//Decrypt a message with openssl
func Decrypt(in []byte, key crypto.PrivateKey) (plain []byte, err error) {

	tmp, err := ioutil.TempFile("", "example")
	defer os.Remove(tmp.Name())

	pem.Encode(tmp, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key.(*rsa.PrivateKey))})

	plain, err = openssl(in, "smime", "-inform", "DER", "-decrypt", "-inkey", tmp.Name())

	return
}

//Create a detached signature with openssl
func SignDetached(in []byte, cert *x509.Certificate, key crypto.PrivateKey, interm ...*x509.Certificate) (plain []byte, err error) {

	tmpCert, err := ioutil.TempFile("", "example")
	defer os.Remove(tmpCert.Name())

	pem.Encode(tmpCert, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})

	tmpKey, err := ioutil.TempFile("", "example")
	defer os.Remove(tmpKey.Name())

	pem.Encode(tmpKey, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key.(*rsa.PrivateKey))})

	tmpInterm, err := ioutil.TempFile("", "example")
	defer os.Remove(tmpInterm.Name())

	for _, i := range interm {
		pem.Encode(tmpInterm, &pem.Block{Type: "CERTIFICATE", Bytes: i.Raw})
	}

	plain, err = openssl(in, "smime", "-sign", "-nodetach", "-outform", "DER", "-signer", tmpCert.Name(), "-inkey", tmpKey.Name(), "-certfile", tmpInterm.Name())

	return
}

//Create a signature with openssl
func Sign(in []byte, cert *x509.Certificate, key crypto.PrivateKey, interm ...*x509.Certificate) (plain []byte, err error) {

	tmpCert, err := ioutil.TempFile("", "example")
	defer os.Remove(tmpCert.Name())

	pem.Encode(tmpCert, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})

	tmpKey, err := ioutil.TempFile("", "example")
	defer os.Remove(tmpKey.Name())

	pem.Encode(tmpKey, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key.(*rsa.PrivateKey))})

	tmpInterm, err := ioutil.TempFile("", "example")
	defer os.Remove(tmpInterm.Name())

	for _, i := range interm {
		pem.Encode(tmpInterm, &pem.Block{Type: "CERTIFICATE", Bytes: i.Raw})
	}

	plain, err = openssl(in, "smime", "-sign", "-outform", "DER", "-signer", tmpCert.Name(), "-inkey", tmpKey.Name(), "-certfile", tmpInterm.Name())

	return
}

//Verify a signature with openssl
func Verify(in []byte, ca *x509.Certificate) (plain []byte, err error) {

	tmpCA, err := ioutil.TempFile("", "example")
	defer os.Remove(tmpCA.Name())

	pem.Encode(tmpCA, &pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})

	plain, err = openssl(in, "smime", "-verify", "-inform", "DER", "-CAfile", tmpCA.Name())

	return
}

func openssl(stdin []byte, args ...string) ([]byte, error) {
	cmd := exec.Command("openssl", args...)

	in := bytes.NewReader(stdin)
	out := &bytes.Buffer{}
	errs := &bytes.Buffer{}

	cmd.Stdin, cmd.Stdout, cmd.Stderr = in, out, errs

	if err := cmd.Run(); err != nil {
		if len(errs.Bytes()) > 0 {
			return nil, fmt.Errorf("error running %s (%s):\n %v", cmd.Args, err, errs.String())
		}
		return nil, err
	}

	return out.Bytes(), nil
}
