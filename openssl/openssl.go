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
func Encrypt(in []byte, cert *x509.Certificate, opts ...string) (der []byte, err error) {

	tmp, err := ioutil.TempFile("", "example")
	defer os.Remove(tmp.Name())

	pem.Encode(tmp, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})

	param := []string{"smime", "-encrypt", "-aes128"}
	param = append(param, opts...)
	param = append(param, tmp.Name())
	der, err = openssl(in, param...)

	return
}

//Decrypt a message with openssl
func Decrypt(in []byte, key crypto.PrivateKey, opts ...string) (plain []byte, err error) {

	tmp, err := ioutil.TempFile("", "example")
	defer os.Remove(tmp.Name())

	pem.Encode(tmp, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key.(*rsa.PrivateKey))})

	param := []string{"smime", "-decrypt"}
	param = append(param, opts...)
	param = append(param, []string{"-decrypt", "-inkey", tmp.Name()}...)
	plain, err = openssl(in, param...)

	return
}

//Create a detached signature with openssl
func SignDetached(in []byte, cert *x509.Certificate, key crypto.PrivateKey, interm []*x509.Certificate, opts ...string) (plain []byte, err error) {

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

	param := []string{"smime", "-sign", "-nodetach"}
	param = append(param, opts...)
	param = append(param, []string{"-signer", tmpCert.Name(), "-inkey", tmpKey.Name(), "-certfile", tmpInterm.Name()}...)
	plain, err = openssl(in, param...)

	return
}

//Create a signature with openssl
func Sign(in []byte, cert *x509.Certificate, key crypto.PrivateKey, interm []*x509.Certificate, opts ...string) (plain []byte, err error) {

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

	param := []string{"smime", "-sign"}
	param = append(param, opts...)
	param = append(param, []string{"-signer", tmpCert.Name(), "-inkey", tmpKey.Name(), "-certfile", tmpInterm.Name()}...)
	plain, err = openssl(in, param...)

	return
}

//Verify a signature with openssl
func Verify(in []byte, ca *x509.Certificate, opts ...string) (plain []byte, err error) {

	tmpCA, err := ioutil.TempFile("", "example")
	defer os.Remove(tmpCA.Name())

	pem.Encode(tmpCA, &pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})

	param := []string{"smime", "-verify"}
	param = append(param, opts...)
	param = append(param, []string{"-CAfile", tmpCA.Name()}...)
	plain, err = openssl(in, param...)

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
