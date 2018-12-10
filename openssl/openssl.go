//Package openssl shells out openssl for testing
package openssl

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
)

// SMIME is the commpand used for openssl smime, can be replaces with cms
var SMIME = "smime"

//Encrypt a message with openssl
func Encrypt(in []byte, cert *x509.Certificate, opts ...string) (der []byte, err error) {

	tmpKey, err := ioutil.TempFile("", "example")
	defer os.Remove(tmpKey.Name())

	pem.Encode(tmpKey, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})

	param := []string{SMIME, "-encrypt", "-aes128"}
	param = append(param, opts...)
	param = append(param, tmpKey.Name())
	der, err = openssl(in, param...)

	return
}

//Decrypt a message with openssl
func Decrypt(in []byte, key crypto.PrivateKey, opts ...string) (plain []byte, err error) {

	tmpKey, err := ioutil.TempFile("", "example")
	defer os.Remove(tmpKey.Name())

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return
	}
	pem.Encode(tmpKey, &pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	param := []string{SMIME, "-decrypt"}
	param = append(param, opts...)
	param = append(param, []string{"-inkey", tmpKey.Name()}...)
	plain, err = openssl(in, param...)

	return
}

// SignDetached creates a detached signature with openssl
func SignDetached(in []byte, cert *x509.Certificate, key crypto.PrivateKey, interm []*x509.Certificate, opts ...string) (plain []byte, err error) {

	tmpCert, err := ioutil.TempFile("", "example")
	defer os.Remove(tmpCert.Name())

	pem.Encode(tmpCert, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})

	tmpKey, err := ioutil.TempFile("", "example")
	defer os.Remove(tmpKey.Name())

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return
	}
	pem.Encode(tmpKey, &pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	tmpInterm, err := ioutil.TempFile("", "example")
	defer os.Remove(tmpInterm.Name())

	for _, i := range interm {
		pem.Encode(tmpInterm, &pem.Block{Type: "CERTIFICATE", Bytes: i.Raw})
	}

	param := []string{SMIME, "-sign", "-nodetach"}
	param = append(param, opts...)
	param = append(param, []string{"-signer", tmpCert.Name(), "-inkey", tmpKey.Name(), "-certfile", tmpInterm.Name()}...)
	plain, err = openssl(in, param...)

	return
}

// Sign creates a signature with openssl
func Sign(in []byte, cert *x509.Certificate, key crypto.PrivateKey, interm []*x509.Certificate, opts ...string) (plain []byte, err error) {

	tmpCert, err := ioutil.TempFile("", "example")
	defer os.Remove(tmpCert.Name())

	pem.Encode(tmpCert, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})

	tmpKey, err := ioutil.TempFile("", "example")
	defer os.Remove(tmpKey.Name())

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return
	}
	pem.Encode(tmpKey, &pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	tmpInterm, err := ioutil.TempFile("", "example")
	defer os.Remove(tmpInterm.Name())

	for _, i := range interm {
		pem.Encode(tmpInterm, &pem.Block{Type: "CERTIFICATE", Bytes: i.Raw})
	}

	param := []string{SMIME, "-sign"}
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

	param := []string{SMIME, "-verify"}
	param = append(param, opts...)
	param = append(param, []string{"-CAfile", tmpCA.Name()}...)
	plain, err = openssl(in, param...)

	return
}

// Openssl runs the openssl command with given args
func Openssl(stdin []byte, args ...string) ([]byte, error) {
	return openssl(stdin, args...)
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

	if strings.Contains(errs.String(), "Error") {
		return nil, fmt.Errorf("error running %s (%s):\n ", cmd.Args, errs.String())
	}

	return out.Bytes(), nil
}
