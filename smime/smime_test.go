package smime

import (
	"bytes"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"log"
	"strings"
	"testing"

	"github.com/InfiniteLoopSpace/go_S-MIME/cms"
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

//https://github.com/fullsailor/pkcs7/issues/9
func TestSampleiTunesReceipt(t *testing.T) {

	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(iTunesReceipt))
	if err != nil {
		t.Error(err)
	}

	CMS, err := cms.New()
	if err != nil {
		t.Error(err)
	}

	_, err = CMS.Verify(b)
	if err != nil {
		t.Error(err)
	}
}

var iTunesReceipt = `MIITtgYJKoZIhvcNAQcCoIITpzCCE6MCAQExCzAJBgUrDgMCGgUAMIIDVwYJKoZI
hvcNAQcBoIIDSASCA0QxggNAMAoCAQgCAQEEAhYAMAoCARQCAQEEAgwAMAsCAQEC
AQEEAwIBADALAgEDAgEBBAMMATEwCwIBCwIBAQQDAgEAMAsCAQ8CAQEEAwIBADAL
AgEQAgEBBAMCAQAwCwIBGQIBAQQDAgEDMAwCAQoCAQEEBBYCNCswDAIBDgIBAQQE
AgIAjTANAgENAgEBBAUCAwFgvTANAgETAgEBBAUMAzEuMDAOAgEJAgEBBAYCBFAy
NDcwGAIBAgIBAQQQDA5jb20uemhpaHUudGVzdDAYAgEEAgECBBCS+ZODNMHwT1Nz
gWYDXyWZMBsCAQACAQEEEwwRUHJvZHVjdGlvblNhbmRib3gwHAIBBQIBAQQU4nRh
YCEZx70Flzv7hvJRjJZckYIwHgIBDAIBAQQWFhQyMDE2LTA3LTIzVDA2OjIxOjEx
WjAeAgESAgEBBBYWFDIwMTMtMDgtMDFUMDc6MDA6MDBaMD0CAQYCAQEENbR21I+a
8+byMXo3NPRoDWQmSXQF2EcCeBoD4GaL//ZCRETp9rGFPSg1KekCP7Kr9HAqw09m
MEICAQcCAQEEOlVJozYYBdugybShbiiMsejDMNeCbZq6CrzGBwW6GBy+DGWxJI91
Y3ouXN4TZUhuVvLvN1b0m5T3ggQwggFaAgERAgEBBIIBUDGCAUwwCwICBqwCAQEE
AhYAMAsCAgatAgEBBAIMADALAgIGsAIBAQQCFgAwCwICBrICAQEEAgwAMAsCAgaz
AgEBBAIMADALAgIGtAIBAQQCDAAwCwICBrUCAQEEAgwAMAsCAga2AgEBBAIMADAM
AgIGpQIBAQQDAgEBMAwCAgarAgEBBAMCAQEwDAICBq4CAQEEAwIBADAMAgIGrwIB
AQQDAgEAMAwCAgaxAgEBBAMCAQAwGwICBqcCAQEEEgwQMTAwMDAwMDIyNTMyNTkw
MTAbAgIGqQIBAQQSDBAxMDAwMDAwMjI1MzI1OTAxMB8CAgaoAgEBBBYWFDIwMTYt
MDctMjNUMDY6MjE6MTFaMB8CAgaqAgEBBBYWFDIwMTYtMDctMjNUMDY6MjE6MTFa
MCACAgamAgEBBBcMFWNvbS56aGlodS50ZXN0LnRlc3RfMaCCDmUwggV8MIIEZKAD
AgECAggO61eH554JjTANBgkqhkiG9w0BAQUFADCBljELMAkGA1UEBhMCVVMxEzAR
BgNVBAoMCkFwcGxlIEluYy4xLDAqBgNVBAsMI0FwcGxlIFdvcmxkd2lkZSBEZXZl
bG9wZXIgUmVsYXRpb25zMUQwQgYDVQQDDDtBcHBsZSBXb3JsZHdpZGUgRGV2ZWxv
cGVyIFJlbGF0aW9ucyBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTAeFw0xNTExMTMw
MjE1MDlaFw0yMzAyMDcyMTQ4NDdaMIGJMTcwNQYDVQQDDC5NYWMgQXBwIFN0b3Jl
IGFuZCBpVHVuZXMgU3RvcmUgUmVjZWlwdCBTaWduaW5nMSwwKgYDVQQLDCNBcHBs
ZSBXb3JsZHdpZGUgRGV2ZWxvcGVyIFJlbGF0aW9uczETMBEGA1UECgwKQXBwbGUg
SW5jLjELMAkGA1UEBhMCVVMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
AQClz4H9JaKBW9aH7SPaMxyO4iPApcQmyz3Gn+xKDVWG/6QC15fKOVRtfX+yVBid
xCxScY5ke4LOibpJ1gjltIhxzz9bRi7GxB24A6lYogQ+IXjV27fQjhKNg0xbKmg3
k8LyvR7E0qEMSlhSqxLj7d0fmBWQNS3CzBLKjUiB91h4VGvojDE2H0oGDEdU8zeQ
uLKSiX1fpIVK4cCc4Lqku4KXY/Qrk8H9Pm/KwfU8qY9SGsAlCnYO3v6Z/v/Ca/Vb
XqxzUUkIVonMQ5DMjoEC0KCXtlyxoWlph5AQaCYmObgdEHOwCl3Fc9DfdjvYLdmI
HuPsB8/ijtDT+iZVge/iA0kjAgMBAAGjggHXMIIB0zA/BggrBgEFBQcBAQQzMDEw
LwYIKwYBBQUHMAGGI2h0dHA6Ly9vY3NwLmFwcGxlLmNvbS9vY3NwMDMtd3dkcjA0
MB0GA1UdDgQWBBSRpJz8xHa3n6CK9E31jzZd7SsEhTAMBgNVHRMBAf8EAjAAMB8G
A1UdIwQYMBaAFIgnFwmpthhgi+zruvZHWcVSVKO3MIIBHgYDVR0gBIIBFTCCAREw
ggENBgoqhkiG92NkBQYBMIH+MIHDBggrBgEFBQcCAjCBtgyBs1JlbGlhbmNlIG9u
IHRoaXMgY2VydGlmaWNhdGUgYnkgYW55IHBhcnR5IGFzc3VtZXMgYWNjZXB0YW5j
ZSBvZiB0aGUgdGhlbiBhcHBsaWNhYmxlIHN0YW5kYXJkIHRlcm1zIGFuZCBjb25k
aXRpb25zIG9mIHVzZSwgY2VydGlmaWNhdGUgcG9saWN5IGFuZCBjZXJ0aWZpY2F0
aW9uIHByYWN0aWNlIHN0YXRlbWVudHMuMDYGCCsGAQUFBwIBFipodHRwOi8vd3d3
LmFwcGxlLmNvbS9jZXJ0aWZpY2F0ZWF1dGhvcml0eS8wDgYDVR0PAQH/BAQDAgeA
MBAGCiqGSIb3Y2QGCwEEAgUAMA0GCSqGSIb3DQEBBQUAA4IBAQANphvTLj3jWysH
bkKWbNPojEMwgl/gXNGNvr0PvRr8JZLbjIXDgFnf4+LXLgUUrA3btrj+/DUufMut
F2uOfx/kd7mxZ5W0E16mGYZ2+FogledjjA9z/Ojtxh+umfhlSFyg4Cg6wBA3Lbmg
BDkfc7nIBf3y3n8aKipuKwH8oCBc2et9J6Yz+PWY4L5E27FMZ/xuCk/J4gao0pfz
p45rUaJahHVl0RYEYuPBX/UIqc9o2ZIAycGMs/iNAGS6WGDAfK+PdcppuVsq1h1o
bphC9UynNxmbzDscehlD86Ntv0hgBgw2kivs3hi1EdotI9CO/KBpnBcbnoB7OUdF
MGEvxxOoMIIEIjCCAwqgAwIBAgIIAd68xDltoBAwDQYJKoZIhvcNAQEFBQAwYjEL
MAkGA1UEBhMCVVMxEzARBgNVBAoTCkFwcGxlIEluYy4xJjAkBgNVBAsTHUFwcGxl
IENlcnRpZmljYXRpb24gQXV0aG9yaXR5MRYwFAYDVQQDEw1BcHBsZSBSb290IENB
MB4XDTEzMDIwNzIxNDg0N1oXDTIzMDIwNzIxNDg0N1owgZYxCzAJBgNVBAYTAlVT
MRMwEQYDVQQKDApBcHBsZSBJbmMuMSwwKgYDVQQLDCNBcHBsZSBXb3JsZHdpZGUg
RGV2ZWxvcGVyIFJlbGF0aW9uczFEMEIGA1UEAww7QXBwbGUgV29ybGR3aWRlIERl
dmVsb3BlciBSZWxhdGlvbnMgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwggEiMA0G
CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDKOFSmy1aqyCQ5SOmM7uxfuH8mkbw0
U3rOfGOAYXdkXqUHI7Y5/lAtFVZYcC1+xG7BSoU+L/DehBqhV8mvexj/avoVEkkV
CBmsqtsqMu2WY2hSFT2Miuy/axiV4AOsAX2XBWfODoWVN2rtCbauZ81RZJ/GXNG8
V25nNYB2NqSHgW44j9grFU57Jdhav06DwY3Sk9UacbVgnJ0zTlX5ElgMhrgWDcHl
d0WNUEi6Ky3klIXh6MSdxmilsKP8Z35wugJZS3dCkTm59c3hTO/AO0iMpuUhXf1q
arunFjVg0uat80YpyejDi+l5wGphZxWy8P3laLxiX27Pmd3vG2P+kmWrAgMBAAGj
gaYwgaMwHQYDVR0OBBYEFIgnFwmpthhgi+zruvZHWcVSVKO3MA8GA1UdEwEB/wQF
MAMBAf8wHwYDVR0jBBgwFoAUK9BpR5R2Cf70a40uQKb3R01/CF4wLgYDVR0fBCcw
JTAjoCGgH4YdaHR0cDovL2NybC5hcHBsZS5jb20vcm9vdC5jcmwwDgYDVR0PAQH/
BAQDAgGGMBAGCiqGSIb3Y2QGAgEEAgUAMA0GCSqGSIb3DQEBBQUAA4IBAQBPz+9Z
viz1smwvj+4ThzLoBTWobot9yWkMudkXvHcs1Gfi/ZptOllc34MBvbKuKmFysa/N
w0Uwj6ODDc4dR7Txk4qjdJukw5hyhzs+r0ULklS5MruQGFNrCk4QttkdUGwhgAqJ
TleMa1s8Pab93vcNIx0LSiaHP7qRkkykGRIZbVf1eliHe2iK5IaMSuviSRSqpd1V
AKmuu0swruGgsbwpgOYJd+W+NKIByn/c4grmO7i77LpilfMFY0GCzQ87HUyVpNur
+cmV6U/kTecmmYHpvPm0KdIBembhLoz2IYrF+Hjhga6/05Cdqa3zr/04GpZnMBxR
pVzscYqCtGwPDBUfMIIEuzCCA6OgAwIBAgIBAjANBgkqhkiG9w0BAQUFADBiMQsw
CQYDVQQGEwJVUzETMBEGA1UEChMKQXBwbGUgSW5jLjEmMCQGA1UECxMdQXBwbGUg
Q2VydGlmaWNhdGlvbiBBdXRob3JpdHkxFjAUBgNVBAMTDUFwcGxlIFJvb3QgQ0Ew
HhcNMDYwNDI1MjE0MDM2WhcNMzUwMjA5MjE0MDM2WjBiMQswCQYDVQQGEwJVUzET
MBEGA1UEChMKQXBwbGUgSW5jLjEmMCQGA1UECxMdQXBwbGUgQ2VydGlmaWNhdGlv
biBBdXRob3JpdHkxFjAUBgNVBAMTDUFwcGxlIFJvb3QgQ0EwggEiMA0GCSqGSIb3
DQEBAQUAA4IBDwAwggEKAoIBAQDkkakJH5HbHkdQ6wXtXnmELes2oldMVeyLGYne
+Uts9QerIjAC6Bg++FAJ039BqJj50cpmnCRrEdCju+QbKsMflZ56DKRHi1vUFjcz
y8QPTc4UadHJGXL1XQ7Vf1+b8iUDulWPTV0N8WQ1IxVLFVkds5T39pyez1C6wVhQ
Z48ItCD3y6wsIG9wtj8BMIy3Q88PnT3zK0koGsj+zrW5DtleHNbLPbU6rfQPDgCS
C7EhFi501TwN22IWq6NxkkdTVcGvL0Gz+PvjcM3mo0xFfh9Ma1CWQYnEdGILEINB
hzOKgbEwWOxaBDKMaLOPHd5lc/9nXmW8Sdh2nzMUZaF3lMktAgMBAAGjggF6MIIB
djAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUK9Bp
R5R2Cf70a40uQKb3R01/CF4wHwYDVR0jBBgwFoAUK9BpR5R2Cf70a40uQKb3R01/
CF4wggERBgNVHSAEggEIMIIBBDCCAQAGCSqGSIb3Y2QFATCB8jAqBggrBgEFBQcC
ARYeaHR0cHM6Ly93d3cuYXBwbGUuY29tL2FwcGxlY2EvMIHDBggrBgEFBQcCAjCB
thqBs1JlbGlhbmNlIG9uIHRoaXMgY2VydGlmaWNhdGUgYnkgYW55IHBhcnR5IGFz
c3VtZXMgYWNjZXB0YW5jZSBvZiB0aGUgdGhlbiBhcHBsaWNhYmxlIHN0YW5kYXJk
IHRlcm1zIGFuZCBjb25kaXRpb25zIG9mIHVzZSwgY2VydGlmaWNhdGUgcG9saWN5
IGFuZCBjZXJ0aWZpY2F0aW9uIHByYWN0aWNlIHN0YXRlbWVudHMuMA0GCSqGSIb3
DQEBBQUAA4IBAQBcNplMLXi37Yyb3PN3m/J20ncwT8EfhYOFG5k9RzfyqZtAjizU
sZAS2L70c5vu0mQPy3lPNNiiPvl4/2vIB+x9OYOLUyDTOMSxv5pPCmv/K/xZpwUJ
fBdAVhEedNO3iyM7R6PVbyTi69G3cN8PReEnyvFteO3ntRcXqNx+IjXKJdXZD9Zr
1KIkIxH3oayPc4FgxhtbCS+SsvhESPBgOJ4V9T0mZyCKM2r3DYLP3uujL/lTaltk
wGMzd/c6ByxW69oPIQ7aunMZT7XZNn/Bh1XZp5m5MkL72NVxnn6hUrcbvZNCJBIq
xw8dtk2cXmPIS4AXUKqK1drk/NAJBzewdXUhMYIByzCCAccCAQEwgaMwgZYxCzAJ
BgNVBAYTAlVTMRMwEQYDVQQKDApBcHBsZSBJbmMuMSwwKgYDVQQLDCNBcHBsZSBX
b3JsZHdpZGUgRGV2ZWxvcGVyIFJlbGF0aW9uczFEMEIGA1UEAww7QXBwbGUgV29y
bGR3aWRlIERldmVsb3BlciBSZWxhdGlvbnMgQ2VydGlmaWNhdGlvbiBBdXRob3Jp
dHkCCA7rV4fnngmNMAkGBSsOAwIaBQAwDQYJKoZIhvcNAQEBBQAEggEAasPtnide
NWyfUtewW9OSgcQA8pW+5tWMR0469cBPZR84uJa0gyfmPspySvbNOAwnrwzZHYLa
ujOxZLip4DUw4F5s3QwUa3y4BXpF4J+NSn9XNvxNtnT/GcEQtCuFwgJ0o3F0ilhv
MTHrwiwyx/vr+uNDqlORK8lfK+1qNp+A/kzh8eszMrn4JSeTh9ZYxLHE56WkTQGD
VZXl0gKgxSOmDrcp1eQxdlymzrPv9U60wUJ0bkPfrU9qZj3mJrmrkQk61JTe3j6/
QfjfFBG9JG2mUmYQP1KQ3SypGHzDW8vngvsGu//tNU0NFfOqQu4bYU4VpQl0nPtD
4B85NkrgvQsWAQ==`

//https://github.com/fullsailor/pkcs7/issues/11
func TestSCEP(t *testing.T) {

	b, err := base64.StdEncoding.DecodeString(SCEP)
	if err != nil {
		t.Error(err)
	}

	CMS, err := cms.New()
	if err != nil {
		t.Error(err)
	}

	_, err = CMS.Verify(b)
	if err != nil {
		t.Error(err)
	}
}

var SCEP = `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
whTwwUupZAvH5XgaOV+L4c8AAAAAAAA=`
