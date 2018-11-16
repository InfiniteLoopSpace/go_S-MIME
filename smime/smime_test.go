package smime

import (
	"bytes"
	"crypto/tls"
	"testing"
)

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
