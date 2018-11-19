// Package cms contains high level functions for cryptographic message syntax RFC 5652.
package cms

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"log"
	"time"

	protocol "github.com/InfiniteLoopSpace/go_S-MIME/cms/protocol"
	oid "github.com/InfiniteLoopSpace/go_S-MIME/oid"
	timestamp "github.com/InfiniteLoopSpace/go_S-MIME/timestamp"
)

// CMS is an instance of cms to en-/decrypt and sign/verfiy CMS data
// with the given keyPairs and options.
type CMS struct {
	Intermediate, roots        *x509.CertPool
	Opts                       x509.VerifyOptions
	ContentEncryptionAlgorithm asn1.ObjectIdentifier
	TimeStampServer            string
	TimeStamp                  bool
	keyPairs                   []tls.Certificate
}

// New create a new instance of CMS with given keyPairs.
func New(cert ...tls.Certificate) (cms *CMS, err error) {
	root, err := x509.SystemCertPool()
	intermediate := x509.NewCertPool()
	cms = &CMS{
		Intermediate: intermediate,
		roots:        root,
		Opts: x509.VerifyOptions{
			Intermediates: intermediate,
			Roots:         root,
			CurrentTime:   time.Now(),
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		},
		ContentEncryptionAlgorithm: oid.EncryptionAlgorithmAES128CBC,
		TimeStampServer:            "http://timestamp.digicert.com",
		TimeStamp:                  false,
	}
	cms.keyPairs = cert

	for i := range cms.keyPairs {
		cms.keyPairs[i].Leaf, err = x509.ParseCertificate(cms.keyPairs[i].Certificate[0])
		if err != nil {
			return
		}
	}

	return
}

// Encrypt encrypts data for the recipients and returns DER-encoded ASN.1 ContentInfo.
func (cms *CMS) Encrypt(data []byte, recipients []*x509.Certificate) (der []byte, err error) {

	eci, key, _, err := protocol.NewEncryptedContentInfo(oid.Data, cms.ContentEncryptionAlgorithm, data)
	if err != nil {
		return
	}

	var reciInfos []protocol.RecipientInfo

	for _, recipient := range recipients {
		rInfo := protocol.NewRecipientInfo(recipient, key)
		reciInfos = append(reciInfos, rInfo)
	}

	ed := protocol.NewEnvelopedData(&eci, reciInfos)

	ci, err := ed.ContentInfo()
	if err != nil {
		return
	}

	return ci.DER()
}

// AuthEncrypt AEAD-encrypts data for the recipients and returns DER-encoded ASN.1 ContentInfo.
func (cms *CMS) AuthEncrypt(data []byte, recipients []*x509.Certificate) (der []byte, err error) {

	eci, key, mac, err := protocol.NewEncryptedContentInfo(oid.Data, oid.EncryptionAlgorithmAES128GCM, data)
	if err != nil {
		return
	}

	var reciInfos []protocol.RecipientInfo

	for _, recipient := range recipients {
		rInfo := protocol.NewRecipientInfo(recipient, key)
		reciInfos = append(reciInfos, rInfo)
	}

	ed := protocol.NewAuthEnvelopedData(&eci, reciInfos, mac)

	ci, err := ed.ContentInfo()
	if err != nil {
		return
	}

	return ci.DER()
}

// AuthDecrypt AEAD-decrypts DER-encoded ASN.1 ContentInfo and returns plaintext.
func (cms *CMS) AuthDecrypt(contentInfo []byte) (plain []byte, err error) {
	contInf, err := protocol.ParseContentInfo(contentInfo)
	if err != nil {
		return
	}

	ed, err := contInf.AuthEnvelopedDataContent()
	if err != nil {
		return
	}

	plain, err = ed.Decrypt(cms.keyPairs)

	return
}

// Decrypt decrypts DER-encoded ASN.1 ContentInfo and returns plaintext.
func (cms *CMS) Decrypt(contentInfo []byte) (plain []byte, err error) {
	contInf, err := protocol.ParseContentInfo(contentInfo)
	if err != nil {
		return
	}

	ed, err := contInf.EnvelopedDataContent()
	if err != nil {
		return
	}

	plain, err = ed.Decrypt(cms.keyPairs)

	return
}

// Sign signs the data and returns returns DER-encoded ASN.1 ContentInfo.
func (cms *CMS) Sign(data []byte, detachedSignature ...bool) (der []byte, err error) {

	enci, err := protocol.NewDataEncapsulatedContentInfo(data)
	if err != nil {
		fmt.Println(err)
	}

	sd, err := protocol.NewSignedData(enci)
	if err != nil {
		fmt.Println(err)
	}

	for i := range cms.keyPairs {
		sd.AddSignerInfo(cms.keyPairs[i])
	}

	if cms.TimeStamp {
		err1 := AddTimestamps(sd, cms.TimeStampServer)
		if err1 != nil {
			log.Println(err1)
		}
	}

	if len(detachedSignature) > 0 && detachedSignature[0] {
		sd.EncapContentInfo.EContent = nil
	}

	ci, err := sd.ContentInfo()
	if err != nil {
		return
	}

	return ci.DER()
}

// Verify verifies the signature in contentInfo and returns returns DER-encoded ASN.1 ContentInfo.
func (cms *CMS) Verify(contentInfo []byte) (chains [][][]*x509.Certificate, err error) {
	ci, err := protocol.ParseContentInfo(contentInfo)
	if err != nil {
		return
	}

	sd, err := ci.SignedDataContent()
	if err != nil {
		return
	}

	chains, err = sd.Verify(cms.Opts, nil)

	return
}

// VerifyDetached verifies the detached signature of msg in contentInfo and returns returns DER-encoded ASN.1 ContentInfo.
func (cms *CMS) VerifyDetached(contentInfo, msg []byte) (chains [][][]*x509.Certificate, err error) {

	ci, err := protocol.ParseContentInfo(contentInfo)
	if err != nil {
		return
	}

	sd, err := ci.SignedDataContent()
	if err != nil {
		return
	}

	chains, err = sd.Verify(cms.Opts, msg)

	return
}

// AddTimestamps adds a timestamp to the SignedData using the RFC3161
// timestamping service at the given URL. This timestamp proves that the signed
// message existed the time of generation, allowing verifiers to have more trust
// in old messages signed with revoked keys.
func AddTimestamps(sd *protocol.SignedData, url string) (err error) {
	var attrs = make([]protocol.Attribute, len(sd.SignerInfos))

	// Fetch all timestamp tokens before adding any to sd. This avoids a partial
	// failure.
	for i := range attrs {
		hash, err := sd.SignerInfos[i].Hash()
		if err != nil {
			return err
		}
		tsToken, err := timestamp.FetchTSToken(url, sd.SignerInfos[i].Signature, hash)
		if err != nil {
			return err
		}

		attr, err := protocol.NewAttribute(oid.AttributeTimeStampToken, tsToken)
		if err != nil {
			return err
		}

		attrs[i] = attr
	}

	for i := range attrs {
		sd.SignerInfos[i].UnsignedAttrs = append(sd.SignerInfos[i].UnsignedAttrs, attrs[i])
	}

	return nil
}
