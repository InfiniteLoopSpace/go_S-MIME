package protocol

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"log"
	"time"

	oid "github.com/InfiniteLoopSpace/go_S-MIME/oid"
)

//RecipientInfo ::= CHOICE {
//	ktri KeyTransRecipientInfo,
//	kari [1] KeyAgreeRecipientInfo,
//	kekri [2] KEKRecipientInfo,
//	pwri [3] PasswordRecipientInfo,
//	ori [4] OtherRecipientInfo }
type RecipientInfo struct {
	KTRI  KeyTransRecipientInfo `asn1:"optional"`
	KARI  KeyAgreeRecipientInfo `asn1:"optional,tag:1"` //KeyAgreeRecipientInfo
	KEKRI asn1.RawValue         `asn1:"optional,tag:2"`
	PWRI  asn1.RawValue         `asn1:"optional,tag:3"`
	ORI   asn1.RawValue         `asn1:"optional,tag:4"`
}

func (recInfo *RecipientInfo) decryptKey(keyPair tls.Certificate) (key []byte, err error) {

	return recInfo.KTRI.decryptKey(keyPair)

}

//KeyTransRecipientInfo ::= SEQUENCE {
//	version CMSVersion,  -- always set to 0 or 2
//	rid RecipientIdentifier,
//	keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
//	encryptedKey EncryptedKey }
type KeyTransRecipientInfo struct {
	Version                int
	Rid                    RecipientIdentifier `asn1:"choice"`
	KeyEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedKey           []byte
}

func (ktri *KeyTransRecipientInfo) decryptKey(keyPair tls.Certificate) (key []byte, err error) {

	ias, err := NewIssuerAndSerialNumber(keyPair.Leaf)
	if err != nil {
		return
	}

	ski := keyPair.Leaf.SubjectKeyId

	//version is the syntax version number.  If the SignerIdentifier is
	//the CHOICE issuerAndSerialNumber, then the version MUST be 1.  If
	//the SignerIdentifier is subjectKeyIdentifier, then the version
	//MUST be 3.
	switch ktri.Version {
	case 0:
		if ias.Equal(ktri.Rid.IAS) {
			alg := oid.PublicKeyAlgorithmToEncrytionAlgorithm[keyPair.Leaf.PublicKeyAlgorithm].Algorithm
			if ktri.KeyEncryptionAlgorithm.Algorithm.Equal(alg) {

				decrypter := keyPair.PrivateKey.(crypto.Decrypter)
				return decrypter.Decrypt(rand.Reader, ktri.EncryptedKey, nil)

			}
			log.Println("Key encrytion algorithm not matching")
		}
	case 2:
		if bytes.Equal(ski, ktri.Rid.SKI) {
			alg := oid.PublicKeyAlgorithmToEncrytionAlgorithm[keyPair.Leaf.PublicKeyAlgorithm].Algorithm
			if ktri.KeyEncryptionAlgorithm.Algorithm.Equal(alg) {
				if alg.Equal(oid.EncryptionAlgorithmRSA) {
					return rsa.DecryptPKCS1v15(rand.Reader, keyPair.PrivateKey.(*rsa.PrivateKey), ktri.EncryptedKey)
				}
				log.Println("Unsupported key encrytion algorithm")
			}
			log.Println("Key encrytion algorithm not matching")
		}
	default:
		fmt.Println(ktri.Version)
		return nil, ErrUnsupported
	}

	return nil, nil
}

//RecipientIdentifier ::= CHOICE {
//	issuerAndSerialNumber IssuerAndSerialNumber,
//	subjectKeyIdentifier [0] SubjectKeyIdentifier }
type RecipientIdentifier struct {
	IAS IssuerAndSerialNumber `asn1:"optional"`
	SKI []byte                `asn1:"optional,tag:0"`
}

// NewRecipientInfo creates RecipientInfo for giben recipient and key.
func NewRecipientInfo(recipient *x509.Certificate, key []byte) RecipientInfo {
	version := 0 //issuerAndSerialNumber

	rid := RecipientIdentifier{}

	switch version {
	case 0:
		ias, err := NewIssuerAndSerialNumber(recipient)
		if err != nil {
			log.Fatal(err)
		}
		rid.IAS = ias
	case 2:
		rid.SKI = recipient.SubjectKeyId
	}

	kea := oid.PublicKeyAlgorithmToEncrytionAlgorithm[recipient.PublicKeyAlgorithm]
	if _, ok := oid.PublicKeyAlgorithmToEncrytionAlgorithm[recipient.PublicKeyAlgorithm]; !ok {
		log.Fatal("NewRecipientInfo: PublicKeyAlgorithm not supported")
	}

	encrypted, _ := encryptKey(key, recipient)

	info := RecipientInfo{
		KTRI: KeyTransRecipientInfo{
			Version:                version,
			Rid:                    rid,
			KeyEncryptionAlgorithm: kea,
			EncryptedKey:           encrypted,
		}}
	return info
}

func encryptKey(key []byte, recipient *x509.Certificate) ([]byte, error) {
	if pub := recipient.PublicKey.(*rsa.PublicKey); pub != nil {
		return rsa.EncryptPKCS1v15(rand.Reader, pub, key)
	}
	return nil, ErrUnsupportedAlgorithm
}

// ErrUnsupportedAlgorithm is returned if the algorithm is unsupported.
var ErrUnsupportedAlgorithm = errors.New("cms: cannot decrypt data: unsupported algorithm")

//KeyAgreeRecipientInfo ::= SEQUENCE {
//	version CMSVersion,  -- always set to 3
//	originator [0] EXPLICIT OriginatorIdentifierOrKey,
//	ukm [1] EXPLICIT UserKeyingMaterial OPTIONAL,
//	keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
//	recipientEncryptedKeys RecipientEncryptedKeys }
type KeyAgreeRecipientInfo struct {
	Version                int
	Originator             OriginatorIdentifierOrKey `asn1:"explicit,choice,tag:0"`
	UKM                    []byte                    `asn1:"explicit,optional,tag:1"`
	KeyEncryptionAlgorithm pkix.AlgorithmIdentifier  ``
	RecipientEncryptedKeys []RecipientEncryptedKey   `asn1:"sequence"` //RecipientEncryptedKeys ::= SEQUENCE OF RecipientEncryptedKey
}

//OriginatorIdentifierOrKey ::= CHOICE {
//	issuerAndSerialNumber IssuerAndSerialNumber,
//	subjectKeyIdentifier [0] SubjectKeyIdentifier,
//	originatorKey [1] OriginatorPublicKey }
type OriginatorIdentifierOrKey struct {
	IAS           IssuerAndSerialNumber `asn1:"optional"`
	SKI           []byte                `asn1:"optional,tag:0"`
	OriginatorKey OriginatorPublicKey   `asn1:"optional,tag:1"`
}

//OriginatorPublicKey ::= SEQUENCE {
//	algorithm AlgorithmIdentifier,
//	publicKey BIT STRING
type OriginatorPublicKey struct {
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

//RecipientEncryptedKey ::= SEQUENCE {
//	rid KeyAgreeRecipientIdentifier,
//	encryptedKey EncryptedKey }
type RecipientEncryptedKey struct {
	RID          KeyAgreeRecipientIdentifier `asn1:"choice"`
	EncryptedKey []byte
}

//KeyAgreeRecipientIdentifier ::= CHOICE {
//	issuerAndSerialNumber IssuerAndSerialNumber,
//	rKeyId [0] IMPLICIT RecipientKeyIdentifier }
type KeyAgreeRecipientIdentifier struct {
	IAS    IssuerAndSerialNumber  `asn1:"optional"`
	RKeyID RecipientKeyIdentifier `asn1:"optional,tag:0"`
}

//RecipientKeyIdentifier ::= SEQUENCE {
//	subjectKeyIdentifier SubjectKeyIdentifier,
//	date GeneralizedTime OPTIONAL,
//	other OtherKeyAttribute OPTIONAL }
type RecipientKeyIdentifier struct {
	SubjectKeyIdentifier []byte            //SubjectKeyIdentifier ::= OCTET STRING
	Date                 time.Time         `asn1:"optional"`
	Other                OtherKeyAttribute `asn1:"optional"`
}

//OtherKeyAttribute ::= SEQUENCE {
//	keyAttrId OBJECT IDENTIFIER,
//	keyAttr ANY DEFINED BY keyAttrId OPTIONAL }
type OtherKeyAttribute struct {
	KeyAttrID asn1.ObjectIdentifier
	KeyAttr   asn1.RawValue `asn1:"optional"`
}
