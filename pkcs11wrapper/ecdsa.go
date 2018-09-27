package pkcs11wrapper

import (
	"encoding/json"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	//"golang.org/x/crypto/pkcs12"

	//"github.com/cloudflare/cfssl/csr"

	"github.com/scottallan/crypto/pkcs12"
	//"golang.org/x/crypto/pbkdf2"
	"github.com/youmark/pkcs8"

	//"github.com/hyperledger/fabric/bccsp"
	//"github.com/hyperledger/fabric/bccsp/utils"

	"os"
)

type EcdsaKey struct {
	PubKey  *ecdsa.PublicKey
	PrivKey *ecdsa.PrivateKey
	SKI     SubjectKeyIdentifier
	Certificate []*x509.Certificate
	//optional
	keyLabel string
	NamedCurveAsString	string
	curveOid	asn1.RawValue
	ephemeral	bool
	exportable	bool
	Token		bool
        asnFullBytes asn1.RawValue


	Req	*CSRInfo
}

type SubjectKeyIdentifier struct {
	Sha1        string
	Sha1Bytes   []byte
	Sha256      string
	Sha256Bytes []byte
}

/*func (csp *impl) signECDSA(k ecdsaPrivateKey, digest []byte, opts bccsp.SignerOpts) (signature []byte, err error) {
	r, s, err := csp.signP11ECDSA(k.ski, digest)
	if err != nil {
		return nil, err
	}

	s, _, err = utils.ToLowS(k.pub.pub, s)
	if err != nil {
		return nil, err
	}

	return utils.MarshalECDSASignature(r, s)
}

func (csp *impl) verifyECDSA(k ecdsaPublicKey, signature, digest []byte, opts bccsp.SignerOpts) (valid bool, err error) {
	r, s, err := utils.UnmarshalECDSASignature(signature)
	if err != nil {
		return false, fmt.Errorf("Failed unmashalling signature [%s]", err)
	}

	lowS, err := utils.IsLowS(k.pub, s)
	if err != nil {
		return false, err
	}

	if !lowS {
		return false, fmt.Errorf("Invalid S. Must be smaller than half the order [%s][%s].", s, utils.GetCurveHalfOrdersAt(k.pub.Curve))
	}

	if csp.softVerify {
		return ecdsa.Verify(k.pub, digest, r, s), nil
	} else {
		return csp.verifyP11ECDSA(k.ski, digest, r, s, k.pub.Curve.Params().BitSize/8)
	}
}*/

// SKI returns the subject key identifier of this key.



func (k *EcdsaKey) GetCSRInfo(jsonFile string) CSRInfo {
	raw, err := ioutil.ReadFile(jsonFile)
	if err != nil {
		fmt.Println("err.Error() %s",jsonFile)
	}

	var host CSRInfo
	err = json.Unmarshal(raw, &host)
	if err != nil {
		fmt.Printf("error unmarshalling json %s\n",err)
	}
	return host


}

func ToJson(p interface{}) string {
    bytes, err := json.Marshal(p)
    if err != nil {
        fmt.Println(err.Error())
        os.Exit(1)
    }
    return string(bytes)
}

func (k *EcdsaKey) GenSKI() {

	if k.PubKey == nil {
		return
	}

	// Marshall the public key
	raw := elliptic.Marshal(k.PubKey.Curve, k.PubKey.X, k.PubKey.Y)

	// Hash it
	hash := sha256.New()
	hash.Write(raw)
	k.SKI.Sha256Bytes = hash.Sum(nil)
	k.SKI.Sha256 = hex.EncodeToString(k.SKI.Sha256Bytes)

	hash = sha1.New()
	hash.Write(raw)
	k.SKI.Sha1Bytes = hash.Sum(nil)
	k.SKI.Sha1 = hex.EncodeToString(k.SKI.Sha1Bytes)
	

	return
}

func (k *EcdsaKey) PublicKey() (Key, error) {
	return k, nil
}

func (k *EcdsaKey) Bytes() (raw []byte, err error) {
	raw, err = x509.MarshalPKIXPublicKey(k.PubKey)
	if err != nil {
		return nil, fmt.Errorf("Failed marshalling key [%s]", err)
	}
	return
}

func (k *EcdsaKey) Generate(namedCurve string) (err error) {

	// generate private key
	switch namedCurve {
	case "P-224":
		k.PrivKey, err = ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	case "P-256":
		k.PrivKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "P-384":
		k.PrivKey, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "P-521":
		k.PrivKey, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	default:
		k.PrivKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}

	// store public key
	k.PubKey = &k.PrivKey.PublicKey

	return
}

func (k *EcdsaKey) ImportPubKeyFromPubKeyFile(file string) (err error) {
	return
}

func (k *EcdsaKey) ImportPubKeyFromCertFile(file string) (err error) {

	certFile, err := ioutil.ReadFile(file)
	if err != nil {
		return
	}

	certBlock, _ := pem.Decode(certFile)
	x509Cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return
	}

	k.PubKey = x509Cert.PublicKey.(*ecdsa.PublicKey)

	return
}

func (k *EcdsaKey) ImportPrivKeyFromP12(file string, password string) (err error) {
	keyFile, err := ioutil.ReadFile(file)
	if err != nil {
		return
	}
	key, cert, err := pkcs12.Decode(keyFile, password)
	if err != nil {
		return
	}
	keyPkcs8, err := pkcs8.ConvertPrivateKeyToPKCS8(key)
	if err != nil {
		return
	}
	if len(cert) != 0 {
		k.Certificate = cert
		for _, certificate := range cert {
			fmt.Printf("\nCertificate[s] Exists in P12 with len of %d value first cert %s\n\n",len(cert), certificate.Subject)
		}
		
	}
	
	if CaseInsensitiveContains(os.Getenv("SECURITY_P11TOOL_DEBUG"), "TRUE") {

		fmt.Printf("\npkcs8 privkey \n%c\n", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyPkcs8}))
		outFile, err := os.Create("out.pem")
		if err != nil {
			return err	
		}
		defer outFile.Close()
		err = pem.Encode(outFile, &pem.Block{Type: "PRIVATE KEY", Bytes: keyPkcs8})
	
		if err != nil {
			return err
		}
	}
	k.PrivKey = key.(*ecdsa.PrivateKey)
	k.PubKey = &k.PrivKey.PublicKey
	
	return
}

func (k *EcdsaKey) ImportPrivKeyFromFile(file string) (err error) {

	keyFile, err := ioutil.ReadFile(file)
	if err != nil {
		return
	}

	keyBlock, _ := pem.Decode(keyFile)
	key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return
	}

	k.PrivKey = key.(*ecdsa.PrivateKey)
	k.PubKey = &k.PrivKey.PublicKey

	return
}

/* returns value for CKA_EC_PARAMS */
func GetECParamMarshaled(namedCurve string) (ecParamMarshaled []byte, err error) {

	// RFC 5480, 2.1.1.1. Named Curve
	//
	// secp224r1 OBJECT IDENTIFIER ::= {
	//   iso(1) identified-organization(3) certicom(132) curve(0) 33 }
	//
	// secp256r1 OBJECT IDENTIFIER ::= {
	//   iso(1) member-body(2) us(840) ansi-X9-62(10045) curves(3)
	//   prime(1) 7 }
	//
	// secp384r1 OBJECT IDENTIFIER ::= {
	//   iso(1) identified-organization(3) certicom(132) curve(0) 34 }
	//
	// secp521r1 OBJECT IDENTIFIER ::= {
	//   iso(1) identified-organization(3) certicom(132) curve(0) 35 }
	//
	// NB: secp256r1 is equivalent to prime256v1

	ecParamOID := asn1.ObjectIdentifier{}

	switch namedCurve {
	case "P-224":
		ecParamOID = asn1.ObjectIdentifier{1, 3, 132, 0, 33}
	case "P-256":
		ecParamOID = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	case "P-384":
		ecParamOID = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	case "P-521":
		ecParamOID = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
	}

	if len(ecParamOID) == 0 {
		err = fmt.Errorf("Error with curve name: %s", namedCurve)
		return
	}

	ecParamMarshaled, err = asn1.Marshal(ecParamOID)
	return
}

func (k *EcdsaKey) namedCurveFromOID(marshaledOID []byte) elliptic.Curve {
	var oid asn1.RawValue
	asn1.Unmarshal(marshaledOID, &oid)
	/*switch {
	case oid.Equal(asn1.ObjectIdentifier{1, 3, 132, 0, 33}):
			return elliptic.P224()
	case oid.Equal(asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}):
			return elliptic.P256()
	case oid.Equal(asn1.ObjectIdentifier{1, 3, 132, 0, 34}):
			return elliptic.P384()
	case oid.Equal(asn1.ObjectIdentifier{1, 3, 132, 0, 35}):
			return elliptic.P521()
	}*/
	fmt.Printf("OID TAG %c \nOID VALUE %c", oid.Tag, oid.Bytes)
	return elliptic.P256()
}

func (k *EcdsaKey) SignMessage(message string) (signature string, err error) {

	// we should always hash the message before signing it
	// TODO: make hash function configurable or detected by key size:
	// https://www.ietf.org/rfc/rfc4754.txt
	// https://tools.ietf.org/html/rfc5656#section-6.2.1
	//  +----------------+----------------+
	//  |   Curve Size   | Hash Algorithm |
	//	+----------------+----------------+
	//  |    b <= 256    |     SHA-256    |
	//  |                |                |
	//  | 256 < b <= 384 |     SHA-384    |
	//  |                |                |
	//  |     384 < b    |     SHA-512    |
	//	+----------------+----------------+
	bs := k.PrivKey.Params().BitSize
	var digest []byte

	switch {

	case bs <= 256:
		d := sha256.Sum256([]byte(message))
		digest = d[:]

	case bs > 256 && bs <= 384:
		d := sha512.Sum384([]byte(message))
		digest = d[:]

	case bs > 384:
		d := sha512.Sum512([]byte(message))
		digest = d[:]
	}

	// sign the hash
	// if the hash length is greater than the key length,
	// then only the first part of the hash that reaches the length of the key will be used
	r, s, err := ecdsa.Sign(rand.Reader, k.PrivKey, digest[:])
	if err != nil {
		return
	}

	// encode the signature {R, S}
	// big.Int.Bytes() will need padding in the case of leading zero bytes
	//params := k.PrivKey.Curve.Params()
	//curveOrderByteSize := params.P.BitLen() / 8
	//rBytes, sBytes := r.Bytes(), s.Bytes()
	//signatureBytes := make([]byte, curveOrderByteSize*2)
	//copy(signatureBytes[curveOrderByteSize-len(rBytes):], rBytes)
	//copy(signatureBytes[curveOrderByteSize*2-len(sBytes):], sBytes)

	signatureBytes := r.Bytes()
	signatureBytes = append(signatureBytes, s.Bytes()...)

	signature = hex.EncodeToString(signatureBytes)

	return
}

func (k *EcdsaKey) VerifySignature(message string, signature string) (verified bool) {

	signatureBytes, err := hex.DecodeString(signature)
	if err != nil {
		return
	}

	// we should always hash the message before signing it
	// TODO: detect what hash function to use by key length:
	// https://www.ietf.org/rfc/rfc4754.txt
	bs := k.PrivKey.Params().BitSize
	var digest []byte

	switch {

	case bs <= 256:
		d := sha256.Sum256([]byte(message))
		digest = d[:]

	case bs > 256 && bs <= 384:
		d := sha512.Sum384([]byte(message))
		digest = d[:]

	case bs > 384:
		d := sha512.Sum512([]byte(message))
		digest = d[:]
	}

	// get curve byte size
	curveOrderByteSize := k.PubKey.Curve.Params().P.BitLen() / 8

	// extract r and s
	r, s := new(big.Int), new(big.Int)
	r.SetBytes(signatureBytes[:curveOrderByteSize])
	s.SetBytes(signatureBytes[curveOrderByteSize:])

	verified = ecdsa.Verify(k.PubKey, digest[:], r, s)

	return
}

func (k *EcdsaKey) DeriveSharedSecret(anotherPublicKey *ecdsa.PublicKey) (secret []byte, err error) {

	x, _ := k.PrivKey.Curve.ScalarMult(anotherPublicKey.X, anotherPublicKey.Y, k.PrivKey.D.Bytes())
	secret = x.Bytes()

	return
}
