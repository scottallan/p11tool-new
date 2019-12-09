package pkcs11wrapper

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/cloudflare/cfssl/csr" //"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/hyperledger/fabric/bccsp/utils"
	"github.com/miekg/pkcs11"
	"github.com/olekukonko/tablewriter"
	"io"
	"io/ioutil"
	"math/big"
	"net"
	"net/mail"
	"os"
	"strings"
)

type Pkcs11Library struct {
	Path string
	Info pkcs11.Info
}

type Pkcs11Wrapper struct {

	// Context
	Library Pkcs11Library
	Context *pkcs11.Ctx

	// Session Handler
	SlotLabel string
	Session   pkcs11.SessionHandle

	// Optional Slot Login
	SlotPin string
}

type Pkcs11Object struct {
	ObjectHandle pkcs11.ObjectHandle

	// Some human readable attributes
	Count     string
	CKA_CLASS string
	CKA_LABEL string
	CKA_ID    string
}

// A BasicP11Request contains the algorithm and key size for a new CSR Generation.
type BasicP11Request struct {
	A string `json:"algo" yaml:"algo"`
	S int    `json:"size" yaml:"size"`
}

type BasicKeyRequest struct {
	Algo string `json:"algo" yaml:"algo"`
	Size int    `json:"size" yaml:"size"`
}

type Key interface {

	// SKI returns the subject key identifier of this key.
	GenSKI()

	PublicKey() (Key, error)

	Bytes() ([]byte, error)

	//Fix Function to be Generic
	//Generate()

}

type EnrollmentRequest struct {
	// The identity name to enroll
	Name string `json:"name" skip:"true"`
	// The secret returned via Register
	Secret string `json:"secret,omitempty" skip:"true" mask:"password"`
	// Profile is the name of the signing profile to use in issuing the certificate
	Profile string `json:"profile,omitempty" help:"Name of the signing profile to use in issuing the certificate"`
	// Label is the label to use in HSM operations
	Label string `json:"label,omitempty" help:"Label to use in HSM operations"`
	// CSR is Certificate Signing Request info
	CSR *CSRInfo `json:"csr,omitempty" help:"Certificate Signing Request info"`
	// CAName is the name of the CA to connect to
	CAName string `json:"caname,omitempty" skip:"true"`
	// AttrReqs are requests for attributes to add to the certificate.
	// Each attribute is added only if the requestor owns the attribute.
	AttrReqs []*AttributeRequest `json:"attr_reqs,omitempty"`
}

type CertificateRequest struct {
	CN           string
	Names        []Name     `json:"names" yaml:"names"`
	Hosts        []string   `json:"hosts" yaml:"hosts"`
	KeyRequest   KeyRequest `json:"key,omitempty" yaml:"key,omitempty"`
	CA           *CAConfig  `json:"ca,omitempty" yaml:"ca,omitempty"`
	SerialNumber string     `json:"serialnumber,omitempty" yaml:"serialnumber,omitempty"`
}

type Name struct {
	C            string `json:"c" yaml:"C"`   // Country
	ST           string `json:"st" yaml:"ST"` // State
	L            string `json:"l" yaml:"ST"`  // Locality
	O            string `json:"o" yaml:"O"`   // OrganisationName
	OU           string `json:"ou" yaml:"OU"` // OrganisationalUnitName
	SerialNumber string `json:"serialnumber" yame:"serialnumber"`
}

// A KeyRequest is a generic request for a new key.
type KeyRequest interface {
	Algo() string
	Size() int
	Generate() (crypto.PrivateKey, error)
	SigAlgo() x509.SignatureAlgorithm
}

// CAConfig is a section used in the requests initialising a new CA.
type CAConfig struct {
	PathLength  int    `json:"pathlen" yaml:"pathlen"`
	PathLenZero bool   `json:"pathlenzero" yaml:"pathlenzero"`
	Expiry      string `json:"expiry" yaml:"expiry"`
	Backdate    string `json:"backdate" yaml:"backdate"`
}

type CSRInfo struct {
	CN           string           `json:"CN"`
	Names        []Name           `json:"names,omitempty"`
	Hosts        []string         `json:"hosts,omitempty"`
	KeyRequest   *BasicP11Request `json:"key,omitempty"`
	CA           *CAConfig        `json:"ca,omitempty"`
	SerialNumber string           `json:"serial_number,omitempty"`
}

type AttributeRequest struct {
	Name     string `json:"name"`
	Optional bool   `json:"optional,omitempty"`
}

type NewMechanism struct {
	p11Mech		uint
	mechParam	[]byte
}

const (
	privateKeyFlag = true
	publicKeyFlag  = false
)

// maps used to convert object into human readable text
var CKA_KEY_TYPE_MAP map[byte]string
var CKA_CLASS_MAP map[uint]string
var CKA_PKCS11_CLASS_MAP map[string]uint
var CKM_MECH_MAP map[string]uint
var CKM_NEWMECH_MAP map[string]NewMechanism

func init() {

	// set up values for CKA_KEY_TYPE
	CKA_KEY_TYPE_MAP = map[byte]string{
		pkcs11.CKK_GENERIC_SECRET: "CKK_GENERIC_SECRET",
		pkcs11.CKK_AES:            "CKK_AES",
		pkcs11.CKK_DES3:           "CKK_DES3",
		pkcs11.CKK_RSA:            "CKK_RSA",
		pkcs11.CKK_ECDSA:          "CKK_ECDSA",
		pkcs11.CKK_SHA256_HMAC:    "CKK_SHA256_HMAC",
		pkcs11.CKK_SHA384_HMAC:    "CKK_SHA384_HMAC",
		pkcs11.CKK_SHA512_HMAC:    "CKK_SHA512_HMAC",
		255:                       "CERTIFICATE",
	}

	// set up values for CKA_CLASS
	CKA_CLASS_MAP = map[uint]string{
		pkcs11.CKO_CERTIFICATE: "CKO_CERTIFICATE",
		pkcs11.CKO_PUBLIC_KEY:  "CKO_PUBLIC_KEY",
		pkcs11.CKO_PRIVATE_KEY: "CKO_PRIVATE_KEY",
		pkcs11.CKO_SECRET_KEY:  "CKO_SECRET_KEY",
		pkcs11.CKO_DATA:        "CKO_DATA",
	}

	//Setup Class Constants for Class as String
	CKA_PKCS11_CLASS_MAP = map[string]uint{
		"CKO_PRIVATE_KEY": pkcs11.CKO_PRIVATE_KEY,
		"CKO_PUBLIC_KEY":  pkcs11.CKO_PUBLIC_KEY,
		"CKO_SECRET_KEY":  pkcs11.CKO_SECRET_KEY,
		"CKO_CERTIFICATE": pkcs11.CKO_CERTIFICATE,
	}

	//Setup Mechanism MAP as String
	CKM_MECH_MAP = map[string]uint{
		"CKM_AES_CBC_PAD": pkcs11.CKM_AES_CBC_PAD,
		"CKM_AES_KEY_WRAP_PAD": pkcs11.CKM_AES_KEY_WRAP_PAD,
		"CKM_AES_KEY_WRAP": pkcs11.CKM_AES_KEY_WRAP,
	}

	//Setup NewMechanism MAP as String
	CKM_NEWMECH_MAP = map[string]NewMechanism{
		"CKM_AES_CBC_PAD": {pkcs11.CKM_AES_CBC_PAD, make([]byte, 16)},
		"CKM_AES_KEY_WRAP_PAD": {pkcs11.CKM_AES_KEY_WRAP_PAD, make([]byte, 16)},
		"CKM_AES_KEY_WRAP": {pkcs11.CKM_AES_KEY_WRAP, nil},
	}
}

// Initialize pkcs11 context
func (p11w *Pkcs11Wrapper) InitContext() (err error) {

	// check if lib file exists
	if _, err = os.Stat(p11w.Library.Path); os.IsNotExist(err) {
		return
	}

	// try to initialize
	p11w.Context = pkcs11.New(p11w.Library.Path)
	err = p11w.Context.Initialize()
	if err != nil {
		return
	}

	// get library info
	p11w.Library.Info, err = p11w.Context.GetInfo()

	return

}

// Initialize Session to slot
func (p11w *Pkcs11Wrapper) InitSession() (err error) {

	// Look for provided slot
	slot, _, err := FindSlotByLabel(p11w.Context, p11w.SlotLabel)
	if err != nil {
		return
	}

	// Create session for matching slot
	p11w.Session, err = p11w.Context.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)

	return

}

// This will perform a login
func (p11w *Pkcs11Wrapper) Login() (err error) {

	err = p11w.Context.Login(p11w.Session, pkcs11.CKU_USER, p11w.SlotPin)

	// ignore login error CKR_USER_ALREADY_LOGGED_IN
	if err != nil && strings.Contains(err.Error(), "CKR_USER_ALREADY_LOGGED_IN") {
		err = nil
	}

	return
}

// This should return a list of object handlers and true if more than max
func (p11w *Pkcs11Wrapper) FindObjects(template []*pkcs11.Attribute, max int) (p11ObjHandlers []pkcs11.ObjectHandle, moreThanMax bool, err error) {

	// start the search for object
	err = p11w.Context.FindObjectsInit(
		p11w.Session,
		template,
	)
	if err != nil {
		return
	}

	// continue the search, get object handlers
	p11ObjHandlers, moreThanMax, err = p11w.Context.FindObjects(p11w.Session, max)
	if err != nil {
		return
	}

	// finishes the search
	err = p11w.Context.FindObjectsFinal(p11w.Session)
	if err != nil {
		return
	}

	return
}

/* Exit with message and code 1 */
func ExitWithMessage(message string, err error) {

	if err == nil {
		fmt.Printf("\nFatal Error: %s\n", message)
	} else {
		fmt.Printf("\nFatal Error: %s\n%s\n", message, err)
	}
	os.Exit(1)
}

/* returns true if substr is in string s */
func CaseInsensitiveContains(s, substr string) bool {
	s, substr = strings.ToUpper(s), strings.ToUpper(substr)
	return strings.Contains(s, substr)
}

/* Return the slotID of token label */
func FindSlotByLabel(p *pkcs11.Ctx, slotLabel string) (slot uint, index int, err error) {

	var slotFound bool

	// Get list of slots
	slots, err := p.GetSlotList(true)
	if err == nil {

		//fmt.Printf("PKCS11 provider found %d slots\n", len(slots))

		// Look for matching slot label
		for i, s := range slots {
			tInfo, errGt := p.GetTokenInfo(s)
			if errGt != nil {
				//ExitWithMessage(fmt.Sprintf("getting TokenInfo slot: %d", s), err)
				err = errGt
				return
			}
			if slotLabel == tInfo.Label {
				slotFound = true
				slot = s
				index = i
				fmt.Printf("PKCS11 provider found specified slot label: %s (slot: %d, index: %d)\n", slotLabel, slot, i)
				break
			}
		}
	}

	// set error if slot not found
	if !slotFound {
		err = errors.New(fmt.Sprintf("Could not find slot with label: %s", slotLabel))
	}

	return
}

//DeleteObj Delete Objects from PKCS11 Token
func (p11w *Pkcs11Wrapper) DeleteObj(objClass string, keyLabel string) (err error) {
	var keyTemplate []*pkcs11.Attribute
	if objClass == "ALL" {
		keyTemplate = []*pkcs11.Attribute{}
	} else {
		fmt.Printf("Searching for Label: %s , ObjClass %s\n", keyLabel, objClass)
		keyTemplate = []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, decodeP11Class(objClass)),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyLabel),
		}
	}

	// start the search for object
	err = p11w.Context.FindObjectsInit(
		p11w.Session,
		keyTemplate,
	)
	if err != nil {
		return err
	}

	// continue the search, get object handlers
	p11ObjHandlers, _, err := p11w.Context.FindObjects(p11w.Session, 1000)
	if err != nil {
		fmt.Printf("Cannot Find Objects %v\n", err)
		return
	}
	fmt.Printf("found %v objects\n", len(p11ObjHandlers))

	// finishes the search
	err = p11w.Context.FindObjectsFinal(p11w.Session)
	if err != nil {
		return
	}
	for _, obj := range p11ObjHandlers {

		err := p11w.Context.DestroyObject(
			p11w.Session,
			obj,
		)
		if err != nil {
			fmt.Printf("Unable to Destroy Object : %v", err)
			return err
		}
	}

	return
}

// List content of slot
func (p11w *Pkcs11Wrapper) ListObjects(template []*pkcs11.Attribute, max int) {

	// do an object search
	objects, _, err := p11w.FindObjects(template, max)

	if err != nil {
		fmt.Println("Could not find any objects:", err)
	} else {

		// prepare table headers
		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"COUNT", "CKA_CLASS", "CKA_LABEL", "CKA_ID", "CKA_KEY_TYPE", "CKA_KEY_LEN", "CKA_SUBJECT", "CKA_ISSUER"})
		table.SetCaption(true, fmt.Sprintf("Total objects found (max %d): %d", max, len(objects)))

		// populate table data
		for i, k := range objects {
			var ckaValueLen, ckaKeyType, ckaSubject, ckaIssuer []*pkcs11.Attribute
			al, err := p11w.Context.GetAttributeValue(
				p11w.Session,
				k,
				[]*pkcs11.Attribute{
					pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
					pkcs11.NewAttribute(pkcs11.CKA_ID, nil),
					pkcs11.NewAttribute(pkcs11.CKA_CLASS, nil),
					//pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, nil),
					//	pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, nil),
				},
			)

			if err != nil {
				panic(err)
			}
			if DecodeCKACLASS(al[2].Value[0]) == "CKO_SECRET_KEY" {
				ckaValueLen, err = p11w.Context.GetAttributeValue(
					p11w.Session,
					k,
					[]*pkcs11.Attribute{
						pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, nil),
					},
				)

				if err != nil {
					ckaValueLen = []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, 0)}
					//panic(err)
				}

			} else {
				ckaValueLen = []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, 0)}
			}

			if DecodeCKACLASS(al[2].Value[0]) == "CKO_CERTIFICATE" {
				ckaKeyType = []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, 255)}
				ckaSubject, err = p11w.Context.GetAttributeValue(
					p11w.Session,
					k,
					[]*pkcs11.Attribute{
						pkcs11.NewAttribute(pkcs11.CKA_SUBJECT, nil),
					},
				)

				if err != nil {
					panic(err)
				}
				ckaIssuer, err = p11w.Context.GetAttributeValue(
					p11w.Session,
					k,
					[]*pkcs11.Attribute{
						pkcs11.NewAttribute(pkcs11.CKA_ISSUER, nil),
					},
				)

			} else {
				ckaKeyType, err = p11w.Context.GetAttributeValue(
					p11w.Session,
					k,
					[]*pkcs11.Attribute{
						pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, nil),
					},
				)

				if err != nil {
					panic(err)
				}
				ckaSubject = []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_SUBJECT, "NOT APPLICABLE FOR NON CKO_CERTIFICATE")}
				ckaIssuer = []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_ISSUER, "NOT APPLICABLE FOR NON CKO_CERTIFICATE")}
			}

			// CKA_VALUE_LEN returns an 8 byte slice, lets convert that into a uint64 (8x8 bits)
			keyLength, _ := binary.Uvarint(ckaValueLen[0].Value[0:8])
			if CaseInsensitiveContains(os.Getenv("SECURITY_P11TOOL_DEBUG"), "TRUE") {
				table.Append(
					[]string{
						fmt.Sprintf("%03d", i+1),
						DecodeCKACLASS(al[2].Value[0]),
						fmt.Sprintf("%s", al[0].Value),
						fmt.Sprintf("%x", al[1].Value),
						DecodeCKAKEY(ckaKeyType[0].Value[0]),
						fmt.Sprintf("%d", keyLength),
						fmt.Sprintf("%c", ckaSubject[0].Value),
						fmt.Sprintf("%c", ckaIssuer[0].Value),
					},
				)
			} else {
				table.Append(
					[]string{
						fmt.Sprintf("%03d", i+1),
						DecodeCKACLASS(al[2].Value[0]),
						fmt.Sprintf("%s", al[0].Value),
						fmt.Sprintf("%x", al[1].Value),
						DecodeCKAKEY(ckaKeyType[0].Value[0]),
						fmt.Sprintf("%d", keyLength),
						fmt.Sprint(""),
						fmt.Sprint(""),
					},
				)
			}
		}

		// render table
		table.Render()

	}
}

func DecodeCKAKEY(b byte) string {

	name, present := CKA_KEY_TYPE_MAP[b]
	if present {
		return name
	} else {
		return "UNKNOWN"
	}

}

func DecodeCKACLASS(b byte) string {

	key := uint(b)
	name, present := CKA_CLASS_MAP[key]
	if present {
		return name
	} else {
		return "UNKNOWN"
	}

}

func decodeP11Class(s string) uint {

	val, present := CKA_PKCS11_CLASS_MAP[s]
	if present {
		return val
	} else {
		return 0
	}
}

func decodeP11Mech(s string, t string) NewMechanism {
        var defaultMech NewMechanism
	switch t {
	case "DES3":
		defaultMech = NewMechanism{pkcs11.CKM_DES3_CBC_PAD, make([]byte, 8)}
	case "AES":
		defaultMech = NewMechanism{pkcs11.CKM_AES_CBC_PAD, make([]byte, 16)}
	default:
		defaultMech = NewMechanism{pkcs11.CKM_DES3_CBC_PAD, make([]byte, 8)}
	}
	val, present := CKM_NEWMECH_MAP[s]
	if present {
		return val
	}else{
		return defaultMech
	}
}

var (
	// ans1 p12 bags
	// see https://tools.ietf.org/html/rfc7292#appendix-D
	oidCertTypeX509Certificate = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 9, 22, 1})
	oidPKCS8ShroundedKeyBag    = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 12, 10, 1, 2})
	oidCertBag                 = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 12, 10, 1, 3})
)

func GetCert(certFile string) (cert []*x509.Certificate) {

	raw, err := ioutil.ReadFile(certFile)
	if err != nil {
		fmt.Println("err.Error() %s", certFile)
	}
	var trustedCerts []*x509.Certificate
	p, rest := pem.Decode(raw)
	for (len(rest)) > 0 {
		block, r := pem.Decode(rest)
		trustedCert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			panic("failed to parse certificate: " + err.Error())
		}
		trustedCerts = append(trustedCerts, trustedCert)
		rest = r
	}
	fmt.Printf("length of chain: %d", len(trustedCerts))
	fmt.Printf("\nCertificate \n%c\n", pem.EncodeToMemory(p))
	c, err := x509.ParseCertificate(p.Bytes)
	if err != nil {
		panic("failed to parse certificate: " + err.Error())
	}
	cert = append(cert, c)
	for _, trc := range trustedCerts {
		cert = append(cert, trc)
	}
	return
}

func (p11w *Pkcs11Wrapper) ImportCertificate(ec EcdsaKey) (err error) {

	if ec.Certificate == nil {
		err = errors.New("no cert to import")
		return
	}

	//TODO calculate from key in cert
	for i, cert := range ec.Certificate {
		if ec.SKI.Sha256Bytes == nil { //True when Importing from a P12 as we have not calculated yet.  On direct import we use keyLabel to calc
			if i == 0 {
				ec.GenSKI()
			} else {
				ec.SKI.Sha256Bytes = cert.SubjectKeyId
			}
		} else if i != 0 {
			ec.SKI.Sha256Bytes = cert.SubjectKeyId
			// SKI is set but need to use for first in chain only otherwise take from cert.SubjectKeyIdentifier
			//Otherwise take the SKI from already set struct
			//if i == 0 {ec.GenSKI()}
		} else if i == 0 { //SKI is SET and the Cert Count is 0 so use what was set
			//Confirm KEY exists for cert[0] otherwise exit.
			_, err = p11w.findKeyPairFromSKI(ec.SKI.Sha256Bytes, true)
			if err != nil {
				fmt.Printf("Private Key not found for Certificate %s\n", err)
				os.Exit(1)
			}
		}
		certSearchTpl := []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),
			pkcs11.NewAttribute(pkcs11.CKA_ID, ec.SKI.Sha256Bytes),
		}

		var c []pkcs11.ObjectHandle
		c, _, err = p11w.FindObjects(certSearchTpl, 1)
		if err != nil {
			fmt.Printf("Unaable to search for Objects on Token %s\n", err)
			os.Exit(1)
		}
		if len(c) > 0 {
			fmt.Printf("Found %d existing object(s) with same CKA_ID!!! Exiting", len(c))
			os.Exit(1)
		}

		keyTemplate := []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),
			pkcs11.NewAttribute(pkcs11.CKA_CERTIFICATE_TYPE, pkcs11.CKC_X_509),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			pkcs11.NewAttribute(pkcs11.CKA_SUBJECT, cert.RawSubject),
			pkcs11.NewAttribute(pkcs11.CKA_ISSUER, cert.RawIssuer),
			//pkcs11.NewAttribute(pkcs11.CKA_VALUE, cert.RawTBSCertificate),
			pkcs11.NewAttribute(pkcs11.CKA_VALUE, cert.Raw),
			pkcs11.NewAttribute(pkcs11.CKA_ID, ec.SKI.Sha256Bytes),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, cert.Subject.CommonName),
		}
		//TODO: Confirm Cert doesnt already exist before importing

		_, err = p11w.Context.CreateObject(p11w.Session, keyTemplate)
		if err == nil {
			fmt.Printf("Object was imported with CKA_LABEL:%s\n", cert.Subject)
		}

	}
	return

}

func (p11w *Pkcs11Wrapper) ImportECKey(ec EcdsaKey) (err error) {

	if ec.PrivKey == nil {
		err = errors.New("no key to import")
		return
	}

	ec.GenSKI()

	marshaledOID, err := GetECParamMarshaled(ec.PrivKey.Params().Name)
	if err != nil {
		return
	}

	// pubkey import
	ecPt := elliptic.Marshal(ec.PubKey.Curve, ec.PubKey.X, ec.PubKey.Y)
	// Add DER encoding for the CKA_EC_POINT
	ecPt = append([]byte{0x04, byte(len(ecPt))}, ecPt...)

	keyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, false),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, ec.Token),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, marshaledOID),

		pkcs11.NewAttribute(pkcs11.CKA_ID, ec.SKI.Sha256Bytes),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, ec.keyLabel),
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, ecPt),
	}

	_, err = p11w.Context.CreateObject(p11w.Session, keyTemplate)
	if err != nil {
		fmt.Printf("Public Object FAILED TO IMPORT with CKA_LABEL:%s CKA_ID:%x\n ERROR %s \n", ec.keyLabel, ec.SKI.Sha256Bytes, err)
		return
	} else {
		fmt.Printf("Public Object was imported with CKA_LABEL:%s CKA_ID:%x\n", ec.keyLabel, ec.SKI.Sha256Bytes)
	}

	keyTemplate = []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, ec.Token),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, marshaledOID),

		pkcs11.NewAttribute(pkcs11.CKA_ID, ec.SKI.Sha256Bytes),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, ec.keyLabel),
		pkcs11.NewAttribute(pkcs11.CKR_ATTRIBUTE_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, ec.PrivKey.D.Bytes()),

		// implicitly enable derive for now
		//pkcs11.NewAttribute(pkcs11.CKA_DERIVE, true),
	}

	_, err = p11w.Context.CreateObject(p11w.Session, keyTemplate)
	if err != nil {
		fmt.Printf("Private Object FAILED TO IMPORT with CKA_LABEL:%s CKA_ID:%x\n ERROR %s \n", ec.keyLabel, ec.SKI.Sha256Bytes, err)
		return
	} else {
		fmt.Printf("Private Object was imported with CKA_LABEL:%s CKA_ID:%x\n", ec.keyLabel, ec.SKI.Sha256Bytes)
	}
	return

}

func (p11w *Pkcs11Wrapper) ImportRSAKey(rsa RsaKey) (err error) {

	if rsa.PrivKey == nil {
		err = errors.New("no key to import")
		return
	}

	rsa.GenSKI()

	// pubkey import
	pubExpBytes := big.NewInt(int64(rsa.PubKey.E)).Bytes()

	keyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, rsa.PubKey.N.Bytes()),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, pubExpBytes),

		pkcs11.NewAttribute(pkcs11.CKA_ID, rsa.SKI.Sha256Bytes),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, rsa.SKI.Sha256),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, false),
	}

	_, err = p11w.Context.CreateObject(p11w.Session, keyTemplate)
	if err != nil {
		return
	} else {
		fmt.Printf("Object was imported with CKA_LABEL:%s CKA_ID:%x\n", rsa.SKI.Sha256, rsa.SKI.Sha256Bytes)
	}

	keyTemplate = []*pkcs11.Attribute{
		// According to: https://www.cryptsoft.com/pkcs11doc/v220/group__SEC__12__1__3__RSA__PRIVATE__KEY__OBJECTS.html
		// if a particular token stores values only for the CKA_PRIVATE_EXPONENT, CKA_PRIME_1, and CKA_PRIME_2 attributes,
		// then Cryptoki is certainly able to report values for all the attributes above (since they can all be computed
		// efficiently from these three values).
		// However, a Cryptoki implementation may or may not actually do this extra computation.
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, rsa.PrivKey.N.Bytes()),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, pubExpBytes),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE_EXPONENT, rsa.PrivKey.D.Bytes()),
		pkcs11.NewAttribute(pkcs11.CKA_PRIME_1, rsa.PrivKey.Primes[0].Bytes()),
		pkcs11.NewAttribute(pkcs11.CKA_PRIME_2, rsa.PrivKey.Primes[1].Bytes()),

		pkcs11.NewAttribute(pkcs11.CKA_ID, rsa.SKI.Sha256Bytes),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, rsa.SKI.Sha256),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, true),

		// Error: pkcs11: 0x12: CKR_ATTRIBUTE_TYPE_INVALID
		//pkcs11.NewAttribute(pkcs11.CKR_ATTRIBUTE_SENSITIVE, false),
	}

	_, err = p11w.Context.CreateObject(p11w.Session, keyTemplate)
	if err == nil {
		fmt.Printf("Object was imported with CKA_LABEL:%s CKA_ID:%x\n", rsa.SKI.Sha256, rsa.SKI.Sha256Bytes)
	}
	return

}

func (p11w *Pkcs11Wrapper) ImportECKeyFromFile(file string, keyStore string, keyStorepass string, keyLabel string) (err error) {

	// read in key from file
	//ec := EcdsaKey{}
	var ec EcdsaKey

	//err = ec.ImportPrivKeyFromFile(file)
	switch keyStore {
	case "p12":
		ec = EcdsaKey{}
		ec.keyLabel = keyLabel
		err = ec.ImportPrivKeyFromP12(file, keyStorepass)
		if err != nil {
			return err
		}
	default:
		ec = EcdsaKey{}
		ec.keyLabel = keyLabel
		err = ec.ImportPrivKeyFromFile(file)
		if err != nil {
			return err
		}
	}

	// import key to hsm
	ec.Token = true
	err = p11w.ImportECKey(ec)
	if len(ec.Certificate) != 0 {
		err = p11w.ImportCertificate(ec)
	}

	return

}

//UnWrapRSAKeyFromFile takes a RSA Key from file imput and unwraps onto an HSM
func (p11w *Pkcs11Wrapper) UnWrapRSAKeyFromFile(file string, keyStore string, keyStorepass string, keyLabel string, w pkcs11.ObjectHandle) (err error) {
	// read in key from file
	//ec := EcdsaKey{}
	var rsa RsaKey
	

	//err = ec.ImportPrivKeyFromFile(file)
	switch keyStore {
	/*case "p12":
		ec = EcdsaKey{}
		ec.keyLabel = keyLabel
		err = ec.ImportPrivKeyFromP12(file, keyStorepass)
		if err != nil {
			return err
		}*/
	default:
		rsa = RsaKey{}
		rsa.keyLabel = keyLabel
		err = rsa.ImportPrivKeyFromFile(file)
		if err != nil {
			return err
		}
	}

	rsa.Token = true

	wrappedKey, err := p11w.WrapRSAKey(&rsa, w)
	//_, err = p11w.WrapRSAKey(rsa, w)
	if err != nil {
		fmt.Printf("Unable to WRAP EC Key %v with error %v", rsa.PrivKeyBlock.Bytes, err)
		return err
	}
	err = p11w.UnwrapRSAKey(rsa, w, wrappedKey, keyLabel)
	if err != nil {
		fmt.Printf("Unable to UnWRAP RSA Key")
		return err
	}

	/* import key to hsm
	err = p11w.UnwrapECKey(ec)
	if len(ec.Certificate) != 0 {
		err = p11w.ImportCertificate(ec)
	}*/

	return
}

//WrapECKey Wraps an EC Key
func (p11w *Pkcs11Wrapper) WrapRSAKey(rsa *RsaKey, w pkcs11.ObjectHandle) (wrappedKey []byte, err error) {
	if rsa.PrivKey == nil {
		err = errors.New("no key to WRAP")
		return
	}

	rsa.GenSKI()

	/*	marshaledOID, err := GetECParamMarshaled(ec.PrivKey.Params().Name)
		if err != nil {
			return
		}
	*/

	/*
		Wrapping a Key requires the key to be in the HSM
		wrappedKey, err := p11w.Context.WrapKey(
			p11w.Session,
			[]*pkcs11.Mechanism{
				pkcs11.NewMechanism(pkcs11.CKM_DES3_CBC,nil),
			},
			"wrappingKey",
			w,
		)
		if err != nil {
			return
		}
	*/
	err = p11w.Context.EncryptInit(
		p11w.Session,
		[]*pkcs11.Mechanism{
			//pkcs11.NewMechanism(pkcs11.CKM_DES3_CBC,make([]byte, 8)),
			pkcs11.NewMechanism(pkcs11.CKM_DES3_CBC_PAD, make([]byte, 8)),
		},
		w, //Wrapping Key
	)
	if err != nil {
		fmt.Printf("Unable to Initialise Encryptor %v with key %v", err, w)
		return nil, err
	}
	wrappedKey, err = p11w.Context.Encrypt(
		p11w.Session,
		rsa.PrivKeyBlock.Bytes,
	)
	if err != nil {
		fmt.Printf("Unable to Encrypt Key : %v", err)
		return nil, err
	}

	fmt.Printf("Wrapped Key with CKM_DES3_CBS with CipherText %v from PrivKey %v\n", wrappedKey, rsa.PrivKeyBlock.Bytes)

	return
}

//UnwrapRSAKeye EC Key Wrapped with DES3 Key
func (p11w *Pkcs11Wrapper) UnwrapRSAKey(rsa RsaKey, w pkcs11.ObjectHandle, wrappedKey []byte, keyLabel string) (err error) {


	// pubkey import
	pubExpBytes := big.NewInt(int64(rsa.PubKey.E)).Bytes()

	keyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, rsa.PubKey.N.Bytes()),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, pubExpBytes),

		pkcs11.NewAttribute(pkcs11.CKA_ID, rsa.SKI.Sha256Bytes),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, rsa.SKI.Sha256),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, false),
	}

	_, err = p11w.Context.CreateObject(p11w.Session, keyTemplate)
	if err != nil {
		fmt.Printf("Public Object FAILED TO IMPORT with CKA_LABEL:%s CKA_ID:%x\n ERROR %s \n", rsa.keyLabel, rsa.SKI.Sha256Bytes, err)
		return
	} else {
		fmt.Printf("Public Object was imported with CKA_LABEL:%s CKA_ID:%x\n", rsa.SKI.Sha256, rsa.SKI.Sha256Bytes)
	}

	//_ = []*pkcs11.Attribute{
	keyTemplate = []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_ID, rsa.SKI.Sha256Bytes),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, rsa.keyLabel),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),

		// implicitly enable derive for now
		//pkcs11.NewAttribute(pkcs11.CKA_DERIVE, true),
	}

	_, err = p11w.Context.UnwrapKey(
		p11w.Session,
		[]*pkcs11.Mechanism{
			//pkcs11.NewMechanism(pkcs11.CKM_DES3_CBC,make([]byte, 8)),
			pkcs11.NewMechanism(pkcs11.CKM_DES3_CBC_PAD, make([]byte, 8)),
		},
		w,
		wrappedKey,
		keyTemplate,
	)

	if err != nil {
		fmt.Printf("Object FAILED TO IMPORT with CKA_LABEL:%s\n ERROR %s\n wrapping key: %v\n DECRYPTING VALUE \n", keyLabel, err, w)
		err = p11w.Context.DecryptInit(
			p11w.Session,
			[]*pkcs11.Mechanism{
				pkcs11.NewMechanism(pkcs11.CKM_DES3_CBC_PAD, make([]byte, 8)),
			},
			w, //Wrapping Key
		)
		if err != nil {
			fmt.Printf("Unable to Initialise Encryptor %v with key %v", err, w)
			return err
		}
		decryptedKey, err := p11w.Context.Decrypt(
			p11w.Session,
			wrappedKey,
		)
		fmt.Printf("DECRYPTED VALUE: %v \n", decryptedKey)
		return err
	} else {
		fmt.Printf("Private Key Object was imported with CKA_LABEL:%x\n", rsa.SKI.Sha256Bytes)
	}
	return

}

//UnWrapECKeyFromFile takes a EC Key from file imput and unwraps onto an HSM
func (p11w *Pkcs11Wrapper) UnWrapECKeyFromFile(file string, keyStore string, keyStorepass string, keyLabel string, w pkcs11.ObjectHandle) (err error) {
	// read in key from file
	//ec := EcdsaKey{}
	var ec EcdsaKey

	//err = ec.ImportPrivKeyFromFile(file)
	switch keyStore {
	case "p12":
		ec = EcdsaKey{}
		ec.keyLabel = keyLabel
		err = ec.ImportPrivKeyFromP12(file, keyStorepass)
		if err != nil {
			return err
		}
	default:
		ec = EcdsaKey{}
		ec.keyLabel = keyLabel
		err = ec.ImportPrivKeyFromFile(file)
		if err != nil {
			return err
		}
	}

	ec.Token = true

	wrappedKey, err := p11w.WrapECKey(ec, w)
	if err != nil {
		fmt.Printf("Unable to WRAP EC Key %v with error %v", ec.PrivKey.D.Bytes(), err)
		return err
	}
	marshaledOID, err := GetECParamMarshaled(ec.PrivKey.Params().Name)
	err = p11w.UnwrapECKey(ec, w, wrappedKey, keyLabel, marshaledOID)
	if err != nil {
		fmt.Printf("Unable to UnWRAP EC Key")
		return err
	}

	/* import key to hsm
	err = p11w.UnwrapECKey(ec)
	if len(ec.Certificate) != 0 {
		err = p11w.ImportCertificate(ec)
	}*/

	return
}

//WrapECKey Wraps an EC Key
func (p11w *Pkcs11Wrapper) WrapECKey(ec EcdsaKey, w pkcs11.ObjectHandle) (wrappedKey []byte, err error) {
	if ec.PrivKey == nil {
		err = errors.New("no key to WRAP")
		return
	}

	ec.GenSKI()

	/*	marshaledOID, err := GetECParamMarshaled(ec.PrivKey.Params().Name)
		if err != nil {
			return
		}
	*/

	/*
		Wrapping a Key requires the key to be in the HSM
		wrappedKey, err := p11w.Context.WrapKey(
			p11w.Session,
			[]*pkcs11.Mechanism{
				pkcs11.NewMechanism(pkcs11.CKM_DES3_CBC,nil),
			},
			"wrappingKey",
			w,
		)
		if err != nil {
			return
		}
	*/
	err = p11w.Context.EncryptInit(
		p11w.Session,
		[]*pkcs11.Mechanism{
			//pkcs11.NewMechanism(pkcs11.CKM_DES3_CBC,make([]byte, 8)),
			pkcs11.NewMechanism(pkcs11.CKM_DES3_CBC_PAD, make([]byte, 8)),
		},
		w, //Wrapping Key
	)
	if err != nil {
		fmt.Printf("Unable to Initialise Encryptor %v with key %v", err, w)
		return nil, err
	}
	wrappedKey, err = p11w.Context.Encrypt(
		p11w.Session,
		//ec.pk8.PrivateKey,
		ec.PrivKeyBlock.Bytes,
	)
	if err != nil {
		fmt.Printf("Unable to Encrypt Key : %v", err)
		return nil, err
	}

	fmt.Printf("Wrapped Key with CKM_DES3_CBS with CipherText %v from PrivKey %v\n", wrappedKey, ec.pk8.PrivateKey)

	return
}

//UnwrapECKeye EC Key Wrapped with DES3 Key
func (p11w *Pkcs11Wrapper) UnwrapECKey(ec EcdsaKey, w pkcs11.ObjectHandle, wrappedKey []byte, keyLabel string, marshaledOID []byte) (err error) {

	ec.GenSKI()

	// pubkey import
	ecPt := elliptic.Marshal(ec.PubKey.Curve, ec.PubKey.X, ec.PubKey.Y)
	// Add DER encoding for the CKA_EC_POINT
	ecPt = append([]byte{0x04, byte(len(ecPt))}, ecPt...)

	keyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_ECDSA),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, false),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, ec.Token),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, marshaledOID),

		pkcs11.NewAttribute(pkcs11.CKA_ID, ec.SKI.Sha256Bytes),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, ec.keyLabel),
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, ecPt),
	}

	_, err = p11w.Context.CreateObject(p11w.Session, keyTemplate)
	if err != nil {
		fmt.Printf("Public Object FAILED TO IMPORT with CKA_LABEL:%s CKA_ID:%x\n ERROR %s \n", ec.keyLabel, ec.SKI.Sha256Bytes, err)
		return
	} else {
		fmt.Printf("Public Object was imported with CKA_LABEL:%s CKA_ID:%x\n", ec.keyLabel, ec.SKI.Sha256Bytes)
	}

	//_ = []*pkcs11.Attribute{
	keyTemplate = []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_ECDSA),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_ID, ec.SKI.Sha256Bytes),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, ec.keyLabel),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),

		// implicitly enable derive for now
		//pkcs11.NewAttribute(pkcs11.CKA_DERIVE, true),
	}

	_, err = p11w.Context.UnwrapKey(
		p11w.Session,
		[]*pkcs11.Mechanism{
			//pkcs11.NewMechanism(pkcs11.CKM_DES3_CBC,make([]byte, 8)),
			pkcs11.NewMechanism(pkcs11.CKM_DES3_CBC_PAD, make([]byte, 8)),
		},
		w,
		wrappedKey,
		keyTemplate,
	)

	if err != nil {
		fmt.Printf("Object FAILED TO IMPORT with CKA_LABEL:%s\n ERROR %s\n wrapping key: %v\n DECRYPTING VALUE \n", keyLabel, err, w)
		err = p11w.Context.DecryptInit(
			p11w.Session,
			[]*pkcs11.Mechanism{
				pkcs11.NewMechanism(pkcs11.CKM_DES3_CBC_PAD, make([]byte, 8)),
			},
			w, //Wrapping Key
		)
		if err != nil {
			fmt.Printf("Unable to Initialise Encryptor %v with key %v", err, w)
			return err
		}
		decryptedKey, err := p11w.Context.Decrypt(
			p11w.Session,
			wrappedKey,
		)
		fmt.Printf("DECRYPTED VALUE: %v \n", decryptedKey)
		return err
	} else {
		fmt.Printf("Private Key Object was imported with CKA_LABEL:%x\n", ec.SKI.Sha256Bytes)
	}
	return

}

func (p11w *Pkcs11Wrapper) WrapP11Key(wrapKeyType string, objClass string, keyLabel string, w pkcs11.ObjectHandle, keyByID bool, mechOver string) (wrappedKey []byte, err error) {

	var keyTemplate []*pkcs11.Attribute
	var keyID []*pkcs11.Attribute

	fmt.Printf("Searching for Label: %s , ObjClass %s\n", keyLabel, objClass)
	keyTemplate = []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, decodeP11Class(objClass)),
		//pkcs11.NewAttribute(pkcs11.CKA_ID, keyLabel),
	}
	if keyByID {
		keyID = []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_ID, keyLabel),
		}
	} else {
		keyID = []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyLabel),
		}
	}
	keyTemplate = append(keyTemplate, keyID...)

	// start the search for object
	err = p11w.Context.FindObjectsInit(
		p11w.Session,
		keyTemplate,
	)
	if err != nil {
		return nil, err
	}
	// continue the search, get object handlers
	p11ObjHandlers, moreThanMax, err := p11w.Context.FindObjects(p11w.Session, 1)
	if err != nil {
		fmt.Printf("Cannot Find Objects %v\n", err)
		return nil, err
	}
	if moreThanMax {
		fmt.Errorf("expected a Single Object... found %v exiting", len(p11ObjHandlers))
		return nil, err
	}
	// finishes the search
	err = p11w.Context.FindObjectsFinal(p11w.Session)
	if err != nil {
		return nil, err
	}
	if len(p11ObjHandlers) == 1 {
		wrappKeyLabel, err := p11w.Context.GetAttributeValue(
			p11w.Session,
			w,
			[]*pkcs11.Attribute{
				pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
			},
		)
		if err != nil {
			fmt.Errorf("Cant retireve label of wrapping key %v", err)
			return nil, err
		}
		fmt.Printf("wrapping object %v out of hms with %s\n", p11ObjHandlers[0], wrappKeyLabel[0].Value)
		switch wrapKeyType {
		case "DES3":
			myMech := decodeP11Mech(mechOver, "DES3")
			fmt.Printf("selected mechanism %v\n",decodeP11Mech(mechOver, "DES3"))
			wrappedKey, err = p11w.Context.WrapKey(
				p11w.Session,
				[]*pkcs11.Mechanism{
					pkcs11.NewMechanism(myMech.p11Mech, myMech.mechParam),
				//	pkcs11.NewMechanism(pkcs11.CKM_DES3_CBC_PAD, make([]byte, 8)),
				},
				w,
				p11ObjHandlers[0],
			)
			if err != nil {
				fmt.Errorf("Unable to Wrap Key %v", err)
				return nil, err
			} else {
				fmt.Printf("Successfully Wrapped key %v", p11ObjHandlers[0])
			}
		case "AES":
			myMech := decodeP11Mech(mechOver, "AES")
			fmt.Printf("selected mechanism %v\n",decodeP11Mech(mechOver, "AES"))
			wrappedKey, err = p11w.Context.WrapKey(
				p11w.Session,
				[]*pkcs11.Mechanism{
					pkcs11.NewMechanism(myMech.p11Mech, myMech.mechParam),
					//pkcs11.NewMechanism(pkcs11.CKM_AES_CBC_PAD, make([]byte, 16)),
				},
				w,
				p11ObjHandlers[0],
			)
			if err != nil {
				fmt.Errorf("Unable to Wrap Key %v\n", err)
				return nil, err
			} else {
				fmt.Printf("Successfully Wrapped key %v", p11ObjHandlers[0])
			}
		}
	} else {
		fmt.Errorf("expected a single object.... exiting")
		return nil, err
	}
	return
}

func (p11w *Pkcs11Wrapper) DecryptP11Key(wrapKeyType string, wrappedKey []byte, w pkcs11.ObjectHandle, mechOver string) (decryptedKey []byte, err error) {

	switch wrapKeyType {
	case "DES3":
		myMech := decodeP11Mech(mechOver, "DES3")
		err = p11w.Context.DecryptInit(
			p11w.Session,
			[]*pkcs11.Mechanism{
				pkcs11.NewMechanism(myMech.p11Mech, myMech.mechParam),
				//pkcs11.NewMechanism(pkcs11.CKM_DES3_CBC_PAD, make([]byte, 8)),
			},
			w, //Wrapping Key
		)
	case "AES":
		err = p11w.Context.DecryptInit(
			p11w.Session,
			[]*pkcs11.Mechanism{
				pkcs11.NewMechanism(pkcs11.CKM_AES_ECB, nil),
				//pkcs11.NewMechanism(pkcs11.CKM_AES_CBC_PAD, make([]byte, 16)),
			},
			w, //Wrapping Key
		)
	}
	if err != nil {
		fmt.Printf("Unable to Initialise Encryptor %v with key %v", err, w)
		return nil, err
	}
	decryptedKey, err = p11w.Context.Decrypt(
		p11w.Session,
		wrappedKey,
	)
	if err != nil {
		fmt.Printf("Unable to Decrypt Key to byte %v\n", err)
		return nil, err
	}
	fmt.Printf("DECRYPTED VALUE: %v \n", decryptedKey)

	return
}

func (p11w *Pkcs11Wrapper) ImportRSAKeyFromFile(file string, keyStore string) (err error) {

	// read in key from file
	rsa := RsaKey{}
	err = rsa.ImportPrivKeyFromFile(file)
	if err != nil {
		return
	}

	// import key to hsm
	err = p11w.ImportRSAKey(rsa)

	return

}

func ecPoint(Context *pkcs11.Ctx, session pkcs11.SessionHandle, key pkcs11.ObjectHandle) (ecpt, oid []byte, err error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, nil),
	}

	attr, err := Context.GetAttributeValue(session, key, template)
	if err != nil {
		return nil, nil, fmt.Errorf("PKCS11: get(EC point) [%s]\n", err)
	}

	for _, a := range attr {
		if a.Type == pkcs11.CKA_EC_POINT {
			fmt.Printf("EC point: attr type %d/0x%x, len %d\n%s\n", a.Type, a.Type, len(a.Value), hex.Dump(a.Value))

			// workarounds, see above
			if (0 == (len(a.Value) % 2)) &&
				(byte(0x04) == a.Value[0]) &&
				(byte(0x04) == a.Value[len(a.Value)-1]) {
				fmt.Printf("Detected opencryptoki bug, trimming trailing 0x04")
				ecpt = a.Value[0 : len(a.Value)-1] // Trim trailing 0x04
			} else if byte(0x04) == a.Value[0] && byte(0x04) == a.Value[2] {
				fmt.Printf("Detected Leading 0x04 on point encoding, trimming leading 0x04 0xXX")
				ecpt = a.Value[2:len(a.Value)]
			} else {
				ecpt = a.Value
			}
		} else if a.Type == pkcs11.CKA_EC_PARAMS {
			fmt.Printf("EC point: attr type %d/0x%x, len %d\n%s\n", a.Type, a.Type, len(a.Value), hex.Dump(a.Value))

			oid = a.Value
		}
	}
	if oid == nil || ecpt == nil {
		return nil, nil, fmt.Errorf("CKA_EC_POINT not found, perhaps not an EC Key?")
	}

	return ecpt, oid, nil
}

func (p11w *Pkcs11Wrapper) GenerateEC(ec EcdsaKey) (ski []byte, err error) {

	publabel := fmt.Sprintf("BCPUB%s", "1")
	prvlabel := fmt.Sprintf("BCPRV%s", "1")
	//TODO pass curve into function

	/*REMOVE:  TODO add all templates to external file
	ec.exportable = true
	*/
	ec.ephemeral = false

	marshaledOID, err := GetECParamMarshaled(ec.NamedCurveAsString)
	if err != nil {
		return nil, fmt.Errorf("Could not marshal OID [%s]", err.Error())
	}

	pubkey_t := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, !ec.ephemeral),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, marshaledOID),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, false),

		pkcs11.NewAttribute(pkcs11.CKA_ID, publabel),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, publabel),
	}

	prvkey_t := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, !ec.ephemeral),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),

		pkcs11.NewAttribute(pkcs11.CKA_ID, prvlabel),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, prvlabel),

		/*REMOVE Explicit Attribute Setting
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, ec.exportable),
		*/
	}

	pub, prv, err := p11w.Context.GenerateKeyPair(p11w.Session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_EC_KEY_PAIR_GEN, nil)},
		pubkey_t, prvkey_t)

	if err != nil {
		return nil, fmt.Errorf("P11: keypair generate failed [%s]\n", err)
	}
	fmt.Printf("\npub key raw %c\n", pub)

	ecpt, _, _ := ecPoint(p11w.Context, p11w.Session, pub)
	hash := sha256.Sum256(ecpt)
	ski = hash[:]

	// set CKA_ID of the both keys to SKI(public key) and CKA_LABEL to hex string of SKI
	setski_t := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ID, ski),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, hex.EncodeToString(ski)),
	}

	fmt.Printf("Generated new P11 key, SKI %x\n", ski)
	err = p11w.Context.SetAttributeValue(p11w.Session, pub, setski_t)
	if err != nil {
		return nil, fmt.Errorf("P11: set-ID-to-SKI[public] failed [%s]\n", err)
	}

	err = p11w.Context.SetAttributeValue(p11w.Session, prv, setski_t)
	if err != nil {
		return nil, fmt.Errorf("P11: set-ID-to-SKI[private] failed [%s]\n", err)
	}

	nistCurve := ec.namedCurveFromOID(marshaledOID)
	if nistCurve == nil {
		return nil, fmt.Errorf("Cound not recognize Curve from OID")
	}
	x, y := elliptic.Unmarshal(nistCurve, ecpt)
	if x == nil {
		return nil, fmt.Errorf("Failed Unmarshaling Public Key")
	}

	pubGoKey := &ecdsa.PublicKey{Curve: nistCurve, X: x, Y: y}
	fmt.Printf("pubGoKey %c\n", pubGoKey.X)
	//pubGoKey := &ec.PubKey{Curve: nistCurve, X: x, Y: y}
	/*if logger.IsEnabledFor(logging.DEBUG) {
			listAttrs(p11lib, session, prv)
			listAttrs(p11lib, session, pub)
	}*/

	return ski, nil
}

func (p11w *Pkcs11Wrapper) GenerateRSA(rsa RsaKey, keySize int, keyLabel string) (err error) {

	publabel := keyLabel
	prvlabel := keyLabel
	n := new(big.Int)
	n, ok := n.SetString("10001", 16)
	if !ok {
		ExitWithMessage("BigInt SetString:", nil)
	}
	//TODO pass curve into function

	/*REMOVE:  TODO add all templates to external file
	ec.exportable = true
	*/
	fmt.Printf("exponent set to %v\n", n)
	rsa.ephemeral = false
	rsa.rsaKeySize = keySize

	pubkey_t := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, !rsa.ephemeral),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, rsa.rsaKeySize),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, false),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, publabel),
		pkcs11.NewAttribute(pkcs11.CKA_ID, publabel),

		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, n.Bytes()),
	}

	prvkey_t := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, !rsa.ephemeral),
		/*Remove MODULUS_BITS from Private Key Object as per PKCS11 Spec.  Should be in Public Object Only
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, rsa.rsaKeySize),
		*/
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		////pkcs11.NewAttribute(pkcs11.CKA_WRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, prvlabel),
		pkcs11.NewAttribute(pkcs11.CKA_ID, publabel),

		/*REMOVE Explicit Attribute Setting
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, ec.exportable),
		*/
	}

	_, _, err = p11w.Context.GenerateKeyPair(p11w.Session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, nil)},
		pubkey_t, prvkey_t)

	if err != nil {
		return fmt.Errorf("P11: keypair generate failed [%s]\n", err)
	}

	return nil

}

func (p11w *Pkcs11Wrapper) findKeyPairFromSKI(ski []byte, keyType bool) (*pkcs11.ObjectHandle, error) {
	ktype := pkcs11.CKO_PUBLIC_KEY
	if keyType == privateKeyFlag {
		ktype = pkcs11.CKO_PRIVATE_KEY
	}

	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, ktype),
		pkcs11.NewAttribute(pkcs11.CKA_ID, ski),
	}
	if err := p11w.Context.FindObjectsInit(p11w.Session, template); err != nil {
		return nil, err
	}

	// single session instance, assume one hit only
	objs, _, err := p11w.Context.FindObjects(p11w.Session, 1)
	if err != nil {
		return nil, err
	}
	if err = p11w.Context.FindObjectsFinal(p11w.Session); err != nil {
		return nil, err
	}

	if len(objs) == 0 {
		return nil, fmt.Errorf("Key not found [%s]", hex.Dump(ski))
	}

	return &objs[0], nil
}

func (p11w *Pkcs11Wrapper) signP11ECDSA(ski SubjectKeyIdentifier, msg []byte) (R, S *big.Int, err error) {

	privateKey, err := p11w.findKeyPairFromSKI(ski.Sha256Bytes, privateKeyFlag)
	if err != nil {
		return nil, nil, fmt.Errorf("Private key not found [%s]\n", err)
	}

	err = p11w.Context.SignInit(p11w.Session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)}, *privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("Sign-initialize  failed [%s]\n", err)
	}

	var sig []byte

	sig, err = p11w.Context.Sign(p11w.Session, msg)
	if err != nil {
		return nil, nil, fmt.Errorf("P11: sign failed [%s]\n", err)
	}

	R = new(big.Int)
	S = new(big.Int)
	R.SetBytes(sig[0 : len(sig)/2])
	S.SetBytes(sig[len(sig)/2:])

	return R, S, nil
}

func (p11w *Pkcs11Wrapper) signECDSA(k EcdsaKey, digest []byte) (signature []byte, err error) {
	r, s, err := p11w.signP11ECDSA(k.SKI, digest)
	if err != nil {
		return nil, err
	}

	s, _, err = utils.ToLowS(k.PubKey, s)
	if err != nil {
		return nil, err
	}

	return utils.MarshalECDSASignature(r, s)
}

func (p11w *Pkcs11Wrapper) Sign(k Key, digest []byte) (signature []byte, err error) {
	// Validate arguments
	if k == nil {
		return nil, errors.New("Invalid Key. It must not be nil.")
	}
	if len(digest) == 0 {
		return nil, errors.New("Invalid digest. Cannot be empty.")
	}

	// Check key type
	switch k.(type) {
	case *EcdsaKey:
		return p11w.signECDSA(*k.(*EcdsaKey), digest)
	default:
		return p11w.signECDSA(*k.(*EcdsaKey), digest)
	}
}

const curveP256 int = 256

// NewBasicKeyRequest returns a default BasicKeyRequest.
func NewBasicKeyRequest() *BasicP11Request {

	return &BasicP11Request{"ecdsa", curveP256}
}
func (p11w *Pkcs11Wrapper) GenCSR(ec EcdsaKey) ([]byte, Key, error) {
	if ec.Req.Names[0].C == "" {
		ec.Req = &CSRInfo{
			Names: []Name{
				{C: "US",
					ST: "California",
					L:  "San Francisco",
					O:  "CloudFlare",
					OU: "Systems Engineering",
				},
			},
			Hosts:      []string{"cloudflare.com"},
			KeyRequest: NewBasicKeyRequest(),
		}
	}

	cr := p11w.newCertificateRequest(ec.Req)
	cr.CN = ec.Req.CN

	if cr.KeyRequest == nil {
		cr.KeyRequest = newCfsslBasicKeyRequest(NewBasicKeyRequest())
	}

	key, cspSigner, err := p11w.BCCSPKeyRequestGenerate(cr, ec)
	//_, cspSigner, err := p11w.BCCSPKeyRequestGenerate(cr, ec)
	if err != nil {
		fmt.Printf("failed generating BCCSP key: %s", err)
		return nil, nil, err
	}

	csrPEM, err := GenerateCSR(cspSigner, cr)
	if err != nil {
		fmt.Printf("failed generating CSR: %s", err)
		return nil, nil, err
	}
	return csrPEM, key, nil

}

// appendIf appends to a if s is not an empty string.
func appendIf(s string, a *[]string) {
	if s != "" {
		*a = append(*a, s)
	}
}

// BasicConstraints CSR information RFC 5280, 4.2.1.9
type BasicConstraints struct {
	IsCA       bool `asn1:"optional"`
	MaxPathLen int  `asn1:"optional,default:-1"`
}

// appendCAInfoToCSR appends CAConfig BasicConstraint extension to a CSR
func appendCAInfoToCSR(reqConf *CAConfig, csr *x509.CertificateRequest) error {
	pathlen := reqConf.PathLength
	if pathlen == 0 && !reqConf.PathLenZero {
		pathlen = -1
	}
	val, err := asn1.Marshal(BasicConstraints{true, pathlen})

	if err != nil {
		return err
	}

	csr.ExtraExtensions = []pkix.Extension{
		{
			Id:       asn1.ObjectIdentifier{2, 5, 29, 19},
			Value:    val,
			Critical: true,
		},
	}

	return nil
}

func (cr *CertificateRequest) Name() pkix.Name {
	var name pkix.Name
	name.CommonName = cr.CN

	for _, n := range cr.Names {
		appendIf(n.C, &name.Country)
		appendIf(n.ST, &name.Province)
		appendIf(n.L, &name.Locality)
		appendIf(n.O, &name.Organization)
		appendIf(n.OU, &name.OrganizationalUnit)
	}
	name.SerialNumber = cr.SerialNumber
	return name
}

// Generate creates a new CSR from a CertificateRequest structure and
// an existing key. The KeyRequest field is ignored.
func GenerateCSR(priv crypto.Signer, req *CertificateRequest) (csr []byte, err error) {
	sigAlgo := helpers.SignerAlgo(priv)
	if sigAlgo == x509.UnknownSignatureAlgorithm {
		return nil, err
	}

	var tpl = x509.CertificateRequest{
		Subject:            req.Name(),
		SignatureAlgorithm: sigAlgo,
	}

	for i := range req.Hosts {
		if ip := net.ParseIP(req.Hosts[i]); ip != nil {
			tpl.IPAddresses = append(tpl.IPAddresses, ip)
		} else if email, err := mail.ParseAddress(req.Hosts[i]); err == nil && email != nil {
			tpl.EmailAddresses = append(tpl.EmailAddresses, email.Address)
		} else {
			tpl.DNSNames = append(tpl.DNSNames, req.Hosts[i])
		}
	}

	if req.CA != nil {
		err = appendCAInfoToCSR(req.CA, &tpl)
		if err != nil {
			println("Error %s", err)
			return
		}
	}

	csr, err = x509.CreateCertificateRequest(rand.Reader, &tpl, priv)
	if err != nil {
		fmt.Errorf("failed to generate a CSR: %v", err)

		return
	}
	block := pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csr,
	}

	fmt.Println("encoded CSR")
	fmt.Printf("\n CSR \n%c\n", pem.EncodeToMemory(&block))

	csr = pem.EncodeToMemory(&block)
	return
}

func (p11w *Pkcs11Wrapper) BCCSPKeyRequestGenerate(req *CertificateRequest, ec EcdsaKey) (Key, crypto.Signer, error) {

	/*
		case *bccsp.ECDSAP256KeyGenOpts:
			ski, pub, err := csp.generateECKey(oidNamedCurveP256, opts.Ephemeral())
			if err != nil {
				return nil, errors.Wrapf(err, "Failed generating ECDSA P256 key")
			}

			k = &ecdsaPrivateKey{ski, ecdsaPublicKey{ski, pub}}
	*/
	Sha256Bytes, err := hex.DecodeString(ec.SKI.Sha256)
	if err != nil {
		return nil, nil, err
	}
	ec.SKI.Sha256Bytes = Sha256Bytes

	//Returns Public Key by Default unless privkeyflag set
	pubkey, err := p11w.findKeyPairFromSKI(ec.SKI.Sha256Bytes, false)
	if err != nil {
		fmt.Printf("count not find key with label %c and byte value %c \n", ec.SKI.Sha256, ec.SKI.Sha256Bytes)
	}
	pub := *pubkey
	ecpt, oid, err := ecPoint(p11w.Context, p11w.Session, pub)
	if err != nil {
		fmt.Printf("could not retrieve EC point values %c\n", err)
	}

	nistCurve := ec.namedCurveFromOID(oid)
	if nistCurve == nil {
		return nil, nil, fmt.Errorf("Cound not recognize Curve from OID")
	}
	x, y := elliptic.Unmarshal(nistCurve, ecpt)
	if x == nil {
		return nil, nil, fmt.Errorf("Failed Unmarshaling Public Key")
	}
	//Have SKI and PublicKey
	pubGoKey := &ecdsa.PublicKey{Curve: nistCurve, X: x, Y: y}
	fmt.Printf("pubGoKey %c\n", pubGoKey.X)
	ec.PubKey = pubGoKey
	var key Key = &ec
	cspSigner, err := p11w.getSigner(key)
	//cspSigner, err := cspsigner.New(myCSP, key)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed initializing CryptoSigner %c", err)
	}
	return key, cspSigner, nil
}

func (p11w *Pkcs11Wrapper) getSigner(key Key) (crypto.Signer, error) {
	// Validate arguments

	if key == nil {
		return nil, errors.New("key must be different from nil.")
	}

	/* TODO:// IMPLEMENT INTERFACE
	if key.Symmetric() {
		return nil, errors.New("key must be asymmetric.")
	}
	*/

	// Marshall the  public key as a crypto.PublicKey
	pub, err := key.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("failed getting public key %s\n", err)
	}

	raw, err := pub.Bytes()
	if err != nil {
		return nil, fmt.Errorf("failed marshalling public key %s\n", err)
	}

	pk, err := DERToPublicKey(raw)
	if err != nil {
		return nil, fmt.Errorf("failed marshalling der to public key %s\n", err)
	}

	return &bccspCryptoSigner{p11w, key, pk}, nil
}

type bccspCryptoSigner struct {
	csp *Pkcs11Wrapper
	//csp2 impl
	key Key
	pk  interface{}
}

// Public returns the public key corresponding to the opaque,
// private key.
func (s *bccspCryptoSigner) Public() crypto.PublicKey {
	return s.pk
}

// Sign signs digest with the private key, possibly using entropy from
// rand. For an RSA key, the resulting signature should be either a
// PKCS#1 v1.5 or PSS signature (as indicated by opts). For an (EC)DSA
// key, it should be a DER-serialised, ASN.1 signature structure.
//
// Hash implements the SignerOpts interface and, in most cases, one can
// simply pass in the hash function used as opts. Sign may also attempt
// to type assert opts to other types in order to obtain algorithm
// specific values. See the documentation in each package for details.
//
// Note that when a signature of a hash of a larger message is needed,
// the caller is responsible for hashing the larger message and passing
// the hash (as digest) and the hash function (as opts) to Sign.
func (s *bccspCryptoSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	//return s.csp.Sign(s.key, digest, opts)
	return s.csp.Sign(s.key, digest)

}

func DERToPublicKey(raw []byte) (pub interface{}, err error) {
	if len(raw) == 0 {
		return nil, errors.New("Invalid DER. It must be different from nil.")
	}
	fmt.Printf("DER Encoded Public Key %c\n", raw)
	key, err := x509.ParsePKIXPublicKey(raw)
	fmt.Printf("Public Key %c\n", key)

	return key, err
}

// newCertificateRequest creates a certificate request which is used to generate
// a CSR (Certificate Signing Request)
func (p11w *Pkcs11Wrapper) newCertificateRequest(req *CSRInfo) *CertificateRequest {
	cr := CertificateRequest{}
	if req != nil && req.Names != nil {
		cr.Names = req.Names
	}
	if req != nil && req.Hosts != nil {
		cr.Hosts = req.Hosts
	} else {
		// Default requested hosts are local hostname
		hostname, _ := os.Hostname()
		if hostname != "" {
			cr.Hosts = make([]string, 1)
			cr.Hosts[0] = hostname
		}
	}
	if req != nil && req.KeyRequest != nil {
		cr.KeyRequest = newCfsslBasicKeyRequest(req.KeyRequest)
	}
	if req != nil {
		cr.CA = req.CA
		cr.SerialNumber = req.SerialNumber
	}
	return &cr
}

func newCfsslBasicKeyRequest(bkr *BasicP11Request) *csr.KeyRequest {
	return &csr.KeyRequest{A: bkr.A, S: bkr.S}
}

//TODO implement Public() for crypto.signer

func (p11w *Pkcs11Wrapper) Public() {
	return
}

/*TODO Implement CSR Request to call csr.Generate with EC Key from HSM with SKI implementing crypto.signer from Pkcs11Wrapper Struct
var req = &CertificateRequest{
	Names: []Name{
		{
			C:  "US",
			ST: "California",
			L:  "San Francisco",
			O:  "CloudFlare",
			OU: "Systems Engineering",
		},
	},
	CN:         "cloudflare.com",
	Hosts:      []string{"cloudflare.com", "www.cloudflare.com", "192.168.0.1", "jdoe@example.com"},
	KeyRequest: &BasicP11Request{"ecdsa", 256},
}

*/
func (p11r *BasicP11Request) Generate() {
	//FAKE the Generate and return a handle to a previously created private key
	return
}

func (p11r *BasicP11Request) SigAlgo() x509.SignatureAlgorithm {
	return 0
}
func (p11r *BasicP11Request) Algo() string {
	return p11r.A
}

// Size returns he requested key size.
func (p11r *BasicP11Request) Size() int {
	return p11r.S
}

func (p11w *Pkcs11Wrapper) SignMessage(message string, key pkcs11.ObjectHandle) (signature string, err error) {

	// TODO: diff mech needed for rsa. example: CKM_RSA_PKCS CKM_ECDSA
	err = p11w.Context.SignInit(p11w.Session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)}, key)
	if err != nil {
		return
	}

	// Test signing with mechanism CKM_ECDSA
	// Hash message first
	// TODO: make this hash dynamic corresponding to key size
	d := sha256.Sum256([]byte(message))
	digest := d[:]
	signatureBytes, err := p11w.Context.Sign(p11w.Session, digest)
	if err != nil {
		return
	}

	signature = hex.EncodeToString(signatureBytes)

	return
}

/* Advanced form of signing message, specify mechanism. Assume data is already prepared for mechanism (not altered in this function) */
func (p11w *Pkcs11Wrapper) SignMessageAdvanced(data []byte, key pkcs11.ObjectHandle, mechanism *pkcs11.Mechanism) (signature string, err error) {

	err = p11w.Context.SignInit(p11w.Session, []*pkcs11.Mechanism{mechanism}, key)
	if err != nil {
		return
	}

	signatureBytes, err := p11w.Context.Sign(p11w.Session, data)
	if err != nil {
		return
	}

	signature = hex.EncodeToString(signatureBytes)

	return
}

func (p11w *Pkcs11Wrapper) VerifySignature(message string, signature string, key pkcs11.ObjectHandle) (verified bool, err error) {

	err = p11w.Context.VerifyInit(p11w.Session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)}, key)
	if err != nil {
		return
	}

	// Test signing with mechanism CKM_ECDSA
	// Hash message first
	// TODO: make this hash dynamic corresponding to key size
	d := sha256.Sum256([]byte(message))
	digest := d[:]

	signatureBytes, err := hex.DecodeString(signature)
	if err != nil {
		return
	}

	// if there is an error, we can assume signature was invalid:
	// Error: pkcs11: 0xC0: CKR_SIGNATURE_INVALID
	errSig := p11w.Context.Verify(p11w.Session, digest, signatureBytes)
	if errSig == nil {
		verified = true
	}

	return
}
