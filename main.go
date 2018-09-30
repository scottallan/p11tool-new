package main

import (
	"encoding/hex"
	//"encoding/json"
	"io/ioutil"
	"flag"
	"fmt"
	"github.com/miekg/pkcs11"
	"os"
	"strings"
	//"github.com/cloudflare/cfssl/csr"
	//"github.com/cloudflare/cfssl/log"

	pw "github.com/scottallan/p11tool-new/pkcs11wrapper"
)

const (

	// locations to search for pkcs11 lib if none are specified
	defaultLibPaths = `
/usr/lib/softhsm/libsofthsm2.so,
/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so,
/usr/lib/s390x-linux-gnu/softhsm/libsofthsm2.so,
/usr/lib/powerpc64le-linux-gnu/softhsm/libsofthsm2.so,
/usr/local/Cellar/softhsm/2.1.0/lib/softhsm/libsofthsm2.so,
/usr/local/lib/softhsm/libsofthsm2.so`
)

var (
	// shared pkcs11 wrapper struct
	p11w pw.Pkcs11Wrapper
)

// exit cleanly when error is no nil
func exitWhenError(err error) {
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
}

// search comma-separated list of paths for pkcs11 lib
func searchForLib(paths string) (firstFound string, err error) {

	libPaths := strings.Split(paths, ",")
	for _, path := range libPaths {
		if _, err = os.Stat(strings.TrimSpace(path)); !os.IsNotExist(err) {
			firstFound = strings.TrimSpace(path)
			break
		}
	}

	if firstFound == "" {
		err = fmt.Errorf("no suitable paths for pkcs11 library found: %s", paths)
	}

	return
}

/* returns true if substr is in string s */
func CaseInsensitiveContains(s, substr string) bool {
	s, substr = strings.ToUpper(s), strings.ToUpper(substr)
	return strings.Contains(s, substr)
}



func main() {

	// get flags
	pkcs11Library := flag.String("lib", "", "Location of pkcs11 library")
	slotLabel := flag.String("slot", "ForFabric", "Slot Label")
	slotPin := flag.String("pin", "98765432", "Slot PIN")
	action := flag.String("action", "list", "list,import,generate,generateAndImport,generateSecret,generateAES,generateDES,unwrapECWithDES3,getSKI,SignHMAC384,TestAESGCM,generateCSR,importCert,deleteObj")
	keyFile := flag.String("keyFile", "/some/dir/key.pem)", "path to key you want to import or getSKI")
	keyType := flag.String("keyType", "EC", "Type of key (EC,RSA,GENERIC_SECRET,AES,SHA256_HMAC,SHA384_HMAC,DES3)")
	keyLen := flag.Int("keyLen", 32, "Key Length for CKK_GENERIC_SECRET (32,48,...)")
	keyLabel := flag.String("keyLabel", "tmpkey", "Label of CKK_GENERIC_SECRET")
	keyStore := flag.String("keyStore", "file", "Keystore Type (file,pkcs12)")
	keyStorepass := flag.String("keyStorepass", "securekey", "Keystore Storepass")
	csrInfo := flag.String("csrInfo", "", "json file with values for CSR Creation")
	wrapKey := flag.String("wrapKey","wrapKey", "DES3 Wrapping Key for unwrapping key material onto Gemalto")
	objClass := flag.String("objClass", "", "CKA_CLASS for Deleteiong of Objects")
    outF := flag.String("outFile","out.pem","output file for CSR Generation")
    maxObjectsToList := flag.Int("maxObjectsToList", 50, "Paramter to be used with -action list to specify how many objects to print")


	flag.Parse()

	var err error

	// complete actions which do not require HSM
	switch *action {

	case "getSKI":
		if *keyType == "RSA" {
			key := pw.RsaKey{}
			err = key.ImportPrivKeyFromFile(*keyFile)
			exitWhenError(err)
			key.GenSKI()
			fmt.Printf("SKI(sha256): %s\n", key.SKI.Sha256)
			os.Exit(0)
		} else {
			key := pw.EcdsaKey{}
			err = key.ImportPrivKeyFromFile(*keyFile)
			exitWhenError(err)
			key.GenSKI()
			fmt.Printf("SKI(sha256): %s\n", key.SKI.Sha256)
			os.Exit(0)
		}

	}

	// complete actions which require HSM

	// initialize pkcs11
	var p11Lib string

	if *pkcs11Library == "" {
		p11Lib, err = searchForLib(defaultLibPaths)
		exitWhenError(err)
	} else {
		p11Lib, err = searchForLib(*pkcs11Library)
		exitWhenError(err)
	}

	p11w = pw.Pkcs11Wrapper{
		Library: pw.Pkcs11Library{
			Path: p11Lib,
		},
		SlotLabel: *slotLabel,
		SlotPin:   *slotPin,
	}

	err = p11w.InitContext()
	exitWhenError(err)

	err = p11w.InitSession()
	exitWhenError(err)

	err = p11w.Login()
	exitWhenError(err)

	// defer cleanup
	defer p11w.Context.Destroy()
	defer p11w.Context.Finalize()
	defer p11w.Context.CloseSession(p11w.Session)
	defer p11w.Context.Logout(p11w.Session)

	switch *action {

	case "import":
		if *keyType == "RSA" {
			err = p11w.ImportRSAKeyFromFile(*keyFile, *keyStore)
			exitWhenError(err)
		} else {
			err = p11w.ImportECKeyFromFile(*keyFile, *keyStore, *keyStorepass, *keyLabel)
			exitWhenError(err)
		}

	case "importCert":
		ec := pw.EcdsaKey{}
		c := pw.GetCert(*keyFile)
		ec.Certificate = c
		ec.SKI.Sha256 = *keyLabel
		Sha256Bytes, err := hex.DecodeString(ec.SKI.Sha256)
		exitWhenError(err)
		ec.SKI.Sha256Bytes = Sha256Bytes
		err = p11w.ImportCertificate(ec)
		exitWhenError(err)

	
	case "generate":
		if *keyType == "RSA" {
			rsa := pw.RsaKey{}
			err := p11w.GenerateRSA(rsa, *keyLen, *keyLabel)
			exitWhenError(err)
		} else if *keyType == "EC" {
			ec := pw.EcdsaKey{}
			//TODO pass in from argument
			ec.NamedCurveAsString = "P-256"
			_, err := p11w.GenerateEC(ec)
			exitWhenError(err)
		}
	
	case "deleteObj":
		if *objClass == "ALL" {
			p11w.DeleteObj("ALL","")
		} else {
			p11w.DeleteObj(*objClass,*keyLabel)
		}

	case "generateCSR":

		if *keyType == "RSA" {
			//rsa := pw.RsaKey{}
			//_, _, err = p11w.GenCSR(rsa)
			//TODO generate and sign RSA
		
		} else if *keyType == "EC" {
			ec := pw.EcdsaKey{}
			ec.SKI.Sha256 = *keyLabel
			
			csrInfo := ec.GetCSRInfo(*csrInfo)
			/*ec.Req = &pw.CSRInfo{
				Names: []pw.Name{names},
				Hosts: hosts.Hosts,
			}*/
			ec.Req = &csrInfo
		
			fmt.Println(pw.ToJson(csrInfo))

			csr, _, err := p11w.GenCSR(ec)
			exitWhenError(err)
			outFile, err := os.Create(*outF)
			if err != nil {
				fmt.Printf("Unable to write CSR %s", err.Error())
				return 	
			}
			defer outFile.Close()
			fmt.Printf("writing csr to %s\n", *outF)
			err = ioutil.WriteFile(*outF,csr,0644)
			if err != nil {
				return
			}
		}

	case "generateAndImport":
		if *keyType == "RSA" {
			rsa := pw.RsaKey{}
			rsa.Generate(2048)
			p11w.ImportRSAKey(rsa)
		} else {
			ec := pw.EcdsaKey{}
			// TODO: fix non working curves (P-521)
			ec.Generate("P-256")
			p11w.ImportECKey(ec)
		}

	case "SignHMAC384":
		pkcs11_attr := pkcs11.NewAttribute(pkcs11.CKA_LABEL, *keyLabel)
		p11w.ListObjects(
			[]*pkcs11.Attribute{
				pkcs11_attr,
			}, *maxObjectsToList,
		)
		o, _, err := p11w.FindObjects([]*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, *keyLabel),
		},
			1,
		)
		exitWhenError(err)
		testMsg := []byte("someRandomString")
		hmac, err := p11w.SignHmacSha384(o[0], testMsg)
		exitWhenError(err)
		fmt.Printf("successfully tested CKM_SHA384_HMAC on key with LABEL: %s\n HMAC %x\n", *keyLabel, hmac)
	
	case "unwrapECWithDES3":	
		w, _, err := p11w.FindObjects([]*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, *wrapKey),
			},
			1,
		)
		exitWhenError(err)

		if *keyType == "EC" {
			err := p11w.UnWrapECKeyFromFile(*keyFile, *keyStore, *keyStorepass, *keyLabel, w[0])
			exitWhenError(err)
		}

	case "TestAESGCM":
		pkcs11Attr := pkcs11.NewAttribute(pkcs11.CKA_LABEL, *keyLabel)
		p11w.ListObjects(
			[]*pkcs11.Attribute{
				pkcs11Attr,
			},  *maxObjectsToList,
		)
		o, _, err := p11w.FindObjects([]*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, *keyLabel),
		},
			1,
		)
		exitWhenError(err)
		testMsg := []byte("ThisIsATestClearTextString")
		enc, iv, err := p11w.EncAESGCM(o[0], testMsg)
		exitWhenError(err)
		fmt.Printf("successfully encrypted  message '%s' with CKM_AES_GCM and key with LABEL: %s\n CipherText %v\n IV: %v\n",testMsg, *keyLabel, enc, iv)
		dec, err := p11w.DecAESGCM(o[0], enc, iv)
		exitWhenError(err)
		fmt.Printf("successfully decrypted ciptherText '%v' with CKM_AES_GCM and key with LABEL: %s\n ClearText %s\n",enc, *keyLabel, dec)

	case "generateSecret":
		if *keyType == "GENERIC_SECRET" || *keyType == "SHA256_HMAC" || *keyType == "SHA384_HMAC" {
			//Generate Key
			symKey, err := p11w.CreateSymKey(*keyLabel, *keyLen, *keyType)
			exitWhenError(err)
			testMsg := []byte("someRandomString")
			hmac, err := p11w.SignHmacSha384(symKey, testMsg)
			exitWhenError(err)
			fmt.Printf("Successfully tested CKM_SHA384_HMAC on key with label: %s \n HMAC %x\n", *keyLabel, hmac)
			p11w.ListObjects(
				[]*pkcs11.Attribute{},
				 *maxObjectsToList,
			)

		}

	case "generateAES":
		if *keyType == "AES" {
			//Generate Key
			_, err := p11w.CreateSymKey(*keyLabel, *keyLen, *keyType)
			exitWhenError(err)
			p11w.ListObjects(
				[]*pkcs11.Attribute{},
				 *maxObjectsToList,
			)

		}

	case "generateDES":
		if *keyType == "DES3" {
			//Generate DES Key
			_, err := p11w.CreateSymKey(*keyLabel, 24, *keyType)
			exitWhenError(err)
		}

	case "testEc":

		message := "Some Test Message"

		// test SW ecdsa sign and verify
		ec := pw.EcdsaKey{}
		ec.ImportPrivKeyFromFile("contrib/testfiles/key.pem")
		sig, err := ec.SignMessage(message)
		exitWhenError(err)
		fmt.Println("Signature:", sig)
		verified := ec.VerifySignature(message, sig)
		fmt.Println("Verified:", verified)

		// test PKCS11 ecdsa sign and verify
		// Find object
		id, err := hex.DecodeString("018f389d200e48536367f05b99122f355ba33572009bd2b8b521cdbbb717a5b5")
		exitWhenError(err)

		o, _, err := p11w.FindObjects([]*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, "BCPRV1"),
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_ID, id),
		},
			2,
		)

		exitWhenError(err)

		sig, err = p11w.SignMessage(message, o[0])
		exitWhenError(err)
		fmt.Println("pkcs11 Signature:", sig)
		verified = ec.VerifySignature(message, sig)
		fmt.Println("Verified:", verified)

		// test pkcs11 verify
		o, _, err = p11w.FindObjects([]*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, "BCPUB1"),
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_ID, id),
		},
			2,
		)

		verified, err = p11w.VerifySignature(message, sig, o[0])
		exitWhenError(err)
		fmt.Println("pkcs11 Verified:", verified)

		// derive test
		ec2 := pw.EcdsaKey{}
		ec2.Generate("P-256")

		secret, err := ec.DeriveSharedSecret(ec2.PubKey)
		exitWhenError(err)
		fmt.Printf("shared secret: %x\n", secret)

		secret, err = ec2.DeriveSharedSecret(ec.PubKey)
		exitWhenError(err)
		fmt.Printf("shared secret: %x\n", secret)

	case "testRsa":
		message := "Some Test Message"

		rsa := pw.RsaKey{}
		//rsa.Generate(2048)
		err = rsa.ImportPrivKeyFromFile("contrib/testfiles/key.rsa.pem")
		exitWhenError(err)
		rsa.GenSKI()

		err = p11w.ImportRSAKey(rsa)
		exitWhenError(err)

		sig, err := rsa.SignMessage(message, 256)
		exitWhenError(err)

		fmt.Println("Signature:", sig)

		// test PKCS11 ecdsa sign and verify
		// Find object
		id, err := hex.DecodeString("0344ae0121e025d998f5923174e9e4d69b899144ac79bfdf01c065bd4d99d6cb")
		exitWhenError(err)

		o, _, err := p11w.FindObjects([]*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, "TLSPRVKEY"),
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_ID, id),
		},
			2,
		)
		exitWhenError(err)

		sig, err = p11w.SignMessageAdvanced([]byte(message), o[0], pkcs11.NewMechanism(pkcs11.CKM_SHA256_RSA_PKCS, nil))
		exitWhenError(err)

		fmt.Println("pkcs11 Signature:", sig)

	default:
		p11w.ListObjects(
			[]*pkcs11.Attribute{},
			 *maxObjectsToList,
		)

	}

}
