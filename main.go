package main

import (
	"github.com/pavel-v-chernykh/keystore-go"
	"os"
	"log"
	"time"
	"io/ioutil"
	"flag"
	"fmt"
	"encoding/pem"
)

func main() {
	directoryPath:=flag.String("directory", "", "The filepath to the directory containing the data")
	password:=flag.String("password", "", "The password to use for the keystores")

	flag.Parse()
	fmt.Print(*directoryPath)
	if *directoryPath == ""{
		log.Fatal("Directory path not provided")
		os.Exit(1)
	}
	if *password == ""{
		log.Fatal("Password not provided")
		os.Exit(2)
	}

	privateKeyPath:= *directoryPath + "/key"
	publicCertPath:= *directoryPath + "/cert"
	serverPublicCertFile:=*directoryPath + "/ca.crt"

	identityStoreFile:=*directoryPath + "/identity.jks"
	trustStoreFile:=*directoryPath + "/truststore.jks"

	//Read private key

	privateKeyBytes, err:=ioutil.ReadFile(privateKeyPath)
	if err!=nil{
		log.Fatal(err)
		os.Exit(10)
	}
	publicCertBytes, err:=ioutil.ReadFile(publicCertPath)
	if err!=nil{
		log.Fatal(err)
		os.Exit(11)
	}
	serverPublicCertBytes, err:=ioutil.ReadFile(serverPublicCertFile)
	if err!=nil{
		log.Fatal(err)
		os.Exit(12)
	}

	privateKey, _:=pem.Decode(privateKeyBytes)
	certificate:=keystore.Certificate{
		Type: "X509",
		Content: publicCertBytes,
	}
	certificateChain:=[]keystore.Certificate{certificate}
	identityStore:=createIdentityStore("user", privateKey.Bytes, certificateChain)

	serverCertificate:=keystore.Certificate{
		Type: "X509",
		Content: serverPublicCertBytes,
	}
	trustStore:=createTrustStore("remote", serverCertificate)

	writeKeyStore(identityStore, identityStoreFile, []byte(*password))
	writeKeyStore(trustStore, trustStoreFile, []byte(*password))
	//Read associated cert
	//write identitystore

	//identityStore:= createIdentityStore()
	//writeKeyStore(identityStore, )

}

func createIdentityStore(alias string, privateKey []byte, publicKeyCert []keystore.Certificate) (keystore.KeyStore){
	identityStore := keystore.KeyStore{
		alias: &keystore.PrivateKeyEntry{
			Entry: keystore.Entry{
				CreationDate: time.Now(),
			},
			PrivKey: privateKey,
			CertChain: publicKeyCert,
		},
	}
	return identityStore
}

func createTrustStore(alias string, certificate keystore.Certificate)(keystore.KeyStore){
	trustStore:= keystore.KeyStore{
		alias: &keystore.TrustedCertificateEntry{
			Entry: keystore.Entry{
				CreationDate: time.Now(),
			},
			Certificate: certificate,
		},
	}
	return trustStore
}

func writeKeyStore(keyStore keystore.KeyStore, filename string, password []byte) {
	o, err := os.Create(filename)
	defer o.Close()
	if err != nil {
		log.Fatal(err)
	}
	err = keystore.Encode(o, keyStore, password)
	if err != nil {
		log.Fatal(err)
	}
}