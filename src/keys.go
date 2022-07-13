package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"sync"
	"time"
)

var (
	keyFile, certFile, rootFile *string
	keypair                     *tls.Certificate
	keypair_count               = 0
	keypair_mu                  sync.RWMutex
	root_count                  = 0
	rootpool                    *x509.CertPool
	certs_loaded                = make(map[string]bool, 0)
)

func keys_init() {
	rootpool = x509.NewCertPool()
	loadKeys()
	go func() {
		ticker := time.NewTicker(time.Minute)
		for {
			select {
			case <-ticker.C:
				loadKeys()
			}
		}
	}()
}

func loadKeys() {
	keypair_mu.RLock()
	defer keypair_mu.RUnlock()
	var err error

	tmp_key, err_k := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err_k != nil {
		logger_Write(fmt.Sprintf("failed to loadkey pair, check that the cert file has a public key and the key file has a private key.\npublic: %s\nprivate: %s, %s", *certFile, *keyFile, err_k))
		if keypair == nil {
			log.Fatalf("failed to loadkey pair, check that the cert file has a public key and the key file has a private key.\npublic: %s\nprivate: %s, %s", *certFile, *keyFile, err_k)
		}
		keypair_count++
		log.Println("WARNING: Cannot load keypair (cert/key)", *certFile, *keyFile, "attempt:", keypair_count)
		if keypair_count > 10 {
			log.Fatalf("failed to loadkey pair, check that the cert file has a public key and the key file has a private key.\npublic: %s\nprivate: %s, %s", *certFile, *keyFile, err_k)
		}
	} else {
		if *debug {
			log.Println("Loaded keypair", *certFile, *keyFile)
		}
		logger_Write(fmt.Sprintf("Loaded keypair", *certFile, *keyFile))
		keypair = &tmp_key
		keypair_count = 0
	}

	err_r := LoadCertficatesFromFile(*rootFile)
	if err_r != nil {
		if rootpool == nil {
			log.Fatalf("failed to load CA: %s", err)
		}
		root_count++
		log.Println("WARNING: Cannot load CA file", *rootFile, "attempt:", root_count)
		if root_count > 10 {
			log.Fatalf("failed to CA: %s", err)
		}
	} else {
		if *debug {
			log.Println("Loaded CA", *rootFile)
		}
		logger_Write(fmt.Sprintf("Loaded CA", *rootFile))
		root_count = 0
	}
}

func LoadCertficatesFromFile(path string) error {
	raw, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}

	for {
		block, rest := pem.Decode(raw)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				fmt.Println("warning: error parsing CA cert", err)
				logger_Write(fmt.Sprintf("Error parsing CA cert %q, %s", cert, err))
				continue
			}
			t := fmt.Sprintf("%v%v", cert.SerialNumber, cert.Subject)
			if _, ok := certs_loaded[t]; !ok {
				if *debug {
					fmt.Println(" Adding CA:", cert.Subject)
				}
				rootpool.AddCert(cert)
				certs_loaded[t] = true
			}
		}
		raw = rest
	}

	return nil
}
