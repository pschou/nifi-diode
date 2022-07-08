//
//  This package was written by Paul Schou in Dec 2020
//
//  Intended to help with linking two NiFis together without the worry of data going in the reverse direction.
//
package main

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/pschou/go-params"
)

type DNS struct {
	Addr string
	Time time.Time
}

var target_addr = ""
var DNSCache = make(map[string]DNS, 0)
var keyFile, certFile, rootFile *string
var keypair *tls.Certificate
var keypair_count = 0
var keypair_mu sync.RWMutex
var root_count = 0
var rootpool *x509.CertPool
var certs_loaded = make(map[string]bool, 0)
var debug *bool
var version = "not set"
var tls_host *string

func loadKeys() {
	keypair_mu.RLock()
	defer keypair_mu.RUnlock()
	var err error

	tmp_key, err_k := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err_k != nil {
		if keypair == nil {
			log.Fatalf("failed to loadkey pair, check that the cert file has a public key and the key file has a private key.\npublic: %s\nprivate: %s", *certFile, *keyFile)
		}
		keypair_count++
		log.Println("WARNING: Cannot load keypair (cert/key)", *certFile, *keyFile, "attempt:", keypair_count)
		if keypair_count > 10 {
			log.Fatalf("failed to loadkey pair, check that the cert file has a public key and the key file has a private key.\npublic: %s\nprivate: %s", *certFile, *keyFile)
		}
	} else {
		if *debug {
			log.Println("Loaded keypair", *certFile, *keyFile)
		}
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
		root_count = 0
	}

}

func main() {
	params.Usage = func() {
		fmt.Fprintf(os.Stderr, "Simple NiFi Diode (github.com/pschou/nifi-diode)\nApache 2.0 license, for personal use only, provided AS-IS -- not responsible for loss.\nUsage implies agreement.  Version: %s\n\nUsage: %s [options...]\n\n", version, os.Args[0])
		params.PrintDefaults()
	}
	debug = params.Pres("debug", "Verbose output")
	params.GroupingSet("Listener")
	var listen = params.String("listen", ":7443", "Incoming/listen address for diode", "HOST:PORT")
	var verify_server = params.Bool("verify-incoming", true, "Verify incoming connections, do certificate checks", "BOOL")
	var secure_server = params.Bool("secure-incoming", true, "Enforce minimum of TLS 1.2 on server side", "BOOL")
	var tls_server = params.Bool("tls-incoming", true, "Enable listener TLS", "BOOL")
	params.GroupingSet("Target")
	var target = params.String("target", "127.0.0.1:443", "Output/target address for diode", "HOST:PORT")
	var verify_client = params.Bool("verify-target", true, "Verify target, do certificate checks", "BOOL")
	var secure_client = params.Bool("secure-target", true, "Enforce minimum of TLS 1.2 on client side", "BOOL")
	var tls_client = params.Bool("tls-target", true, "Enable output TLS", "BOOL")
	tls_host = params.String("host", "", "Hostname for output/target NiFi - This should be set to what the target is expecting", "FQDN[:PORT]")
	params.GroupingSet("Certificate")
	certFile = params.String("cert", "/etc/pki/server.pem", "File to load with CERT - automatically reloaded every minute\n", "FILE")
	keyFile = params.String("key", "/etc/pki/server.pem", "File to load with KEY - automatically reloaded every minute\n", "FILE")
	rootFile = params.String("ca", "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", "File to load with ROOT CAs - reloaded every minute by adding any new entries\n", "FILE")
	params.CommandLine.Indent = 2
	params.Parse()

	if *tls_host == "" {
		tls_host = target
	}

	var err error

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

	var l net.Listener
	if *tls_server {
		var config tls.Config
		if *secure_server {
			config = tls.Config{RootCAs: rootpool,
				Certificates: []tls.Certificate{},
				ClientCAs:    rootpool, InsecureSkipVerify: *verify_server == false,
				MinVersion:               tls.VersionTLS12,
				CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
				Renegotiation:            tls.RenegotiateOnceAsClient,
				PreferServerCipherSuites: true,
				CipherSuites: []uint16{
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_RSA_WITH_AES_256_CBC_SHA,
				},
			}
		} else {
			config = tls.Config{RootCAs: rootpool,
				ClientCAs: rootpool, InsecureSkipVerify: *verify_server == false}
		}
		config.GetCertificate = func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if *debug {
				log.Println("  Get Cert Returning keypair")
			}
			return keypair, nil
		}

		config.Rand = rand.Reader
		if *debug {
			fmt.Println("TLS Listening on", *listen)
		}
		if l, err = tls.Listen("tcp", *listen, &config); err != nil {
			log.Fatal(err)
		}
	} else {
		var err error
		if *debug {
			fmt.Println("Listening on", *listen)
		}
		if l, err = net.Listen("tcp", *listen); err != nil {
			log.Fatal(err)
		}
	}

	log.Println("Target set to", *target)
	log.Println("Host set to", *tls_host)
	target_addr = *target

	defer l.Close()
	for {
		conn, err := l.Accept() // Wait for a connection.
		if err != nil {
			fmt.Println("Error on accept", err)
			continue
		}
		if *debug {
			fmt.Println("New connection from", conn.RemoteAddr())
		}

		go func(input net.Conn) {
			defer conn.Close()
			defer input.Close()
			var target net.Conn
			var err error
			if *debug {
				log.Println("dialing endpoint:", target_addr)
			}

			if *tls_client {
				var tlsConfig *tls.Config
				if *secure_client {
					tlsConfig = &tls.Config{Certificates: []tls.Certificate{*keypair}, RootCAs: rootpool,
						ClientCAs: rootpool, InsecureSkipVerify: *verify_client == false, ServerName: *tls_host,
						MinVersion:               tls.VersionTLS12,
						CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
						PreferServerCipherSuites: true,
						CipherSuites: []uint16{
							tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
							tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
							tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
							tls.TLS_RSA_WITH_AES_256_CBC_SHA,
						},
					}
				} else {
					tlsConfig = &tls.Config{Certificates: []tls.Certificate{*keypair}, RootCAs: rootpool,
						ClientCAs: rootpool, InsecureSkipVerify: *verify_client == false, ServerName: *tls_host}
				}

				tlsConfig.Rand = rand.Reader

				var target_tls *tls.Conn
				target_tls, err = tls.Dial("tcp", target_addr, tlsConfig)
				target = target_tls
			} else {
				target, err = net.Dial("tcp", target_addr)
			}
			if err != nil {
				log.Println("error dialing endpoint:", target_addr, "error:", err)
				return
			}
			if *debug {
				log.Println("connected!", target_addr)
			}

			err = diode(input, target)
			if *debug {
				fmt.Println(conn.RemoteAddr(), "->", target_addr, err)
			}
		}(conn)
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
