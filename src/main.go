//
//  This package was written by Paul Schou in Dec 2020
//
//  Intended to help with linking two NiFis together without the worry of data going in the reverse direction.
//
package main

import (
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"time"

	"github.com/pschou/go-params"
)

type DNS struct {
	Addr string
	Time time.Time
}

var (
	target_addr *string
	debug       *bool
	version     = "not set"
	tls_host    *string
	listen      *string
)

func main() {
	params.Usage = func() {
		fmt.Fprintf(os.Stderr, "Simple NiFi Diode (github.com/pschou/nifi-diode)\nApache 2.0 license, for personal use only, provided AS-IS -- not responsible for loss.\nUsage implies agreement.  Version: %s\n\nUsage: %s [options...]\n\n", version, os.Args[0])
		params.PrintDefaults()
	}
	debug = params.Pres("debug", "Verbose output")
	log_server = params.String("logger", "", "Remote logging server to use for collecting logs on events, SysLog or SPLUNK capable.\n"+
		"Format:  [proto]://[tag]@[host:port]/[priority] for example:  tcp://NiFi-Diode@123.123.123.123:515/LOG_NOTICE\n"+
		"Multiple log targets can be specified with commas udp://10.0.0.1,udp://10.0.0.2 (UDP is preferred)", "STRING")
	metrics_server = params.String("metrics", "", "Remote metrics-collector server for collecting OpenMetrics for system monitoring.", "")
	watchdog_max = params.Duration("watchdog", time.Duration(0), "Trigger a reboot if no connection is seen within this time window\nYou'll neet to make sure you have the watchdog module enabled on the host and kernel.", "DURATION")
	var init_run = params.String("init-run", "", "Run shell script before starting server. Use this to enable networking when nifi-diode\nis started by the kernel in INIT 1 state (single process)", "PATH")
	var max_conn = params.Int("max-sockets", 2048, "Maximum number of sockets allowed to be open at once for DoS protection", "INT")

	params.GroupingSet("Listener")
	listen = params.String("l listen", ":7443", "Incoming/listen address for diode", "HOST:PORT")
	verify_server = params.Bool("verify-incoming", true, "Verify incoming connections, do certificate checks", "BOOL")
	secure_server = params.Bool("secure-incoming", true, "Enforce minimum of TLS 1.2 on server side", "BOOL")
	tls_server = params.Bool("tls-incoming", true, "Enable listener TLS", "BOOL")
	params.GroupingSet("Target")
	target_addr = params.String("t target", "127.0.0.1:443", "Output/target address for diode", "HOST:PORT")
	var verify_client = params.Bool("verify-target", true, "Verify target, do certificate checks", "BOOL")
	var secure_client = params.Bool("secure-target", true, "Enforce minimum of TLS 1.2 on client side", "BOOL")
	var tls_client = params.Bool("tls-target", true, "Enable output TLS", "BOOL")
	tls_host = params.String("H host", "", "Hostname for output/target NiFi - This should be set to what the target is expecting", "FQDN[:PORT]")
	params.GroupingSet("Certificate")
	certFile = params.String("E cert", "/etc/pki/server.pem", "File to load with CERT - automatically reloaded every minute\n", "FILE")
	keyFile = params.String("key", "/etc/pki/server.pem", "File to load with KEY - automatically reloaded every minute\n", "FILE")
	rootFile = params.String("ca", "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", "File to load with ROOT CAs - reloaded every minute by adding any new entries\n", "FILE")
	params.CommandLine.Indent = 2
	params.Parse()

	log_init()  // Setup the Logging server
	keys_init() // Load in the PKI certs and chains

	if *tls_host == "" {
		tls_host = target_addr
	}

	// Run any init shell scripts
	if len(*init_run) > 2 {
		log.Printf("Running %s...", *init_run)
		cmd, err := exec.Command("/bin/sh", *init_run).Output()
		if err != nil {
			fmt.Printf("error %s", err)
		}
		fmt.Println(cmd)
	}

	watchdog_init() // Setup the watchdog

	// Setup the server for listening
	l, err := server_init()
	if err != nil {
		return
	}

	log.Println("Target set to", *target_addr)
	log.Println("Host set to", *tls_host)

	defer l.Close()

	// Master loop to listen for incoming connections
	conn_count := 0
	for {
		if conn_count > *max_conn {
			// When we have too many concurrent connections, close the port entirely
			// so the host no longer replies to TCP SYN requests.  Loop every second
			// and wait until the connection count to drop before re-openning.
			l.Close()
			for conn_count > *max_conn {
				time.Sleep(time.Second)
			}
			l, err = server_init()
			if err != nil {
				return
			}
		}
		conn, err := l.Accept() // Wait for a connection.
		logger_Write("New connection from " + conn.RemoteAddr().String())
		if *debug {
			fmt.Println("New connection from", conn.RemoteAddr())
		}
		last_connection = time.Now()
		if err != nil {
			fmt.Println("Error on accept", err)
			logger_Write(fmt.Sprintf("Error accepting connection from %s, %q", conn.RemoteAddr(), err))
			continue
		}

		go func(input net.Conn) {
			conn_count++
			defer func() {
				conn.Close()
				input.Close()
				conn_count--
			}()
			var target net.Conn
			var err error
			if *debug {
				log.Println("dialing endpoint:", *target_addr)
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
				target_tls, err = tls.Dial("tcp", *target_addr, tlsConfig)
				target = target_tls
			} else {
				target, err = net.Dial("tcp", *target_addr)
			}
			if err != nil {
				log.Println("error dialing endpoint:", *target_addr, "error:", err)
				logger_Write(fmt.Sprintf("Diode connection from %q, error dialing %q", conn.RemoteAddr(), *target_addr))
				return
			}
			logger_Write(fmt.Sprintf("Diode connection from %q via %q -> %q", conn.RemoteAddr(), target.LocalAddr(), target.RemoteAddr()))
			if *debug {
				log.Println("connected!", *target_addr)
			}

			// We have established TCP connections with an upstream and a downstream
			// NiFi.  Here we pass off the connection to the diode function for
			// making sure the data is transferred in a safe manner:
			err = diode(input, target)

			if err != nil {
				if *debug {
					fmt.Println(conn.RemoteAddr(), "->", *target_addr, err)
				}
				logger_Write(fmt.Sprintf("Diode connection err with %q via %q -> %q, err: %s", conn.RemoteAddr(), target.LocalAddr(), target.RemoteAddr(), err))
			}
		}(conn)
	}
}
