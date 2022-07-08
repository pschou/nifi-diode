# NiFi Diode
Super simple NiFi Diode that does one thing, takes in data and passes it on to
another NiFi without letting anything go the other direction.  Hence it's a
simple, no-cache-diode.

The idea here is this server listens on a ip:port and then any incomming
connection is streamed to another ip:port, but data can only transfer one way.
The sending side will have no idea what server it is sending to nor be able to
get any information from the downstream NiFi.

## Usage
```
$ ./nifi-diode -h
Simple NiFi Diode (github.com/pschou/nifi-diode)
Apache 2.0 license, for personal use only, provided AS-IS -- not responsible for loss.
Usage implies agreement.  Version: 0.1.20220708.1148

Usage: ./nifi-diode [options...]

Option:
  --debug               Verbose output
Listener options:
  --listen HOST:PORT    Incoming/listen address for diode  (Default: ":7443")
  --secure-incoming BOOL  Enforce minimum of TLS 1.2 on server side  (Default: true)
  --tls-incoming BOOL   Enable listener TLS  (Default: true)
  --verify-incoming BOOL  Verify incoming connections, do certificate checks  (Default: true)
Target options:
  --host FQDN[:PORT]    Hostname for output/target NiFi - This should be set to what the target is expecting  (Default: "localhost")
  --secure-target BOOL  Enforce minimum of TLS 1.2 on client side  (Default: true)
  --target HOST:PORT    Output/target address for diode  (Default: "127.0.0.1:443")
  --tls-target BOOL     Enable output TLS  (Default: true)
  --verify-target BOOL  Verify target, do certificate checks  (Default: true)
Certificate options:
  --ca FILE             File to load with ROOT CAs - reloaded every minute by adding any new entries
                          (Default: "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem")
  --cert FILE           File to load with CERT - automatically reloaded every minute
                          (Default: "/etc/pki/server.pem")
  --key FILE            File to load with KEY - automatically reloaded every minute
                          (Default: "/etc/pki/server.pem")
```
