# NiFi Diode
Super simple NiFi Diode that does one thing, takes in data and passes it on to
another NiFi without letting anything go the other direction.  Hence it's a
simple, no-cache-diode.

The idea here is this server listens on a IP:Port and then any incomming
connection is streamed to another IP:Port, but data can only transfer one way.
The sending side will have no idea what server it is sending to nor be able to
get any information from the downstream NiFi.

Think of the NiFi diode like a one way glass.  The downstream NiFi sees
everything from the sending NiFi server as if the diode is not there but the
sending side only sees "NiFi Diode".  So if the downstream NiFi is expecting a
POST to go to an alternate content listener URL, the client must be configured
to point to the same URL as the diode will only reply with success if a success
happens.  No notifications are sent to the sending side what may have gone
wrong if a transfer fails.  This is to ensure nothing gets leaked back to the
sending side via server replies.

The only fields which are changed going through the diode in the forward
direction are the `Host` field (which NiFi needs to ensure connection
authenticity) and `X-Forwarded-For` which lists the remote endpoint(s).  If
multiple NiFi diode servers are stacked one upon another, the X-Forwarded-For
will have a complete list of source IP addresses seperated by commas.


![NiFi-Diode diagram showing a NiFi box on the left, and arrow representing a TCP flow pointing to a NiFi Diode in the middle, and another arrow to the right going to a NiFi box on the right, again representing a TCP flow](NiFi-Diode.png)

Moving data between domains with a "FOSS Hardware" solution.


## Why do I need this?

Imagine, if you will, you need to get data into a secure environment, a
hospital network with 3128 windows machines.  Well, to be more specific,
windows software updates.  With all the HIPAA regulations, how can you get this
regular flow of patches into the network?  Well, the tool of choice is NiFi...
But, how often can people make a mistake and leave a NiFi open/unsecured?  One
accident is too often.

So, we need a super-secure, no accidents allowed, flow.  How do you do this
task of bringing in updates while ensuring that data has no chance of escaping
the network?  Enter stage right, nifi-diode.  This tool has a good resume:

- Free and open-source (FOSS is good)
- Has a memory footprint of 1-50 MB. (It runs on cheap hardware) 
- Can run directly from a kernel INIT= call - Avoid purchasing a dedicated 
  hardware appliance.  Download your favorite distro and then modify the grub
  init to point to this binary instead of the standard init and you have yourself
  a linux based "hardware" NiFi diode.
- Standard data diode protections apply - place this on a box in a locked server
  room, and by denying physical access, you effectively prohibit data from going
  the wrong way. (It's a win-win!)
- Threadable, the server handles multiple concurrent flows which can help with
  latency issues and increase throughput.

What are the pitfalls?

- If the server dies, who knows for what reason, you need to get to the
  physical server to restore the diode.  A watchdog timer is included for this
  purpose, so set the timeout to an acceptable outage window size.  (overall this
  seems like a good risk when preventing reverse data flow)
- It's command line, so you have to know Linux. (my manager included this, but
  techies should know Linux)
- If you like burning all your data to a DVD and sneaker netting it between
  buildings, you'll have to find a gym now.  :(

## Usage
```
$ ../nifi-diode  -h
Simple NiFi Diode (github.com/pschou/nifi-diode)
Apache 2.0 license, for personal use only, provided AS-IS -- not responsible for loss.
Usage implies agreement.  Version: 0.1.20220713.2129

Usage: ./nifi-diode [options...]

Options:
      --debug           Verbose output
      --init-run PATH   Run shell script before starting server. Use this to enable networking when nifi-diode
                        is started by the kernel in INIT 1 state (single process)  (Default: "")
      --logger STRING   Remote logging server to use for collecting logs on events, SysLog or SPLUNK capable.
                        Format:  [proto]://[tag]@[host:port]/[priority] for example:  tcp://NiFi-Diode@123.123.123.123:515/LOG_NOTICE
                        Multiple log targets can be specified with commas udp://10.0.0.1,udp://10.0.0.2 (UDP is preferred)  (Default: "")
      --max-sockets INT  Maximum number of sockets allowed to be open at once for DoS protection  (Default: 2048)
      --metrics         Remote metrics-collector server for collecting OpenMetrics for system monitoring.  (Default: "")
      --watchdog DURATION  Trigger a reboot if no connection is seen within this time window
                        You'll neet to make sure you have the watchdog module enabled on the host and kernel.  (Default: 0s)
Listener options:
  -l, --listen HOST:PORT  Incoming/listen address for diode  (Default: ":7443")
      --secure-incoming BOOL  Enforce minimum of TLS 1.2 on server side  (Default: true)
      --tls-incoming BOOL  Enable listener TLS  (Default: true)
      --verify-incoming BOOL  Verify incoming connections, do certificate checks  (Default: true)
Target options:
  -H, --host FQDN[:PORT]  Hostname for output/target NiFi - This should be set to what the target is expecting  (Default: "")
      --secure-target BOOL  Enforce minimum of TLS 1.2 on client side  (Default: true)
  -t, --target HOST:PORT  Output/target address for diode  (Default: "127.0.0.1:443")
      --tls-target BOOL  Enable output TLS  (Default: true)
      --verify-target BOOL  Verify target, do certificate checks  (Default: true)
Certificate options:
      --ca FILE         File to load with ROOT CAs - reloaded every minute by adding any new entries
                          (Default: "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem")
  -E, --cert FILE       File to load with CERT - automatically reloaded every minute
                          (Default: "/etc/pki/server.pem")
      --key FILE        File to load with KEY - automatically reloaded every minute
                          (Default: "/etc/pki/server.pem")
```

## Example Usage 

```
$ ./nifi-diode --target http://software-server.mydomain.edu:8000 --tls-target false --tls-incoming true --cert /etc/pki/server.pem --key /etc/pki/server.pem --ca /etc/pki/CA.pem
```

In this example, the Domain 1 side is encrypted with an internal signed cert
and Domain 2 is unencrypted.  One can turn on or off encryption on either side.
The reason why encryption is turned on for the Domain 1 is to ensure the
connection is established by our NiFi box and not another system on the same
public network.  Internally, the encryption is not needed as the system sits
inside the same server room as the software-server

Note that the `--host` was left off as the target DNS matches the remote system
hostname.  If it didn't, one would have to do something like this:
```
$ ./nifi-diode --host mysecure-host:8000 --target http://10.99.99.2:8000 --tls-target false --tls-incoming false --listen :8000
```

This example shows a "drop in" replacement for a NiFi target.  Point the diode
to the actual downstream NiFi and assign the diode to a static IP address.

