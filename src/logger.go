package main

import (
	"log"
	"log/syslog"
	"net/url"
	"strings"
	"time"
)

var loggers []*syslog.Writer
var log_server *string

func logger_Write(s string) {
	for _, l := range loggers {
		l.Write([]byte(s))
	}
}

func log_init() {
	if *log_server != "" {
		log_connect := func() {
			var old_loggers, new_loggers []*syslog.Writer
			for _, srvr := range strings.Split(*log_server, ",") {
				lh, err := url.Parse(srvr)
				if err != nil {
					log.Fatal("Could not parse the log_server, " + srvr)
				}
				lh.Scheme = strings.ToLower(lh.Scheme)
				switch lh.Scheme {
				case "tcp", "udp":
				default:
					log.Fatal("Unknown log_server scheme, " + lh.Scheme)
				}

				tag := "NiFi-Diode"
				if lh.User != nil {
					tag = lh.User.Username()
				}
				priority := syslog.LOG_NOTICE
				switch strings.SplitN(strings.ToLower(strings.TrimPrefix(lh.Path, "/")), "/", 2)[0] {
				case "LOG_EMERG":
					priority = syslog.LOG_EMERG
				case "LOG_ALERT":
					priority = syslog.LOG_ALERT
				case "LOG_CRIT":
					priority = syslog.LOG_CRIT
				case "LOG_ERR":
					priority = syslog.LOG_ERR
				case "LOG_WARNING":
					priority = syslog.LOG_WARNING
				case "LOG_NOTICE":
					priority = syslog.LOG_NOTICE
				case "LOG_INFO":
					priority = syslog.LOG_INFO
				case "LOG_DEBUG":
					priority = syslog.LOG_DEBUG
				}
				logger, err := syslog.Dial(lh.Scheme, lh.Host, priority, tag)
				if err != nil {
					log.Println("Error dialing loghost", err)
				} else {
					new_loggers = append(new_loggers, logger)
				}
			}
			old_loggers, loggers = loggers, new_loggers
			for _, logger := range old_loggers {
				logger.Close()
			}
		}
		log_connect()
		ticker := time.NewTicker(10 * time.Minute)
		// Refresh the logger connection every 10 minutes
		go func() {
			for range ticker.C {
				log_connect()
			}
		}()
	}
}
