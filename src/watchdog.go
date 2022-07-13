package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/mdlayher/watchdog"
)

var (
	watchdog_max    *time.Duration
	last_connection time.Time
)

func watchdog_init() {
	last_connection = time.Now()
	if *watchdog_max > time.Duration(1000) {
		d, err := watchdog.Open()
		if err != nil {
			log.Fatalf("failed to open watchdog: %v", err)
		}
		log.Println("Watchdog setup for interval:", *watchdog_max)

		// Handle control-c / sigterm by closing out the watchdog timer
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			for sig := range sigs {
				log.Printf("captured %v, stopping watchdog...", sig)
				d.Close()
				os.Exit(1)
			}
		}()

		go func() {
			// We purposely double-close the file to ensure that the explicit Close
			// later on also disarms the device as the program exits. Otherwise it's
			// possible we may exit early or with a subtle error and leave the system
			// in a doomed state.
			defer d.Close()

			timeout, err := d.Timeout()
			if err != nil {
				log.Fatalf("failed to fetch watchdog timeout: %v", err)
			}

			interval := 10 * time.Second
			if timeout < interval {
				interval = timeout
			}

			for {
				if time.Now().Sub(last_connection) < *watchdog_max {
					if err := d.Ping(); err != nil {
						log.Printf("failed to ping watchdog: %v", err)
					}
				}

				time.Sleep(interval)
			}

			// Safely disarm the device before exiting.
			if err := d.Close(); err != nil {
				log.Printf("failed to disarm watchdog: %v", err)
			}
		}()
	}
}
