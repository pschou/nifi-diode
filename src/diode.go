package main

import (
	"bufio"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

func diode(input net.Conn, output io.ReadWriter) error {
	var total_bytes uint64
	connection_counter++
	// To protect any "information" from going backwards over the wire, we'll
	// create a uuid translation map so DELETE commands can reference a flowfile
	// which is called something different on the other side of the diode.
	//uuid_map := make(map[string]string)
	// TODO: Should this be implemented?

	// A buffer reader is used to ensure lines are read one at a time and that a
	// buffer overflow does not happen when reading in headers, etc.
	inbuf := bufio.NewReader(input)
	outbuf := bufio.NewWriter(output)

	// HTTP responses from target, all thrown away.
	anti_diode := bufio.NewReader(output)

	FLOWFILE_CONFIRMATION_HEADER := "x-prefer-acknowledge-uri"

	var output_pipe io.Writer
	for {
		header_map := make(map[string]string)
		var method, target, forward string
		var has_method bool

		for {
			str, err := inbuf.ReadString('\n')
			if err != nil {
				return fmt.Errorf("Diode: Error reading in input header, %s", err)
			}
			if strings.TrimSpace(str) == "" {
				if err != nil {
					return fmt.Errorf("Diode: Error writing header end to output, %s", err)
				}
				break
			}

			// Strip off the action from the input request
			if !has_method {
				parts := strings.SplitN(str, " ", 3)
				if len(parts) < 3 {
					return fmt.Errorf("Diode: Malformed HTTP method line, %q", str)
				}
				method = parts[0]
				target = parts[1]
				switch method {
				case "POST", "HEAD":
					output_pipe = outbuf
				case "DELETE", "GET":
					// Write everything to discard, as DELETE and GET are not needed here
					output_pipe = ioutil.Discard
				default:
					return fmt.Errorf("Diode: Unrecognized HTTP method, %q", method)
				}
				has_method = true
			} else {
				parts := strings.SplitN(str, " ", 2)
				if strings.HasSuffix(parts[0], ":") {
					header_map[strings.ToLower(parts[0][:len(parts[0])-1])] = strings.TrimSpace(parts[1])
				}
				if len(header_map) > 1000 {
					// Header size may become an issue, git up early
					return fmt.Errorf("Diode: Too many headers in input")
				}
				if strings.EqualFold(parts[0], FLOWFILE_CONFIRMATION_HEADER+":") {
					continue
				}
				if strings.EqualFold(parts[0], "Host:") {
					str = "Host: " + *tls_host + "\r\n"
				}
				if strings.EqualFold(parts[0], "X-Forwarded-For:") {
					forward = str
					continue
				}
			}

			// We are a diode, so write the input header request to the output
			_, err = output_pipe.Write([]byte(str))
			if err != nil {
				return fmt.Errorf("Diode: Error writing to output, %s", err)
			}
		}

		if !has_method {
			return fmt.Errorf("Diode: Input does not have an HTTP method")
		}

		if forward == "" {
			// Create a pipeline log
			output_pipe.Write([]byte("X-Forwarded-For: " + input.RemoteAddr().String() + "\r\n\r\n"))
		} else {
			// Build a pipeline log
			output_pipe.Write([]byte(strings.TrimSpace(forward) + "," + input.RemoteAddr().String() + "\r\n\r\n"))
		}
		outbuf.Flush()

		switch method {
		case "HEAD":
			input.Write([]byte("HTTP/1.1 200 OK\r\n" +
				"Date: " + time.Now().UTC().Format(time.RFC1123) + "\r\n" +
				"Accept: application/flowfile-v3,application/octet-stream;q=0.8\r\n" +
				"x-nifi-transfer-protocol-version: 3\r\n" +
				"Content-Length: 0\r\n" +
				"Server: NiFi-Diode (github.com/pschou/nifi-diode)\r\n" +
				"\r\n"))
		case "GET":
			myself := "NiFi Diode is ready"
			input.Write([]byte("HTTP/1.1 200 OK\r\n" +
				"Date: " + time.Now().UTC().Format(time.RFC1123) + "\r\n" +
				"Content-Type: text-plain\r\n" +
				"Content-Length: " + fmt.Sprintf("%d", len(myself)) + "\r\n" +
				"Server: NiFi-Diode (github.com/pschou/nifi-diode)\r\n" +
				"\r\n" +
				myself))
		case "DELETE":
			// We really don't care about deleting stuff upstream.  So here we give
			// the client a false sense of success!
			input.Write([]byte("HTTP/1.1 200 OK\r\n" +
				"Date: " + time.Now().UTC().Format(time.RFC1123) + "\r\n" +
				"Transfer-Encoding: chunked\r\n" +
				"Server: NiFi-Diode (github.com/pschou/nifi-diode)\r\n" +
				"\r\n" +
				"0\r\n" +
				"\r\n"))
		case "POST":
			if cl, ok := header_map["content-length"]; ok {
				i, err := strconv.ParseInt(cl, 10, 64)
				if err != nil {
					return fmt.Errorf("Diode: Invalid content length, %q", cl)
				}
				if i > 0 {
					io.Copy(outbuf, &io.LimitedReader{R: inbuf, N: i})
				}
			} else {
				if strings.ToLower(header_map["transfer-encoding"]) != "chunked" {
					return fmt.Errorf("Diode: No content-length specified or invalid transfer-encoding, %q", header_map["transfer-encoding"])
				}

			post:
				for {
					str, err := inbuf.ReadString('\n')
					if str == "" && err != nil {
						return fmt.Errorf("Diode: Error reading in post payload, %s", err)
					}
					_, err = outbuf.Write([]byte(str))
					if err != nil {
						return fmt.Errorf("Diode: Error writing post payload, %s", err)
					}
					switch trim := strings.TrimSpace(str); trim {
					case "":
						// Ignore extra blank line (example: between the end of flowfile and 0 line)
					case "0":
						// End of session
						str, err := inbuf.ReadString('\n')
						if str == "" && err != nil {
							return fmt.Errorf("Diode: Error reading end of post payload, %s", err)
						}
						_, err = outbuf.Write([]byte(str))
						if err != nil {
							return fmt.Errorf("Diode: Error writing end of post payload, %s", err)
						}
						break post
					default:
						if header_map["content-type"] == "application/flowfile-v3" {
							// Handle the case of a flow file
							i, err := strconv.ParseInt(trim, 16, 64)
							if err != nil {
								return fmt.Errorf("Diode: Invalid flowfile length, %q", trim)
							}
							n, _ := io.Copy(outbuf, &io.LimitedReader{R: inbuf, N: i})
							total_bytes += uint64(n)
						} else {
							// Simple octect stream
							i, err := strconv.ParseInt(trim, 10, 64)
							if err != nil {
								return fmt.Errorf("Diode: Invalid flowfile length, %q", trim)
							}
							n, _ := io.Copy(outbuf, &io.LimitedReader{R: inbuf, N: i})
							total_bytes += uint64(n)
						}
					}
					outbuf.Flush()
				}
			}
			outbuf.Flush()

			var firstLine string
			for {
				// Sink everything to /dev/null from downstream except the return code
				str, err := anti_diode.ReadString('\n')
				if firstLine == "" {
					firstLine = str
				}
				if err != nil {
					return fmt.Errorf("Diode: Error reading in target header, %s", err)
				}
				if strings.TrimSpace(str) == "" {
					break
				}
			}

			if method == "POST" {
				if *debug {
					// Display the return code to the logger if logging is turned on locally
					log.Println("Downstream got:", firstLine)
				}
				returnMethod := strings.SplitN(firstLine, " ", 3)
				if len(returnMethod) >= 2 {
					if returnMethod[1] == "303" {
						byte_counter += total_bytes
						transfer_counter++
						if v, ok := header_map[FLOWFILE_CONFIRMATION_HEADER]; ok && strings.HasPrefix(v, "t") {
							// Generate some random UUID string just to make the client happy
							rand_uuid := uuid.New()
							path := strings.TrimSuffix(target, "/") + "/holds/" + rand_uuid.String()
							input.Write([]byte("HTTP/1.1 303 See Other\r\n" +
								"Date: " + time.Now().UTC().Format(time.RFC1123) + "\r\n" +
								"Content-Type: text-plain\r\n" +
								"Location: " + path + "\r\n" +
								"x-location-uri-intent: flowfile-hold\r\n" +
								"Content-Length: " + fmt.Sprintf("%d", len(path)) + "\r\n" +
								"Server: NiFi-Diode (github.com/pschou/nifi-diode)\r\n" +
								"\r\n" +
								path))
							return nil
						}
					} else if returnMethod[1] == "200" {
						byte_counter += total_bytes
						transfer_counter++
						input.Write([]byte("HTTP/1.1 200 OK\r\n" +
							"Date: " + time.Now().UTC().Format(time.RFC1123) + "\r\n" +
							"Content-Type: text-plain\r\n" +
							"Content-Length: 0\r\n" +
							"Server: NiFi-Diode (github.com/pschou/nifi-diode)\r\n" +
							"\r\n"))
						return nil
					}
				}
				// Downstream encountered an error, just close the connection.  We
				// don't really want details of why it failed to be passed on.
				return fmt.Errorf("Diode: Target did not reply with a valid http method.")
			}
		}
	}
	return nil
}
