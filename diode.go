package main

import (
	"bufio"
	"fmt"
	"io"
	"io/ioutil"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

func diode(input io.ReadWriter, output io.ReadWriter) error {
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
		var method, target string
		var has_method bool

		for {
			str, err := inbuf.ReadString('\n')
			if err != nil {
				return fmt.Errorf("Diode: Error reading in input header, %s", err)
			}
			if strings.TrimSpace(str) == "" {
				_, err = output_pipe.Write([]byte(str))
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
				case "POST":
					output_pipe = outbuf
				case "DELETE", "GET", "HEAD":
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
		outbuf.Flush()

		switch method {
		case "HEAD":
			input.Write([]byte("HTTP/1.1 200 OK\r\n" +
				"Date: " + time.Now().UTC().Format(time.RFC1123) + "\r\n" +
				"Accept: application/flowfile-v3,*/*;q=0.8\r\n" +
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
						break
					case "1fe9":
						// Handle the case of a flow file
						outbuf.Flush()
						for {
							n, err := parseFlowFileLength(inbuf)
							if err != nil {
								return fmt.Errorf("Diode: Error decoding flowfile segment, %s", err)
							}
							if n == 0 {
								break
							}
							io.Copy(outbuf, &io.LimitedReader{R: inbuf, N: n})
						}

					default:
						// Simple string field
						i, err := strconv.ParseInt(trim, 10, 64)
						if err != nil {
							return fmt.Errorf("Diode: Invalid flowfile length, %q", trim)
						}
						io.Copy(outbuf, &io.LimitedReader{R: inbuf, N: i})
					}
				}
			}
			outbuf.Flush()

			for {
				str, err := anti_diode.ReadString('\n')
				if err != nil {
					return fmt.Errorf("Diode: Error reading in target header, %s", err)
				}
				if strings.TrimSpace(str) == "" {
					break
				}
			}

			if v, ok := header_map[FLOWFILE_CONFIRMATION_HEADER]; ok && strings.HasPrefix(v, "t") {
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
			} else {
				input.Write([]byte("HTTP/1.1 303 See Other\r\n" +
					"Date: " + time.Now().UTC().Format(time.RFC1123) + "\r\n" +
					"Content-Type: text-plain\r\n" +
					"Content-Length: 0\r\n" +
					"Server: NiFi-Diode (github.com/pschou/nifi-diode)\r\n" +
					"\r\n"))
			}
		}
	}
	return nil
}
