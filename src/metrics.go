package main

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
)

var metrics_server *string
var byte_counter, connection_counter, transfer_counter uint64

func push_metrics() {
	request, error := http.NewRequest("POST", *metrics_server, bytes.NewBuffer([]byte(fmt.Sprintf(
		"NiFiDiode_Transfer_bytes %d\nNiFiDiode_Connection_count %d\nNiFiDiode_Transfer_count %d\n",
		byte_counter, connection_counter, transfer_counter))))
	request.Header.Set("Content-Type", "text/text; charset=UTF-8")

	client := &http.Client{}
	response, error := client.Do(request)
	if error != nil {
		panic(error)
	}
	defer response.Body.Close()

	io.Copy(ioutil.Discard, response.Body)
}
