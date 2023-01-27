// copyright amazon.com inc. or its affiliates. all rights reserved.
//
// licensed under the apache license, version 2.0 (the "license"). you may
// not use this file except in compliance with the license. a copy of the
// license is located at
//
//	http://aws.amazon.com/apache2.0/
//
// or in the "license" file accompanying this file. this file is distributed
// on an "as is" basis, without warranties or conditions of any kind, either
// express or implied. see the license for the specific language governing
// permissions and limitations under the license.
package handlers

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/cihub/seelog"
)

// Error to be returned when a resource is not found in the database
var errNotFound = errors.New("not found")

// Getter for an error to be returned when a resource is not found in the database
func ErrNotFound() error {
	return errNotFound
}

// LoggingHandler is used to log all requests for an endpoint.
type LoggingHandler struct{ h http.Handler }

// NewLoggingHandler creates a new LoggingHandler object.
func NewLoggingHandler(handler http.Handler) LoggingHandler {
	return LoggingHandler{h: handler}
}

// ServeHTTP logs the method and remote address of the request.
func (lh LoggingHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	seelog.Debug("Handling http request", " method ", r.Method, " from ", r.RemoteAddr)
	lh.h.ServeHTTP(w, r)
}

// WriteJSONToResponse writes the header, JSON response to a ResponseWriter, and
// log the error if necessary.
func WriteJSONToResponse(w http.ResponseWriter, httpStatusCode int, responseJSON []byte, requestType string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpStatusCode)
	_, err := w.Write(responseJSON)
	if err != nil {
		seelog.Errorf(
			"Unable to write %s json response message to ResponseWriter",
			requestType)
	}

	if httpStatusCode >= 400 && httpStatusCode <= 599 {
		seelog.Errorf("HTTP response status code is '%d', request type is: %s, and response in JSON is %s", httpStatusCode, requestType, string(responseJSON))
	}
}

func HandleDBError(w http.ResponseWriter, err error, requestType string) {
	if errors.Is(err, ErrNotFound()) {
		HandleNotFoundError(w, err, requestType)
	} else {
		HandleInternalServerError(w, err, requestType)
	}
}

func HandleNotFoundError(w http.ResponseWriter, err error, requestType string) {
	data, _ := json.Marshal(err)
	WriteJSONToResponse(w, http.StatusNotFound, data, requestType)
}

func HandleBadRequestError(w http.ResponseWriter, err error, requestType string) {
	data, _ := json.Marshal(err)
	WriteJSONToResponse(w, http.StatusBadRequest, data, requestType)
}

// InternalServer writes internal server error in JSON format to http response writer.
func HandleInternalServerError(w http.ResponseWriter, err error, requestType string) {
	// TODO do something about metrics
	// defer h.MetricsFactory.New(metrics.InternalServerErrorMetricName).Done(err)()
	data, _ := json.Marshal(err)
	WriteJSONToResponse(w, http.StatusInternalServerError, data, requestType)
}
