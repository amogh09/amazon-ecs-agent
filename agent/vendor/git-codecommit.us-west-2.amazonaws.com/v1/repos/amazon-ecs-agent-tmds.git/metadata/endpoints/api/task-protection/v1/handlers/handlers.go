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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"git-codecommit.us-west-2.amazonaws.com/v1/repos/amazon-ecs-agent-tmds.git/ecs_client/model/ecs"
	"git-codecommit.us-west-2.amazonaws.com/v1/repos/amazon-ecs-agent-tmds.git/metadata/endpoints/api/task-protection/v1/types"
	utils "git-codecommit.us-west-2.amazonaws.com/v1/repos/amazon-ecs-agent-tmds.git/utils/handlers"
	muxutils "git-codecommit.us-west-2.amazonaws.com/v1/repos/amazon-ecs-agent-tmds.git/utils/mux"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	awscreds "github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/gorilla/mux"
)

const (
	ExpectedProtectionResponseLength = 1
	V3EndpointIDMuxName              = "v3EndpointIDMuxName"
	ecsCallTimeout                   = 4 * time.Second // TODO injection
	ecsCallTimedOutError             = "Timed out calling ECS Task Protection API"
)

// putTaskProtectionRequest is the data model for a PutTaskProtection request
type putTaskProtectionRequest struct {
	ProtectionEnabled *bool  `json:"ProtectionEnabled"`
	ExpiresInMinutes  *int64 `json:"ExpiresInMinutes,omitempty"`
}

type TaskProtectionResponse struct {
	Protection *ecs.ProtectedTask `json:"protection,omitempty"`
	Failure    *ecs.Failure       `json:"failure,omitempty"`
	RequestID  *string            `json:"requestID,omitempty"`
	Error      *RequestError      `json:"error,omitempty"`
}

type RequestError struct {
	Arn     string `json:"Arn,omitempty"`
	Code    string `json:"Code"`
	Message string `json:"Message"`
}

type TaskProtectionClientFactoryInterface interface {
	newTaskProtectionClient(taskRoleCredential types.AWSCredentials) types.ECSTaskProtectionSDK
}

// TaskProtectionClientFactory implements TaskProtectionClientFactoryInterface
type TaskProtectionClientFactory struct {
	Region             string
	Endpoint           string
	AcceptInsecureCert bool
}

// Helper function for retrieving credential from credentials manager and create ecs client
func (factory TaskProtectionClientFactory) newTaskProtectionClient(
	taskCredential types.AWSCredentials) *ecs.ECS {
	cfg := aws.NewConfig().
		WithCredentials(awscreds.NewStaticCredentials(taskCredential.AccessKeyID,
			taskCredential.SecretAccessKey,
			taskCredential.SessionToken)).
		WithRegion(factory.Region)
		// TODO inject http client
		// WithHTTPClient(httpclient.New(ecsclient.RoundtripTimeout, factory.AcceptInsecureCert)).
		// WithEndpoint(factory.Endpoint)

	ecsClient := ecs.New(session.Must(session.NewSession()), cfg)
	return ecsClient
}

// TaskProtectionPath Returns endpoint path for UpdateTaskProtection API
func TaskProtectionPath() string {
	return fmt.Sprintf(
		"/api/%s/task-protection/v1/state",
		muxutils.ConstructMuxVar(V3EndpointIDMuxName, muxutils.AnythingButSlashRegEx))
}

func RegisterHandlers(muxRouter *mux.Router, credsGetter types.CredentialsGetter,
	taskGetter types.TaskGetter, cluster, region string) {
	factory := TaskProtectionClientFactory{Region: region}
	muxRouter.
		HandleFunc(
			TaskProtectionPath(),
			putTaskProtection(credsGetter, taskGetter, factory, cluster)).
		Methods("PUT")
	muxRouter.
		HandleFunc(
			TaskProtectionPath(),
			GetTaskProtectionHandler(taskGetter, credsGetter, factory, cluster)).
		Methods("GET")
}

func putTaskProtection(
	credsGetter types.CredentialsGetter,
	taskGetter types.TaskGetter,
	factory TaskProtectionClientFactory,
	cluster string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		updateTaskProtectionRequestType := "api/UpdateTaskProtection/v1"

		var request putTaskProtectionRequest
		jsonDecoder := json.NewDecoder(r.Body)
		jsonDecoder.DisallowUnknownFields()
		if err := jsonDecoder.Decode(&request); err != nil {
			log.Printf("UpdateTaskProtection: failed to decode request: %v", err)
			writeJSONResponse(w, http.StatusBadRequest,
				types.NewTaskProtectionResponseError(
					types.NewErrorResponsePtr("", ecs.ErrCodeInvalidParameterException,
						"UpdateTaskProtection: failed to decode request"), nil),
				updateTaskProtectionRequestType)
			return
		}

		taskPtr, err := getTaskFromRequest(r, taskGetter)
		if err != nil {
			writeJSONResponse(w, http.StatusNotFound,
				types.NewTaskProtectionResponseError(
					types.NewErrorResponsePtr(
						"", ecs.ErrCodeResourceNotFoundException, err.Error()),
					nil),
				updateTaskProtectionRequestType)
			return
		}
		task := *taskPtr

		if request.ProtectionEnabled == nil {
			writeJSONResponse(w, http.StatusBadRequest,
				types.NewTaskProtectionResponseError(
					types.NewErrorResponsePtr(task.ARN, ecs.ErrCodeInvalidParameterException,
						"Invalid request: does not contain 'ProtectionEnabled' field"), nil),
				updateTaskProtectionRequestType)
			return
		}

		taskProtection := types.NewTaskProtection(*request.ProtectionEnabled, request.ExpiresInMinutes)

		log.Printf("UpdateTaskProtection endpoint was called")

		taskRoleCredential, err := credsGetter.GetTaskRoleCredentials(task)
		if err != nil {
			err = errors.New("Invalid Request: no task IAM role credentials available for task")
			writeJSONResponse(w, http.StatusForbidden,
				types.NewTaskProtectionResponseError(types.NewErrorResponsePtr(task.ARN,
					ecs.ErrCodeAccessDeniedException, err.Error()), nil),
				updateTaskProtectionRequestType)
			return
		}
		ecsClient := factory.newTaskProtectionClient(*taskRoleCredential)

		ctx, cancel := context.WithTimeout(r.Context(), ecsCallTimeout)
		defer cancel()
		response, err := ecsClient.UpdateTaskProtectionWithContext(
			ctx,
			&ecs.UpdateTaskProtectionInput{
				Cluster:           aws.String(cluster),
				ExpiresInMinutes:  taskProtection.GetExpiresInMinutes(),
				ProtectionEnabled: aws.Bool(taskProtection.GetProtectionEnabled()),
				Tasks:             aws.StringSlice([]string{task.ARN}),
			})

		if err != nil {
			errorCode, errorMsg, statusCode, reqId := getErrorCodeAndStatusCode(err)
			log.Printf("Got an exception when calling UpdateTaskProtection: %v", err)
			writeJSONResponse(w, statusCode,
				types.NewTaskProtectionResponseError(
					types.NewErrorResponsePtr(task.ARN, errorCode, errorMsg), reqId),
				updateTaskProtectionRequestType)
			return
		}

		// there are no exceptions but there are failures when setting protection in scheduler
		if len(response.Failures) > 0 {
			if len(response.Failures) > ExpectedProtectionResponseLength {
				err := fmt.Errorf(
					"expect at most %v failure in response, get %v",
					ExpectedProtectionResponseLength, len(response.Failures))
				log.Printf("Unexpected number of failures: %v", err)
				writeJSONResponse(w, http.StatusInternalServerError,
					types.NewTaskProtectionResponseError(
						types.NewErrorResponsePtr(task.ARN, ecs.ErrCodeServerException,
							"Unexpected error occurred"), nil),
					updateTaskProtectionRequestType)
				return
			}
			writeJSONResponse(w, http.StatusOK,
				types.NewTaskProtectionResponseFailure(response.Failures[0]),
				updateTaskProtectionRequestType)
			return
		}
		if len(response.ProtectedTasks) > ExpectedProtectionResponseLength {
			err := fmt.Errorf(
				"expect %v protectedTask in response when no failure, get %v",
				ExpectedProtectionResponseLength, len(response.ProtectedTasks))
			log.Printf("Unexpected number of protections: %v", err)
			writeJSONResponse(w, http.StatusInternalServerError,
				types.NewTaskProtectionResponseError(
					types.NewErrorResponsePtr(
						task.ARN, ecs.ErrCodeServerException, "Unexpected error occurred"),
					nil),
				updateTaskProtectionRequestType)
			return
		}
		writeJSONResponse(w, http.StatusOK,
			types.NewTaskProtectionResponseProtection(response.ProtectedTasks[0]),
			updateTaskProtectionRequestType)
	}
}

// GetTaskProtectionHandler returns a handler function for GetTaskProtection API
func GetTaskProtectionHandler(taskGetter types.TaskGetter, credsGetter types.CredentialsGetter,
	factory TaskProtectionClientFactory, cluster string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		getTaskProtectionRequestType := "api/GetTaskProtection/v1"

		task, err := getTaskFromRequest(r, taskGetter)
		if err != nil {
			writeJSONResponse(w, http.StatusNotFound,
				types.NewTaskProtectionResponseError(
					types.NewErrorResponsePtr("", ecs.ErrCodeResourceNotFoundException, err.Error()),
					nil),
				getTaskProtectionRequestType)
			return
		}

		log.Printf("GetTaskProtection endpoint was called")

		taskRoleCredential, err := credsGetter.GetTaskRoleCredentials(*task)
		if err != nil {
			err = errors.New("Invalid Request: no task IAM role credentials available for task")
			writeJSONResponse(w, http.StatusForbidden,
				types.NewTaskProtectionResponseError(types.NewErrorResponsePtr(task.ARN,
					ecs.ErrCodeAccessDeniedException, err.Error()), nil),
				getTaskProtectionRequestType)
			return
		}

		ecsClient := factory.newTaskProtectionClient(*taskRoleCredential)
		ctx, cancel := context.WithTimeout(r.Context(), ecsCallTimeout)
		defer cancel()
		response, err := ecsClient.GetTaskProtectionWithContext(ctx, &ecs.GetTaskProtectionInput{
			Cluster: aws.String(cluster),
			Tasks:   aws.StringSlice([]string{task.ARN}),
		})

		if err != nil {
			errorCode, errorMsg, statusCode, reqId := getErrorCodeAndStatusCode(err)
			log.Printf("Got an exception when calling GetTaskProtection: %v", err)
			writeJSONResponse(w, statusCode,
				types.NewTaskProtectionResponseError(
					types.NewErrorResponsePtr(task.ARN, errorCode, errorMsg),
					reqId),
				getTaskProtectionRequestType)
			return
		}

		// there are no exceptions but there are failures when getting protection in scheduler
		if len(response.Failures) > 0 {
			if len(response.Failures) > ExpectedProtectionResponseLength {
				err := fmt.Errorf(
					"expect at most %v failure in response, get %v",
					ExpectedProtectionResponseLength, len(response.Failures))
				log.Printf("Unexpected number of failures: %v", err)
				writeJSONResponse(w, http.StatusInternalServerError,
					types.NewTaskProtectionResponseError(
						types.NewErrorResponsePtr(
							task.ARN, ecs.ErrCodeServerException, "Unexpected error occurred"),
						nil),
					getTaskProtectionRequestType)
				return
			}
			writeJSONResponse(w, http.StatusOK,
				types.NewTaskProtectionResponseFailure(response.Failures[0]),
				getTaskProtectionRequestType)
			return
		}

		if len(response.ProtectedTasks) > ExpectedProtectionResponseLength {
			err := fmt.Errorf(
				"expect %v protectedTask in response when no failure, get %v",
				ExpectedProtectionResponseLength, len(response.ProtectedTasks))
			log.Printf("Unexpected number of protections %v", err)
			writeJSONResponse(w, http.StatusInternalServerError, types.NewTaskProtectionResponseError(
				types.NewErrorResponsePtr(
					task.ARN, ecs.ErrCodeServerException, "Unexpected error occurred"),
				nil),
				getTaskProtectionRequestType)
			return
		}
		writeJSONResponse(w, http.StatusOK,
			types.NewTaskProtectionResponseProtection(response.ProtectedTasks[0]),
			getTaskProtectionRequestType)
	}
}

// Writes the provided response to the ResponseWriter and handles any errors
func writeJSONResponse(w http.ResponseWriter, statusCode int,
	response types.TaskProtectionResponse, requestType string) {
	bytes, err := json.Marshal(response)
	if err != nil {
		log.Printf("Agent API Task Protection V1: failed to marshal response as JSON: %v", err)
		utils.WriteJSONToResponse(w, http.StatusInternalServerError, []byte(`{}`),
			requestType)
	} else {
		utils.WriteJSONToResponse(w, statusCode, bytes, requestType)
	}
}

func getTaskFromRequest(r *http.Request, taskGetter types.TaskGetter) (*types.Task, error) {
	v3EndpointID, ok := muxutils.GetMuxValueFromRequest(r, V3EndpointIDMuxName)
	if !ok {
		return nil, errors.New("unable to get v3 endpoint ID from request")
	}

	// Get task Arn from the v3 endpoint ID.
	task, err := taskGetter.GetTaskByV3EndpointID(v3EndpointID)
	if err != nil {
		return nil, fmt.Errorf("unable to get task Arn from v3 endpoint ID %s: %w", v3EndpointID, err)
	}

	return task, nil
}

// Helper function to parse error to get ErrorCode, ExceptionMessage, HttpStatusCode, RequestID.
// RequestID will be empty if the request is not able to reach AWS
func getErrorCodeAndStatusCode(err error) (string, string, int, *string) {
	msg := err.Error()
	// The error is a Generic AWS Error with Code, Message, and original error (if any)
	if awsErr, ok := err.(awserr.Error); ok {
		// The error is an AWS service error occurred
		msg = awsErr.Message()
		if reqErr, ok := err.(awserr.RequestFailure); ok {
			reqId := reqErr.RequestID()
			return awsErr.Code(), msg, reqErr.StatusCode(), &reqId
		} else if aerr, ok := err.(awserr.Error); ok && aerr.Code() == request.CanceledErrorCode {
			return aerr.Code(), ecsCallTimedOutError, http.StatusGatewayTimeout, nil
		} else {
			log.Printf(fmt.Sprintf(
				"got an exception that does not implement RequestFailure interface but is an aws error. "+
					"This should not happen, return statusCode 500 for whatever errorCode. "+
					"Original err: %v.",
				err))
			return awsErr.Code(), msg, http.StatusInternalServerError, nil
		}
	} else {
		log.Printf(fmt.Sprintf("non aws error received: %v", err))
		return ecs.ErrCodeServerException, msg, http.StatusInternalServerError, nil
	}
}
