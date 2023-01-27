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
package types

import (
	"encoding/json"
	"fmt"

	"git-codecommit.us-west-2.amazonaws.com/v1/repos/amazon-ecs-agent-tmds.git/ecs_client/model/ecs"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/request"
)

// TaskProtectionResponse is response type for all Update/GetTaskProtection requests
type TaskProtectionResponse struct {
	RequestID  *string            `json:"requestID,omitempty"`
	Protection *ecs.ProtectedTask `json:"protection,omitempty"`
	Failure    *ecs.Failure       `json:"failure,omitempty"`
	Error      *ErrorResponse     `json:"error,omitempty"`
}

// NewTaskProtectionResponseError creates a TaskProtectionResponse when there is an error response with optional requestID
func NewTaskProtectionResponseError(error *ErrorResponse, requestID *string) TaskProtectionResponse {
	return TaskProtectionResponse{RequestID: requestID, Error: error}
}

// ErrorResponse is the type for all Update/GetTaskProtection request errors
type ErrorResponse struct {
	Arn     string `json:"Arn,omitempty"`
	Code    string
	Message string
}

// NewErrorResponsePtr creates a *ErrorResponse for Agent input validations failures and exceptions
func NewErrorResponsePtr(arn string, code string, message string) *ErrorResponse {
	return &ErrorResponse{
		Arn:     arn,
		Code:    code,
		Message: message,
	}
}

// NewTaskProtectionResponseProtection creates a TaskProtectionResponse when it is a successful response (has protection)
func NewTaskProtectionResponseProtection(protection *ecs.ProtectedTask) TaskProtectionResponse {
	return TaskProtectionResponse{Protection: protection}
}

// taskProtection is type of Protection for a Task
type taskProtection struct {
	protectionEnabled bool
	expiresInMinutes  *int64
}

// MarshalJSON is custom JSON marshal function to marshal unexported fields for logging purposes
func (taskProtection *taskProtection) MarshalJSON() ([]byte, error) {
	jsonBytes, err := json.Marshal(struct {
		ProtectionEnabled bool
		ExpiresInMinutes  *int64
	}{
		ProtectionEnabled: taskProtection.protectionEnabled,
		ExpiresInMinutes:  taskProtection.expiresInMinutes,
	})

	if err != nil {
		return nil, err
	}

	return jsonBytes, nil
}

// NewTaskProtection creates a taskProtection
func NewTaskProtection(protectionEnabled bool, expiresInMinutes *int64) *taskProtection {
	return &taskProtection{
		protectionEnabled: protectionEnabled,
		expiresInMinutes:  expiresInMinutes,
	}
}

func (taskProtection *taskProtection) GetProtectionEnabled() bool {
	return taskProtection.protectionEnabled
}

func (taskProtection *taskProtection) GetExpiresInMinutes() *int64 {
	return taskProtection.expiresInMinutes
}

func (taskProtection *taskProtection) String() string {
	jsonBytes, err := taskProtection.MarshalJSON()
	if err != nil {
		return fmt.Sprintf("failed to get string representation of taskProtection type: %v", err)
	}
	return string(jsonBytes)
}

type AWSCredentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
}

type CredentialsGetter interface {
	GetTaskRoleCredentials(task Task) (*AWSCredentials, error)
}

type TaskGetter interface {
	GetTaskByV3EndpointID(v3EndpointID string) (*Task, error)
}

type Task struct {
	ARN           string
	CredentialsID string
}

// ECSTaskProtectionSDK is an interface with customized ecs client that
// implements the UpdateTaskProtection and GetTaskProtection
type ECSTaskProtectionSDK interface {
	UpdateTaskProtection(input *ecs.UpdateTaskProtectionInput) (*ecs.UpdateTaskProtectionOutput, error)
	UpdateTaskProtectionWithContext(ctx aws.Context, input *ecs.UpdateTaskProtectionInput,
		opts ...request.Option) (*ecs.UpdateTaskProtectionOutput, error)
	GetTaskProtection(input *ecs.GetTaskProtectionInput) (*ecs.GetTaskProtectionOutput, error)
	GetTaskProtectionWithContext(ctx aws.Context, input *ecs.GetTaskProtectionInput,
		opts ...request.Option) (*ecs.GetTaskProtectionOutput, error)
}

func NewTaskProtectionResponseFailure(failure *ecs.Failure) TaskProtectionResponse {
	return TaskProtectionResponse{Failure: failure}
}
