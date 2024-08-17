//go:build windows
// +build windows

// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"). You may
// not use this file except in compliance with the License. A copy of the
// License is located at
//
//      http://aws.amazon.com/apache2.0/
//
// or in the "license" file accompanying this file. This file is distributed
// on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
// express or implied. See the License for the specific language governing
// permissions and limitations under the License.

package ebs

import "time"

const (
	// Setting the node stage timeout to 30 seconds as Windows takes longer to stage
	nodeStageTimeout = 30 * time.Second
	// Host mount root path where the EBS volumes will be mounted
	hostMountDir = "C:\\ProgramData\\Amazon\\ECS\\ebs\\"
)