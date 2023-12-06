// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"). You may
// not use this file except in compliance with the License. A copy of the
// License is located at
//
//	http://aws.amazon.com/apache2.0/
//
// or in the "license" file accompanying this file. This file is distributed
// on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
// express or implied. See the License for the specific language governing
// permissions and limitations under the License.

package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
)

const (
	volumePluginRemovePath = "VolumeDriver.Remove"
	networkUnix            = "unix"
	schemeHTTP             = "http"
	volumePluginSocketPath = "/run/docker/plugins/amazon-ecs-volume-plugin.sock"
)

type VolumePluginClient interface {
	Remove(ctx context.Context, dockerVolumeName string) error
}

type volumePluginClient struct {
	httpClient *http.Client
}

func NewVolumePluginClient() VolumePluginClient {
	httpClient := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return net.Dial(networkUnix, volumePluginSocketPath)
		},
	}}
	return &volumePluginClient{httpClient: httpClient}
}

type removeRequest struct {
	Name string
}

func (c *volumePluginClient) Remove(ctx context.Context, dockerVolumeName string) error {
	removeReq := removeRequest{Name: dockerVolumeName}
	bodyBytes, err := json.Marshal(removeReq)
	if err != nil {
		return fmt.Errorf("failed to serialize Remove request %+v to JSON: %w", removeReq, err)
	}

	removeURL := fmt.Sprintf("http://unix/%s", volumePluginRemovePath)
	log.Printf("request body is %v", string(bodyBytes))
	body := bytes.NewReader(bodyBytes)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, removeURL, body)
	if err != nil {
		return fmt.Errorf("failed to create volume remove request with URL %v: %w", removeURL, err)
	}

	res, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("HTTP request to remove volume at URL %v failed: %w", removeURL, err)
	}
	if res.StatusCode != http.StatusOK {
		resBodyBytes, err := io.ReadAll(res.Body)
		if err != nil {
			return fmt.Errorf(
				"request to remove volume at URL %s failed with code %v and failed to read response body: %w",
				removeURL, res.StatusCode, err)
		}
		return fmt.Errorf("HTTP request to remove volume at URL %s failed with code %v: %v",
			removeURL, res.StatusCode, string(resBodyBytes))
	}

	return nil
}
