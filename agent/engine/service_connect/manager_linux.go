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

package serviceconnect

import (
	"fmt"
	"os"
	"path/filepath"

	apicontainer "github.com/aws/amazon-ecs-agent/agent/api/container"
	apitask "github.com/aws/amazon-ecs-agent/agent/api/task"
	dockercontainer "github.com/docker/docker/api/types/container"
)

const (
	defaultRelayPathContainer  = "/var/run/ecs/relay/"
	defaultRelayPathHost       = "/var/run/ecs/service_connect/instance/relay/"
	defaultRelayFileName       = "envoy_xds.sock"
	defaultRelayENV            = "APPMESH_XDS_ENDPOINT"
	defaultStatusPathContainer = "/var/run/ecs/"
	// Expected to have task.GetID() appended to form actual host path
	defaultStatusPathHostRoot = "/var/run/ecs/service_connect/"
	defaultStatusFileName     = "appnet_admin.sock"
	defaultStatusENV          = "APPNET_AGENT_UDS_PATH"
)

type manager struct {
	// Path to where relayFileName exists which Envoy in the container will connect to
	relayPathContainer string
	// Path to where relayFileName exists on Host
	relayPathHost string
	// Filename without Path which Relay will create and Envoy in the container will connect to
	relayFileName string
	// Environment variable to set on Container with contents of relayPathContainer/relayFileName
	relayENV string
	// Path to where statusFileName exists which Envoy in the container will create for status endpoint
	statusPathContainer string
	// PathRoot to be appended with TaskID statusPathHostRoot/task.GetID() where statusFileName exists on Host
	statusPathHostRoot string
	// Filename without Path which Envoy in container will create for status endpoint
	statusFileName string
	// Environment variable to set on Container with contents of statusPathContainer/statusFileName
	statusENV string
}

func NewManager() Manager {
	return &manager{
		relayPathContainer:  defaultRelayPathContainer,
		relayPathHost:       defaultRelayPathHost,
		relayFileName:       defaultRelayFileName,
		relayENV:            defaultRelayENV,
		statusPathContainer: defaultStatusPathContainer,
		statusPathHostRoot:  defaultStatusPathHostRoot,
		statusFileName:      defaultStatusFileName,
		statusENV:           defaultStatusENV,
	}
}

func (m *manager) initializeAgentContainer(task *apitask.Task, container *apicontainer.Container, hostConfig *dockercontainer.HostConfig) error {
	return m.initServiceConnectDirectoryMounts(task.GetID(), container, hostConfig)
}

func getBindMountMapping(hostDir, containerDir string) string {
	return hostDir + ":" + containerDir
}

func (m *manager) initServiceConnectDirectoryMounts(taskId string, container *apicontainer.Container, hostConfig *dockercontainer.HostConfig) error {
	statusPathHost := filepath.Join(m.statusPathHostRoot, taskId)

	// Create host directories if they don't exist
	for _, path := range []string{statusPathHost, m.relayPathHost} {
		_, err := os.Stat(path)
		if os.IsNotExist(err) {
			err = os.MkdirAll(path, 0770)
		}
		if err != nil {
			return err
		}
	}

	hostConfig.Binds = append(hostConfig.Binds, getBindMountMapping(statusPathHost, m.statusPathContainer))
	hostConfig.Binds = append(hostConfig.Binds, getBindMountMapping(m.relayPathHost, m.relayPathContainer))

	scEnv := map[string]string{
		m.relayENV:  filepath.Join(m.relayPathContainer, m.relayFileName),
		m.statusENV: filepath.Join(m.statusPathContainer, m.statusFileName),
	}

	container.MergeEnvironmentVariables(scEnv)
	return nil
}

// DNSConfigToDockerExtraHostsFormat converts a []DNSConfigEntry slice to a list of ExtraHost entries that Docker will
// recognize.
func DNSConfigToDockerExtraHostsFormat(dnsConfigs []apitask.DNSConfigEntry) []string {
	var hosts []string
	for _, dnsConf := range dnsConfigs {
		if len(dnsConf.Address) > 0 {
			hosts = append(hosts,
				fmt.Sprintf("%s:%s", dnsConf.HostName, dnsConf.Address))
		}
	}
	return hosts
}

func (m *manager) AugmentTaskContainer(task *apitask.Task, container *apicontainer.Container, hostConfig *dockercontainer.HostConfig) error {
	var err error
	// Add SC VIPs to pause container's known hosts
	if container.Type == apicontainer.ContainerCNIPause {
		hostConfig.ExtraHosts = append(hostConfig.ExtraHosts,
			DNSConfigToDockerExtraHostsFormat(task.ServiceConnectConfig.DNSConfig)...)
	}
	if container == task.GetServiceConnectContainer() {
		m.initializeAgentContainer(task, container, hostConfig)
	}
	return err
}