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

// Utilities for container image reference strings.
package reference

import (
	"fmt"

	"github.com/aws/amazon-ecs-agent/ecs-agent/logger"
	"github.com/aws/amazon-ecs-agent/ecs-agent/logger/field"
	"github.com/docker/distribution/reference"
	"github.com/opencontainers/go-digest"
)

// Helper function to parse an image reference and get digest from it if found.
// The caller must check that the returned digest is non-empty before using it.
func GetDigestFromImageRef(imageRef string) digest.Digest {
	parsedRef, err := reference.Parse(imageRef)
	if err != nil {
		return ""
	}
	switch v := parsedRef.(type) {
	case reference.Digested:
		return v.Digest()
	default:
		return ""
	}
}

// Finds a repo digest matching the provided image reference from a list of repo digests
// and returns the repo digest's digest.
func GetDigestFromRepoDigests(repoDigests []string, imageRef string) (digest.Digest, error) {
	// Parse image reference
	ref, err := reference.Parse(imageRef)
	if err != nil {
		return "", fmt.Errorf("failed to parse image reference '%s': %w", imageRef, err)
	}
	namedRef, ok := ref.(reference.Named)
	if !ok {
		return "", fmt.Errorf(
			"failed to parse image reference '%s' as a named reference, it was parsed as '%v'",
			imageRef, ref)
	}

	// Find a repo digest matching imageRef and return its digest
	for _, repoDigest := range repoDigests {
		repoDigestRef, err := reference.Parse(repoDigest)
		if err != nil {
			logger.Error("Error in parsing repo digest. Skipping it.", logger.Fields{
				"repoDigest": repoDigest,
				field.Error:  err,
			})
			continue
		}
		repoDigestCanonicalRef, ok := repoDigestRef.(reference.Canonical)
		if !ok {
			logger.Warn("Parsed repo digest is not in canonical form. Skipping it.", logger.Fields{
				"repoDigest":       repoDigest,
				"parsedRepoDigest": repoDigestRef.String(),
			})
			continue
		}
		if repoDigestCanonicalRef.Name() == namedRef.Name() {
			return repoDigestCanonicalRef.Digest(), nil
		}
	}

	return "", fmt.Errorf("found no repo digest matching '%s'", imageRef)
}