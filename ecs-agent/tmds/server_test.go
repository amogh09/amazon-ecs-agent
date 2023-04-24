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
package tmds

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewServerErrors(t *testing.T) {
	t.Run("listenAddress is required", func(t *testing.T) {
		_, err := NewServer(nil)
		assert.EqualError(t, err, "listenAddress cannot be empty")
	})
	t.Run("router is required", func(t *testing.T) {
		_, err := NewServer(nil, WithListenAddress(IPv4))
		assert.EqualError(t, err, "router cannot be nil")
	})
}
