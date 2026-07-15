package managementuser

import (
	"errors"
	"testing"

	apimgmtv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TestDeferredStartClusterHandler_NilObject verifies that the handler returns
// nil without calling the starter when obj is nil.
func TestDeferredStartClusterHandler_NilObject(t *testing.T) {
	t.Parallel()

	starterCalls := 0
	starter := func() error {
		starterCalls++
		return nil
	}

	handler := deferredStartClusterHandler("test-cluster", starter)

	obj, err := handler("", nil)
	require.NoError(t, err)
	assert.Nil(t, obj)
	assert.Equal(t, 0, starterCalls, "starter should not be called when obj is nil")
}

// TestDeferredStartClusterHandler_MismatchedName verifies that the handler
// returns the object without calling the starter when the cluster name doesn't match.
func TestDeferredStartClusterHandler_MismatchedName(t *testing.T) {
	t.Parallel()

	starterCalls := 0
	starter := func() error {
		starterCalls++
		return nil
	}

	handler := deferredStartClusterHandler("test-cluster", starter)

	cluster := &apimgmtv3.Cluster{
		ObjectMeta: metav1.ObjectMeta{
			Name: "other-cluster",
		},
	}

	returnedObj, err := handler("", cluster)
	require.NoError(t, err)
	assert.Equal(t, cluster, returnedObj)
	assert.Equal(t, 0, starterCalls, "starter should not be called when cluster name doesn't match")
}

// TestDeferredStartClusterHandler_StarterError verifies that the handler
// returns the starter error for requeue when the cluster name matches and
// starter fails.
func TestDeferredStartClusterHandler_StarterError(t *testing.T) {
	t.Parallel()

	starterErr := errors.New("starter failed")
	starterCalls := 0
	starter := func() error {
		starterCalls++
		return starterErr
	}

	handler := deferredStartClusterHandler("test-cluster", starter)

	cluster := &apimgmtv3.Cluster{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-cluster",
		},
	}

	returnedObj, err := handler("", cluster)
	require.Error(t, err)
	assert.ErrorIs(t, err, starterErr)
	assert.Equal(t, cluster, returnedObj)
	assert.Equal(t, 1, starterCalls, "starter should be called once")
}

// TestDeferredStartClusterHandler_FailThenSucceed verifies the fail→succeed→no-op
// contract at the wiring level for a matching cluster.
func TestDeferredStartClusterHandler_FailThenSucceed(t *testing.T) {
	t.Parallel()

	starterCalls := 0
	starterErr := errors.New("transient error")
	starter := func() error {
		starterCalls++
		if starterCalls == 1 {
			return starterErr
		}
		return nil
	}

	handler := deferredStartClusterHandler("test-cluster", starter)

	cluster := &apimgmtv3.Cluster{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-cluster",
		},
	}

	// First call: starter fails
	returnedObj, err := handler("", cluster)
	require.Error(t, err)
	assert.ErrorIs(t, err, starterErr)
	assert.Equal(t, cluster, returnedObj)
	assert.Equal(t, 1, starterCalls)

	// Second call: starter succeeds
	returnedObj, err = handler("", cluster)
	require.NoError(t, err)
	assert.Equal(t, cluster, returnedObj)
	assert.Equal(t, 2, starterCalls)

	// Third call: starter succeeds again (handler always calls starter; the starter itself is idempotent)
	returnedObj, err = handler("", cluster)
	require.NoError(t, err)
	assert.Equal(t, cluster, returnedObj)
	assert.Equal(t, 3, starterCalls, "handler calls starter each time; starter's internal state makes it a no-op")
}
