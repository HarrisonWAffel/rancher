package config

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDeferredStart_RetryOnFailure verifies that a failing register function
// does not wedge the starter and can be retried on subsequent calls.
func TestDeferredStart_RetryOnFailure(t *testing.T) {
	t.Parallel()

	registerErr := errors.New("register failed")
	registerCalls := 0
	register := func(ctx context.Context) error {
		registerCalls++
		return registerErr
	}

	startCalls := 0
	start := func(ctx context.Context) error {
		startCalls++
		return nil
	}

	starter := deferredStart(context.Background(), register, start)

	// Call starter 3 times, each should return error and invoke register
	for i := 0; i < 3; i++ {
		err := starter()
		require.Error(t, err)
		assert.ErrorIs(t, err, registerErr)
	}

	assert.Equal(t, 3, registerCalls, "register should be called on each attempt")
	assert.Equal(t, 0, startCalls, "start should never be called when register fails")
}

// TestDeferredStart_EventualSuccessThenNoOp verifies that after a successful
// start, the starter becomes a no-op without re-invoking register or start.
func TestDeferredStart_EventualSuccessThenNoOp(t *testing.T) {
	t.Parallel()

	const failCount = 2
	startCalls := 0
	start := func(ctx context.Context) error {
		startCalls++
		if startCalls <= failCount {
			return errors.New("start failed")
		}
		return nil
	}

	registerCalls := 0
	register := func(ctx context.Context) error {
		registerCalls++
		return nil
	}

	starter := deferredStart(context.Background(), register, start)

	// First failCount calls should fail
	for i := 0; i < failCount; i++ {
		err := starter()
		require.Error(t, err)
	}

	assert.Equal(t, failCount, startCalls, "start should be called each time it fails")
	assert.Equal(t, failCount, registerCalls, "register should be called each time start fails")

	// Next call should succeed
	err := starter()
	require.NoError(t, err)
	assert.Equal(t, failCount+1, startCalls)
	assert.Equal(t, failCount+1, registerCalls)

	// Subsequent calls should be no-op
	for i := 0; i < 3; i++ {
		err := starter()
		require.NoError(t, err)
	}

	assert.Equal(t, failCount+1, startCalls, "start should not be called again after success")
	assert.Equal(t, failCount+1, registerCalls, "register should not be called again after success")
}

// TestDeferredStart_RegisterFailureNeverReachesStart verifies that if register
// fails, the start function is never invoked.
func TestDeferredStart_RegisterFailureNeverReachesStart(t *testing.T) {
	t.Parallel()

	registerErr := errors.New("register error")
	register := func(ctx context.Context) error {
		return registerErr
	}

	startCalls := 0
	start := func(ctx context.Context) error {
		startCalls++
		return nil
	}

	starter := deferredStart(context.Background(), register, start)

	err := starter()
	require.Error(t, err)
	assert.ErrorIs(t, err, registerErr)
	assert.Equal(t, 0, startCalls, "start should never be called when register fails")
}

// TestDeferredStart_PerInstanceState verifies that two separate deferredStart
// closures have independent started state.
func TestDeferredStart_PerInstanceState(t *testing.T) {
	t.Parallel()

	register1Calls := 0
	register1 := func(ctx context.Context) error {
		register1Calls++
		return nil
	}

	start1Calls := 0
	start1 := func(ctx context.Context) error {
		start1Calls++
		return nil
	}

	register2Calls := 0
	register2 := func(ctx context.Context) error {
		register2Calls++
		return nil
	}

	start2Calls := 0
	start2 := func(ctx context.Context) error {
		start2Calls++
		return nil
	}

	starter1 := deferredStart(context.Background(), register1, start1)
	starter2 := deferredStart(context.Background(), register2, start2)

	// Succeed starter1
	err := starter1()
	require.NoError(t, err)
	assert.Equal(t, 1, register1Calls)
	assert.Equal(t, 1, start1Calls)

	// starter2 should still be independent and work
	err = starter2()
	require.NoError(t, err)
	assert.Equal(t, 1, register2Calls)
	assert.Equal(t, 1, start2Calls)

	// Calling starter1 again should be a no-op
	err = starter1()
	require.NoError(t, err)
	assert.Equal(t, 1, register1Calls, "starter1 register should not be called again")
	assert.Equal(t, 1, start1Calls, "starter1 start should not be called again")

	// Calling starter2 again should also be a no-op
	err = starter2()
	require.NoError(t, err)
	assert.Equal(t, 1, register2Calls, "starter2 register should not be called again")
	assert.Equal(t, 1, start2Calls, "starter2 start should not be called again")
}
