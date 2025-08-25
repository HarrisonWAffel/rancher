package wrangler

import (
	"context"
	"fmt"

	"github.com/sirupsen/logrus"
	"sync"
	"time"
)

type DeferredInit[T any] interface {
	// InitContext is a custom function which creates an instance of a clientContext to be passed to
	// all deferred functions. See Deferred for more information on clientContexts.
	InitContext(w *Context) (T, error)
	// Poller is a custom function which periodically check some condition to become true.
	// Poller is used by Deferred to wait for an arbitrary condition to become true before
	// executing deferred functions and initializing any clientContexts.
	Poller() (bool, error)
}

// Deferred provides a way to defer the execution of functions and registration of event handlers
// until a custom poller returns true. It accepts two generic types, T and I. T represents
// a scoped context struct which is passed to all deferred functions. This scoped context should contain
// the clients, caches, and factories, that will be initialized once the defined slice of CRDs become available.
// I represents a function which implements the DeferredInit interface, and is used to initialize T before it is
// passed to any deferred functions. Deferred holds a single instance of T, which is shared amongst all
// deferred function calls.
type Deferred[T any, I DeferredInit[T]] struct {
	Name string

	wg    sync.WaitGroup
	mutex sync.Mutex

	registrationFuncs []func(ctx context.Context, clients T) error
	funcs             []func(clients T)

	// clientContext will be passed to all deferred functions. If the context
	// is expected to hold wrangler clients or factories, it should be a pointer.
	// Deferred will pass this instance of T to all deferred functions.
	clientContext T

	// InitClientContext is a struct which implements the DeferredInit interface, and
	// is responsible for initializing the clientContext once the CRDs are available
	InitClientContext I

	init bool
}

func (d *Deferred[T, I]) Initialized() bool {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	return d.init
}

func (d *Deferred[T, I]) log(msg string) {
	logrus.Debugf("[deferred-%s] %s", d.Name, msg)
}

func (d *Deferred[T, I]) logf(msg string, args ...string) {
	logrus.Debugf("[deferred-%s] %s", d.Name, fmt.Sprintf(msg, args))
}

func (d *Deferred[T, I]) error(msg string) {
	logrus.Errorf("[deferred-%s] %s", d.Name, msg)
}

func (d *Deferred[T, I]) errorf(msg string, args ...string) {
	logrus.Errorf("[deferred-%s] %s", d.Name, fmt.Sprintf(msg, args))
}

// TODO: Ideally we should provide multiple ways to indicate that Deferred is ready, including simple polling

func (d *Deferred[T, I]) ManageDeferredFunctions(ctx context.Context, w *Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	d.log("[ManageDeferredFunctions] Starting to poll using initializer")

	for {
		ready, err := d.InitClientContext.Poller()
		if err != nil {
			logrus.Fatalf("[%s] failed to poll", d.Name)
		}

		if ready {
			d.log("[ManageDeferredFunctions] poller complete, initializing factory")
			d.initFactory(ctx, w)
			return
		}

		select {
		case <-ctx.Done():
			d.error("[ManageDeferredFunctions] Context cancelled while polling")
			return
		case <-ticker.C:
		}
	}
}

func (d *Deferred[T, I]) initFactory(ctx context.Context, w *Context) {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	clientCtx, err := d.InitClientContext.InitContext(w)
	if err != nil {
		logrus.Fatalf("[%s] failed to initilize client context: %v", d.Name, err)
	}
	d.clientContext = clientCtx

	// If the larger wrangler context has not started yet, do not start it prematurely
	w.controllerLock.Lock()
	wranglerHasStarted := w.started
	if !wranglerHasStarted {
		err := d.invokePools(ctx, d.clientContext)
		if err != nil {
			logrus.Fatalf("[%s] Encountered unexpected error while invoking deferred pools: %v", d.Name, err)
		}
		d.init = true
		d.log("[initFactory] Not starting controller factory as larger wrangler context has not yet started")
		w.controllerLock.Unlock()
		return
	}
	w.controllerLock.Unlock()

	// If wrangler has already started, start the factory again to pick up new registrations
	if err := w.StartFactoryWithTransaction(ctx, func(ctx context.Context) error {
		err := d.invokePools(ctx, d.clientContext)
		if err != nil {
			logrus.Fatalf("[%s] Encountered unexpected error while invoking deferred pools: %v", d.Name, err)
		}
		return nil
	}); err != nil {
		logrus.Fatalf("[%s] failed to invoke deferrred function pools", d.Name)
	}

	d.log("[initFactory] Starting controller factory after initial wrangler start")
	if err := w.ControllerFactory.Start(ctx, defaultControllerWorkerCount); err != nil {
		logrus.Fatalf("[%s] Encountered unexpected error while starting capi factory: %v", d.Name, err)
	}

	d.init = true
}

// invokePools sequentially executes all functions pooled within the Deferred.registrationFuncs and
// Deferred.funcs slices, in that order. The caller of invokePools must first acquire
// the lock on Deferred.mutex. Once all functions from both slices have been invoked, the
// slices are reset.
func (d *Deferred[T, I]) invokePools(ctx context.Context, clients T) error {
	d.log("[invokePools] Executing deferred registration function pool")
	err := d.invokeRegistrationFuncs(ctx, d.registrationFuncs)
	if err != nil {
		return err
	}
	d.log("[invokePools] deferred registration functions have completed")

	d.log("[invokePools] Executing deferred function pool")
	for _, f := range d.funcs {
		f(clients)
		d.wg.Done()
	}
	d.log("[invokePools] deferred functions have completed")

	d.registrationFuncs = []func(ctx context.Context, clients T) error{}
	d.funcs = []func(clients T){}

	return nil
}

// DeferFunc enqueues a function to be executed once Deferred is initialized by adding it to the function pool.
// Calls to DeferFunc are processed in the order they are made. Calls to DeferFunc made after Deferred is initialized
// available will execute immediately.
func (d *Deferred[T, I]) DeferFunc(f func(clients T)) {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	if d.init {
		d.log("[DeferFunc] Executing deferred function as CAPI is initialized")
		defer func() {
			d.log("[DeferFunc] deferred function has completed")
		}()
		f(d.clientContext)
		return
	}

	d.wg.Add(1)
	d.log("[DeferFunc] Adding function to pool")
	d.funcs = append(d.funcs, f)
}

// DeferFuncWithError creates a new go routine which invokes f once the DeferredCAPIRegistration wait group completes.
// It returns an error channel to indicate if f encountered any errors during execution.
func (d *Deferred[T, I]) DeferFuncWithError(f func(wrangler T) error) chan error {
	errChan := make(chan error, 1)
	go func(errs chan error) {
		d.wg.Wait()
		d.log("[DeferFuncWithError] Executing deferred function with error as CAPI is initialized")
		defer func() {
			d.log("[DeferFuncWithError] deferred function with error has completed")
		}()
		err := f(d.clientContext)
		defer close(errChan)

		if err != nil {
			errChan <- err
		}
	}(errChan)
	return errChan
}

// DeferRegistration enqueues a function to be executed once the CAPI CRDs are available by adding it to the registration function pool.
// The functions passed to DeferRegistration are expected to register one or more event handlers which rely on the clientContext.
// Calls to DeferRegistration are processed in the order they are made. Calls to DeferRegistration made after Deferred has been
// initialized will execute immediately, and the controller factory will be immediately started.
func (d *Deferred[T, I]) DeferRegistration(ctx context.Context, clients *Context, register func(ctx context.Context, clients T) error) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	d.wg.Add(1)

	if d.init {
		d.log("[DeferRegistration] Executing deferred registration function as CAPI is initialized")
		defer func() {
			d.log("[DeferRegistration] deferred registration function has completed")
		}()

		invoke := func() (bool, error) {
			clients.controllerLock.Lock()
			defer clients.controllerLock.Unlock()
			wranglerStarted := clients.started
			if !wranglerStarted {
				d.log("[DeferRegistration] wrangler context has not yet started, will not start controller factory after registration")
				return true, d.invokeRegistrationFuncs(ctx, []func(ctx context.Context, clients T) error{register})
			}
			return false, nil
		}

		invoked, err := invoke()
		if invoked {
			if err != nil {
				return err
			}
			return nil
		}

		return clients.StartFactoryWithTransaction(ctx, func(ctx context.Context) error {
			return d.invokeRegistrationFuncs(ctx, []func(ctx context.Context, clients T) error{register})
		})
	}

	d.log("[DeferRegistration] Adding registration function to pool")
	d.registrationFuncs = append(d.registrationFuncs, register)
	return nil
}

func (d *Deferred[T, I]) invokeRegistrationFuncs(transaction context.Context, f []func(ctx context.Context, clients T) error) error {
	for _, register := range f {
		if err := register(transaction, d.clientContext); err != nil {
			return err
		}
		d.wg.Done()
	}
	return nil
}
