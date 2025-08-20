package wrangler

import (
	"context"
	"sync"
	"time"

	capi "github.com/rancher/rancher/pkg/generated/controllers/cluster.x-k8s.io"
	capicontrollers "github.com/rancher/rancher/pkg/generated/controllers/cluster.x-k8s.io/v1beta1"
	"github.com/rancher/wrangler/v3/pkg/generic"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ManageDeferredCAPIContext polls for the availability of CAPI CRDs and registers deferred controllers
// and executes deferred functions once they are available. Once CAPI CRDs are found, this function will
// not continue polling. Individual registration calls can be made once polling is complete by directly using
// the DeferredCAPIRegistration struct.
func (w *Context) ManageDeferredCAPIContext(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	logrus.Debug("[deferred-capi] Starting to monitor CAPI CRD availability")

	if w.DeferredCAPIRegistration.CAPIInitialized() {
		return
	}

	for {
		allCRDsReady := w.checkCAPICRDs()
		if allCRDsReady {
			logrus.Debug("[deferred-capi] All CAPI CRDs are now available and established.")
			w.createCAPIFactoryAndStart(ctx)
			return
		}

		select {
		case <-ctx.Done():
			logrus.Error("[deferred-capi] Context cancelled while waiting for CAPI CRDs")
			return
		case <-ticker.C:
		}
	}
}

func (w *Context) checkCAPICRDs() bool {
	requiredCRDs := []string{
		"clusters.cluster.x-k8s.io",
		"machines.cluster.x-k8s.io",
		"machinesets.cluster.x-k8s.io",
		"machinedeployments.cluster.x-k8s.io",
		"machinehealthchecks.cluster.x-k8s.io",
	}

	logrus.Debug("[deferred-capi] Checking CAPI CRDs availability and establishment status")
	allCRDsReady := true
	for _, crdName := range requiredCRDs {
		crd, err := w.CRD.CustomResourceDefinition().Get(crdName, metav1.GetOptions{})
		if err != nil {
			if errors.IsNotFound(err) {
				logrus.Debugf("[deferred-capi] CRD %s not found, continuing to wait", crdName)
				allCRDsReady = false
				break
			}
			logrus.Debugf("[deferred-capi] Error checking for CAPI CRD %s: %v", crdName, err)
			allCRDsReady = false
			break
		}

		established := false
		for _, condition := range crd.Status.Conditions {
			if condition.Type == "Established" && condition.Status == "True" {
				established = true
				break
			}
		}

		if !established {
			logrus.Debugf("[deferred-capi] CRD %s exists but is not yet established, continuing to wait", crdName)
			allCRDsReady = false
			break
		}

		logrus.Debugf("[deferred-capi] CRD %s is available and established", crdName)
	}

	return allCRDsReady
}

func (w *Context) createCAPIFactoryAndStart(ctx context.Context) {
	opts := &generic.FactoryOptions{
		SharedControllerFactory: w.SharedControllerFactory,
	}

	defer func() {
		// don't panic in the event that rancher dies before
		// the factory caches can sync
		if r := recover(); r != nil {
			logrus.Errorf("Encountered error while starting capi factory")
		}
	}()

	capi, err := capi.NewFactoryFromConfigWithOptions(w.RESTConfig, opts)
	if err != nil {
		logrus.Fatalf("[deferred-capi] failed to instantiate new CAPI factory: %v", err)
	}

	w.DeferredCAPIRegistration.capi = capi
	w.DeferredCAPIRegistration.capiClients = w.DeferredCAPIRegistration.capi.Cluster().V1beta1()

	err = w.DeferredCAPIRegistration.invokePools(ctx, w)
	if err != nil {
		logrus.Fatalf("[deferred-capi] failed to invoked deferred CAPI registration pools: %v", err)
	}

	if err := w.SharedControllerFactory.Start(ctx, defaultControllerWorkerCount); err != nil {
		logrus.Fatalf("[deferred-capi] failed to start shared controller factory after instantitation of CAPI factory: %v", err)
	}

	w.DeferredCAPIRegistration.mutex.Lock()
	w.DeferredCAPIRegistration.CAPIInitComplete = true
	w.DeferredCAPIRegistration.mutex.Unlock()
}

type DeferredCAPIRegistration struct {
	CAPIInitComplete bool
	userAgent        string

	wg    *sync.WaitGroup
	mutex sync.Mutex

	capiClients capicontrollers.Interface
	capi        *capi.Factory

	registrationFuncs []func(ctx context.Context, clients *CAPIContext) error
	funcs             []func(clients *CAPIContext)
}

func (d *DeferredCAPIRegistration) CAPIInitialized() bool {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	return d.CAPIInitComplete
}

func (d *DeferredCAPIRegistration) Copy() *DeferredCAPIRegistration {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	return &DeferredCAPIRegistration{
		CAPIInitComplete:  d.CAPIInitComplete,
		userAgent:         d.userAgent,
		wg:                &sync.WaitGroup{},
		capiClients:       d.capiClients,
		capi:              d.capi,
		registrationFuncs: d.registrationFuncs,
		funcs:             d.funcs,
	}
}

func (d *DeferredCAPIRegistration) invokePools(ctx context.Context, clients *Context) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	if err := clients.StartSharedFactoryWithTransaction(ctx, func(ctx context.Context) error {
		return d.invokeRegistrationFuncs(ctx, clients, d.registrationFuncs)
	}); err != nil {
		return err
	}

	for _, f := range d.funcs {
		f(&CAPIContext{
			Context: clients,
			CAPI:    d.capiClients,
			capi:    d.capi,
		})
		d.wg.Done()
	}

	d.registrationFuncs = []func(ctx context.Context, clients *CAPIContext) error{}
	d.funcs = []func(clients *CAPIContext){}

	return nil
}

func (d *DeferredCAPIRegistration) DeferFunc(clients *Context, f func(clients *CAPIContext)) {
	if d.CAPIInitialized() {
		f(&CAPIContext{
			Context: clients,
			CAPI:    d.capiClients,
			capi:    d.capi,
		})
		return
	}

	d.mutex.Lock()
	d.wg.Add(1)
	d.funcs = append(d.funcs, f)
	d.mutex.Unlock()
}

func (d *DeferredCAPIRegistration) DeferFuncWithError(clients *Context, f func(wrangler *CAPIContext) error) chan error {
	errChan := make(chan error, 1)
	go func(errs chan error) {
		d.wg.Wait()
		err := f(&CAPIContext{
			Context: clients,
			CAPI:    d.capiClients,
			capi:    d.capi,
		})
		defer close(errChan)

		if err != nil {
			errChan <- err
		}
	}(errChan)
	return errChan
}

func (d *DeferredCAPIRegistration) DeferRegistration(ctx context.Context, clients *Context, register func(ctx context.Context, clients *CAPIContext) error) error {
	d.wg.Add(1)
	if d.CAPIInitComplete {
		d.mutex.Lock()
		defer d.mutex.Unlock()
		return clients.StartSharedFactoryWithTransaction(ctx, func(ctx context.Context) error {
			if err := d.invokeRegistrationFuncs(ctx, clients, []func(ctx context.Context, clients *CAPIContext) error{register}); err != nil {
				return err
			}
			return nil
		})
	}

	d.mutex.Lock()
	d.registrationFuncs = append(d.registrationFuncs, register)
	d.mutex.Unlock()
	return nil
}

func (d *DeferredCAPIRegistration) invokeRegistrationFuncs(transaction context.Context, clients *Context, f []func(ctx context.Context, clients *CAPIContext) error) error {
	for _, register := range f {
		if err := register(transaction, &CAPIContext{
			Context: clients,
			CAPI:    d.capiClients,
			capi:    d.capi,
		}); err != nil {
			return err
		}
		d.wg.Done()
	}
	return nil
}
