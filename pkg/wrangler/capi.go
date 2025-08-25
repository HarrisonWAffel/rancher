package wrangler

import (
	"fmt"

	capi "github.com/rancher/rancher/pkg/generated/controllers/cluster.x-k8s.io"
	capicontrollers "github.com/rancher/rancher/pkg/generated/controllers/cluster.x-k8s.io/v1beta1"
	"github.com/rancher/wrangler/v3/pkg/generic"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// DeferredCAPIInitializer implements the DeferredInit interface for CAPI CRDs.
// It provides a poller which waits for CAPI CRDs to be created, and initializes
// the CAPIContext to be used when executing deferred functions.
type DeferredCAPIInitializer struct {
	*Context
	RequiredCRDS []string
}

// CAPIContext is a scoped context which embeds a wrangler context. It provides
// an additional client and factory for CAPI CRDs, and is passed to all Deferred
// CAPI functions.
type CAPIContext struct {
	*Context
	capi *capi.Factory
	CAPI capicontrollers.Interface
}

func (d *DeferredCAPIInitializer) InitContext(w *Context) (*CAPIContext, error) {
	logrus.Info("[deferred-capi] initializing clients")
	opts := &generic.FactoryOptions{
		SharedControllerFactory: d.ControllerFactory,
	}

	capi, err := capi.NewFactoryFromConfigWithOptions(d.RESTConfig, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create CAPI factory: %w", err)
	}

	return &CAPIContext{
		Context: w,
		CAPI:    capi.Cluster().V1beta1(),
		capi:    capi,
	}, nil
}

func (d *DeferredCAPIInitializer) Poller() (bool, error) {
	return d.checkCRDS(), nil
}

func (d *DeferredCAPIInitializer) checkCRDS() bool {
	allCRDsReady := true
	for _, crdName := range d.RequiredCRDS {
		crd, err := d.CRD.CustomResourceDefinition().Get(crdName, metav1.GetOptions{})
		if err != nil {
			if errors.IsNotFound(err) {
				logrus.Infof("CRD %s not found, continuing to wait", crdName)
				allCRDsReady = false
				break
			}
			logrus.Infof("Error checking CRD %s: %v", crdName, err.Error())
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
			logrus.Infof("CRD %s exists but is not yet established, continuing to wait", crdName)
			allCRDsReady = false
			break
		}

		logrus.Infof("CRD %s is available and established", crdName)
	}

	return allCRDsReady
}
