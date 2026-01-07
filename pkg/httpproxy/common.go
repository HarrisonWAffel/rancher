package httpproxy

import (
	"net/http"
	"net/url"
	"strings"

	prov "github.com/rancher/rancher/pkg/apis/provisioning.cattle.io/v1"
	"github.com/rancher/rancher/pkg/controllers/management/cluster"
	provcluster "github.com/rancher/rancher/pkg/controllers/provisioningv2/cluster"
	mgmtv3 "github.com/rancher/rancher/pkg/generated/controllers/management.cattle.io/v3"
	provv1 "github.com/rancher/rancher/pkg/generated/controllers/provisioning.cattle.io/v1"
	v3 "github.com/rancher/rancher/pkg/generated/norman/management.cattle.io/v3"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
)

func checkIndirectAccessViaCluster(req *http.Request, user user.Info, clusterID, credID string, mgmtClustersCache mgmtv3.ClusterCache, provClustersCache provv1.ClusterCache, auth authorizer.Authorizer) (authorizer.Decision, error) {
	var (
		mgmtClusters []*v3.Cluster
		provClusters []*prov.Cluster
		err          error
	)
	if clusterID == "" {
		// If no clusterID is passed, then we check all clusters that the user has access to and are associated to the cloud credential.
		// Both management and provisioning clusters should be checked.
		mgmtClusters, err = mgmtClustersCache.GetByIndex(cluster.ByCloudCredential, credID)
		if err != nil {
			return authorizer.DecisionDeny, err
		}

		provClusters, err = provClustersCache.GetByIndex(provcluster.ByCloudCred, credID)
		if err != nil {
			return authorizer.DecisionDeny, err
		}
	} else {
		if c, err := mgmtClustersCache.Get(clusterID); err == nil {
			mgmtClusters = []*v3.Cluster{c}
		} else {
			return authorizer.DecisionDeny, err
		}
		provClusters, err = provClustersCache.GetByIndex(provcluster.ByCluster, clusterID)
		if err != nil {
			return authorizer.DecisionDeny, err
		}
	}
	if len(mgmtClusters)+len(provClusters) == 0 {
		return authorizer.DecisionDeny, err
	}

	for _, c := range mgmtClusters {
		if c.Spec.EKSConfig == nil || c.Spec.EKSConfig.AmazonCredentialSecret != credID {
			continue
		}

		decision, err := checkAccessToV3ClusterWithID(req, user, c.Name, auth)
		if err == nil && decision == authorizer.DecisionAllow {
			return decision, nil
		}
	}

	for _, c := range provClusters {
		if c.Spec.CloudCredentialSecretName != credID {
			continue
		}

		// Check that the user has access to the management cluster associated to the provisioning cluster.
		// If a user has access to the management cluster, then the user has access to the provisioning cluster.
		decision, err := checkAccessToV3ClusterWithID(req, user, c.Status.ClusterName, auth)
		if err == nil && decision == authorizer.DecisionAllow {
			return decision, nil
		}
	}
	return authorizer.DecisionDeny, nil
}

func checkAccessToV3ClusterWithID(req *http.Request, user user.Info, clusterID string, auth authorizer.Authorizer) (authorizer.Decision, error) {
	decision, _, err := auth.Authorize(req.Context(), authorizer.AttributesRecord{
		User:            user,
		Verb:            "update",
		APIGroup:        v3.GroupName,
		APIVersion:      v3.Version,
		Resource:        "clusters",
		Name:            clusterID,
		ResourceRequest: true,
	})

	return decision, err
}

func retrieveURLAndHostname(req *http.Request, prefix string) (string, *url.URL, error) {
	path := req.URL.String()
	index := strings.Index(path, prefix)
	destPath := path[index+len(prefix):]

	if httpsStart.MatchString(destPath) {
		destPath = httpsStart.ReplaceAllString(destPath, "https://$1")
	} else if httpStart.MatchString(destPath) {
		destPath = httpStart.ReplaceAllString(destPath, "http://$1")
	} else {
		destPath = "https://" + destPath
	}

	destURL, err := url.Parse(destPath)
	if err != nil {
		return "", nil, err
	}

	destURL.RawQuery = req.URL.RawQuery
	destURLHostname := destURL.Hostname()
	return destURLHostname, destURL, nil
}

func setModifiedHeaders(res *http.Response) error {
	// replace set cookies
	res.Header.Del(APISetCookie)
	// There may be multiple set cookies
	for _, setCookie := range res.Header[SetCookie] {
		res.Header.Add(APISetCookie, setCookie)
	}
	res.Header.Del(SetCookie)
	// add security headers (similar to raw.githubusercontent)
	res.Header.Set(CSP, "default-src 'none'; style-src 'unsafe-inline'; sandbox")
	res.Header.Set(XContentType, "nosniff")
	return nil
}
