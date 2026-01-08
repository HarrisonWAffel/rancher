package httpproxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"regexp"
	"slices"
	"strings"
	"time"

	ui "github.com/rancher/rancher/pkg/apis/ui.cattle.io/v1"
	mgmtv3 "github.com/rancher/rancher/pkg/generated/controllers/management.cattle.io/v3"
	provv1 "github.com/rancher/rancher/pkg/generated/controllers/provisioning.cattle.io/v1"
	uiv1 "github.com/rancher/rancher/pkg/generated/controllers/ui.cattle.io/v1"
	v1 "github.com/rancher/rancher/pkg/generated/norman/core/v1"
	"github.com/rancher/rancher/pkg/settings"
	"github.com/rancher/rancher/pkg/types/config"
	"github.com/rancher/steve/pkg/auth"
	"github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	v2 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/authorization/authorizerfactory"
	"k8s.io/apiserver/pkg/endpoints/request"
)

type proxyV2 struct {
	validHostsSupplier      Supplier
	prefix                  string
	credentials             v1.SecretInterface
	mgmtClustersCache       mgmtv3.ClusterCache
	provClustersCache       provv1.ClusterCache
	authorizer              authorizer.Authorizer
	endpointCollectionCache uiv1.ProxyEndpointCollectionCache
	dynamicSchemaCache      mgmtv3.DynamicSchemaCache
	dynamicCAPool           *DynamicCAPool
}

const (
	templateFormat = "\\{\\{cattle\\.auth\\.io:(.*?)\\}\\}"
)

var (
	templateRegex = regexp.MustCompile(templateFormat)
	bySourceID    = "bySourceID"
)

func NewProxyV2(prefix string, validHosts Supplier, scaledContext *config.ScaledContext, dynamicCAPool *DynamicCAPool) (http.Handler, error) {
	cfg := authorizerfactory.DelegatingAuthorizerConfig{
		SubjectAccessReviewClient: scaledContext.K8sClient.AuthorizationV1(),
		AllowCacheTTL:             time.Second * time.Duration(settings.AuthorizationCacheTTLSeconds.GetInt()),
		DenyCacheTTL:              time.Second * time.Duration(settings.AuthorizationDenyCacheTTLSeconds.GetInt()),
		WebhookRetryBackoff:       &auth.WebhookBackoff,
	}

	authz, err := cfg.New()
	if err != nil {
		return nil, err
	}

	p := &proxyV2{
		authorizer:              authz,
		prefix:                  prefix,
		validHostsSupplier:      validHosts,
		credentials:             scaledContext.Core.Secrets("cattle-global-data"),
		mgmtClustersCache:       scaledContext.Wrangler.Mgmt.Cluster().Cache(),
		provClustersCache:       scaledContext.Wrangler.Provisioning.Cluster().Cache(),
		endpointCollectionCache: scaledContext.Wrangler.UI.ProxyEndpointCollection().Cache(),
		dynamicSchemaCache:      scaledContext.Wrangler.Mgmt.DynamicSchema().Cache(),
		dynamicCAPool:           dynamicCAPool,
	}

	p.endpointCollectionCache.AddIndexer(bySourceID, func(obj *ui.ProxyEndpointCollection) ([]string, error) {
		if obj == nil {
			return []string{}, nil
		}
		if obj.Spec.SourceID == "" {
			return []string{"rancher"}, nil
		}
		return []string{obj.Spec.SourceID}, nil
	})

	transport := &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			tlsConfig := dynamicCAPool.GetTLSConfig()

			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				host = addr
			}
			tlsConfig.ServerName = host

			dialer := &tls.Dialer{
				NetDialer: &net.Dialer{
					Timeout:   30 * time.Second,
					KeepAlive: 30 * time.Second,
				},
				Config: tlsConfig,
			}

			return dialer.DialContext(ctx, network, addr)
		},
	}

	return &httputil.ReverseProxy{
		Transport: transport,
		Director: func(req *http.Request) {
			if err := p.proxy(req); err != nil {
				logrus.Infof("Failed to proxy: %v", err)
			}
		},
		ModifyResponse: setModifiedHeaders,
	}, nil
}

func (p *proxyV2) proxy(req *http.Request) error {
	destURLHostname, destURL, err := retrieveURLAndHostname(req, p.prefix)
	if err != nil {
		return err
	}

	sourceID := req.Header.Get("X-Cattle-Source-Id")
	if sourceID == "" {
		sourceID = "rancher"
	}

	// Need to identify the correct ProxyEndpoint CR for the incoming domain
	// TODO: find out if a meta CR exists for this domain.
	// 		 This requires a pretty interesting lookup algorithm
	//		 since we could have wild cards and absolute paths
	allowed, endpoint := p.isAllowed(destURL.String(), sourceID)
	if !allowed {
		return fmt.Errorf("invalid host: %v", destURLHostname)
	}

	// setup the required headers
	headerCopy := http.Header{}
	if req.TLS != nil {
		headerCopy.Set(ForwardProto, "https")
	}

	auth := req.Header.Get(APIAuth)
	ccID := req.Header.Get("cloud-credential-id")
	cAuth := req.Header.Get(CattleAuth)
	for key, value := range req.Header {
		if isBadHeader(key) {
			continue
		}

		copy := make([]string, len(value))
		for i := range value {
			copy[i] = strings.TrimPrefix(value[i], "rancher:")
		}
		headerCopy[key] = copy
	}

	req.Host = destURLHostname
	req.URL = destURL
	req.Header = headerCopy

	if auth != "" { // non-empty AuthHeader is noop
		req.Header.Set(AuthHeader, auth)
	} else if cAuth != "" {
		// setting CattleAuthHeader will replace credential id with secret data
		// and generate signature
		signer := newSigner(cAuth)
		if signer != nil {
			return signer.sign(req, p.secretGetter(req, cAuth), cAuth)
		}
		req.Header.Set(AuthHeader, cAuth)
	}

	// play with cookies
	replaceCookies(req)

	if ccID != "" {
		user, ok := request.UserFrom(req.Context())
		if !ok {
			return fmt.Errorf("failed to find user")
		}
		decision, reason, err := p.authorizer.Authorize(req.Context(), authorizer.AttributesRecord{
			User:            user,
			Verb:            "get",
			Namespace:       "cattle-global-id",
			APIVersion:      "v1",
			Resource:        "secrets",
			Name:            ccID,
			ResourceRequest: true,
		})
		if err != nil {
			return err
		}

		unauthorizedErr := fmt.Errorf("unauthorized %s to %s/%s: %s", user.GetName(), "cattle-global-id", ccID, reason)
		if decision != authorizer.DecisionAllow {
			return unauthorizedErr
		}

		cc, err := p.credentials.Get(ccID, v2.GetOptions{})
		if err != nil {
			return err
		}

		p.templateHeaders(endpoint, req, cc.Data)
		if err := p.templateJSONBody(endpoint, req, cc.Data); err != nil {
			return err
		}
	}

	return nil
}

// TODO: we should support entries that specify a host and a path.
func (p *proxyV2) isAllowed(fullURL, sourceID string) (bool, ui.Endpoint) {

	// strip the protocol first
	fullURL = strings.ReplaceAll(fullURL, "https://", "")
	fullURL = strings.ReplaceAll(fullURL, "http://", "")

	meta, err := p.endpointCollectionCache.GetByIndex(bySourceID, sourceID)
	if err != nil {
		if !apierrors.IsNotFound(err) {
			return false, ui.Endpoint{}
		}
	}

	if len(meta) == 0 {
		return false, ui.Endpoint{}
	}

	// would add a webhook check to ensure only one source ID can exist at a time
	// and default to this if two are ever created for some reason
	slices.SortFunc(meta, func(a, b *ui.ProxyEndpointCollection) int {
		if a.Name > b.Name {
			return 1
		}
		return -1
	})

	for _, endpoints := range meta[0].Spec.Endpoints {
		found, match := findEndpointFromCollection(fullURL, endpoints)
		if found {
			if match.DenyAccess {
				return false, match
			}
			return true, match
		}
	}

	return false, ui.Endpoint{}
}

func findEndpointFromCollection(url string, collection ui.ProxyEndpointSet) (bool, ui.Endpoint) {
	var lastMatchLength int
	match := ui.Endpoint{}
	for _, endpoint := range collection.Endpoints {
		// match the urlPattern with the incoming host
		regxp, err := wildcardToRegex(endpoint.UrlPattern)
		if err != nil {
			continue
		}
		if regxp.MatchString(url) {
			// We want the most absolute match (i.e. the longest)
			if len(regxp.String()) > lastMatchLength {
				lastMatchLength = len(regxp.String())
				match = endpoint
			}
		}
	}
	if lastMatchLength == 0 {
		return false, ui.Endpoint{}
	}
	return true, match
}

func wildcardToRegex(pattern string) (*regexp.Regexp, error) {
	// TODO: if we want to maintain % as the wild card symbol we can just swap it out here
	// Escape special characters (e.g., "." becomes "\.", "*" becomes "\*")
	// Replace the escaped wildcard "\*" with the regex wildcard ".*"
	// (?i) flag makes the whole expression case-insensitive
	return regexp.Compile("(?i)^" + strings.ReplaceAll(regexp.QuoteMeta(pattern), "\\*", ".*") + "$")
}

func (p *proxyV2) templateHeaders(rules ui.Endpoint, req *http.Request, ccFields map[string][]byte) {

}

func (p *proxyV2) templateJSONBody(rules ui.Endpoint, req *http.Request, cc map[string][]byte) error {
	if req.Header.Get("Content-Type") != "application/json" {
		return nil
	}
	defer req.Body.Close()

	var body map[string]interface{}
	bodyContent, err := io.ReadAll(req.Body)
	req.Body = io.NopCloser(bytes.NewReader(bodyContent))

	if err := json.Unmarshal(bodyContent, &body); err != nil {
		return err
	}

	bodyJSON, err := json.Marshal(body)
	if err != nil {
		return err
	}

	modifiedJSON := bodyContent

	for _, allowRule := range rules.InjectionDetails.BodyInjectionRules {
		// Use gjson to determine if a template key exists in
		// an allowed path
		for _, allowedPath := range allowRule.Paths {
			gjsonPath := ConvertJSONPathToGJSON(allowedPath)
			result := gjson.GetBytes(bodyJSON, gjsonPath)
			if result.IsArray() {
				result.ForEach(func(key, value gjson.Result) bool {
					if value.Type == gjson.String {
						strValue := value.String()
						if templateRegex.MatchString(strValue) {
							actualPath := gjsonPath
							if key.Exists() {
								actualPath = strings.Replace(gjsonPath, "#", key.String(), 1)
							}

							newValue := p.replaceTemplate(strValue, cc)
							modifiedJSON, _ = sjson.SetBytes(modifiedJSON, actualPath, newValue)
							logrus.Debugf("Replaced template at %s", actualPath)
						}
					}
					return true
				})
			} else if result.Type == gjson.String {
				strValue := result.String()
				if templateRegex.MatchString(strValue) {
					newValue := p.replaceTemplate(strValue, cc)
					modifiedJSON, err = sjson.SetBytes(modifiedJSON, gjsonPath, newValue)
					if err != nil {
						return err
					}
					logrus.Debugf("Replaced template at %s", gjsonPath)
				}
			}
		}
	}

	req.Body = io.NopCloser(bytes.NewReader(modifiedJSON))
	req.ContentLength = int64(len(modifiedJSON))

	return nil
}

func (p *proxyV2) replaceTemplate(value string, cc map[string][]byte) string {
	result := value
	for _, templatedValue := range templateRegex.FindAllString(value, -1) {
		_, secretKey, found := strings.Cut(templatedValue, ":")
		if !found {
			continue
		}
		secretKey = strings.TrimSuffix(secretKey, "}}")
		realValue, found := cc[secretKey]
		if !found {
			continue
		}
		result = strings.ReplaceAll(result, templatedValue, string(realValue))
	}
	return result
}

// ConvertJSONPathToGJSON converts JSONPath syntax to gjson syntax.
// Examples:
//
//	$.items[*].credentials.password -> items.#.credentials.password
//	$.data.users[0].name -> data.users.0.name
//	$['special-key'].value -> special\-key.value
func ConvertJSONPathToGJSON(jsonPath string) string {
	result := strings.TrimPrefix(jsonPath, "$.")
	result = strings.TrimPrefix(result, "$")

	result = strings.ReplaceAll(result, "[*]", ".#")

	indexPattern := regexp.MustCompile(`\[(\d+)\]`)
	result = indexPattern.ReplaceAllString(result, ".$1")

	quotedPattern := regexp.MustCompile(`\['([^']+)'\]|\["([^"]+)"\]`)
	result = quotedPattern.ReplaceAllStringFunc(result, func(match string) string {
		key := strings.Trim(match, "[]'\"")
		key = strings.ReplaceAll(key, "-", "\\-")
		key = strings.ReplaceAll(key, ".", "\\.")
		return "." + key
	})

	result = strings.ReplaceAll(result, "..", ".")

	result = strings.TrimPrefix(result, ".")

	return result
}

func (p *proxyV2) secretGetter(req *http.Request, cAuth string) SecretGetter {
	clusterID := getRequestParams(cAuth)["clusterID"]
	return func(namespace, name string) (*corev1.Secret, error) {
		user, ok := request.UserFrom(req.Context())
		if !ok {
			return nil, fmt.Errorf("failed to find user")
		}
		decision, reason, err := p.authorizer.Authorize(req.Context(), authorizer.AttributesRecord{
			User:            user,
			Verb:            "get",
			Namespace:       namespace,
			APIVersion:      "v1",
			Resource:        "secrets",
			Name:            name,
			ResourceRequest: true,
		})
		if err != nil {
			return nil, err
		}
		unauthorizedErr := fmt.Errorf("unauthorized %s to %s/%s: %s", user.GetName(), namespace, name, reason)
		if decision != authorizer.DecisionAllow {
			decision, err = checkIndirectAccessViaCluster(req, user, clusterID, fmt.Sprintf("%s:%s", namespace, name), p.mgmtClustersCache, p.provClustersCache, p.authorizer)
			if err != nil {
				return nil, err
			}
			if decision != authorizer.DecisionAllow {
				return nil, unauthorizedErr
			}
		}
		return p.credentials.Controller().Lister().Get(namespace, name)
	}
}
