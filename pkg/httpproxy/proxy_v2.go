package httpproxy

import (
	bytes "bytes"
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
	validHostsSupplier Supplier
	prefix             string
	credentials        v1.SecretInterface
	mgmtClustersCache  mgmtv3.ClusterCache
	provClustersCache  provv1.ClusterCache
	authorizer         authorizer.Authorizer
	endpointCache      uiv1.ProxyEndpointCache
	dynamicSchemaCache mgmtv3.DynamicSchemaCache
	dynamicCAPool      *DynamicCAPool
}

const (
	templateFormat = "\\{\\{cattle\\.auth\\.io:(.*?)\\}\\}"
)

var (
	templateRegex = regexp.MustCompile(templateFormat)
	byURL         = "byURLPattern"
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
		authorizer:         authz,
		prefix:             prefix,
		validHostsSupplier: validHosts,
		credentials:        scaledContext.Core.Secrets("cattle-global-data"),
		mgmtClustersCache:  scaledContext.Wrangler.Mgmt.Cluster().Cache(),
		provClustersCache:  scaledContext.Wrangler.Provisioning.Cluster().Cache(),
		endpointCache:      scaledContext.Wrangler.UI.ProxyEndpoint().Cache(),
		dynamicSchemaCache: scaledContext.Wrangler.Mgmt.DynamicSchema().Cache(),
		dynamicCAPool:      dynamicCAPool,
	}

	p.endpointCache.AddIndexer(byURL, func(obj *ui.ProxyEndpoint) ([]string, error) {
		if obj == nil {
			return []string{}, nil
		}
		if strings.Contains(obj.Spec.UrlPattern, "*") {
			return []string{"wildcard"}, nil
		}
		return []string{obj.Spec.UrlPattern}, nil
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

	// Need to identify the correct ProxyEndpoint CR for the incoming domain
	// TODO: find out if a meta CR exists for this domain.
	// 		 This requires a pretty interesting lookup algorithm
	//		 since we could have wild cards and absolute paths
	allowed, endpoint := p.isAllowed(destURL.String())
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

	if endpoint != nil {
		// TODO: We should only be getting the fields which are set for the schema
		//		 associated with the incoming cloud credential. idk how that would work.
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

			p.templateHeaders(endpoint.Spec, req, cc.Data)
			if err := p.templateJSONBody(endpoint.Spec, req, cc.Data); err != nil {
				return err
			}
		}
	}

	return nil
}

// TODO: we should support entries that specify a host and a path.
func (p *proxyV2) isAllowed(fullURL string) (bool, *ui.ProxyEndpoint) {

	// strip the protocol first
	fullURL = strings.ReplaceAll(fullURL, "https://", "")
	fullURL = strings.ReplaceAll(fullURL, "http://", "")

	// first check the index to see if we have a direct match (no wildcard)
	meta, err := p.endpointCache.GetByIndex(byURL, fullURL)
	if err != nil {
		if !apierrors.IsNotFound(err) {
			return false, nil
		}
	}

	if len(meta) > 0 {
		return true, meta[0]
	}

	// If not get all the wild cards and see if our host matches one of them
	allWildCards, err := p.endpointCache.GetByIndex(byURL, "wildcard")
	if err != nil {
		return false, nil
	}

	var match *ui.ProxyEndpoint
	var lastMatchLength int
	for _, entry := range allWildCards {
		// match the urlPattern with the incoming host
		regxp, err := wildcardToRegex(entry.Spec.UrlPattern)
		if err != nil {
			continue
		}
		if regxp.MatchString(fullURL) {
			// We want the most absolute match (i.e. the longest)
			if len(regxp.String()) > lastMatchLength {
				lastMatchLength = len(regxp.String())
				match = entry
			}
		}
	}

	if match != nil && lastMatchLength != 0 {
		return true, match
	}

	return false, nil
}

func wildcardToRegex(pattern string) (*regexp.Regexp, error) {
	// Escape special characters (e.g., "." becomes "\.", "*" becomes "\*")
	regexStr := regexp.QuoteMeta(pattern)

	// Replace the escaped wildcard "\*" with the regex wildcard ".*"
	regexStr = strings.ReplaceAll(regexStr, "\\*", ".*")

	// matche the entire string
	regexStr = "^" + regexStr + "$"

	// (?i) flag makes the whole expression case-insensitive
	return regexp.Compile("(?i)" + regexStr)
}

// TEMPLATING AND HEADERS!!!

func (p *proxyV2) templateHeaders(rules ui.ProxyEndpointSpec, req *http.Request, ccFields map[string][]byte) {
	newHeaders := req.Header
	for name, values := range req.Header {
		if !slices.Contains(rules.InjectionDetails.AllowedHeaders, name) {
			continue
		}
		for _, value := range values {
			newValue := value
			for _, templatedValue := range templateRegex.FindAllString(value, -1) {
				_, secretValue, found := strings.Cut(templatedValue, ":")
				if !found {
					continue
				}
				realValue, found := ccFields[strings.TrimSuffix(secretValue, "}}")]
				if !found {
					continue
				}
				newValue = strings.ReplaceAll(newValue, templatedValue, string(realValue))
			}
			newHeaders.Add(name, newValue)
		}
	}
	req.Header = newHeaders
}

func (p *proxyV2) templateJSONBody(rules ui.ProxyEndpointSpec, req *http.Request, cc map[string][]byte) error {
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
