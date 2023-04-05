package installer

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	"github.com/rancher/rancher/pkg/settings"
	"github.com/rancher/rancher/pkg/systemtemplate"
	"github.com/rancher/rancher/pkg/tls"
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
)

const (
	SystemAgentInstallPath = "/system-agent-install.sh" // corresponding curl -o in package/Dockerfile
	WindowsRke2InstallPath = "/wins-agent-install.ps1"  // corresponding curl -o in package/Dockerfile
)

var (
	localAgentInstallScripts = []string{
		settings.UIPath.Get() + "/assets" + SystemAgentInstallPath,
		"." + SystemAgentInstallPath,
	}
	localWindowsRke2InstallScripts = []string{
		settings.UIPath.Get() + "/assets" + WindowsRke2InstallPath,
		"." + WindowsRke2InstallPath}
)

func installScript(setting settings.Setting, files []string) ([]byte, error) {
	if setting.Get() == setting.Default {
		// no setting override, check for local file first
		for _, f := range files {
			script, err := ioutil.ReadFile(f)
			if err != nil {
				if !os.IsNotExist(err) {
					logrus.Debugf("error pulling system agent installation script %s: %s", f, err)
				}
				continue
			}
			return script, err
		}
		logrus.Debugf("no local installation script found, moving on to url: %s", setting.Get())
	}

	resp, err := http.Get(setting.Get())
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return ioutil.ReadAll(resp.Body)
}

func LinuxInstallScript(ctx context.Context, token string, envVars []corev1.EnvVar, defaultHost string, preAgentHooks, postAgentHooks []string) ([]byte, error) {
	data, err := installScript(
		settings.SystemAgentInstallScript,
		localAgentInstallScripts)
	if err != nil {
		return nil, err
	}
	binaryURL := ""
	if settings.SystemAgentVersion.Get() != "" {
		if settings.ServerURL.Get() != "" {
			binaryURL = fmt.Sprintf("CATTLE_AGENT_BINARY_BASE_URL=\"%s/assets\"", settings.ServerURL.Get())
		} else if defaultHost != "" {
			binaryURL = fmt.Sprintf("CATTLE_AGENT_BINARY_BASE_URL=\"https://%s/assets\"", defaultHost)
		}
	}
	ca := systemtemplate.CAChecksum()
	if v, ok := ctx.Value(tls.InternalAPI).(bool); ok && v {
		ca = systemtemplate.InternalCAChecksum()
	}
	if ca != "" {
		ca = "CATTLE_CA_CHECKSUM=\"" + ca + "\""
	}
	if token != "" {
		token = "CATTLE_ROLE_NONE=true\nCATTLE_TOKEN=\"" + token + "\""
	}
	envVarBuf := &strings.Builder{}
	for _, envVar := range envVars {
		if envVar.Value == "" {
			continue
		}
		envVarBuf.WriteString(fmt.Sprintf("%s=\"%s\"\n", envVar.Name, envVar.Value))
	}
	server := ""
	if settings.ServerURL.Get() != "" {
		server = fmt.Sprintf("CATTLE_SERVER=%s", settings.ServerURL.Get())
	}

	// build all the user defined hooks. Each hook is a set of commands
	// that can be used to configure a node.
	// Each hook will be added in the following format
	//
	// #HOOK_NAME
	// HOOK_VALUE
	preBuilder := strings.Builder{}
	if len(preAgentHooks) > 0 {
		preBuilder.WriteString("#user specified hooks\n")
		for _, hookName := range preAgentHooks {
			if hookValue := GetLinuxHook(hookName); hookValue != "" {
				preBuilder.WriteString(fmt.Sprintf("#%s\n%s\n", hookName, hookValue))
			}
		}
	}

	postBuilder := strings.Builder{}
	if len(postAgentHooks) > 0 {
		postBuilder.WriteString("#user specified hooks\n")
		for _, hookName := range preAgentHooks {
			if hookValue := GetLinuxHook(hookName); hookValue != "" {
				postBuilder.WriteString(fmt.Sprintf("#%s\n%s\n", hookName, hookValue))
			}
		}
	}

	x := []byte(fmt.Sprintf(`#!/usr/bin/env sh
%s
%s
%s
%s
%s
%s
%s
%s
`, preBuilder.String(), envVarBuf.String(), binaryURL, server, ca, token, data, postBuilder.String()))
	return x, nil
}

func WindowsInstallScript(ctx context.Context, token string, envVars []corev1.EnvVar, defaultHost string, preAgentHooks, postAgentHooks []string) ([]byte, error) {
	data, err := installScript(
		settings.WinsAgentInstallScript,
		localWindowsRke2InstallScripts)
	if err != nil {
		return nil, err
	}

	binaryURL := ""
	if settings.WinsAgentVersion.Get() != "" {
		if settings.ServerURL.Get() != "" {
			binaryURL = fmt.Sprintf("$env:CATTLE_AGENT_BINARY_BASE_URL=\"%s/assets\"", settings.ServerURL.Get())
		} else if defaultHost != "" {
			binaryURL = fmt.Sprintf("$env:CATTLE_AGENT_BINARY_BASE_URL=\"https://%s/assets\"", defaultHost)
		}
	}

	csiProxyURL := settings.CSIProxyAgentURL.Get()
	csiProxyVersion := "v1.0.0"
	if settings.CSIProxyAgentVersion.Get() != "" {
		csiProxyVersion = settings.CSIProxyAgentVersion.Get()
		if settings.ServerURL.Get() != "" {
			csiProxyURL = fmt.Sprintf("%s/assets/csi-proxy-%%[1]s.tar.gz", settings.ServerURL.Get())
		} else if defaultHost != "" {
			csiProxyURL = fmt.Sprintf("https://%s/assets/csi-proxy-%%[1]s.tar.gz", defaultHost)
		}
	}

	ca := systemtemplate.CAChecksum()
	if v, ok := ctx.Value(tls.InternalAPI).(bool); ok && v {
		ca = systemtemplate.InternalCAChecksum()
	}
	if ca != "" {
		ca = "$env:CATTLE_CA_CHECKSUM=\"" + ca + "\""
	}
	if token != "" {
		token = "$env:CATTLE_ROLE_NONE=\"true\"\n$env:CATTLE_TOKEN=\"" + token + "\""
	}
	envVarBuf := &strings.Builder{}
	for _, envVar := range envVars {
		if envVar.Value == "" {
			continue
		}
		envVarBuf.WriteString(fmt.Sprintf("$env:%s=\"%s\"\n", envVar.Name, envVar.Value))
	}
	server := ""
	if settings.ServerURL.Get() != "" {
		server = fmt.Sprintf("$env:CATTLE_SERVER=\"%s\"", settings.ServerURL.Get())
	}

	// build all the user defined hooks. Each hook is a set of commands
	// that can be used to configure a node.
	// Each hook will be added in the following format
	//
	// #HOOK_NAME
	// HOOK_VALUE
	combinedHooks := ""
	if len(preAgentHooks) > 0 {
		combinedHooks = "#user specified hooks\n"
		for _, hookName := range preAgentHooks {
			if hookValue := GetWindowsHook(hookName); hookValue != "" {
				combinedHooks = fmt.Sprintf("%s\n#%s%s", combinedHooks, hookName, hookValue)
			}
		}
	}
	return []byte(fmt.Sprintf(`%s

%s
%s
%s
%s
%s
%s

# Enables CSI Proxy
$env:CSI_PROXY_URL = "%s"
$env:CSI_PROXY_VERSION = "%s"
$env:CSI_PROXY_KUBELET_PATH = "C:/var/lib/rancher/rke2/bin/kubelet.exe"

Invoke-WinsInstaller @PSBoundParameters
exit 0
`, data, combinedHooks, envVarBuf.String(), binaryURL, server, ca, token, csiProxyURL, csiProxyVersion)), nil
}
