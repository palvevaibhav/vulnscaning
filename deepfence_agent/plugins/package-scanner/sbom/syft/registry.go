package syft

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ecr"
)

type registryCredentialResponse struct {
	Data    map[string]interface{} `json:"data,omitempty"`
	Error   interface{}            `json:"error,omitempty"`
	Success bool                   `json:"success,omitempty"`
}

func callRegistryCredentialAPI(registryID string) (registryCredentialResponse, error) {
	var registryCredentialsOutput registryCredentialResponse
	client := &http.Client{}
	req, err := http.NewRequest("POST", "http://deepfence-api:9997/registry_credential",
		bytes.NewBuffer([]byte(`{"id":"`+registryID+`"}`)))
	if err != nil {
		return registryCredentialsOutput, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return registryCredentialsOutput, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return registryCredentialsOutput, err
	}
	err = json.Unmarshal(body, &registryCredentialsOutput)
	if err != nil {
		return registryCredentialsOutput, err
	}
	return registryCredentialsOutput, err
}

func GetConfigFileFromRegistry(registryID string) (string, error) {
	registryURL, username, password, err := GetCredentialsFromRegistry(registryID)
	if err != nil {
		return "", fmt.Errorf("GetCredentialsFromRegistry: %w", err)
	}
	if username == "" {
		return "", nil
	}
	authFile, err := createAuthFile(registryID, registryURL, username, password)
	if err != nil {
		return "", fmt.Errorf("unable to create credential file for docker: %w", err)
	}
	return authFile, nil
}

func GetCredentialsFromRegistry(registryID string) (string, string, string, error) {
	registryData, err := callRegistryCredentialAPI(registryID)
	if err != nil || !registryData.Success {
		return "", "", "", fmt.Errorf("unable to get registry credentials")
	}
	if registryData.Data == nil {
		return "", "", "", fmt.Errorf("invalid registry credentials obtained from API")
	}
	registryURL, username, password := GetDockerCredentials(registryData.Data)

	if username == "" {
		return "", "", "", fmt.Errorf("unable to get credentials for specified registry")
	}
	if password == "" {
		decodedBytes, err := base64.StdEncoding.DecodeString(username)
		if err != nil {
			return "", "", "", fmt.Errorf("invalid credentials for specified registry")
		}
		splitCredentials := strings.SplitN(string(decodedBytes), ":", 2)
		if len(splitCredentials) != 2 {
			return "", "", "", fmt.Errorf("invalid credentials for specified registry")
		}
		username = splitCredentials[0]
		password = splitCredentials[1]
	}
	return registryURL, username, password, nil
}

func GetDockerCredentials(registryData map[string]interface{}) (string, string, string) {
	var registryType string
	registryType, ok := registryData["registry_type"].(string)
	if !ok {
		return "", "", ""
	}
	switch registryType {
	case "ecr":
		var awsAccessKey, awsSecret, awsRegionName, registryID, targetAccountRoleARN string
		var useIAMRole bool
		if awsAccessKey, ok = registryData["aws_access_key_id"].(string); !ok {
			awsAccessKey = ""
		}
		if awsSecret, ok = registryData["aws_secret_access_key"].(string); !ok {
			awsSecret = ""
		}
		if awsRegionName, ok = registryData["aws_region_name"].(string); !ok {
			return "", "", ""
		}
		if registryID, ok = registryData["registry_id"].(string); !ok {
			registryID = ""
		}
		if useIAMRole, ok = registryData["use_iam_role"].(bool); !ok {
			useIAMRole = false
		}
		if targetAccountRoleARN, ok = registryData["target_account_role_arn"].(string); !ok {
			targetAccountRoleARN = ""
		}
		ecrProxyURL, ecrAuth := getEcrCredentials(awsAccessKey, awsSecret, awsRegionName, registryID, useIAMRole, targetAccountRoleARN)
		return ecrProxyURL, ecrAuth, ""
	case "docker_hub":
		var dockerUsername, dockerPassword string
		if dockerUsername, ok = registryData["docker_hub_username"].(string); !ok {
			return "", "", ""
		}
		if dockerPassword, ok = registryData["docker_hub_password"].(string); !ok {
			return "", "", ""
		}
		return "https://index.docker.io/v1/", dockerUsername, dockerPassword
	case "docker_private_registry":
		return getDefaultDockerCredentials(registryData, "docker_registry_url", "docker_username", "docker_password")
	case "azure_container_registry":
		return getDefaultDockerCredentials(registryData, "azure_registry_url", "azure_registry_username", "azure_registry_password")
	case "google_container_registry":
		var dockerPassword, registryURL string
		if dockerPassword, ok = registryData["service_account_json"].(string); !ok {
			return "", "", ""
		}
		if registryURL, ok = registryData["registry_hostname"].(string); !ok {
			return "", "", ""
		}
		return registryURL, "_json_key", dockerPassword
	case "harbor":
		return getDefaultDockerCredentials(registryData, "harbor_registry_url", "harbor_username", "harbor_password")
	case "quay":
		var dockerPassword, registryURL string
		if dockerPassword, ok = registryData["quay_access_token"].(string); !ok {
			return "", "", ""
		}
		if registryURL, ok = registryData["quay_registry_url"].(string); !ok {
			return "", "", ""
		}
		return registryURL, "$oauthtoken", dockerPassword
	case "gitlab":
		var dockerPassword, registryURL string
		if dockerPassword, ok = registryData["gitlab_access_token"].(string); !ok {
			return "", "", ""
		}
		if registryURL, ok = registryData["gitlab_registry_url"].(string); !ok {
			return "", "", ""
		}
		return registryURL, "gitlab-ci-token", dockerPassword
	case "jfrog_container_registry":
		return getDefaultDockerCredentials(registryData, "jfrog_registry_url", "jfrog_username", "jfrog_password")
	default:
		return "", "", ""
	}
}

func getDefaultDockerCredentials(registryData map[string]interface{}, registryURLKey, registryUsernameKey, registryPasswordKey string) (string, string, string) {
	var dockerUsername, dockerPassword, dockerRegistryURL string
	var ok bool
	if dockerUsername, ok = registryData[registryUsernameKey].(string); !ok {
		return "", "", ""
	}
	if dockerPassword, ok = registryData[registryPasswordKey].(string); !ok {
		return "", "", ""
	}
	if dockerRegistryURL, ok = registryData[registryURLKey].(string); !ok {
		return "", "", ""
	}
	return dockerRegistryURL, dockerUsername, dockerPassword
}

type dockerConfig struct {
	Auths map[string]dockerAuth `json:"auths"`
}

type dockerAuth struct {
	Auth string `json:"auth"`
}

func createAuthFile(registryID, registryURL, username, password string) (string, error) {
	authDirPath, err := os.MkdirTemp("", "auth_"+registryID+"_*")
	if err != nil {
		return "", fmt.Errorf("failed to create temp dir for auth file: %w", err)
	}

	var authString string
	if password == "" {
		authString = username
	} else {
		authString = base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
	}

	config := dockerConfig{
		Auths: map[string]dockerAuth{
			registryURL: {
				Auth: authString,
			},
		},
	}

	configJSON, err := json.Marshal(config)
	if err != nil {
		return "", fmt.Errorf("failed to marshal auth config: %w", err)
	}

	configPath := authDirPath + "/config.json"
	if err := os.WriteFile(configPath, configJSON, 0600); err != nil {
		return "", fmt.Errorf("failed to write auth config file: %w", err)
	}

	return authDirPath, nil
}

func getEcrCredentials(awsAccessKey, awsSecret, awsRegionName, registryID string, useIAMRole bool, targetAccountRoleARN string) (string, string) {
	awsConfig := aws.Config{
		Region: aws.String(awsRegionName),
	}

	if !useIAMRole {
		awsConfig.Credentials = credentials.NewStaticCredentials(awsAccessKey, awsSecret, "")
	}

	mySession := session.Must(session.NewSession(&awsConfig))

	var svc *ecr.ECR
	if useIAMRole && targetAccountRoleARN != "" {
		creds := stscreds.NewCredentials(mySession, targetAccountRoleARN)
		svc = ecr.New(mySession, &aws.Config{Credentials: creds})
	} else {
		svc = ecr.New(mySession)
	}

	var authorizationTokenRequestInput ecr.GetAuthorizationTokenInput
	if registryID != "" {
		authorizationTokenRequestInput.SetRegistryIds([]*string{&registryID})
	}
	authorizationTokenResponse, err := svc.GetAuthorizationToken(&authorizationTokenRequestInput)
	if err != nil {
		// NOTE: It would be good practice to log this error for easier debugging.
		return "", ""
	}
	authorizationData := authorizationTokenResponse.AuthorizationData
	if len(authorizationData) == 0 {
		return "", ""
	}
	authData := *authorizationData[0]
	return *authData.ProxyEndpoint, *authData.AuthorizationToken
}
