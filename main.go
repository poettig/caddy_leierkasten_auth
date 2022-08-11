package caddy_leierkasten_auth

import (
	"encoding/json"
	"fmt"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/caddyauth"
	"go.uber.org/zap"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

func init() {
	caddy.RegisterModule(&LeierkastenAuth{})
	httpcaddyfile.RegisterHandlerDirective("leierkastenauth", parseCaddyfile)
}

type LeierkastenAuth struct {
	LeierkastenUrl string `json:"leierkasten_api_url"`
	CookieName     string `json:"cookie_name"`

	Logger *zap.Logger
}

type AuthResponse struct {
	Id        string `json:"id"`
	Name      string `json:"name"`
	LoginName string `json:"loginName"`
}

// CaddyModule returns the Caddy module information.
func (leierkastenAuth *LeierkastenAuth) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.authentication.providers.leierkasten",
		New: func() caddy.Module { return new(LeierkastenAuth) },
	}
}

// parseCaddyfile unmarshals tokens from h into a new Middleware.
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var leierkastenAuth LeierkastenAuth

	d := h.Dispenser
	for d.Next() {
		for h.NextBlock(0) {
			switch h.Val() {
			case "leierkasten_api_url":
				if !h.AllArgs(&leierkastenAuth.LeierkastenUrl) {
					return nil, h.Err("More than one argument for leierkasten URL provided.")
				}

				if strings.HasSuffix(leierkastenAuth.LeierkastenUrl, "/") {
					// Remove ending slashes in path
					r := regexp.MustCompile(`.*/+$`)
					leierkastenAuth.LeierkastenUrl = r.ReplaceAllString(leierkastenAuth.LeierkastenUrl, "")
				}

			case "cookie_name":
				if !h.AllArgs(&leierkastenAuth.CookieName) {
					return nil, h.Err("More than one argument for cookie name provided.")
				}

			default:
				return nil, h.Errf("unrecognized argument %s", h.Val())
			}
		}
	}

	return caddyauth.Authentication{
		ProvidersRaw: caddy.ModuleMap{
			"leierkasten": caddyconfig.JSON(leierkastenAuth, nil),
		},
	}, nil
}

func (leierkastenAuth *LeierkastenAuth) Provision(caddyContext caddy.Context) error {
	leierkastenAuth.Logger = caddyContext.Logger(leierkastenAuth)
	return nil
}

func (leierkastenAuth *LeierkastenAuth) Validate() error {
	if leierkastenAuth.LeierkastenUrl == "" {
		return fmt.Errorf("the URL for Leierkasten is empty or missing")
	}

	if leierkastenAuth.CookieName == "" {
		return fmt.Errorf("the leierkasten auth cookie name is empty or missing")
	}

	parsedUrl, err := url.ParseRequestURI(leierkastenAuth.LeierkastenUrl)
	if err != nil {
		return fmt.Errorf("leierkasten URL is not valid: %s", err)
	}

	if parsedUrl.Scheme != "http" && parsedUrl.Scheme != "https" {
		return fmt.Errorf("leierkasten URL is not an http(s) URL")
	}

	return nil
}

func (leierkastenAuth *LeierkastenAuth) Authenticate(_ http.ResponseWriter, request *http.Request) (caddyauth.User, bool, error) {
	failureUser := caddyauth.User{}

	// Get leierkasten cookie from request
	foundCookie := false
	var authCookie *http.Cookie
	for _, cookie := range request.Cookies() {
		if cookie.Name == leierkastenAuth.CookieName {
			foundCookie = true
			authCookie = cookie
		}
	}

	if !foundCookie {
		return failureUser, false, fmt.Errorf("the leierkasten auth cookie was not provided with the request")
	}

	request, err := http.NewRequest("GET", fmt.Sprintf("%s/me/get", leierkastenAuth.LeierkastenUrl), nil)
	if err != nil {
		return failureUser, false, fmt.Errorf("failed to construct request to leierkasten auth endpoint: %s", err)
	}

	request.AddCookie(authCookie)
	client := &http.Client{}
	response, err := client.Do(request)
	if err != nil {
		return failureUser, false, fmt.Errorf("failed to request leierkasten auth endpoint: %s", err)
	}

	defer response.Body.Close()

	bodyBytes, err := io.ReadAll(response.Body)
	if err != nil {
		return failureUser, false, err
	}

	if response.StatusCode != http.StatusOK {
		if response.StatusCode == http.StatusUnauthorized {
			return failureUser, false, fmt.Errorf("leierkasten rejected authentication: %s", string(bodyBytes))
		}

		return failureUser, false, fmt.Errorf("leierkasten returned unexpected status code %d", response.StatusCode)
	}

	var authResponse AuthResponse
	err = json.Unmarshal(bodyBytes, &authResponse)
	if err != nil {
		return failureUser, false, fmt.Errorf("authentication was successful, but unmarshaling response failed: %s", err)
	}

	return caddyauth.User{
		ID: authResponse.Id,
		Metadata: map[string]string{
			"name":      authResponse.Name,
			"loginName": authResponse.LoginName,
		},
	}, true, nil
}
