# Caddy Leierkasten Authentication
An HTTP authentication provider for caddyserver using the Leierkasten as authentication backend.

## Build
Simply build with `xcaddy build --with github.com/kdf-leierkasten/caddy_leierkasten_auth`

## Sample Caddyfile
Two values are necessary:
* The URL path to the leierkasten API that is providing the `/me/get` endpoint
* The name of the authentication cookie used by Leierkasten (specified in `Leierkasten.toml` as `cookie-name` in the `[server]` section

```
localhost:12345 {
    route * {
        leierkastenauth {
            leierkasten_api_url https://localhost/api
            cookie_name leierkasten-session
        }
        respond 200 {
            body "User Authenticated with ID: {http.auth.user.id}. Metadata: DisplayName {http.auth.user.name}, LoginName {http.auth.user.loginName}"
        }
    }
}
```
