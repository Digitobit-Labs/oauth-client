# OAuth2 Client

A lightweight OAuth 2.0 and OpenID Connect (OIDC) client library for PHP built on top of **league/oauth2-client**.

This library simplifies integration with OAuth 2.0 / OIDC providers by providing a clean API for:

- Authorization Code Flow
- Client Credentials Flow
- Refresh Tokens
- UserInfo
- Token Introspection (RFC 7662)
- Token Revocation (RFC 7009)
- OpenID Connect Discovery

It is framework independent and can be used with CodeIgniter, Laravel, Symfony or any PHP application.

---

## Features

- Lightweight
- Framework independent
- Built on league/oauth2-client
- OpenID Connect Discovery
- Authorization Code Grant
- Client Credentials Grant
- Refresh Tokens
- UserInfo Endpoint
- Token Introspection
- Token Revocation
- Automatic endpoint discovery
- Laravel Passport compatible
- Standards compliant OAuth 2.0 / OIDC

---

## Requirements

- PHP 8.2+
- ext-curl
- ext-json

---

## Installation

```bash
composer require digitobit/oauth2-client
```

---

## Configuration

```php
use Digitobit\OAuthClient\OAuthClient;

$oauth = new OAuthClient(
    clientId: 'vector',
    clientSecret: 'your-client-secret',
    redirectUri: 'https://vector.example.com/auth/callback',
    baseUrl: 'https://auth.example.com',
    scopes: [
        'openid',
        'profile',
        'email'
    ]
);
```

If the authorization server supports OpenID Connect Discovery, endpoints are discovered automatically.

Otherwise the library falls back to standard OAuth endpoints.

---

# Authorization Code Flow

## Redirect user

```php
$url = $oauth->getAuthorizationUrl();

return redirect()->to($url);
```

Store the generated OAuth state before redirecting.

```php
session()->set('oauth_state', $oauth->getState());
```

---

## Callback

```php
$token = $oauth->token(
    $this->request->getGet('code')
);
```

---

# Client Credentials

```php
$token = $oauth->clientCredentials();
```

or

```php
$token = $oauth->clientCredentials([
    'api'
]);
```

---

# Refresh Token

```php
$newToken = $oauth->refresh(
    $token
);
```

or

```php
$newToken = $oauth->refresh(
    $refreshToken
);
```

---

# User Information

```php
$user = $oauth->userinfo($token);
```

or

```php
$user = $oauth->userinfo(
    $token->getToken()
);
```

Returns the UserInfo response as an associative array.

---

# Token Introspection

```php
$result = $oauth->introspect(
    $token
);
```

Example response

```json
{
    "active": true,
    "client_id": "vector",
    "sub": "123",
    "scope": "openid profile"
}
```

---

# Token Revocation

```php
$oauth->revoke(
    $token
);
```

Returns

```php
true
```

if revocation succeeds.

---

# Access Token

Current token

```php
$token = $oauth->getToken();
```

Check expiration

```php
if ($oauth->isExpired()) {

}
```

---

# OpenID Connect Discovery

If available, the client automatically loads

```
https://server/.well-known/openid-configuration
```

The following endpoints are discovered automatically:

- authorization_endpoint
- token_endpoint
- userinfo_endpoint
- revocation_endpoint
- introspection_endpoint
- jwks_uri

If discovery is unavailable, standard OAuth endpoint paths are used.

---

# CodeIgniter Example

```php
$oauth = new OAuthClient(
    clientId: env('oauth.clientId'),
    clientSecret: env('oauth.clientSecret'),
    redirectUri: route_to('oauth.callback'),
    baseUrl: env('oauth.baseUrl')
);

return redirect()->to(
    $oauth->getAuthorizationUrl()
);
```

---

# Laravel Example

```php
$oauth = new OAuthClient(
    clientId: config('oauth.client_id'),
    clientSecret: config('oauth.client_secret'),
    redirectUri: route('oauth.callback'),
    baseUrl: config('oauth.base_url')
);

return redirect(
    $oauth->getAuthorizationUrl()
);
```

---

# Supported OAuth Flows

| Flow | Supported |
|-------|-----------|
| Authorization Code | ✅ |
| Client Credentials | ✅ |
| Refresh Token | ✅ |
| Token Introspection | ✅ |
| Token Revocation | ✅ |
| UserInfo | ✅ |
| OIDC Discovery | ✅ |
| PKCE | Planned |
| JWT Local Verification | Planned |
| Device Authorization | Planned |

---

# Roadmap

Future releases may include:

- JWT verification using JWKS
- PKCE support
- Device Authorization Flow
- Token Exchange (RFC 8693)
- Dynamic Client Registration
- PSR-18 HTTP Client support
- Automatic JWKS caching

---

# Contributing

Issues and pull requests are welcome.

Please ensure new features remain standards compliant and framework independent.

---

# License

MIT License