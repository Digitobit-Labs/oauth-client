<?php

namespace Digitobit\OAuthClient;

use League\OAuth2\Client\Provider\GenericProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Token\AccessToken;
use Firebase\JWT\JWT;
use Firebase\JWT\JWK;

class OAuthClient
{
    protected GenericProvider $provider;

    protected ?AccessToken $token = null;

    /**
     * OIDC Discovery Metadata
     */
    protected array $metadata = [];

    /**
     * PKCE + State
     */
    protected ?string $state = null;

    protected ?string $pkceCode = null;

    /**
     * OAuth Endpoints
     */
    protected string $authorizationEndpoint;

    protected string $tokenEndpoint;

    protected string $resourceOwnerEndpoint;

    protected string $revocationEndpoint;

    protected string $introspectionEndpoint;

    /**
     * Cached JWKS.
     */
    protected ?array $jwks = null;

    /**
     * Default endpoint paths.
     *
     * Used only when OIDC discovery is unavailable.
     */
    protected array $defaultEndpoints = [

        'authorization_endpoint' => '/oauth/authorize',

        'token_endpoint' => '/oauth/token',

        'userinfo_endpoint' => '/oauth/userinfo',

        'introspection_endpoint' => '/oauth/introspect',

        'revocation_endpoint' => '/oauth/revoke',

    ];

    public function __construct(
        protected string $clientId,
        protected string $clientSecret,
        protected string $redirectUri,
        protected string $baseUrl,
        protected array $scopes = ['openid', 'profile', 'email']
    ) {

        $this->discoverEndpoints();

        $this->provider = new GenericProvider([

            'clientId'                => $this->clientId,

            'clientSecret'            => $this->clientSecret,

            'redirectUri'             => $this->redirectUri,

            'urlAuthorize'            => $this->authorizationEndpoint,

            'urlAccessToken'          => $this->tokenEndpoint,

            'urlResourceOwnerDetails' => $this->resourceOwnerEndpoint,

            'scopes'                  => $this->scopes,

            'scopeSeparator'          => ' '

        ]);
    }

    /**
     * Discover OAuth/OIDC endpoints.
     *
     * If discovery fails we simply fall back to
     * Passport defaults.
     */
    /**
     * Discover OAuth/OIDC endpoints from the issuer.
     *
     * Falls back to Laravel Passport defaults if discovery
     * is unavailable.
     */
    /**
     * Discover OAuth/OIDC endpoints.
     *
     * If discovery is unavailable, falls back to the
     * configured default endpoint paths.
     */
    protected function discoverEndpoints(): void
    {
        $base = rtrim($this->baseUrl, '/');

        $this->authorizationEndpoint = $base . $this->defaultEndpoints['authorization_endpoint'];
        $this->tokenEndpoint         = $base . $this->defaultEndpoints['token_endpoint'];
        $this->resourceOwnerEndpoint = $base . $this->defaultEndpoints['userinfo_endpoint'];
        $this->introspectionEndpoint = $base . $this->defaultEndpoints['introspection_endpoint'];
        $this->revocationEndpoint    = $base . $this->defaultEndpoints['revocation_endpoint'];

        $curl = curl_init($base . '/.well-known/openid-configuration');

        curl_setopt_array($curl, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => 10,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_HTTPHEADER => [
                'Accept: application/json'
            ]
        ]);

        $response = curl_exec($curl);

        curl_close($curl);

        if (!$response) {
            return;
        }

        $metadata = json_decode($response, true);

        if (!is_array($metadata)) {
            return;
        }

        $this->metadata = $metadata;

        $this->authorizationEndpoint =
            $metadata['authorization_endpoint']
            ?? $this->authorizationEndpoint;

        $this->tokenEndpoint =
            $metadata['token_endpoint']
            ?? $this->tokenEndpoint;

        $this->resourceOwnerEndpoint =
            $metadata['userinfo_endpoint']
            ?? $this->resourceOwnerEndpoint;

        $this->introspectionEndpoint =
            $metadata['introspection_endpoint']
            ?? $this->introspectionEndpoint;

        $this->revocationEndpoint =
            $metadata['revocation_endpoint']
            ?? $this->revocationEndpoint;
    }

    /**
     * Returns provider.
     */
    public function provider(): GenericProvider
    {
        return $this->provider;
    }

    /**
     * Authorization URL.
     */
    public function getAuthorizationUrl(
        array $options = []
    ): string {

        $defaults = [

            'scope' => implode(
                ' ',
                $this->scopes
            )

        ];

        $url = $this->provider->getAuthorizationUrl(
            array_merge(
                $defaults,
                $options
            )
        );

        $this->state = $this->provider->getState();

        /*
         * League automatically generates PKCE
         * if PKCE is enabled.
         *
         * Store it so the application
         * can persist it in session.
         */
        if (method_exists($this->provider, 'getPkceCode')) {
            $this->pkceCode = $this->provider->getPkceCode();
        }

        return $url;
    }

    /**
     * Alias
     */
    public function authorizationUrl(
        array $options = []
    ): string {

        return $this->getAuthorizationUrl(
            $options
        );
    }



    /**
     * OAuth state.
     */
    public function getState(): ?string
    {
        return $this->state;
    }

    /**
     * PKCE verifier.
     */
    public function getPkceCode(): ?string
    {
        return $this->pkceCode;
    }

    /**
     * Store current token.
     */
    public function setToken(
        AccessToken $token
    ): self {

        $this->token = $token;

        return $this;
    }

    /**
     * Current token.
     */
    public function getToken(): ?AccessToken
    {
        return $this->token;
    }

    /**
     * Current token expired?
     */
    public function isExpired(): bool
    {
        return $this->token?->hasExpired()
            ?? true;
    }

    /**
     * Resolve access token.
     */
    protected function resolveAccessToken(
        AccessToken|string $token
    ): string {

        if ($token instanceof AccessToken) {
            return $token->getToken();
        }

        return $token;
    }

    /**
     * HTTP Client
     */
    protected function http()
    {
        return $this->provider->getHttpClient();
    }

    /**
     * Exchange authorization code for access token.
     */
    public function token(string $code): AccessToken
    {
        try {

            $this->token = $this->provider->getAccessToken(
                'authorization_code',
                [
                    'code' => $code,
                ]
            );

            return $this->token;
        } catch (IdentityProviderException $e) {

            throw new \RuntimeException(
                'Failed to obtain access token: ' . $e->getMessage(),
                0,
                $e
            );
        }
    }

    /**
     * Client Credentials Grant.
     */
    public function clientCredentials(
        array|string|null $scopes = null
    ): AccessToken {

        if (is_array($scopes)) {
            $scope = implode(' ', $scopes);
        } elseif (is_string($scopes)) {
            $scope = $scopes;
        } else {
            $scope = implode(' ', $this->scopes);
        }

        try {

            $this->token = $this->provider->getAccessToken(
                'client_credentials',
                [
                    'scope' => $scope
                ]
            );

            return $this->token;
        } catch (IdentityProviderException $e) {

            throw new \RuntimeException(
                'Failed to obtain client credentials token: '
                    . $e->getMessage(),
                0,
                $e
            );
        }
    }

    /**
     * Refresh token.
     */
    public function refresh(
        AccessToken|string $refreshToken
    ): AccessToken {

        if ($refreshToken instanceof AccessToken) {
            $refreshToken = $refreshToken->getRefreshToken();
        }

        if (empty($refreshToken)) {
            throw new \RuntimeException(
                'Refresh token is missing.'
            );
        }

        try {

            $this->token = $this->provider->getAccessToken(
                'refresh_token',
                [
                    'refresh_token' => $refreshToken
                ]
            );

            return $this->token;
        } catch (IdentityProviderException $e) {

            throw new \RuntimeException(
                'Failed to refresh token: '
                    . $e->getMessage(),
                0,
                $e
            );
        }
    }

    /**
     * UserInfo endpoint.
     */
    public function userinfo(
        AccessToken|string|null $token = null
    ): array {

        $token = $this->resolveToken($token);

        try {

            $resourceOwner = $this->provider->getResourceOwner(
                $token
            );

            return $resourceOwner->toArray();
        } catch (IdentityProviderException $e) {

            throw new \RuntimeException(
                'Failed to retrieve user information: '
                    . $e->getMessage(),
                0,
                $e
            );
        }
    }

    /**
     * RFC7662 Introspection.
     */
    public function introspect(
        AccessToken|string|null $token = null
    ): array {

        $token = $this->resolveToken($token);

        try {

            $response = $this->http()->request(
                'POST',
                $this->introspectionEndpoint,
                [

                    'auth' => [
                        $this->clientId,
                        $this->clientSecret
                    ],

                    'form_params' => [

                        'token' => $token->getToken(),

                        'token_type_hint' => 'access_token'

                    ]

                ]
            );

            return json_decode(
                $response
                    ->getBody()
                    ->getContents(),
                true
            );
        } catch (\Throwable $e) {

            throw new \RuntimeException(
                'Token introspection failed: '
                    . $e->getMessage(),
                0,
                $e
            );
        }
    }

    /**
     * RFC7009 Revocation.
     */
    public function revoke(
        AccessToken|string|null $token = null,
        string $hint = 'access_token'
    ): bool {

        $token = $this->resolveToken($token);

        try {

            $response = $this->http()->request(
                'POST',
                $this->revocationEndpoint,
                [

                    'auth' => [
                        $this->clientId,
                        $this->clientSecret
                    ],

                    'form_params' => [

                        'token' => $token->getToken(),

                        'token_type_hint' => $hint

                    ]

                ]
            );

            return $response->getStatusCode() === 200;
        } catch (\Throwable $e) {

            throw new \RuntimeException(
                'Token revocation failed: '
                    . $e->getMessage(),
                0,
                $e
            );
        }
    }

    /**
     * Resolve token.
     */
    protected function resolveToken(
        AccessToken|string|null $token
    ): AccessToken {

        if ($token instanceof AccessToken) {
            return $token;
        }

        if (is_string($token)) {
            return new AccessToken([
                'access_token' => $token
            ]);
        }

        if ($this->token instanceof AccessToken) {
            return $this->token;
        }

        throw new \RuntimeException(
            'No access token available.'
        );
    }

    /**
     * Exchange authorization code from callback parameters.
     */
    public function tokenFromCallback(array $query): AccessToken
    {
        if (empty($query['code'])) {
            throw new \RuntimeException(
                'Authorization code missing.'
            );
        }

        return $this->token($query['code']);
    }

    /**
     * Verify and decode a JWT (access token or ID token).
     *
     * @throws \RuntimeException
     */
    public function verify(
        AccessToken|string $token,
        ?string $expectedAudience = null,
        ?string $expectedIssuer = null
    ): object {

        $jwt = $token instanceof AccessToken
            ? $token->getToken()
            : $token;

        $keys = $this->getVerificationKeys();

        try {

            $claims = JWT::decode(
                $jwt,
                $keys
            );
        } catch (\Throwable $e) {

            /*
         * Key rotation may have occurred.
         * Reload JWKS once and retry.
         */
            $this->jwks = null;

            $keys = $this->getVerificationKeys();

            $claims = JWT::decode(
                $jwt,
                $keys
            );
        }

        if (
            $expectedIssuer !== null &&
            ($claims->iss ?? null) !== $expectedIssuer
        ) {
            throw new \RuntimeException('Invalid issuer.');
        }

        if ($expectedAudience !== null) {

            $aud = $claims->aud ?? null;

            $valid = false;

            if (is_array($aud)) {
                $valid = in_array($expectedAudience, $aud, true);
            } else {
                $valid = $aud === $expectedAudience;
            }

            if (!$valid) {
                throw new \RuntimeException('Invalid audience.');
            }
        }

        return $claims;
    }

    /**
     * Get verification keys.
     */
    protected function getVerificationKeys(): array
    {
        if ($this->jwks !== null) {
            return JWK::parseKeySet($this->jwks);
        }

        $jwksUri = $this->metadata['jwks_uri']
            ?? throw new \RuntimeException(
                'JWKS URI not available.'
            );

        $response = $this->http()->request(
            'GET',
            $jwksUri
        );

        $jwks = json_decode(
            $response->getBody()->getContents(),
            true
        );

        if (!is_array($jwks)) {
            throw new \RuntimeException(
                'Invalid JWKS response.'
            );
        }

        $this->jwks = $jwks;

        return JWK::parseKeySet($jwks);
    }

    public function verifyCurrent(): object
    {
        if (!$this->token) {
            throw new \RuntimeException(
                'No current token.'
            );
        }

        return $this->verify($this->token);
    }
}
