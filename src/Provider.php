<?php
namespace WebrockSk\Oauth2Client;

use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Provider\GenericResourceOwner;

use WebrockSk\Oauth2Client\AccessToken\Storage\StorageInterface;

use Psr\Http\Message\ResponseInterface;

class Provider extends AbstractProvider {

	/**
	 * $server
	 *
	 * @var string
	 */
	private $server;

	const URL_AUTHORIZE = '/oauth/authorize';
	const URL_ACCESS_TOKEN = '/api/oauth/token';
	const URL_RESOURCE_OWNER = '/api/oauth/resource';

	/**
	 * @param array $options
	 * @param array $collaborators
	 */
	public function __construct($server, array $options = [], array $collaborators = []) {
		$this->server = $server;
		parent::__construct($options, $collaborators);
	}

	/**
	 * Returns authorization headers for the 'bearer' grant.
	 *
	 * @param  mixed|null $token Either a string or an access token instance
	 * @return array
	 */
	protected function getAuthorizationHeaders($token = null) {
		return ['Authorization' => 'Bearer ' . $token];
	}

	/**
	 * Returns the base URL for authorizing a client.
	 *
	 * Eg. https://oauth.service.com/authorize
	 *
	 * @return string
	 */
	public function getBaseAuthorizationUrl() {
		return $this->server.self::URL_AUTHORIZE;
	}

	/**
	 * Returns the base URL for requesting an access token.
	 *
	 * Eg. https://oauth.service.com/token
	 *
	 * @param array $params
	 * @return string
	 */
	public function getBaseAccessTokenUrl(array $params) {
		return $this->server.self::URL_ACCESS_TOKEN;
	}

	/**
	 * Returns the URL for requesting the resource owner's details.
	 *
	 * @param AccessToken $token
	 * @return string
	 */
	public function getResourceOwnerDetailsUrl(AccessToken $token) {
		return $this->server.self::URL_RESOURCE_OWNER;
	}

	 /**
	 * Returns the default scopes used by this provider.
	 *
	 * This should only be the scopes that are required to request the details
	 * of the resource owner, rather than all the available scopes.
	 *
	 * @return array
	 */
	protected function getDefaultScopes() {
		return null;
	}
	
	/**
	 * Checks a provider response for errors.
	 *
	 * @throws IdentityProviderException
	 * @param  ResponseInterface $response
	 * @param  array|string $data Parsed response data
	 * @return void
	 */
	protected function checkResponse(ResponseInterface $response, $data) {

		if(!empty($data['error'])) {

			$error = $data['error'];

			if(!is_string($error))
				$error = var_export($error, true);

			$code  = 0;

			if(!is_int($code))
				$code = intval($code);

			throw new IdentityProviderException($error, $code, $data);
		}
	}

	/**
	 * Generates a resource owner object from a successful resource owner
	 * details request.
	 *
	 * @param  array $response
	 * @param  AccessToken $token
	 * @return ResourceOwnerInterface
	 */
	protected function createResourceOwner(array $response, AccessToken $token) {
		return new GenericResourceOwner($response, 'id');
	}
}
