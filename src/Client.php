<?php
namespace WebrockSk\Oauth2Client;

use League\OAuth2\Client\Provider\Exception\IdentityProviderException as LeagueIPException;

use WebrockSk\Oauth2Client\AccessToken\Storage\StorageInterface;
use WebrockSk\Oauth2Client\AccessToken\Storage\RequestHeader as RequestHeaderStorage;

use Exception;

class Client {

	static $instance;

	/**
	 * $config
	 *
	 * @var array
	 */
	private $config;

	/**
	 * $provider
	 *
	 * @var Provider
	 */
	private $provider;

	/**
	 * $accessToken
	 *
	 * @var AccessToken
	 */
	private $accessToken;

	/**
	 * $tokenStorage
	 *
	 * @var StorageInterface
	 */
	private $tokenStorage;

	/**
	 * $user
	 *
	 * @var ResourceOwnerInterface
	 */
	private $resourceOwner;

	/**
	 * __construct
	 *
	 * @param mixed $config
	 * @return void
	 */
	public function __construct($config = []) {

		if(!isset($config['server']))
			throw new IdentityProviderException('Provide server');

		$this->config = [
			'server'                         => $config['server'],
			'providerConfig' => [
				'clientId'                   => @$config['client_id'],
				'clientSecret'               => @$config['client_secret'],
				'redirectUri'                => @$config['redirect_uri'],
				'proxy'                      => @$config['proxy'] ?: null,
				'verify'                     => false
			],
			'auto_load_token'                => isset($config['auto_load_token']) ? (bool) $config['auto_load_token'] : true,
			'auto_refresh_token'             => isset($config['auto_refresh_token']) ? (bool) $config['auto_refresh_token'] : true,
			'token_verify_public_key'        => @$config['token_verify_public_key'] ?: null,
		];

		if(isset($config['token_storage']))
			$this->setTokenStorage($config['token_storage']);
		else
			$this->setTokenStorage(new RequestHeaderStorage);

		//Pre-set access token
		if($this->config['auto_load_token'])
			$this->getAccessToken();
			
		$this->provider = new Provider($this->config['server'], $this->config['providerConfig']);
	}

	/**
	 * getInstance
	 *
	 * @return Client
	 */
	public static function getInstance($config = []) {

		if(!self::$instance)
			self::$instance = new self($config);

		return self::$instance;
	}

	/**
	 * setInstance
	 *
	 * @return void
	 */
	public static function setInstance(Client $client) {
		self::$instance = $client;
	}

	/**
	 * getProvider
	 *
	 * @return string
	 */
	public function getServer() {
		return $this->config['server'];
	}

	/**
	 * getProvider
	 *
	 * @return Provider
	 */
	public function getProvider() {
		return $this->provider;
	}

	/**
	 * setTokenStorage
	 *
	 * @param StorageInterface $storage
	 * @return void
	 */
	public function setTokenStorage(StorageInterface $storage) {
		$this->tokenStorage = $storage;
	}

	/**
	 * getResourceOwner
	 *
	 * @param AccessToken $token
	 * @return ResourceOwnerInterface|null
	 */
	public function getResourceOwner() {

		if(!$this->hasValidAccessToken())
			throw new IdentityProviderException('invalid_token');

		try {

			if(!$this->resourceOwner)
				$this->resourceOwner = $this->provider->getResourceOwner($this->getAccessToken());
			
		} catch (LeagueIPException $e) {
			$this->clearAccessToken();
			$this->resourceOwner = null;
			throw IdentityProviderException::fromLeague($e);
		}

		return $this->resourceOwner;
	}

	/**
	 * getAccessToken
	 *
	 * @return AccessToken
	 */
	public function getAccessToken() {
		
		if($this->tokenStorage)
			$this->accessToken = $this->tokenStorage->getToken();

		if(!$this->accessToken) {
			$headerStorage = new RequestHeaderStorage;
			$this->accessToken = $headerStorage->getToken();
		}

		return $this->accessToken;
	}

	

	/**
	 * setAccessToken
	 *
	 * @param AccessToken $token
	 * @return void
	 */
	public function setAccessToken(AccessToken $token) {

		$this->accessToken = $token;

		if($this->tokenStorage)
			$this->tokenStorage->saveToken($token);
	}

	/**
	 * clearAccessToken
	 *
	 * @return void
	 */
	public function clearAccessToken() {

		$this->accessToken = null;

		if($this->tokenStorage)
			$this->tokenStorage->deleteToken();
	}

	/**
	 * hasAccessToken
	 *
	 * @return bool
	 */
	public function hasAccessToken() {
		return !empty($this->getAccessToken());
	}

	/**
	 * hasValidAccessToken
	 *
	 * @return boolean
	 */
	public function hasValidAccessToken() {

		$token = $this->getAccessToken();

		if(!$token)
			return false;

		if(
			$this->config['auto_refresh_token'] === true 
			&& $token->hasExpired() 
			&& !empty($token->getRefreshToken())
		)
			$token = $this->refreshAccessToken();
		
		return $this->validateAccessToken();
	}

	/**
	 * validateAccessToken
	 *
	 * @param AccessToken $token
	 * @return void
	 */
	public function validateAccessToken(AccessToken $token = null){

		if(!$token)
			$token = $this->getAccessToken();

		if(!$token || $token->hasExpired())
			return false;

		if(!empty($this->config['token_verify_public_key']))
			return $token->validate($this->config['token_verify_public_key']);
		
		return true;
	}

	/**
	 * assertValidAccessToken
	 *
	 * @param mixed AccessToken
	 * @return void
	 */
	public function assertValidAccessToken(AccessToken $token = null) {
		if(!$this->verifyAccessToken($token))
			throw new IdentityProviderException('invalid_token');
	}

	/**
	 * checkScope
	 *
	 * @return void
	 */
	public function checkScope(...$scope) {

		if(!$this->hasValidAccessToken())
			return false;
		
		$token = $this->getAccessToken();

		return count(array_diff($scope, $token->getScopeArray())) == 0;
	}

	/**
	 * refreshAccessToken
	 *
	 * @param mixed $refreshToken
	 * @return AccessToken|null
	 */
	public function refreshAccessToken($refreshToken = null) {

		$token = $this->getAccessToken();

		if(!$token)
			return null;

		if(!$token->hasExpired())
			return $token;
			
		try {

			$refreshToken = $refreshToken ?: $token->getRefreshToken();

			if(!$refreshToken)
				throw new IdentityProviderException('no_refresh_token');

			$this->assertValidTokenRequest();

			$token = $this->provider->getAccessToken('refresh_token', [
				'refresh_token' => $refreshToken
			]);

			$this->setAccessToken($token);

			return $token;

		} catch(Exception $e) {
			$this->clearAccessToken();
			throw $e;
		}
	}

	/**
	 * getAuthorizationUrl
	 *
	 * @param mixed array
	 * @return void
	 */
	public function getAuthorizationUrl(array $options = []) {

		$provider = $this->provider;

		if(isset($options['client_id'])) {
			$config = array_merge($this->config['providerConfig'], ['clientId' => $options['client_id']]);
			$provider = new Provider($this->config['server'], $config);
		}

		return $provider->getAuthorizationUrl($options);
	}

	/**
	 * doPasswordGrant
	 *
	 * @param mixed $username
	 * @param mixed $password
	 * @return AccessToken
	 */
	public function doPasswordGrant($username, $password) {

		$this->assertValidTokenRequest();
			
		try {

			$token = $this->provider->getAccessToken('password', [
				'username' => $username,
				'password' => $password
			]);

			$this->setAccessToken($token);
		} catch (LeagueIPException $e) {
			throw IdentityProviderException::fromLeague($e);
		}

		return $this->getAccessToken();
	}

	/**
	 * doClientGrant
	 *
	 * @return AccessToken
	 */
	public function doClientGrant() {

		$this->assertValidTokenRequest();

		try {
			
			$token = $this->provider->getAccessToken('client_credentials');

			$this->setAccessToken($token);
		} catch (LeagueIPException $e) {
			throw IdentityProviderException::fromLeague($e);
		}

		return $this->getAccessToken();
	}

	/**
	 * assertValidTokenRequest
	 *
	 * @return void
	 * @throws IdentityProviderException
	 */
	private function assertValidTokenRequest() {

		if(!isset($this->config['providerConfig']['clientId']))
			throw new IdentityProviderException('Provide clientId');

		if(!isset($this->config['providerConfig']['clientSecret']))
			throw new IdentityProviderException('Provide clientSecret');
	}

	/**
	 * isLoggedIn
	 *
	 * @return boolean
	 */
	public static function isLoggedIn() {
		return self::getInstance()->hasValidAccessToken();
	}

}
