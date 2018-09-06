<?php
namespace WebrockSk\Oauth2Client;

use Lcobucci\JWT\Parser;

use League\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Provider\GenericResourceOwner;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException as LeagueIdentityProviderException;

use WebrockSk\Oauth2Client\AccessToken\Storage\StorageInterface;

use Exception;

class Client {

	static $instance;

	/**
	 * Config
	 *
	 * @var array
	 */
	private $config;

	/**
	 * Provider
	 *
	 * @var Provider
	 */
	private $provider;

	/**
	 * Access Token
	 *
	 * @var AccessToken
	 */
	private $accessToken;

	/**
	 * Token Storage
	 *
	 * @var StorageInterface
	 */
	private $tokenStorage;

	/**
	 * Resource Owner
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
			'auto_load_token'                => isset($config['auto_load_token']) ? $config['auto_load_token'] : true,
			'auto_refresh_token'             => isset($config['auto_refresh_token']) ? $config['auto_refresh_token'] : true,
			// 'token_verify_hs_key'         => @$config['token_verify_hs_key'], //TODO: add verification
			// 'token_verify_rs_public_key'  => @$config['token_verify_rs_public_key'], //TODO: add verification
			// 'token_verify_rs_private_key' => @$config['token_verify_rs_private_key'], //TODO: add verification
		];

		if(isset($config['token_storage']))
			$this->setTokenStorage($config['token_storage']);

		//Pre-set access token
		if(!!$this->config['auto_load_token'])
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
			
		} catch(Exception $e) {
			$this->clearAccessToken();
			$this->resourceOwner = null;
		}

		return $this->resourceOwner;
	}

	/**
	 * getAccessToken
	 *
	 * @return AccessToken
	 */
	public function getAccessToken() {
		
		if(!$this->accessToken) {
			if($this->tokenStorage) 
				$this->accessToken = $this->tokenStorage->getToken();

			if(!$this->accessToken)
				$this->accessToken = $this->getAccessTokenFromHeader(); 
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
	 * getAccessTokenFromHeader
	 *
	 * @return AccessToken
	 */
	public function getAccessTokenFromHeader() {

		$headers = apache_request_headers();

		if(!array_key_exists('Authorization', $headers))
			return null;
		
		if(!preg_match('/^\s*Bearer\s*([A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+(\.[A-Za-z0-9-_.+\=]+)*)$/', $headers['Authorization'], $matches))
			return null;

		$token = (new Parser())->parse((string) $matches[1]);
		$claims = (object) $token->getClaims();

		return new AccessToken([
			'access_token' => $matches[1],
			'refresh_token' => null,
			'scope' => $claims->scope->getValue(),
			'expires' => $claims->exp->getValue(),
		]);	
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
			&& $token->getRefreshToken()
		)
			return (boolean) $this->refreshAccessToken() ? true : false;
		
		return !$token->hasExpired() && $this->verifyAccessToken();
	}

	/**
	 * verifyAccessToken
	 *
	 * @param AccessToken $token
	 * @return void
	 */
	public function verifyAccessToken(AccessToken $token = null){

		if(!$token)
			$token = $this->getAccessToken();

		if(!$token)
			return false;

		// for now
		//TODO: add token verification
		return true;
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
				throw new IdentityProviderException('No refresh token');

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
		} catch (LeagueIdentityProviderException $e) {
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
		} catch (LeagueIdentityProviderException $e) {
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
