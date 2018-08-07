<?php
namespace WebrockSk\PanzerAuthClient;

use League\OAuth2\Client\Token\AccessToken;

use Exception;

class Client {

	static $instance;

	/**
	 * $server
	 *
	 * @var string
	 */
	private $server;

	/**
	 * $loginUrl
	 *
	 * @var string
	 */
	private $loginUrl = '/login';

	/**
	 * $config
	 *
	 * @var array
	 */
	private $config;

	/**
	 * $providerOptions
	 *
	 * @var array
	 */
	private $providerOptions;

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
	 * $user
	 *
	 * @var ResourceOwnerInterface
	 */
	private $user;

	/**
	 * Konstruktor
	 *
	 * @return void
	 */
	public function __construct($config = []) {

		$this->server = $config['server'];

		$this->providerOptions = [
			'clientId'                => $config['clientId'],
			'clientSecret'            => $config['clientSecret'],
			'redirectUri'             => $config['redirectUri'],
			'urlAuthorize'            => $config['server'].'/oauth/authorize',
			'urlAccessToken'          => $config['server'].'/api/oauth/token',
			'urlResourceOwnerDetails' => $config['server'].'/api/oauth/resource',
			'proxy'                   => @$config['proxyIp'] ?: null,
			'verify'                  => false
		];

		$this->provider = $this->createProvider();

		$this->accessToken = Token::fromCookie() ?: Token::fromHeader();
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
	 * createProvider
	 *
	 * @param array $options
	 * @return Provider;
	 */
	public function createProvider(array $options = []){
		
		$options = array_merge($this->providerOptions, $options);

		if(!array_key_exists('clientId', $options))
			throw new Exception('Provide clientId');
		if(!array_key_exists('redirectUri', $options))
			throw new Exception('Provide redirectUri');

		$strip = function($str) { return preg_replace('/^\/(.*)\/$/', '$1', $str); };

		$options['redirectUri'] = $strip($options['redirectUri']);
		$options['urlAuthorize'] = $strip($options['urlAuthorize']);
		$options['urlAccessToken'] = $strip($options['urlAccessToken']);
		$options['urlResourceOwnerDetails'] = $strip($options['urlResourceOwnerDetails']);
			
		return new Provider($options);
	}

	/**
	 * getProvider
	 *
	 * @return Provider
	 */
	public function getProvider($options = []) {
		return $this->provider;
	}

	/**
	 * setResourceOwner
	 *
	 * @param ResourceOwnerInterface $owner
	 * @return ResourceOwnerInterface
	 */
	public function setResourceOwner(ResourceOwnerInterface $owner) {
		$this->user = new ResourceOwnerInterface($owner->toArray());
		return $this->user;
	}

	/**
	 * getResourceOwner
	 *
	 * @param AccessToken $token
	 * @return ResourceOwnerInterface
	 */
	public function getResourceOwner(AccessToken $token = null) {
		try {

			if(!$this->hasValidAccessToken(true))
				return null;

			return $this->provider->getResourceOwner($token ?: $this->getAccessToken());	
			
		} catch(Exception $e) {
			$this->clearAccessToken();
		}
	}

	/**
	 * getAccessToken
	 *
	 * @return AccessToken
	 */
	public function getAccessToken() {
		
		if(!$this->accessToken)
			$this->accessToken = Token::fromCookie();

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
		Token::setCookie($token);
	}

	/**
	 * clearAccessToken
	 *
	 * @return void
	 */
	public function clearAccessToken() {
		$this->accessToken = null;
		Token::clearCookie();
	}

	/**
	 * getUser
	 *
	 * @return ResourceOwnerInterface
	 */
	public function getUser() {
		return $this->user;
	}

	/**
	 * hasValidAccessToken
	 *
	 * @param boolean $tryToRefresh
	 * @return boolean
	 */
	public function hasValidAccessToken($tryToRefresh = false) {

		$token = $this->getAccessToken();

		if(!$token)
			return false;

		if($tryToRefresh && $token->hasExpired() && $token->getRefreshToken())
			return $this->refreshAccessToken() ? true : false;
		
		return !$token->hasExpired() && $this->verifyAccessToken();
	}

	/**
	 * verifyAccessToken
	 *
	 * @param AccessToken AccessToken
	 * @return boolean
	 */
	public function verifyAccessToken(AccessToken $token = null){

		if(!$token)
			$token = $this->getAccessToken();

		if(!$token)
			return false;

		// for now
		return true;
	}

	/**
	 * refreshAccessToken
	 *
	 * @param AccessToken $token
	 * @return AccessToken|null
	 */
	public function refreshAccessToken(AccessToken $token = null) {

		if(!$token)
			$token = $this->getAccessToken();

		if(!$token)
			return null;

		if(!$token->hasExpired())
			return $token;

		try {

			$refreshToken = $token->getRefreshToken();

			if(!$refreshToken)
				return null;

			$token = $this->provider->getAccessToken('refresh_token', [
				'refresh_token' => $refreshToken
			]);
	
			$this->setAccessToken($token);

			return $token;

		} catch(Exception $e) {
			$this->clearAccessToken();
			return null;
		}
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
