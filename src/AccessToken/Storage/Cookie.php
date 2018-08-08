<?php
namespace WebrockSk\Oauth2Client\AccessToken\Storage;

use League\OAuth2\Client\Token\AccessToken;

class Cookie implements StorageInterface {

	private $cookieKey;

	/**
	 * __construct
	 *
	 * @param mixed $key
	 * @return void
	 */
	public function __construct($cookieKey = 'wrskoauth2token') {
		$this->cookieKey = $cookieKey;
	}

	/**
	 * getToken
	 *
	 * @return void
	 */
	public function getToken() {

		$rawToken = $_COOKIE[$this->cookieKey];

		if(!$rawToken)
			return null;

		$token = json_decode($rawToken, true);

		if(!$token)
			return null;

		return new AccessToken([
			'access_token' => $token['access_token'],
			'refresh_token' => $token['refresh_token'],
			'scope' => $token['scope'],
			'expires' => $token['expires'],
		]);
	}

	/**
	 * saveToken
	 *
	 * @param AccessToken $accessToken
	 * @return void
	 */
	public function saveToken(AccessToken $accessToken, $expire = 604800, $path = '/', $domain = '', $secure = false, $httpOnly = true) {
		$serialized = json_encode($accessToken->jsonSerialize());
		setcookie($this->cookieKey, $serialized, time()+$expire, $path, $domain, $secure, $httpOnly);
	}

	/**
	 * deleteToken
	 *
	 * @return void
	 */
	public function deleteToken() {
		setcookie($this->cookieKey, null, -1, '/');
		unset($_COOKIE[$this->cookieKey]);
	}
}
