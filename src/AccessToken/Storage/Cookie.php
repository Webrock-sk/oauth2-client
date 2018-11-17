<?php
namespace WebrockSk\Oauth2Client\AccessToken\Storage;

use WebrockSk\Oauth2Client\AccessToken;
use WebrockSk\Oauth2Client\IdentityProviderException;

class Cookie implements StorageInterface {

	/**
	 * $cookieKey
	 *
	 * @var string
	 */
	private $cookieKey;

	/**
	 * __construct
	 *
	 * @param mixed $key
	 * @return void
	 */
	public function __construct($cookieKey = 'AccessToken') {
		if (empty($cookieKey)) {
			throw new IdentityProviderException('Token cookie storage needs cookie key');
		}
		$this->cookieKey = $cookieKey;
	}

	/**
	 * getToken
	 *
	 * @return void
	 */
	public function getToken() {
		if (!isset($_COOKIE[$this->cookieKey])) {
			return null;
		}

		$token = json_decode($_COOKIE[$this->cookieKey], true);

		if (!$token) {
			return null;
		}

		return new AccessToken([
			'access_token' => $token['access_token'],
			'refresh_token' => @$token['refresh_token'],
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
		$_COOKIE[$this->cookieKey] = $serialized;
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
