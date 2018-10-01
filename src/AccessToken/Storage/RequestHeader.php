<?php
namespace WebrockSk\Oauth2Client\AccessToken\Storage;

use WebrockSk\Oauth2Client\AccessToken;
use WebrockSk\Oauth2Client\IdentityProviderException;

class RequestHeader implements StorageInterface {

	/**
	 * $memory
	 *
	 * @var AccessToken
	 */
	private $memory;

	/**
	 * getToken
	 *
	 * @return void
	 */
	public function getToken() {

		if(!empty($this->memory))
			return $this->memory;

		if(!function_exists('apache_request_headers'))
			return null;

		$headers = apache_request_headers();

		if(!array_key_exists('Authorization', $headers))
			return null;
		
		if(!preg_match('/^\s*Bearer\s*(([A-Za-z0-9-_=]*)\.([A-Za-z0-9-_=]*)\.([A-Za-z0-9-_+\=]+)*)$/', $headers['Authorization'], $matches))
			return null;

		return new AccessToken([
			'access_token' => $matches[1],
			'refresh_token' => null,
		]);	
	}

	/**
	 * saveToken
	 *
	 * @param AccessToken $accessToken
	 * @return void
	 */
	public function saveToken(AccessToken $accessToken) {
		$this->memory = $accessToken;
	}

	/**
	 * deleteToken
	 *
	 * @return void
	 */
	public function deleteToken() {
		$this->memory = null;
	}
}
