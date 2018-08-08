<?php
namespace WebrockSk\Oauth2Client\AccessToken\Storage;

use League\OAuth2\Client\Token\AccessToken;

class File implements StorageInterface {

	private $path;

	/**
	 * __construct
	 *
	 * @param mixed $path
	 * @return void
	 */
	public function __construct($path) {
		$this->path = $path;
	}

	/**
	 * getToken
	 *
	 * @return void
	 */
	public function getToken() {

		if(!file_exists($this->path))
			return null;

		$token = json_decode(file_get_contents($this->path), true);

		if(!$token)
			return null;

		

		return new AccessToken([
			'access_token' => $token['access_token'],
			'refresh_token' => @$token['refresh_token'],
			'scope' => @$token['scope'],
			'expires' => $token['expires'],
		]);
	}

	/**
	 * saveToken
	 *
	 * @param AccessToken $accessToken
	 * @return void
	 */
	public function saveToken(AccessToken $accessToken) {
		$file = fopen($this->path, 'w');
		fwrite($file, json_encode($accessToken->jsonSerialize()));
	}

	/**
	 * deleteToken
	 *
	 * @return void
	 */
	public function deleteToken() {
		if(file_exists($this->path))
			unlink($this->path);
	}
}
