<?php
namespace WebrockSk\Oauth2Client\AccessToken\Storage;

use Lcobucci\JWT\Parser;

use WebrockSk\Oauth2Client\AccessToken;
use WebrockSk\Oauth2Client\IdentityProviderException;

class RequestHeader implements StorageInterface {

	/**
	 * getToken
	 *
	 * @return void
	 */
	public function getToken() {

		if(!function_exists('apache_request_headers'))
			return null;

		$headers = apache_request_headers();

		if(!array_key_exists('Authorization', $headers))
			return null;
		
		if(!preg_match('/^\s*Bearer\s*([A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+(\.[A-Za-z0-9-_.+\=]+)*)$/', $headers['Authorization'], $matches))
			return null;

		$parser = new Parser;
		$token = $parser->parse($matches[1]);

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
	public function saveToken(AccessToken $accessToken) {}

	/**
	 * deleteToken
	 *
	 * @return void
	 */
	public function deleteToken() {}
}
