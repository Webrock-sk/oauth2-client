<?php
namespace WebrockSk\Oauth2Client\AccessToken\Storage;

use WebrockSk\Oauth2Client\AccessToken;

interface StorageInterface {

	/**
	 * getToken
	 *
	 * @return void
	 */
	public function getToken();

	/**
	 * saveToken
	 *
	 * @param AccessToken $accessToken
	 * @return void
	 */
	public function saveToken(AccessToken $accessToken);

	/**
	 * deleteToken
	 *
	 * @return void
	 */
	public function deleteToken();
}
