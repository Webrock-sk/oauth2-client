<?php
namespace WebrockSk\Oauth2Client;

use League\OAuth2\Client\Provider\Exception\IdentityProviderException as LeagueIdentityProviderException;

class IdentityProviderException extends LeagueIdentityProviderException {

	public function __construct($message = null, $code = null, $response = null) {
		parent::__construct($message, $code, $response);
 	}

	public static function fromLeague(LeagueIdentityProviderException $e) {
		return new self($e->getMessage(), $e->getCode(), $e->getResponseBody());
	}
}
