<?php
namespace WebrockSk\Oauth2Client;

use League\OAuth2\Client\Token\AccessToken;

use Lcobucci\JWT\Parser;

use Exception;

class Token {

	const COOKIE_KEY = 'token';

	/**
	 * setAccessToken
	 *
	 * @param AccessToken $token
	 * @return void
	 */
	public static function setCookie(AccessToken $token) {
		if(class_exists(\Cookie::class))
			\Cookie::queue(self::COOKIE_KEY, json_encode($token->jsonSerialize()), 604800, '/');
		else
			setcookie(self::COOKIE_KEY, json_encode($token->jsonSerialize()), time()+604800, '/');
	}

	/**
	 * clearAccessToken
	 *
	 * @return void
	 */
	public static function clearCookie() {
		if(class_exists(\Cookie::class))
			\Cookie::queue(\Cookie::forget(self::COOKIE_KEY));
		else {
			setcookie(self::COOKIE_KEY, null, -1, '/');
			unset($_COOKIE[self::COOKIE_KEY]);
		}
	}

	/**
	 * fromCookie
	 *
	 * @return AccessToken
	 */
	public static function fromCookie() {

		if(class_exists(\Cookie::class))
			$rawToken = \Cookie::get(self::COOKIE_KEY);
		else
			$rawToken = $_COOKIE[self::COOKIE_KEY];

		if(!$rawToken)
			return null;

		$token = json_decode($rawToken);

		if(!$token)
			return null;

		$jwt = (new Parser())->parse((string) $token);
		$claims = (object) $jwt->getClaims();

		return new AccessToken([
			'access_token' => $token->access_token,
			'refresh_token' => $token->refresh_token,
			'scope' => $claims->scope->getValue(),
			'expires' => $claims->exp->getValue(),
			'resource_owner_id' => $claims->sub->getValue(),
		]);
	}

	/**
	 * fromHeader
	 *
	 * @return void
	 */
	public static function fromHeader() {

		$token = self::extractFromHeader();

		if(!$token)
			return null;

		$jwt = (new Parser())->parse((string) $token);
		$claims = (object) $jwt->getClaims();

		return new AccessToken([
			'access_token' => $token,
			'refresh_token' => null,
			'scope' => $claims->scope->getValue(),
			'expires' => $claims->exp->getValue(),
			'resource_owner_id' => $claims->sub->getValue(),
		]);	
	}

	/**
	 * fromHeader
	 *
	 * @return void
	 */
	public static function extractFromHeader() {

		$headers = apache_request_headers();

		if(!array_key_exists('Authorization', $headers))
			return null;

		return preg_replace('/\s*Bearer\s*/', '', $headers['Authorization']);
	}
}