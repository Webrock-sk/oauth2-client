<?php
namespace WebrockSk\Oauth2Client;

use League\OAuth2\Client\Token\AccessToken as LeagueAccessToken;

use Lcobucci\JWT\Token;
use Lcobucci\JWT\ValidationData;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key;

use WebrockSk\Oauth2Client\IdentityProviderException;

class AccessToken extends LeagueAccessToken {

	static $tokenAlgs = [
		'HS256' => Signer\Hmac\Sha256::class,
		'HS384' => Signer\Hmac\Sha384::class,
		'HS512' => Signer\Hmac\Sha512::class,
		'RS256' => Signer\Rsa\Sha256::class,
		'RS384' => Signer\Rsa\Sha384::class,
		'RS512' => Signer\Rsa\Sha512::class
	];

	/**
	 * $jwt
	 *
	 * @var string
	 */
	private $jwt;

	/**
	 * $headers
	 *
	 * @var array
	 */
	private $headers;

	/**
	 * $claims
	 *
	 * @var array
	 */
	private $claims;

	/**
	 * $refresh_token
	 *
	 * @var string
	 */
	private $refresh_token;

	public function __construct(array $options = []) {

		$parser = new Parser;
		$parsedToken = $parser->parse((string) $options['access_token']);

		if(!$parsedToken)
			throw new IdentityProviderException('token_cannot_parse');

		$this->headers = $parsedToken->getHeaders();

		if(!array_key_exists($this->headers['alg'], self::$tokenAlgs)) {
			$supported = implode(' ', array_keys(self::$tokenAlgs));
			throw new IdentityProviderException("Token algorithm {$this->headers['alg']} not supported. Supported algs: ".$supported);
		}

		$this->claims = array_map(function($item){
			return $item->getValue();
		}, $parsedToken->getClaims());

		$this->jwt = $options['access_token'];
		$this->refresh_token = @$options['refresh_token'];

		unset($this->accessToken);
		unset($this->expires);
		unset($this->refreshToken);
		unset($this->resourceOwnerId);
		unset($this->values);
	}

	/**
	 * getHeaders
	 *
	 * @return array
	 */
	public function getHeaders() {
		return $this->headers;
	}

	/**
	 * getHeaders
	 *
	 * @return array
	 */
	public function getClaims() {
		return $this->claims;
	}

	/**
	 * Returns the access token string of this instance.
	 *
	 * @return string
	 */
	public function getToken() {
		return $this->jwt;
	}

	/**
	 * Returns the expiration timestamp, if defined.
	 *
	 * @return integer|null
	 */
	public function getExpires() {
		return $this->getClaims()['exp'];
	}

	/**
	 * Returns the resource owner identifier, if defined.
	 *
	 * @return string|null
	 */
	public function getResourceOwnerId() {
		return $this->getClaims()['sub'];
	}

	/**
	 * Returns the refresh token, if defined.
	 *
	 * @return string|null
	 */
	public function getRefreshToken() {
		return $this->refresh_token;
	}

	/**
	 * getScope
	 *
	 * @return void
	 */
	public function getScope() {
		return $this->getClaims()['scope'];
	}

	/**
	 * getScope
	 *
	 * @return void
	 */
	public function getScopeArray() {
		return explode(' ', $this->getScope());
	}

	/**
	 * Checks if this token has expired.
	 *
	 * @return boolean true if the token has expired, false otherwise.
	 * @throws RuntimeException if 'expires' is not set on the token.
	 */
	public function hasExpired() {

		$expires = $this->getExpires();

		if (empty($expires)) {
			throw new IdentityProviderException('"expires" is not set on the token');
		}

		return $expires < time();
	}

	/**
	 * validate
	 *
	 * @param mixed $public_key
	 * @param mixed $passphrase
	 * @return void
	 */
	public function validate($public_key, $passphrase = null) {

		$data = new ValidationData();

		$data->setId($this->claims['id']);
		$data->setIssuer($this->claims['iss']);
		$data->setAudience($this->claims['aud']);
		$data->setSubject($this->claims['sub']);

		$parser = new Parser;
		$parsedToken = $parser->parse($this->jwt);

		if(!$parsedToken->validate($data))
			throw new IdentityProviderException('token_data_invalid');

		$signer = new self::$tokenAlgs[$this->headers['alg']];

		if(!$parsedToken->verify($signer, new Key($public_key, $passphrase)))
			throw new IdentityProviderException('token_signature_invalid');

		return true;
	}

	/**
	 * Returns the token key.
	 *
	 * @return string
	 */
	public function __toString() {
		return (string) $this->getToken();
	}

	/**
	 * Returns an array of parameters to serialize when this is serialized with
	 * json_encode().
	 *
	 * @return array
	 */
	public function jsonSerialize() {
		return [
			'access_token' 		=> $this->getToken(),
			'refresh_token' 	=> $this->getRefreshToken(),
			'expires' 			=> $this->getExpires(),
			'resource_owner_id' => $this->getResourceOwnerId()
		];
	}

	/**
	 * fromLeague
	 *
	 * @param LeagueAccessToken $accessToken
	 * @return void
	 */
	public static function fromLeague(LeagueAccessToken $accessToken) {

		$values = $accessToken->getValues();

		$instance = new self([
			'access_token' => $accessToken->accessToken,
			'refresh_token' => $accessToken->refreshToken,
		]);

		return $instance;
	}
}
