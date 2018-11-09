<?php
namespace WebrockSk\Oauth2Client;

use GuzzleHttp\Client as GuzzleClient;

use WebrockSk\Oauth2Client\Client as Oauth2Client;

use Exception;

class Connector extends HttpService {

	/**
	 * $oauth2Client
	 *
	 * @var Oauth2Client
	 */
	protected $oauth2client;


	/**
	 * $config
	 *
	 * @var array
	 */
	protected $config;

	/**
	 * __construct
	 *
	 * @param mixed array
	 * @return void
	 */
	public function __construct(Oauth2Client $oauth2client, $config = []) {
		$this->oauth2client = $oauth2client;
		$this->config = $config;
	}

	/**
	 * getHttpClient
	 *
	 * @return GuzzleClient
	 */
	public function getHttpClient() {
		$token = $this->oauth2client->getAccessToken();

		return new GuzzleClient([
			'base_uri' => trim($this->oauth2client->getServer(), '/').'/api/',
			'timeout'  => 30,
			'headers' => [
				'Agent' => $_SERVER['HTTP_USER_AGENT'],
				'Content-Type' => 'application/json',
				'Authorization' => $token ? 'Bearer '.$token->getToken() : '',
			],
			'proxy' => isset($this->config['proxy']) ? $this->config['proxy'] : null,
		]);
	}

	/**
	 * usersWhoAmI
	 *
	 * @return void
	 */
	public function usersWhoAmI() {
		return $this->get('users/whoAmI');
	}

	/**
	 * usersLoad
	 *
	 * @param mixed $uuid
	 * @param mixed $query
	 * @return void
	 */
	public function usersLoad($uuid = null, $query = []) {
		return $this->get('users'.($uuid ? "/$uuid" : ''), $query);
	}

	/**
	 * usersCreate
	 *
	 * @param mixed $params
	 * @return void
	 */
	public function usersCreate($params = []) {
		return $this->post('users', $params);
	}

	/**
	 * usersSave
	 *
	 * @param mixed $uuid
	 * @param mixed $params
	 * @return void
	 */
	public function usersSave($uuid = null, $params = []) {
		return $this->put('users'.($uuid ? "/$uuid" : ''), $params);
	}

	/**
	 * usersDelete
	 *
	 * @param mixed $uuid
	 * @return void
	 */
	public function usersDelete($uuid) {
		return $this->delete("users/{$uuid}");
	}

	/**
	 * passwordRecoveryRequest
	 *
	 * @param string $password
	 * @return void
	 */
	public function passwordRecoveryRequest($email) {
		return $this->post('user/password-recovery/request', [
			'email' => $email,
		]);
	}

	/**
	 * passwordRecoveryVerifyToken
	 *
	 * @param string $token
	 * @return void
	 */
	public function passwordRecoveryVerifyToken($token) {
		return $this->post('user/password-recovery/validate-token', [
			'token' => $token,
		]);
	}

	/**
	 * passwordRecoveryChangePassword
	 *
	 * @param mixed $password
	 * @param mixed $token
	 * @return void
	 */
	public function passwordRecoveryChangePassword($password, $token) {
		return $this->post('user/password-recovery/change-password', [
			'password' => $password,
			'token' => $token,
		]);
	}
}
