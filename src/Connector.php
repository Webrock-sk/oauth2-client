<?php
namespace WebrockSk\Oauth2Client;

use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\Exception\ClientException;

use WebrockSk\Oauth2Client\Client as Oauth2Client;

use Exception;

class Connector {

	/**
	 * $oauth2Client
	 *
	 * @var Oauth2Client
	 */
	private $oauth2client;

	/**
	 * $httpClient
	 *
	 * @var GuzzleClient
	 */
	private $httpClient;

	/**
	 * __construct
	 *
	 * @param mixed array
	 * @return void
	 */
	public function __construct(Oauth2Client $oauth2client, $config = []) {

		$this->oauth2client = $oauth2client;

		$token = $oauth2client->getAccessToken();

		$config = array_merge([
			'base_uri' => trim($oauth2client->getServer(), '/').'/api/',
			'timeout'  => 30,
			'headers' => [
				'Content-Type' => 'application/json',
				'Authorization' => $token ? 'Bearer '.$token->getToken() : '',
			],
			'proxy' => isset($config['proxy']) ? $config['proxy'] : null
		], $config);

		$this->httpClient = new GuzzleClient($config);
	}

	/**
	 * get
	 *
	 * @param mixed $url
	 * @param array array
	 * @return mixed
	 */
	private function get($url, array $query = []) {

		$response = $this->httpClient->request('GET', $url, [
			'query' => $query
		]);

		return $this->parseResponse((string) $response->getBody());
	}

	/**
	 * post
	 *
	 * @param mixed $url
	 * @param array array
	 * @return mixed
	 */
	private function post($url, array $params = []) {

		$response = $this->httpClient->request('POST', $url, [
			'json' => $params
		]);

		return $this->parseResponse((string) $response->getBody());
	}

	/**
	 * put
	 *
	 * @param mixed $url
	 * @param array array
	 * @return mixed
	 */
	public function put($url, array $params = []) {

		$response = $this->httpClient->request('PUT', $url, [
			'json' => $params
		]);

		return $this->parseResponse((string) $response->getBody());
	}

	/**
	 * delete
	 *
	 * @param mixed $url
	 * @param array array
	 * @return mixed
	 */
	private function delete($url, array $params = []) {

		$response = $this->httpClient->request('DELETE', $url, [
			'json' => $params
		]);

		return $this->parseResponse((string) $response->getBody());
	}

	/**
	 * parseResponse
	 *
	 * @param string $jsonContent
	 * @return void
	 */
	private function parseResponse($jsonContent) {

		$content = json_decode($jsonContent, JSON_FORCE_OBJECT);

		if(json_last_error() !== JSON_ERROR_NONE)
			return $jsonContent;

		return $content;
	}

	/**
	 * getResponseFromE
	 *
	 * @param mixed $e
	 * @return void
	 */
	public function getResponseFromE($e) {

		if(method_exists($e, 'getResponse'))
			$jsonContent = $e->getResponse()->getBody()->getContents();
		else
			return $e->getMessage();

		$content = json_decode($jsonContent, true);

		if(json_last_error() !== JSON_ERROR_NONE)
			return $jsonContent;

		return $content;
	}

	/**
	 * whoIs
	 *
	 * @param string $uuid
	 * @return void
	 */
	public function loadUser($uuid) {
		return $this->get("user/{$uuid}");
	}

	/**
	 * updateUser
	 *
	 * @param mixed $params
	 */
	public function createUser($params = []) {
		return $this->post('user', $params);
	}

	/**
	 * updateUser
	 *
	 * @param mixed $uuid
	 * @param mixed $params
	 * @return void
	 */
	public function updateUser($uuid, $params = []) {
		return $this->put("user/{$uuid}", $params);
	}

	/**
	 * updateUser
	 *
	 * @param mixed $params
	 */
	public function removeUser($uuid) {
		return $this->delete("user/{$uuid}");
	}

	/**
	 * passwordRecoveryRequest
	 *
	 * @param string $password
	 * @return void
	 */
	public function passwordRecoveryRequest($email) {
		return $this->post('user/password-recovery/request', [
			'email' => $email
		]);
	}

	/**
	 * verifyToken
	 *
	 * @param string $token
	 * @return void
	 */
	public function verifyPasswordRecoveryToken($token) {
		return $this->post('user/password-recovery/validate-token', [
			'token' => $token
		]);
	}

	/**
	 * changePassword
	 *
	 * @param mixed $token
	 * @param mixed $password
	 * @return void
	 */
	public function changePassword($token, $password) {
		return $this->post('user/password-recovery/change-password', [
			'token' => $token,
			'password' => $password
		]);
	}
}