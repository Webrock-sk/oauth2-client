<?php
namespace WebrockSk\Oauth2Client;

use GuzzleHttp\Client as GuzzleClient;

use Exception;

abstract class HttpService {

	//Needs to be defined and return GuzzleHttp\Client
	abstract protected function getHttpClient();

	/**
	 * get
	 *
	 * @param mixed $url
	 * @param array array
	 * @return mixed
	 */
	protected function get($url, array $query = []) {
		$response = $this->getHttpClient()->request('GET', $url, [
			'query' => $query,
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
	protected function post($url, array $params = []) {
		$response = $this->getHttpClient()->request('POST', $url, [
			'json' => $params,
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
		$response = $this->getHttpClient()->request('PUT', $url, [
			'json' => $params,
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
	protected function delete($url, array $params = []) {
		$response = $this->getHttpClient()->request('DELETE', $url, [
			'json' => $params,
		]);

		return $this->parseResponse((string) $response->getBody());
	}

	/**
	 * parseResponse
	 *
	 * @param string $jsonContent
	 * @return void
	 */
	protected function parseResponse($jsonContent) {
		$content = json_decode($jsonContent, JSON_FORCE_OBJECT);

		if (json_last_error() !== JSON_ERROR_NONE) {
			return $jsonContent;
		}

		return $content;
	}

	/**
	 * getResponseFromE
	 *
	 * @param mixed $e
	 * @return void
	 */
	public function getResponseFromE($e) {
		if (method_exists($e, 'getResponse')) {
			$jsonContent = $e->getResponse()->getBody()->getContents();
		} else {
			return $e->getMessage();
		}

		$content = json_decode($jsonContent, true);

		if (json_last_error() !== JSON_ERROR_NONE) {
			return $jsonContent;
		}

		return $content;
	}
}
