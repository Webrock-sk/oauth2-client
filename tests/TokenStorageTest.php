<?php
declare(strict_types=1);
namespace WebrockSk\Oauth2Client\Tests;

use PHPUnit\Framework\TestCase;

use WebrockSk\Oauth2Client\AccessToken\Storage;
use WebrockSk\Oauth2Client\AccessToken;

final class TokenStorageTest extends TestCase {

	public function testFileSaveAndLoad(): void {

		$file = 'tests/oauth_token.json';

		$storage = new Storage\File($file);

		$token = new AccessToken([
			'access_token' => 'trololo',
			'refresh_token' => 'trololo',
			'scope' => null,
			'expires' => time(),
		]);

		$storage->saveToken($token);

		$token = $storage->getToken();

		$this->assertTrue($token instanceof AccessToken);

		unlink($file);
	}
}
