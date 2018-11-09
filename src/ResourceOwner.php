<?php
namespace WebrockSk\Oauth2Client;

use League\OAuth2\Client\Provider\ResourceOwnerInterface;

use DateTime;
use DateTimeZone;

class ResourceOwner implements ResourceOwnerInterface {
	private $data;

	/**
	 * __construct
	 *
	 * @param array $data
	 * @return void
	 */
	public function __construct(array $data) {
		foreach ($data as $key => $value) {
			switch ($key) {
				case 'user_id': continue;
				case 'created_at':
					$this->data['created_at'] = new DateTime($value['date'], new DateTimeZone($value['timezone']));
				break;
				default:
					$this->data[$key] = $value;
			}
		}
	}

	/**
	 * Returns the identifier of the authorized resource owner.
	 *
	 * @return mixed
	 */
	public function getId() {
		return $this->data['id'];
	}

	/**
	 * toArray
	 *
	 * @return void
	 */
	public function toArray() {
		return $this->data;
	}
}
