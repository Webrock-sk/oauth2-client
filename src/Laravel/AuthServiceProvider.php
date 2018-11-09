<?php
namespace WebrockSk\Oauth2Client\Laravel;

use Illuminate\Support\ServiceProvider;

use WebrockSk\Oauth2Client\Client;

use EntityManager;

class AuthServiceProvider extends ServiceProvider {

	/**
	 * Bootstrap services.
	 *
	 * @return void
	 */
	public function boot() {
	}

	/**
	 * Register services.
	 *
	 * @return void
	 */
	public function register() {

		//Register OauthClient singleton
		$this->app->singleton(Client::class, function ($app) {
			return new Client([
				'server'		=> env('OAUTH_CLIENT_SERVER'),
				'clientId'		=> env('OAUTH_CLIENT_UUID'),
				'clientSecret'  => env('OAUTH_CLIENT_SECRET'),
				'redirectUri'	=> env('OAUTH_CLIENT_REDIRECT_URL'),
				'proxy'			=> env('OAUTH_CLIENT_ENABLE_PROXY') ? env('OAUTH_CLIENT_PROXY_IP') : null,
			]);
		});
	}
}
