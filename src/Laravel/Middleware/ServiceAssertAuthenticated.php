<?php
namespace WebrockSk\PanzerAuthClient\Laravel\Middleware;

use WebrockSk\PanzerAuthClient\Client;

use App;
use Closure;
use Exception;

class ServiceAssertAuthenticated {
	
	/**
	 * Handle an incoming request.
	 *
	 * @param  \Illuminate\Http\Request  $request
	 * @param  \Closure  $next
	 * @return mixed
	 */
	public function handle($request, Closure $next) {
		
		$oauthClient = App::make(Client::class);

		if(!$oauthClient->hasValidAccessToken(true))
			return response()->json('Forbidden', 403);

		try {
			$result = $oauthClient->getResourceOwner();
		} catch(Exception $e) {
			return response()->json('Forbidden', 403);
		}
		
		return $next($request);
	}
}
