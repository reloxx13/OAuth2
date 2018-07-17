<?php

namespace Muffin\OAuth2\Auth;

use Cake\Auth\BaseAuthenticate;
use Cake\Controller\ComponentRegistry;
use Cake\Core\Configure;
use Cake\Event\EventDispatcherTrait;
use Cake\Network\Request;
use Cake\Network\Response;
use Cake\Utility\Hash;
use Composer\Config;
use Exception;
use League\OAuth2\Client\Provider\AbstractProvider;
use Muffin\OAuth2\Auth\Exception\InvalidProviderException;
use Muffin\OAuth2\Auth\Exception\InvalidSettingsException;
use Muffin\OAuth2\Auth\Exception\MissingEventListenerException;
use Muffin\OAuth2\Auth\Exception\MissingProviderConfigurationException;
use RuntimeException;

class OAuthAuthenticate extends BaseAuthenticate
{
	
	use EventDispatcherTrait;
	
	/**
	 * Instance of OAuth2 provider.
	 *
	 * @var \League\OAuth2\Client\Provider\AbstractProvider
	 */
	protected $_provider;
	
	/**
	 * Constructor
	 *
	 * @param \Cake\Controller\ComponentRegistry $registry The Component registry used on this request.
	 * @param array                              $config   Array of config to use.
	 *
	 * @throws \Exception
	 */
	public function __construct(ComponentRegistry $registry, array $config = [])
	{
		$config = $this->normalizeConfig($config);
		parent::__construct($registry, $config);
	}
	
	/**
	 * Normalizes providers' configuration.
	 *
	 * @param array $config Array of config to normalize.
	 *
	 * @return array
	 * @throws \Exception
	 */
	public function normalizeConfig(array $config)
	{
		$config = Hash::merge((array)Configure::read('Muffin/OAuth2'), $config);
		
		if (empty($config['providers']))
		{
			throw new MissingProviderConfigurationException();
		}
		
		array_walk($config['providers'], [$this, '_normalizeConfig'], $config);
		
		return $config;
	}
	
	/**
	 * Callback to loop through config values.
	 *
	 * @param array  $config Configuration.
	 * @param string $alias  Provider's alias (key) in configuration.
	 * @param array  $parent Parent configuration.
	 *
	 * @return void
	 */
	protected function _normalizeConfig(&$config, $alias, $parent)
	{
		unset($parent['providers']);
		
		$defaults = [
				'className'     => NULL,
				'options'       => [],
				'collaborators' => [],
				'mapFields'     => [],
			] + $parent + $this->_defaultConfig;
		
		$config = array_intersect_key($config, $defaults);
		$config += $defaults;
		
		array_walk($config, [$this, '_validateConfig']);
		
		foreach (['options', 'collaborators'] as $key)
		{
			if (empty($parent[$key]) || empty($config[$key]))
			{
				continue;
			}
			
			$config[$key] = array_merge($parent[$key], $config[$key]);
		}
	}
	
	/**
	 * Validates the configuration.
	 *
	 * @param mixed  $value Value.
	 * @param string $key   Key.
	 *
	 * @return void
	 * @throws \Muffin\OAuth2\Auth\Exception\InvalidProviderException
	 * @throws \Muffin\OAuth2\Auth\Exception\InvalidSettingsException
	 */
	protected function _validateConfig(&$value, $key)
	{
		if ($key === 'className' && !class_exists($value))
		{
			throw new InvalidProviderException([$value]);
		} elseif (!is_array($value) && in_array($key, ['options', 'collaborators']))
		{
			throw new InvalidSettingsException([$key]);
		}
	}
	
	/**
	 * Get a user based on information in the request.
	 *
	 * @param \Cake\Network\Request  $request  Request object.
	 * @param \Cake\Network\Response $response Response object.
	 *
	 * @return bool
	 * @throws \RuntimeException If the `Muffin/OAuth2.newUser` event is missing or returns empty.
	 */
	public function authenticate(Request $request, Response $response)
	{
		return $this->getUser($request);
	}
	
	/**
	 * Get a user based on information in the request.
	 *
	 * @param \Cake\Network\Request $request Request object.
	 *
	 * @return mixed Either false or an array of user information
	 * @throws \RuntimeException If the `Muffin/OAuth2.newUser` event is missing or returns empty.
	 */
	public function getUser(Request $request)
	{
		if (!$rawData = $this->_authenticate($request))
		{
			return FALSE;
		}
		//
		//		$user = $this->_map($rawData);
		//
		//		if (!$user || !$this->config('userModel'))
		//		{
		//			return FALSE;
		//		}
		//
		//				if (!$result = $this->_touch($user))
		//				{
		//					return FALSE;
		//				}
		
		
		$result = $rawData;
		
		$args = [$this->_provider, $result];
		$this->dispatchEvent('Muffin/OAuth2.afterIdentify', $args);
		
		return $result;
	}
	
	/**
	 * Authenticates with OAuth2 provider by getting an access token and
	 * retrieving the authorized user's profile data.
	 *
	 * @param \Cake\Network\Request $request Request object.
	 *
	 * @return array|bool
	 */
	protected function _authenticate(Request $request)
	{
		if (!$this->_validate($request))
		{
			return FALSE;
		}
		
		$provider = $this->provider($request);
		
		$grant = "authorization_code";
		$options = array();
		
		switch ($this->getConfig('options.grant'))
		{
			case "client_credentials":
				$grant = "client_credentials";
				if (!empty($request->getData("username")))
				{
					$options = [
						"username" => $request->getData('username'),
						"password" => $request->getData('password'),
						"format"   => "json",
					];
				} else
				{
					$options = [
						"username" => $request->param('username'),
						"password" => $request->param('password'),
					];
				}
				
				
				break;
			
			default:
				
				$options = [
					"code" => $request->query('code'),
				];
				break;
		}
		
		$result = FALSE;
		
		$options["headers"] = array('Accept' => 'application/json',);
		
		try
		{
			$token = $provider->getAccessToken($grant, $options);
			//			$token["body"]["access_token"] = $token->getToken();
			
			
			$token = json_decode(json_encode($token), TRUE);
			
			//			$t = array(
			//				"access_token" => $token->getToken(),
			//				"softwareid"   => Configure::read("OAUTH.SOFTWARE"),
			//			);
			//			$params["body"] = http_build_query($t, NULL, '&');
			//			$params["headers"] = [
			//				'content-type' => 'application/x-www-form-urlencoded',
			//			];
			
			//			$request = $provider->getRequest(
			//				"POST",
			//				$this->getConfig('options.urlResourceOwnerDetails'),
			//				$params
			//			);
			
			//			$response = $provider->getResponse($request);
			
			//			$DATA["userData"] = $response;
			//
			//
			//			$params["body"] .= '&' . http_build_query(array("uid" => $DATA["userData"]["uid"]), NULL, '&');
			//
			//			$request = $provider->getRequest(
			//				"POST",
			//				$this->getConfig('options.urlGetRoleData'),
			//				$params
			//			);
			//
			//			$response = $provider->getResponse($request);
			//			$response = array_shift($response)["softwarerights"][$this->getConfig('options.softwareID')];
			//			$DATA["roleData"] = $response;
			
		} catch (Exception $e)
		{
			// Silently catch exceptions
		}
		
		return $token;
	}
	
	/**
	 * Finds or creates a local user.
	 *
	 * @param array $data Mapped user data.
	 *
	 * @return array
	 * @throws \Muffin\OAuth2\Auth\Exception\MissingEventListenerException
	 */
	protected function _touch(array $data)
	{
		if ($result = $this->_findUser($data[$this->config('fields.username')]))
		{
			return array_merge($data, $result);
		}
		
		$event = 'Muffin/OAuth2.newUser';
		$args = [$this->_provider, $data];
		$event = $this->dispatchEvent($event, $args);
		if (empty($event->result))
		{
			throw new MissingEventListenerException([$event]);
		}
		
		return $event->result;
	}
	
	/**
	 * Validates OAuth2 request.
	 *
	 * @param \Cake\Network\Request $request Request object.
	 *
	 * @return bool
	 */
	protected function _validate(Request $request)
	{
		if (!$this->provider($request))
		{
			return FALSE;
		}
		$session = $request->session();
		$sessionKey = 'oauth2state';
		$state = $request->query('state');
		
		$result = TRUE;
		if ($this->config('options.state') &&
			(!$state || $state !== $session->read($sessionKey)))
		{
			$session->delete($sessionKey);
			$result = FALSE;
		}
		
		return $result;
	}
	
	/**
	 * Maps raw provider's user profile data to local user's data schema.
	 *
	 * @param array $data Raw user data.
	 *
	 * @return array
	 */
	protected function _map($data)
	{
		if (!$map = $this->config('mapFields'))
		{
			return $data;
		}
		
		foreach ($map as $dst => $src)
		{
			$data[$dst] = Hash::get($data, $src);
			$data = Hash::remove($data, $src);
		}
		
		return $data;
	}
	
	/**
	 * Handles unauthenticated access attempts. Will automatically forward to the
	 * requested provider's authorization URL to let the user grant access to the
	 * application.
	 *
	 * @param \Cake\Network\Request  $request  Request object.
	 * @param \Cake\Network\Response $response Response object.
	 *
	 * @return \Cake\Network\Response|null
	 */
	public function unauthenticated(Request $request, Response $response)
	{
		$provider = $this->provider($request);
		if (empty($provider) || !empty($request->query['code']))
		{
			return NULL;
		}
		
		if ($this->config('options.state'))
		{
			$request->session()->write('oauth2state', $provider->getState());
		}
		
		$response->location($provider->getAuthorizationUrl($this->_queryParams()));
		
		return $response;
	}
	
	/**
	 * Returns the `$request`-ed provider.
	 *
	 * @param \Cake\Network\Request $request Current HTTP request.
	 *
	 * @return \League\Oauth2\Client\Provider\GenericProvider|false
	 */
	public function provider(Request $request)
	{
		//Check post and get
		if (!empty($request->getData("provider")))
		{
			$alias = $request->getData('provider');
		} else
		{
			$alias = $request->param('provider');
		}
		
		if (!$alias)
		{
			return FALSE;
		}
		
		if (empty($this->_provider))
		{
			$this->_provider = $this->_getProvider($alias);
		}
		
		return $this->_provider;
	}
	
	/**
	 * Instantiates provider object.
	 *
	 * @param string $alias of the provider.
	 *
	 * @return \League\Oauth2\Client\Provider\GenericProvider
	 */
	protected function _getProvider($alias)
	{
		if (!$config = $this->config('providers.' . $alias))
		{
			return FALSE;
		}
		
		$this->config($config);
		
		if (is_object($config) && $config instanceof AbstractProvider)
		{
			return $config;
		}
		
		$class = $config['className'];
		
		return new $class($config['options'], $config['collaborators']);
	}
	
	/**
	 * Pass only the custom query params.
	 *
	 * @return array
	 */
	protected function _queryParams()
	{
		$queryParams = $this->config('options');
		
		unset(
			$queryParams['clientId'],
			$queryParams['clientSecret'],
			$queryParams['redirectUri']
		);
		
		return $queryParams;
	}
}
