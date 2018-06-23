<?php

namespace K7\SSO;

use Nette\Http\IRequest;
use Nette\Http\IResponse;

/**
 * Single sign-on broker.
 *
 * The broker lives on the website visited by the user. The broken doesn't have any user credentials stored. Instead it
 * will talk to the SSO server in name of the user, verifying credentials and getting user information.
 */
class Broker
{
    /**
     * Url of SSO server
     * @var string
     */
    protected $url;

    /**
     * My identifier, given by SSO provider.
     * @var string
     */
    public $broker;

    /**
     * My secret word, given by SSO provider.
     * @var string
     */
    protected $secret;

    /**
     * Session token of the client
     * @var string
     */
    public $token;

    /**
     * User info recieved from the server.
     * @var array
     */
    protected $userinfo;

    /**
     * Cookie lifetime
     * @var int
     */
    protected $cookieLifetime;
    /**
     * @var IRequest
     */
    private $request;
    /**
     * @var IResponse
     */
    private $response;

    /**
     * Broker constructor.
     * @param IRequest $request
     * @param IResponse $response
     * @param string $url Url of SSO server
     * @param string $broker My identifier, given by SSO provider.
     * @param string $secret My secret word, given by SSO provider.
     * @param int $cookieLifetime
     * @throws InvalidArgumentException
     */
    public function __construct(
        IRequest $request,
        IResponse $response,
        $url,
        $broker,
        $secret,
        $cookieLifetime = 3600
    ) {
        if (!$url) throw new InvalidArgumentException("SSO server URL not specified");
        if (!$broker) throw new InvalidArgumentException("SSO broker id not specified");
        if (!$secret) throw new InvalidArgumentException("SSO broker secret not specified");

        $this->request = $request;
        $this->response = $response;
        $this->url = $url;
        $this->broker = $broker;
        $this->secret = $secret;
        $this->cookieLifetime = $cookieLifetime;

        $cookieName = $this->getCookieName();
        if ($cookie = $request->getCookie($cookieName)) {
            $this->token = $cookie;
        }
    }

    /**
     * Get the cookie name.
     *
     * Note: Using the broker name in the cookie name.
     * This resolves issues when multiple brokers are on the same domain.
     *
     * @return string
     */
    protected function getCookieName()
    {
        return 'sso_token_' . preg_replace('/[_\W]+/', '_', strtolower($this->broker));
    }

    /**
     * Generate session id from session key
     *
     * @return string
     */
    protected function getSessionId()
    {
        if (!isset($this->token)) return null;

        $checksum = hash('sha256', 'session' . $this->token . $this->secret);
        return "SSO-{$this->broker}-{$this->token}-$checksum";
    }

    /**
     * Generate session token
     */
    public function generateToken()
    {
        if (isset($this->token)) return;

        $this->token = base_convert(md5(uniqid(rand(), true)), 16, 36);
        $this->response->setCookie($this->getCookieName(), $this->token, time() + $this->cookieLifetime, '/');
    }

    /**
     * Clears session token
     */
    public function clearToken()
    {
        $this->response->setCookie($this->getCookieName(), null, 1, '/');
        $this->token = null;
    }

    /**
     * Check if we have an SSO token.
     *
     * @return boolean
     */
    public function isAttached()
    {
        return isset($this->token);
    }

    /**
     * Get URL to attach session at SSO server.
     *
     * @param array $params
     * @return string
     */
    public function getAttachUrl($params = [])
    {
        $this->generateToken();

        $data = [
                'command' => 'attach',
                'broker' => $this->broker,
                'token' => $this->token,
                'checksum' => hash('sha256', 'attach' . $this->token . $this->secret)
            ] + $this->request->getQuery();

        // TODO: rebuild url nette way
        $str = $this->url . "?" . http_build_query($data + $params);
        return $str;
    }

    /**
     * Attach our session to the user's session on the SSO server.
     *
     * @param string|true $returnUrl The URL the client should be returned to after attaching
     */
    public function attach($returnUrl = null)
    {
        if ($this->isAttached()) return;

        if ($returnUrl === true) {
            $returnUrl = (string)$this->request->getUrl();
        }

        $params = ['return_url' => $returnUrl];
        $url = $this->getAttachUrl($params);

        $this->response->redirect($url, IResponse::S307_TEMPORARY_REDIRECT);
        exit();
    }

    /**
     * Get the request url for a command
     *
     * @param string $command
     * @param array $params Query parameters
     * @return string
     */
    protected function getRequestUrl($command, $params = [])
    {
        $params['command'] = $command;
        // TODO: build url nette way
        return $this->url . '?' . http_build_query($params);
    }

    /**
     * Execute on SSO server.
     *
     * @param string $method HTTP method: 'GET', 'POST', 'DELETE'
     * @param string $command Command
     * @param array|string $data Query or post parameters
     * @return array|object
     * @throws Exception
     * @throws NotAttachedException
     */
    protected function request($method, $command, $data = null)
    {
        if (!$this->isAttached()) {
            throw new NotAttachedException('No token');
        }
        $url = $this->getRequestUrl($command, !$data || $method === 'POST' ? [] : $data);

        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);
        $sessionID = $this->getSessionID();
        curl_setopt($ch, CURLOPT_HTTPHEADER, ['Accept: application/json', 'Authorization: Bearer ' . $sessionID]);

        if ($method === 'POST' && !empty($data)) {
            $post = is_string($data) ? $data : http_build_query($data);
            curl_setopt($ch, CURLOPT_POSTFIELDS, $post);
        }

        $response = curl_exec($ch);
        if (curl_errno($ch) != 0) {
            $message = 'Server request failed: ' . curl_error($ch);
            throw new Exception($message);
        }

        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        list($contentType) = explode(';', curl_getinfo($ch, CURLINFO_CONTENT_TYPE));

        if ($contentType != 'application/json') {
            $message = 'Expected application/json response, got ' . $contentType;
            throw new Exception($message);
        }

        $data = json_decode($response, true);
        if ($httpCode == IResponse::S403_FORBIDDEN) {
            $this->clearToken();
            throw new NotAttachedException($data['error'] ?: $response, $httpCode);
        }
        if ($httpCode >= IResponse::S400_BAD_REQUEST) throw new Exception($data['error'] ?: $response, $httpCode);

        return $data;
    }


    /**
     * Log the client in at the SSO server.
     *
     * Only brokers marked trusted can collect and send the user's credentials. Other brokers should omit $username and
     * $password.
     *
     * @param string $username
     * @param string $password
     * @return array  user info
     * @throws Exception if login fails eg due to incorrect credentials
     */
    public function login($username = null, $password = null)
    {
        $qUsername = $this->request->getPost('username');
        $qPassword = $this->request->getPost('password');

        if (!isset($username) && isset($qUsername)) {
            $username = $qUsername;
        }

        if (!isset($password) && isset($qPassword)) {
            $password = $qPassword;
        }

        $result = $this->request('POST', 'login', compact('username', 'password'));
        $this->userinfo = $result;

        return $this->userinfo;
    }

    /**
     * Logout at sso server.
     * @throws Exception
     * @throws NotAttachedException
     */
    public function logout()
    {
        $this->request('POST', 'logout', 'logout');
    }

    /**
     * Get user information.
     *
     * @return object|null
     * @throws Exception
     * @throws NotAttachedException
     */
    public function getUserInfo()
    {
        if (!isset($this->userinfo)) {
            $this->userinfo = $this->request('GET', 'userInfo');
        }

        return $this->userinfo;
    }

    /**
     * Magic method to do arbitrary request
     *
     * @param string $fn
     * @param array $args
     * @return mixed
     * @throws Exception
     * @throws NotAttachedException
     */
    public function __call($fn, $args)
    {
        $sentence = strtolower(preg_replace('/([a-z0-9])([A-Z])/', '$1 $2', $fn));
        $parts = explode(' ', $sentence);

        $method = count($parts) > 1 && in_array(strtoupper($parts[0]), ['GET', 'DELETE'])
            ? strtoupper(array_shift($parts))
            : 'POST';
        $command = join('-', $parts);

        return $this->request($method, $command, $args);
    }
}
