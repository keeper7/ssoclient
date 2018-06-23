<?php

namespace K7\SSO;

use Nette\Caching\Cache;
use Nette\Caching\IStorage;
use Nette\Caching\Storages\FileStorage;
use Nette\Http\IRequest;
use Nette\Http\IResponse;
use Nette\Http\Session;
use Nette\Http\Url;

/**
 * Single sign-on server.
 *
 * The SSO server is responsible of managing users sessions which are available for brokers.
 *
 * To use the SSO server, extend this class and implement the abstract methods.
 * This class may be used as controller in an MVC application.
 */
abstract class Server
{
    /**
     * @var array
     */
    protected $options = [
        'files_cache_directory' => '/tmp',
        'files_cache_ttl' => 36000
    ];

    /**
     * Cache that stores the special session data for the brokers.
     *
     * @var Cache
     */
    protected $cache;
    /** @var string */
    protected $returnType;
    /** @var mixed */
    protected $brokerId;
    /** @var IStorage */
    private $storage;
    /** @var int|mixed */
    private $ttl = 36000;
    /** @var IResponse */
    private $response;
    /** @var IRequest */
    private $request;
    /** @var Session */
    private $session;

    /**
     * Class constructor
     *
     * @param array $options
     * @param IResponse $response
     * @param IRequest $request
     * @param Session $session
     */
    public function __construct(
        array $options = [],
        IResponse $response,
        IRequest $request,
        Session $session
    ) {
        $this->response = $response;
        $this->request = $request;
        $this->options = $options + $this->options;
//        $this->storage = new SQLiteStorage();
        // TODO: Cache to interface?
        $this->storage = new FileStorage($this->options['files_cache_directory']);
        $this->cache = new Cache($this->storage);
        $this->ttl = $this->options['files_cache_ttl'];
        $this->session = $session;
        $this->session->close();
    }


    /**
     * Start the session for broker requests to the SSO server
     * @throws Exception
     */
    public function startBrokerSession()
    {
        if (isset($this->brokerId)) return;

        $sid = $this->getBrokerSessionID();

        if ($sid === false) {
            $this->fail("Broker didn't send a session key", IResponse::S400_BAD_REQUEST);
            return;
        }

        $linkedId = $this->cache->load($sid);

        if (!$linkedId) {
            $this->fail("The broker session id isn't attached to a user session", IResponse::S403_FORBIDDEN);
            return;
        }

        if (session_status() === PHP_SESSION_ACTIVE) {
            if ($linkedId !== session_id()) throw new Exception("Session has already started", IResponse::S400_BAD_REQUEST);
            return;
        }

        session_id($linkedId);
        session_start();

        $this->brokerId = $this->validateBrokerSessionId($sid);
    }

    /**
     * Get session ID from header Authorization or from GET/POST
     */
    protected function getBrokerSessionID()
    {
        $authorizationHeader = $this->request->getHeader('Authorization');
        $accessTokenGetParam = $this->request->getQuery('access_token');
        $ssoSessionGetParam = $this->request->getQuery('sso_session');
        $accessTokenPostParam = $this->request->getPost('access_token');

        if ($authorizationHeader && strpos($authorizationHeader, 'Bearer') === 0) {
            $authorizationHeader = substr($authorizationHeader, 7);
            return $authorizationHeader;
        }

        if ($accessTokenGetParam) {
            return $accessTokenGetParam;
        }

        if ($ssoSessionGetParam) {
            return $ssoSessionGetParam;
        }

        if ($accessTokenPostParam) {
            return $accessTokenPostParam;
        }

        return false;
    }

    /**
     * Validate the broker session id
     *
     * @param string $sid session id
     * @return string  the broker id
     * @throws Exception
     */
    protected function validateBrokerSessionId($sid)
    {
        $matches = null;

        if (!preg_match('/^SSO-(\w*+)-(\w*+)-([a-z0-9]*+)$/', $this->getBrokerSessionID(), $matches)) {
            return $this->fail("Invalid session id");
        }

        $brokerId = $matches[1];
        $token = $matches[2];

        if ($this->generateSessionId($brokerId, $token) != $sid) {
            return $this->fail("Checksum failed: Client IP address may have changed", 403);
        }

        return $brokerId;
    }

    /**
     * Start the session when a user visits the SSO server
     */
    protected function startUserSession()
    {
        if (session_status() !== PHP_SESSION_ACTIVE) session_start();
    }

    /**
     * Generate session id from session token
     *
     * @param string $brokerId
     * @param string $token
     * @return string
     */
    protected function generateSessionId($brokerId, $token)
    {
        $broker = $this->getBrokerInfo($brokerId);

        if (!isset($broker)) return null;

        return "SSO-{$brokerId}-{$token}-" . hash('sha256', 'session' . $token . $broker['secret']);
    }

    /**
     * Generate session id from session token
     *
     * @param string $brokerId
     * @param string $token
     * @return string
     */
    protected function generateAttachChecksum($brokerId, $token)
    {
        $broker = $this->getBrokerInfo($brokerId);

        if (!isset($broker)) return null;

        return hash('sha256', 'attach' . $token . $broker['secret']);
    }


    /**
     * Detect the type for the HTTP response.
     * Should only be done for an `attach` request.
     */
    protected function detectReturnType()
    {
        $returnUrl = $this->request->getQuery('return_url');
        $callback = $this->request->getQuery('callback');
        $accept = $this->request->getHeader('Accept');

        if ($returnUrl) {
            $this->returnType = 'redirect';
        } elseif ($callback) {
            $this->returnType = 'jsonp';
        } elseif (strpos($accept, 'image/') !== false) {
            $this->returnType = 'image';
        } elseif (strpos($accept, 'application/json') !== false) {
            $this->returnType = 'json';
        }
    }

    /**
     * Attach a user session to a broker session
     * @throws Exception
     */
    public function attach()
    {
        $this->detectReturnType();

        $brokerParam = $this->request->getQuery('broker');
        $tokenParam = $this->request->getQuery('token');
        $checksumParam = $this->request->getQuery('checksum');

        if (!$brokerParam) {
            return $this->fail("No broker specified", IResponse::S400_BAD_REQUEST);
        }
        if (!$tokenParam) {
            return $this->fail("No token specified", IResponse::S400_BAD_REQUEST);
        }

        if (!$this->returnType) {
            return $this->fail("No return url specified", IResponse::S400_BAD_REQUEST);
        }

        $checksum = $this->generateAttachChecksum($brokerParam, $tokenParam);

        if (!$checksumParam || $checksum != $checksumParam) {
            return $this->fail("Invalid checksum", IResponse::S400_BAD_REQUEST);
        }

        $this->startUserSession();
        $sid = $this->generateSessionId($brokerParam, $tokenParam);

        $this->cache->save($sid, $this->getSessionData('id'), [Cache::EXPIRATION => $this->ttl]);
        $this->outputAttachSuccess();
    }

    /**
     * Output on a successful attach
     */
    protected function outputAttachSuccess()
    {
        if ($this->returnType === 'image') {
            $this->outputImage();
        }

        if ($this->returnType === 'json') {
            header('Content-type: application/json; charset=UTF-8');
            echo json_encode(['success' => 'attached']);
        }

        if ($this->returnType === 'jsonp') {
            $data = json_encode(['success' => 'attached']);
            $qCallback = $this->request->getQuery('callback');
            echo $qCallback . "($data, 200);";
        }

        if ($this->returnType === 'redirect') {
            $url = $this->request->getQuery('return_url');
            $this->response->redirect($url, IResponse::S307_TEMPORARY_REDIRECT);
        }
    }

    /**
     * Output a 1x1px transparent image
     */
    protected function outputImage()
    {
        $this->response->setContentType('image/png');
        echo base64_decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABAQ'
            . 'MAAAAl21bKAAAAA1BMVEUAAACnej3aAAAAAXRSTlMAQObYZg'
            . 'AAAApJREFUCNdjYAAAAAIAAeIhvDMAAAAASUVORK5CYII=');
    }

    /**
     * Authenticate
     *
     * @throws Exception
     */
    public function login()
    {
        $this->startBrokerSession();

        $qUsername = $this->request->getPost('username');
        $qPassword = $this->request->getPost('password');

        if (empty($qUsername)) {
            $this->fail("No username specified", IResponse::S400_BAD_REQUEST);
        }

        if (empty($qPassword)) {
            $this->fail("No password specified", IResponse::S400_BAD_REQUEST);
        }

        $validation = json_decode($this->authenticate($qUsername, $qPassword));

        if (isset($validation->errors)) {
            $this->fail($validation->errors, IResponse::S400_BAD_REQUEST);
            return;
        }

        $this->setSessionData('sso_user', $qUsername);
        $this->userInfo();
    }

    /**
     * Log out
     * @throws Exception
     */
    public function logout()
    {
        $this->startBrokerSession();
        $this->setSessionData('sso_user', null);

        $this->response->setContentType('application/json', 'UTF-8');
        $this->response->setCode(IResponse::S204_NO_CONTENT);
    }

    /**
     * Output user information as json.
     * @throws Exception
     */
    public function userInfo()
    {
        $this->startBrokerSession();
        $user = null;

        $username = $this->getSessionData('sso_user');

        if ($username) {
            $user = $this->getUserInfo($username);
            if (!$user) return $this->fail("User not found", IResponse::S500_INTERNAL_SERVER_ERROR); // Shouldn't happen
        }

        $this->response->setContentType('application/json','UTF-8');
        echo json_encode($user);
    }


    /**
     * Set session data
     *
     * @param string $key
     * @param string $value
     */
    protected function setSessionData($key, $value)
    {
        if (!isset($value)) {
            unset($_SESSION[$key]);
            return;
        }

        $_SESSION[$key] = $value;
    }

    /**
     * Get session data
     *
     * @param $key
     * @return null|string
     */
    protected function getSessionData($key)
    {
        if ($key === 'id') return session_id();

        return isset($_SESSION[$key]) ? $_SESSION[$key] : null;
    }


    /**
     * An error occured.
     *
     * @param $message
     * @param int $http_status
     * @throws Exception
     */
    protected function fail($message, $http_status = IResponse::S500_INTERNAL_SERVER_ERROR)
    {
        if (!empty($this->options['fail_exception'])) {
            throw new Exception($message, $http_status);
        }

        if ($http_status === IResponse::S500_INTERNAL_SERVER_ERROR) trigger_error($message, E_USER_WARNING);

        if ($this->returnType === 'jsonp') {
            $qCallback = $this->request->getQuery('callback');
            echo $qCallback . "(" . json_encode(['error' => $message]) . ", $http_status);";
            exit();
        }

        if ($this->returnType === 'redirect') {
            $url = new Url($this->request->getQuery('return_url'));
            $url->setQueryParameter('sso_error', $message);
            $this->response->redirect($url, IResponse::S307_TEMPORARY_REDIRECT);
            exit();
        }

        $this->response->setCode($http_status);
        $this->response->setContentType('application/json', 'UTF-8');
        echo json_encode(['error' => $message]);
        exit();
    }


    /**
     * Authenticate using user credentials
     *
     * @param string $username
     * @param string $password
     * @return array
     */
    abstract protected function authenticate($username, $password);

    /**
     * Get the secret key and other info of a broker
     *
     * @param string $brokerId
     * @return array
     */
    abstract protected function getBrokerInfo($brokerId);

    /**
     * Get the information about a user
     *
     * @param string $username
     * @return array|object
     */
    abstract protected function getUserInfo($username);
}

