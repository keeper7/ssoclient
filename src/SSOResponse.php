<?php

namespace K7\SSO;


use Nette\Utils\Json;
use Nette\Utils\JsonException;

class SSOResponse
{


    /** @var array */
    private $data;

    /** @var string */
    private $error;

    /** @var string */
    private $success;

    public function __construct($data = null, $error = null, $success = null)
    {
        if ($data) {
            $this->data = $data;
        }
        $this->error = $error;
        $this->setSuccess($success);
    }

    /**
     * @return bool
     */
    public function hasError()
    {
        return isset($this->error);
    }

    /**
     * @return string
     */
    public function getError()
    {
        return $this->error;
    }

    /**
     * @param mixed $data
     */
    public function setData($data)
    {
        if (!$data) {
            $this->data = [];
        }

        $this->data[] = $data;
    }

    /**
     * @return array
     */
    public function getData()
    {
        return $this->data;
    }

    /**
     * @return string
     */
    public function getSuccess()
    {
        return $this->success;
    }

    /**
     * @param string $success
     */
    public function setSuccess($success)
    {
        $this->success = $success;
        if ($this->hasError()) {
            $this->success = null;
        }
    }

    public function isSuccess()
    {
        return isset($this->success);
    }


    public function decode($data)
    {
        $decoded = Json::decode($data, true);
        if (isset($decoded['error'])) {
            $this->errors = $decoded['error'];
        }

        if (isset($decoded['data'])) {
            $this->data += $decoded['data'];
        }

        if (isset($decoded['success'])) {
            $this->success = $decoded['success'];
        }

        return $this;
    }

    /**
     * @return string
     * @throws JsonException
     */
    public function __toString()
    {
        $result = [];
        if (isset($this->data)) {
            $result['data'] = $this->data;
        }

        if ($this->hasError()) {
            $result['error'] = $this->error;
        }

        if ($this->success) {
            $result['success'] = $this->success;
        }

        $encode = Json::encode($result);
        return $encode;
    }


}