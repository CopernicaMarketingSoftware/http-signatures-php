<?php

/**
 *  Digest.php
 *
 *  Helper class to verify `Digest: ...` header.
 *
 *  @author Michael van der Werve
 *  @copyright 2018 Copernica BV
 */

/**
 *  Namespace definition
 */
namespace Copernica;

/**
 *  Class for parsing the Digest field according to RFC3230.
 *  https://tools.ietf.org/html/rfc3230
 */
class Digest
{
    /**
     *  The algorithm
     *  @var string
     */
    private $algorithm;

    /**
     *  The value
     *  @var string
     */
    private $value;

    /**
     * Default constructor
     *
     */
    function __construct()
    {

    }

    /**
     * Get digest string for message
     *
     * @param      string  $body       Body of the message
     * @param      string  $algorithm  Algorithm used for creating digest string
     *
     * @return     string  Digested message string
     */
    public function create($body, $algorithm = "sha256")
    {
        $algorithm = $algorithm;
        $value = hash($algorithm, $body, true);
        return $value;
    }

    public function read($value = null)
    {
        if ($value == null) {
            // parse the message digest
            list($algorithm, $value) = explode('=', $_SERVER['HTTP_DIGEST']);
        }

        // decode the value
        $this->value = base64_decode($value);
    }

    /**
     *  Check if data matches to this digest
     *  @param  data
     *  @return bool
     */
    public function matches($data)
    {
        // hash the data and compare it
        return hash($this->algorithm, $data, true) === $value;
    }
}
