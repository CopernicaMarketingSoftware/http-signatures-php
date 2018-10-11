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
     *  Construct the digest
     *  @param  value   digest tuple, e.g. sha256=...
     */
    function __construct($value)
    {
        // parse the message digest
        list($algorithm, $encoded) = explode('=', $_SERVER['HTTP_DIGEST']);

        // decode the value
        $value = base64_decode($encoded);
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