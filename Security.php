<?php

/**
 *  Security.php
 *  
 *  Object which verifies the current HTTP request to have a valid
 *  signature, correct message digest and not too old (to prevent replay).
 * 
 *  @author Michael van der Werve
 *  @copyright 2018 Copernica BV
 */

/**
 *  Namespace definition
 */
namespace Copernica;

/**
 *  Dependencies
 */
require 'Signature.php';
require 'Digest.php';

/**
 *  Class definition
 */
class Security 
{
    /**
     *  The message digest
     *  @var Digest
     */
    private $digest;

    /**
     *  The message signature
     *  @var Signature
     */
    private $signature;

    /**
     *  Constructor for the security object.
     */
    function __construct()
    {
        // parse the date
        $date = new DateTime($_SERVER['HTTP_DATE']);

        // discard anything that is more than 5 minutes old
        if ($date->getTimestamp() < time() - 300) throw new Exception("request older than 5 minutes");
        
        // parse the digest
        $this->digest = new Digest($_SERVER['HTTP_DIGEST']);

        // if the digest doesn't match the data, we fail
        if (!$this->digest->matches(file_get_contents('php://stdin'))) throw new Exception("message digest mismatch");

        // construct the signature
        $this->signature = new Signature($_SERVER['HTTP_SIGNATURE']);
    }
}
