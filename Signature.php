<?php

/**
 *  Signature.php
 *  
 *  Helper class to verify signed headers in accordance with draft-cavage-http-signatures
 *  version 10. Only does RSA for now.
 * 
 *  https://tools.ietf.org/html/draft-cavage-http-signatures-10
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
require 'DkimKey.php';

/**
 *  Class definition
 */
class Signature
{
    /**
     *  The key ID
     *  @var string
     */
    private $keyId;

    /**
     *  The key as obtained from the DNS system
     *  @var DkimKey
     */
    private $key;

    /**
     *  The (decoded) signature
     *  @var string
     */
    private $signature;

    /**
     *  The headers
     *  @var array
     */
    private $headers;

    /**
     *  The algorithm  
     *  @var string
     */
    private $algorithm;

    /**
     *  Utility function to reconstruct the signing body
     */
    private function body()
    {
        // we start out empty
        $body = "";

        // append all relevant headers
        foreach ($this->headers as $header)
        {
            // if the sign body is empty, don't post a newline
            if (!empty($body)) $body .= "\n";

            // the key in the server vars
            $key = 'HTTP_' . str_replace('-', '_', strtoupper($header));

            // add the header and its value to the sign body
            $body .= $header . ": " . $_SERVER[$key];
        }
    }

    /**
     *  Constructor for the signature
     *  @param  line    Header field, e.g. keyId="...",algorithm="..." etc.
     */
    function __construct($line)
    {
        // @todo parse the records better, being stateful with the quotation mark
        // parse the signature fields, splitting on ',' character
        foreach (explode(',', $line) as $tuple)
        {
            // split on the '=' character
            list($key, $value) = explode('=', $tuple);

            // set the value in the key, removing string quotes
            $this->{$key} = substr($value, 1, -1);
        }

        // check that this is an RSA signature
        if (substr($this->algorithm, 0, 4) != "rsa-") throw new Exception("signature algorithm not supported");

        // remove the 'rsa-' part from the algorithm
        $this->algorithm = substr($this->algorithm, 4);

        // if the keyid is not a copernica subdomain, this is not a valid signature
        if (strlen($this->keyId) < 14 || substr($this->keyId, -14) != ".copernica.com") throw new Exception("keyId is not copernica.com subdomain");

        // explode the headers further
        $this->headers = explode(' ', $this->headers);

        // find the actual key
        $this->key = new DkimKey($keyId); 

        // the required header fields
        $required = array("(request-target)", "host", "date", "x-copernica-id", "digest");

        // verify that some important fields are actually in the header
        if (array_diff($required, $this->headers)) throw new Exception("required header fields missing");

        // and finally check the digest
        if (openssl_verify($this->body(), $this->signature, $this->key->key(), $this->algorithm) != 1) throw new Exception("signature invalid"); 
    }
}