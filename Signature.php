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
     *  The actual signature
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
     *  Constructor for the signature
     *  @param  line    Header field, e.g. keyId="...",algorithm="..." etc.
     *  @throws Exception
     */
    function __construct($line)
    {
        // @todo parse the records better, being stateful with the quotation mark
        // parse the signature fields, splitting on ',' character
        foreach (explode(',', $line) as $tuple)
        {
            // split on the '=' character
            list($key, $value) = explode('=', $tuple);

            // supported members
            if (!in_array($key, array('keyId','signature','headers','algorithm'))) continue;

            // set the value in the key, removing string quotes
            $this->{$key} = substr($value, 1, -1);
        }

        // explode the headers further
        $this->headers = explode(' ', $this->headers);
        
        // there are a couple of headers that must be included
        foreach (array('(request-target)','date','digest') as $header)
        {
            // is it included?
            if (!$this->contains($header)) throw new Exception("header $header not included in signature");
        }
    }

    /**
     *  Utility function to reconstruct the signing body
     *  @return string
     */
    private function body()
    {
        // we start out empty
        $body = "";

        // append all relevant headers
        foreach ($this->headers as $header)
        {
            // @todo (request-target) is constructed in a different way
            
            // if the sign body is empty, don't post a newline
            if (!empty($body)) $body .= "\n";

            // the key in the server vars
            $key = 'HTTP_' . str_replace('-', '_', strtoupper($header));

            // add the header and its value to the sign body
            $body .= $header . ": " . $_SERVER[$key];
        }
    }
    
    /**
     *  The key-ID
     *  @return string
     */
    public function keyId()
    {
        return $this->keyId;
    }
    
    /**
     *  The headers that were included in the signature
     *  @return array
     */
    public function headers()
    {
        return $this->headers;
    }
    
    /**
     *  Check if a specific header is included in the signature
     *  @param  string
     *  @return bool
     */
    public function contains($header)
    {
        return in_array($header, $this->headers);
    }
    
    /**
     *  Check if the signature is valid given a certain key
     *  @param  string      the key to check the signature
     *  @return bool
     */
    public function verify($key)
    {
        // split algorithm in signing algorithm and hashing algorithm
        list($procedure, $hash) = explode('-', $this->algorithm);
        
        // do we need the rsa or hmac algorithm?
        if ($this->algorithm == 'rsa') return openssl_verify($this->body(), $this->signature, $key, $hash) == 1;
        
        // @todo implement hmac
        
        // no match
        return false;
    }
}

