<?php
/**
 *  Verifier.php
 *
 *  Helper class for verifying headers in accordance with draft-cavage-http-signatures
 *  version 10.
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
require_once(__DIR__.'/Signature.php');

/**
 *  Class definition
 */
class Verifier
{
    /**
     *  All incoming HTTP headers
     *  @var array
     */
    private $headers;

    /**
     *  The parsed signature
     *  @var Signature
     */
    private $signature;


    /**
     *  Constructor for the verifier
     *  @param  array       Array of all incoming HTTP headers
     *  @param  string      optional Name of the method of the incoming call (POST, GET, et cetera)
     *  @param  string      optional Location of the incoming script
     *  @throws Exception   If there was no signature, or when it could not be parsed
     */
    function __construct(array $headers, string $method = null, string $location = null)
    {
        // store the headers
        $this->headers = $headers;

        // if $method and $location provided, (request-target) header can be added
        if (isset($method) && isset($location))
        {
            // $method needs to be lowercased
            $method = strtolower($method);

            // add (request-target) header
            $this->addHeader("(request-target)", "{$method} {$location}");
        }

        // we must have a signature header
        if (!isset($headers["Signature"])) throw new \Exception("No signature found");

        // now we can parse the signature
        $this->signature = new Signature($headers["Signature"]);
    }

    /**
     *  Retrieve the key-id
     *  This key should be used by the user to lookup the crypto-key
     *  @return string
     */
    public function keyId()
    {
        // forward to the signature
        return $this->signature->keyId();
    }

    /**
     *  The algorithm used
     *  @return string
     */
    public function algorithm()
    {
        // forward to the signature
        return $this->signature->algorithm();
    }

    /**
     * Add a header to signature
     * @param header array [name, value]
     */
    private function addHeader($name, $value)
    {
        // add header for signature creation
        $this->headers[$name] = $value;

        // allow chaining
        return $this;
    }

    /**
     *  Check if a certain header is included in the signature
     *  It is advised to only accept signatures that contain a certain
     *  minimal set of headers
     *  @param  string      the name of the header
     *  @param  string      optional required value
     *  @return bool
     */
    public function contains($key, $value = null)
    {
        // check if the header is included in the signature
        if (!$this->signature->contains($key)) return false;

        // does the user also want to check the value?
        if (is_null($value)) return true;

        // check the value as well
        foreach ($this->headers as $header => $headerValue)
        {
            // header name is case insensitive
            // https://tools.ietf.org/html/rfc7230#section-3.2
            if (strtolower($header) == strtolower($key))
            {
                // verify that value is correct
                return $this->headers[$header] == $value;
            }
        }
        return false;
    }

    /**
     *  Check if the signature is valid given a certain key
     *  The supplied key should match the algorithm and keyId
     *  @param  string      the key to check the signature
     *  @return boolean     true if signature matches, else false
     */
    public function verify(string $cryptoKey)
    {
        // normalize the input for the verification
        $input = new SignatureString($this->signature->headers(), $this->headers);

        // split algorithm in signing algorithm and hashing algorithm
        list($procedure, $hash) = explode('-', strtolower($this->signature->algorithm()));

        // do we need the rsa algorithm?
        switch ($procedure) {
        case 'rsa':  return openssl_verify(strval($input), base64_decode($this->signature->signature()), $cryptoKey, $hash) == 1;
        case 'hmac': return hash_hmac($hash, strval($input), $cryptoKey) == base64_decode($this->signature->signature());
        default:     return false;
        }
    }
}

