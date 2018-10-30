<?php
/**
 *  Signature.php
 *
 *  Helper class for signing headers in accordance with draft-cavage-http-signatures
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
class Signer
{
    /**
     *  Associative array headers to be included in the signature
     *  @param  array
     */
    private $headers;

    /**
     *  The key that is used for signing (either a private key or a shared password)
     *  @var string
     */
    private $key;

    /**
     * The key needs to have identifiable ID
     * @var string
     */
    private $keyId;

    /**
     * Algorithm that will be used for singing
     * @var string
     */
    private $algorithm;

    /**
     *  Constructor for the signature
     *  @param      string  $cryptoKey  The cryptographic key that will be used for signing
     *  @param      string  $keyId      Key identification for signature
     *  @param      string  $algorithm  Algorithm for signature
     *  @param      string  $method     optional The HTTP method (POST, GET, etc) for (request-target) header
     *  @param      string  $location   optional The location of the requested resource for (request-target) header
     */
    function __construct(string $cryptoKey, string $keyId, string $algorithm, string $method = null, string $location = null)
    {
        // we start with no headers
        $this->headers = array();

        // if method and location are provided we can add (request-target) header
        if (isset($method) && isset($location))
        {
            // $method needs to be lowercased
            $method = strtolower($method);

            // add (request-target) header
            $this->headers[] = array("(request-target)", "{$method} {$location}");
        }

        // store the private key
        $this->key = $cryptoKey;

        // store keyId
        $this->keyId = $keyId;

        // store algorithm
        $this->algorithm = $algorithm;
    }

    /**
     * Add a header to signature
     * @param header array [name, value]
     */
    public function addHeader($header)
    {
        // add header for signature creation
        $this->headers[] = $header;

        // allow chaining
        return $this;
    }

    /**
     *  Expose the headers as associative array
     *  @return array
     */
    private function headers()
    {
        // the return value
        $result = array();

        // because the internal storage is not an assoc array, we need to do a conversion
        foreach ($this->headers as $header)
        {
            // convert to assoc array
            $result[$header[0]] = $header[1];
        }

        // done
        return $result;
    }

    /**
     *  Signature header value as a string
     *  @return string
     */
    public function __toString()
    {
        // we start with an empty signature
        $signature = new Signature();

        // iterate over all headers
        foreach ($this->headers as $header)
        {
            // this header should be included in the signature
            $signature->addHeader($header[0]);
        }

        // set keyId for signature
        $signature->setKeyId($this->keyId);

        // set algorithm for signature
        $signature->setAlgorithm($this->algorithm);

        // now we have to create the actual signature, start with the input-string
        $input = new SignatureString($signature->headers(),  $this->headers());

        // the openssl_sign() method needs a result parameter
        $result = "";

        // split algorithm in signing algorithm and hashing algorithm
        list($procedure, $hash) = explode('-', strtolower($this->algorithm));

        // decide which method we proceed
        switch ($procedure) {
        case "rsa":
            openssl_sign(strval($input), $result, $this->key, $this->algorithm);
            break;
        case "hmac":
            $result = hash_hmac($hash, strval($input), $this->key, true);
            break;
        default:
            return "";
        }

        // put the signature base64-encoded in the signature
        $signature->setSignature(base64_encode($result));

        // expose the string representation of the signature
        return strval($signature);
    }
}

