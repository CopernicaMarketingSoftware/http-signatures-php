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
class Verifier extends Signature
{
    /**
     * Constructor for the verifier
     *
     * @param      array  $headers  Array of headers for signature lookup and headers used in signature
     */
    function __construct(array $headers = null)
    {
        if ($headers != null)
        {
            // Check if signature is in the headers
            if (in_array("Signature", array_keys($headers)))
            {
                // read signature and all it's values
                $this->readSignature($headers['Signature']);
            }
            // Add all headers for later use in verification
            foreach ($headers as $key => $value)
            {
                $this->addHeader($key, $value);
            }
        }
    }

    /**
     * Read signature from header
     *
     * @param      string   $signature  The signature from request
     *
     * @return     boolean  true if everything ready for verification, false otherwise
     */
    public function readSignature(string $signature)
    {
        // perform a regular expression to match as much as possible
        preg_match_all('/([a-zA-Z]*)="(.*?)"/', $signature, $matches, PREG_SET_ORDER);

        // parse the signature fields, splitting on ',' character
        foreach ($matches as $idx => $match)
        {
            // get the key and value
            $key = $match[1];

            // supported members
            if (!in_array( $key, ['keyId','signature','algorithm', 'headers'])) continue;

            // set the value in the key, removing string quotes
            $this->{"_".$key} = $match[2];
        }
        return true;
    }

    /**
     *  Check if the signature is valid given a certain key
     *
     *  @param  string      the key to check the signature
     *
     *  @return boolean     true if signature matches, else false
     */
    public function verify(string $cryptoKey)
    {
        // explode the headers for testing
        $headers = explode(' ', $this->_headers);

        // verify if all headers are added
        foreach ($headers as $header)
        {
            if ($this->contains($header) === false) return false;
        }

        // split algorithm in signing algorithm and hashing algorithm
        list($procedure, $hash) = explode('-', strtolower($this->_algorithm));

        // do we need the rsa algorithm?
        if ($procedure == 'rsa')
            return openssl_verify($this->signatureString(), base64_decode($this->_signature), $cryptoKey, $hash) == 1;

        // do we need the hmac algorithm?
        if ($procedure == 'hmac')
            return hash_hmac($hash, $this->signatureString(), $cryptoKey) == base64_decode($this->_signature);

        return false;
    }
}

