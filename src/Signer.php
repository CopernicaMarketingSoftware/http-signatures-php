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
class Signer extends Signature
{
    /**
     * Constructor for the signature
     *
     * @param      string  $cryptoKey  The cryptographic key that will be used for signing
     */
    function __construct(string $cryptoKey)
    {
        $this->_cryptoKey = $cryptoKey;
    }

    /**
     * Signature header value as a string
     *
     */
    public function __toString()
    {
        // split algorithm in signing algorithm and hashing algorithm
        list($procedure, $hash) = explode('-', strtolower($this->_algorithm));

        if ($procedure == 'rsa')
            // sign message and save signature
            openssl_sign($this->signatureString(), $this->_signature, $this->_cryptoKey, $this->_algorithm);

        if ($procedure == 'hmac')
            $this->_signature = hash_hmac($hash, $this->signatureString(), $this->_cryptoKey, true);

        // encode in base64 so it's readable
        $this->_signature = base64_encode($this->_signature);

        // signature header created according to specification
        $signatureHeader = "keyId=\"".$this->getKeyId()."\",algorithm=\"".strtolower($this->algorithm());
        $signatureHeader .= "\",headers=\"".$this->headersString()."\",signature=\"".$this->_signature."\"";

        return $signatureHeader;
    }
}

