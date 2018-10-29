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
    // @todo special properties for location, and method??
    
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
     *  Constructor for the signature
     *  @param      string  $cryptoKey  The cryptographic key that will be used for signing
     * 
     * 
     *  @todo do we already want to pass some extra properties to the constructor that we must always have?
     */
    function __construct(string $cryptoKey)
    {
        // we start with no headers
        $this->headers = array();
        
        // store the private key
        $this->key = $cryptoKey;
    }
    
    /**
     *  Add headers to be included in the header
     *  @param  string      header name
     *  @param  string      header value
     *  @return Signer
     */
    public function addHeader($key, $value)
    {
        // append the header (we use an array to keep the same order)
        $this->headers[] = array($key, $value);
        
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
        
        // @todo store other properties in the signature
        $signature->setKeyId(???);
        $signature->setAlgorithm(???);
        
        // now we have to create the actual signature, start with the input-string
        $input = new SignatureString($signature->headers(), ??, ??, $this->headers());
        
        // the openssl_sign() method needs a result parameter
        $result = "";
        
        // now sign the input string
        openssl_sign(strval($input), $result, $this->cryptoKey, ??);
        
        // @todo also handle hmac
        
        // put the signature base64-encoded in the signature
        $signature->setSignature(base64_encode($result));
        
        // expose the string representation of the signature
        return strval($ignature);
        
        /* 
        
        
        
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
        */
    }
}

