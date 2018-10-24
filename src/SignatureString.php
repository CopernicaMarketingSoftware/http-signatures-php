<?php

/**
$signing_string = "(request-target): post /foo
   host: example.org
   date: Tue, 07 Jun 2014 20:51:35 GMT
   digest: SHA-256=".$digest."
   content-length: 18";
**/

/**
 *  Namespace definition
 */
namespace Copernica;

/**
 *  Dependencies
 */
require_once(__DIR__.'/Digest.php');
/**
 *  Class definition
 */
class SignatureString
{
    /**
     * Headers in signature
     */
    private $_headers_arr;

    /**
     * Generated signature string
     */
    private $_signature_string;

    /**
     * Constructor for the signature string
     *
     * @param      array  $headers  The signature headers
     */
    function __construct(array $headers)
    {
        $this->_headers_arr = $headers;

        // follow signature string creation
        $result = "";
        foreach($this->_headers_arr as $header){
            $result .= $header->key().": ".$header->value()."\n";
        }
        $this->_signature_string = trim($result);
    }

    /**
     * Signature string getter
     *
     * @return     string  signature string
     */
    public function signature()
    {
        return $this->_signature_string;
    }

    /**
     * Headers getter
     *
     * @return     string  signature string headers
     */
    public function headers()
    {
        return $this->_headers_arr;
    }
}

