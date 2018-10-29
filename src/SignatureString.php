<?php
/**
 *  SignatureString.php
 *
 *  Class for generating signature string from headers provided.
 *
 *  @author Radek Brzezinski
 *  @copyright 2018 Copernica BV
 */


/**
 *  Namespace definition
 */
namespace Copernica;

/**
 *  Class definition
 */
class SignatureString
{
    /**
     * Generated signature string
     *
     * @var        string
     */
    private $_signature_string = "";

    /**
     * Constructor for the signature string
     *
     * @param      array  $headers  The signature headers array
     */
    function __construct(array $headers)
    {
        // follow signature string creation
        foreach ($headers as $header)
        {
            $this->_signature_string .= $header->key().": ".$header->value()."\n";
        }
        $this->_signature_string = trim($this->_signature_string);
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
}

