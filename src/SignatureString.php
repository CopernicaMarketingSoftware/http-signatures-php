<?php
/**
 *  SignatureString.php
 *
 *  Class for generating the normalized input string that is going to be 
 *  passed to the signing or verification algorithm
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
     *  Generated signature string
     *  @var string
     */
    private $value = "";

    /**
     *  Constructor for the signature string
     *  @param  array   The headers inside the actual signature object
     *  @param  string  The HTTP method (POST, GET, etc)
     *  @param  string  The location of the requested resource
     *  @param  array   Associative array with the actual headers to be sent or received
     */
    function __construct(array $signatureheaders, $method, $location, array $actualheaders)
    {
        // check the headers in the signature, and look up the actual header
        foreach ($signatureheaders as $name)
        {
            // @todo special handling for (request-type) and location?
            
            // look up the actual header
            // @todo do we have to remove spaces from the value?
            // @todo do we have to change case?
            $value = isset($actualheaders[$name]) ? trim($actualheaders[$name]) : "";
            
            // add to the value
            $this->value .= "$name: $value\n";
        }
        
        // the last newline should be removed
        $this->value = $this->value;
    }
    
    /**
     *  Get string representation
     *  @return string
     */
    public function __toString()
    {
        // get the value
        return $this->value;
    }
}

