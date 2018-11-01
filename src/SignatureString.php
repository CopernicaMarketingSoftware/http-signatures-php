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
     *  Created by concatenating the lowercased header field name followed with an ASCII colon `:`,
     *  an ASCII space ` `, and the header field value. Leading and trailing optional whitespace (OWS)
     *  in the header field value MUST be omitted
     *  @param  array   The headers inside the actual signature object
     *  @param  array   Associative array with the actual headers to be sent or received
     */
    function __construct($signatureheaders, $actualheaders)
    {
        // change all headers names to be case insensitive
        $actualheaders = array_change_key_case($actualheaders, CASE_LOWER);

        // check if $signatureheaders is empty
        if (count($signatureheaders) == 0)
        {
            // we will use only a "Date" header
            if (isset($actualheaders["date"]))
            {
                $this->value = "date: ".trim($actualheaders["date"]);
            }
        }

        // check the headers in the signature, and look up the actual header
        foreach ($signatureheaders as $name)
        {
            // look up the actual header
            $value = isset($actualheaders[$name]) ? trim($actualheaders[$name]) : "";

            // add to the value
            // header name needs to be lowercase
            $this->value .= strtolower($name).": $value\n";
        }

        // the last newline should be removed
        $this->value = rtrim($this->value, "\n");
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

