<?php
/**
 *  Digest.php
 *
 *  Helper class to verify `Digest: ...` header.
 *
 *  @author Michael van der Werve
 *  @copyright 2018 Copernica BV
 */

/**
 *  Namespace definition
 */
namespace Copernica;

/**
 *  Class for parsing the Digest field according to RFC3230.
 *  https://tools.ietf.org/html/rfc3230
 */
class Digest
{
    /**
     *  The algorithm
     *  @var string
     */
    private $algorithm;

    /**
     *  The value
     *  @var string
     */
    private $value;

    /**
     * Default constructor
     *
     * @param      <type>  $header  Digest header value
     *
     */
    function __construct($header = null)
    {
        if ($header == null) {
            $header = $_SERVER['HTTP_DIGEST'];
        }

        // parse the message digest
        list($this->algorithm, $this->value) = explode('=', $header);

        // decode the value
        $this->value = base64_decode($this->value);
    }

    /**
     *  Check if data matches to this digest
     *  @param  data
     *  @return bool
     */
    public function matches($data)
    {
        // hash the data and compare it
        return hash($this->algorithm, $data, true) === $this->value;
    }
}
