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
     * Associative list of available algorithms specified by IANA
     * https://www.iana.org/assignments/http-dig-alg/http-dig-alg.xhtml
     * @var        array
     */
    private $algorithms = array(
        "adler32"   => "adler32",
        "crc32c"    => "",          // not implemented
        "md5"       => "md5",
        "sha"       => "sha1",
        "sha-256"   => "sha256",
        "sha-512"   => "sha512",
        "unixsum"   => "",          // not implemented
        "unixcksum" => ""           // not implemented
    );

    /**
     * Default constructor
     *
     * @param      <type>  $header  Digest header value
     *
     */
    function __construct($header = null)
    {
        if ($header == null)
        {
            $header = $_SERVER['HTTP_DIGEST'];
        }

        // parse the message digest
        list($this->algorithm, $this->value) = explode('=', $header);

        // verify that algorithm is one from algorithms specified by IANA
        if (!in_array($this->algorithm, array_keys($this->algorithms))) throw new \Exception("Invalid hashing algorithm");

        // check if hashing function is available
        if (empty($this->algorithms[$this->algorithm])) throw new \Exception("Algorithm not implemented");

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
        return hash($this->algorithms[$this->algorithm], $data, true) === $this->value;
    }
}
