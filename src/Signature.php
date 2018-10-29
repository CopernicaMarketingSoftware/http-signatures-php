<?php
/**
 *  Signature.php
 *
 *  Base class for generating signature string in accordance with draft-cavage-http-signatures
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
require_once(__DIR__.'/SignatureString.php');
require_once(__DIR__.'/Header.php');

/**
 *  Class definition
 */
class Signature
{
    /**
     *  The key ID
     *
     *  REQUIRED.  The `keyId` field is an opaque string that the server can
     *  use to look up the component they need to validate the signature.  It
     *  could be an SSH key fingerprint, a URL to machine-readable key data,
     *  an LDAP DN, etc.
     *
     *  @var string
     */
    protected $_keyId;

    /**
     *  The actual signature base64 encoded for readability
     *
     *  REQUIRED.  The `signature` parameter is a base 64 encoded digital
     *  signature, as described in RFC 4648 [RFC4648], Section 4 [5].  The
     *  client uses the `algorithm` and `headers` signature parameters to
     *  form a canonicalized `signing string`.  This `signing string` is then
     *  signed with the key associated with `keyId` and the algorithm
     *  corresponding to `algorithm`.  The `signature` parameter is then set
     *  to the base 64 encoding of the signature.
     *
     *  @var string
     */
    protected $_signature;

    /**
     *  The headers
     *
     *  OPTIONAL.  The `headers` parameter is used to specify the list of
     *  HTTP headers included when generating the signature for the message.
     *  If specified, it should be a lowercased, quoted list of HTTP header
     *  fields, separated by a single space character.  If not specified,
     *  implementations MUST operate as if the field were specified with a
     *  single value, the `Date` header, in the list of HTTP headers.  Note
     *  that the list order is important, and MUST be specified in the order
     *  the HTTP header field-value pairs are concatenated together during
     *  signing.
     *
     *  @var string
     */
    protected $_headers;

    /**
     *  The algorithm
     *
     * OPTIONAL.  The `algorithm` parameter is used to specify the digital
     * signature algorithm to use when generating the signature.  Valid
     * values for this parameter can be found in the Signature Algorithms
     * registry located at http://www.iana.org/assignments/signature-
     * algorithms [6] and MUST NOT be marked "deprecated".  It is preferred
     * that the algorithm used by an implementation be derived from the key
     * metadata identified by the `keyId` rather than from this field.  If
     * `algorithm` is provided and differs from the key metadata identified
     * by the `keyId` then an implementation MUST produce an error.  The
     * `algorithm` parameter, which may be specified by an attacker, has the
     * potential to create security vulnerabilities and will most likely be
     * deprecated in the future.
     *
     *  @var string
     */
    protected $_algorithm;

    /**
     * key that will be used in signing.
     *
     * @var        string
     */
    protected $_cryptoKey;

    /**
     * Array for storing header objects.
     *
     * @var        array
     */
    protected $_headersArray = [];

    /**
     *  The key-ID getter
     *
     *  @return string
     */
    public function getKeyId()
    {
        return $this->_keyId ? $this->_keyId : "";
    }

    /**
     *  Check if a specific header is included in the signature
     *
     *  @param  string
     *
     *  @return boolean
     */
    public function contains($header)
    {
        // Iterate through list of available headers
        foreach ($this->_headersArray as $header_obj)
        {
            // check if requested header is included
            if ($header_obj->key() == $header)
            {
                return true;
            }
        }
        return false;
    }

    /**
     * The algorithm setter and getter
     *
     * @param      string  $algorithm  The algorithm value to be set
     *
     * @return     string
     */
    public function algorithm(string $algorithm = null)
    {
        // if algorithm is provided
        if ($algorithm != null)
        {
            // set it for provided value
            $this->_algorithm = $algorithm;
        }
        // return current algorithm
        return $this->_algorithm ? $this->_algorithm : "";
    }

    /**
     * Getter for signature string
     *
     * @return     string Signature string
     */
    public function signatureString()
    {
        // check if headers string is available
        if ($this->_headers != null)
        {
            // if available, sort headers objects in same order as specified in list of headers
            $headers = explode(' ', $this->_headers);

            // copy headers array and clean it
            $headersArray = $this->_headersArray;

            // result array of sorted headers
            $sorted = [];

            // repopulate headers array in order provided
            foreach ($headers as $header)
            {
                foreach ($headersArray as $index => $headerObj)
                {
                    if ($headerObj->key() == $header)
                    {
                        array_push($sorted, $headerObj);

                        // remove element so it's not checked for anymore
                        unset($headersArray[$index]);
                        break;
                    }
                }
            }
            // use sorted headers array
            $this->_headersArray = $sorted;
        }

        // generate signature string from headers
        $signtureStr = new SignatureString($this->_headersArray);

        return $signtureStr->signature();
    }

    /**
     *  Get headers that are included in the signature as array of strings "{$header}: {$key}"
     *
     * @param      boolean  $as_array  As array
     *
     * @return     string/array
     */
    public function headersArray()
    {
        $result = [];
        // iterate over all available headers
        foreach ($this->_headersArray as $header)
        {
            // include only headers that will not cause server issue
            if ($header->key() !== "(request-target)" && $header->key() !== "host")
                array_push($result, (string)$header);
        }
        return $result;
    }

    /**
     *  The headers string that is used in a signature
     *
     *  @return string
     */
    public function headersString()
    {
        $str = "";
        // iterate over available headers, order is important as it's used for creating signature
        foreach ($this->_headersArray as $header)
        {
            // we need only header keys separated by single space character, all lowercase
            $str .= strtolower($header->key())." ";
        }
        return trim($str);
    }

    /**
     * Adds a header to signature.
     * These headers will be used for signature string creation.
     *
     * @param      string  $key    New headers key
     * @param      string  $value  New headers value
     */
    public function addHeader(string $key, string $value = "")
    {
        // check if header exists, then replace it
        foreach ($this->_headersArray as &$header)
        {
            // if header already defined
            if ($header->key() === $key)
            {
                // update this header value
                $header->value($value);
                return;
            }
        }
        // new header
        array_push($this->_headersArray, new Header($key, $value));
    }
}

