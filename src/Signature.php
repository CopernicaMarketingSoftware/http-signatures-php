<?php
/**
 *  Signature.php
 *
 *  Base class for generating the normalized signature string in accordance
 *  with draft-cavage-http-signatures version 10.
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
    protected $keyId = null;

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
    protected $signature = null;

    /**
     *  The headers included in the signature
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
     *  @var array
     */
    protected $headers = array();

    /**
     *  The algorithm
     *
     *  OPTIONAL.  The `algorithm` parameter is used to specify the digital
     *  signature algorithm to use when generating the signature.  Valid
     *  values for this parameter can be found in the Signature Algorithms
     *  registry located at http://www.iana.org/assignments/signature-
     *  algorithms [6] and MUST NOT be marked "deprecated".  It is preferred
     *  that the algorithm used by an implementation be derived from the key
     *  metadata identified by the `keyId` rather than from this field.  If
     *  `algorithm` is provided and differs from the key metadata identified
     *  by the `keyId` then an implementation MUST produce an error.  The
     *  `algorithm` parameter, which may be specified by an attacker, has the
     *  potential to create security vulnerabilities and will most likely be
     *  deprecated in the future.
     *
     *  @var string
     */
    protected $algorithm = null;


    /**
     *  Constructor
     *  @param  string      the optional signature to parse
     *  @throws Exception   if an invalid signature header was passed
     */
    public function __construct($signature = null)
    {
        // do nothing if no signature was passed
        if (is_null($signature)) return;

        // perform a regular expression to match as much as possible
        preg_match_all('/([a-zA-Z]*)="(.*?)"/', $signature, $matches, PREG_SET_ORDER);

        // parse the signature fields, splitting on ',' character
        foreach ($matches as $idx => $match)
        {
            // get the key and value
            $key = $match[1];

            // supported members
            if (!in_array( $key, ['keyId','signature','algorithm','headers'])) continue;

            // set the value in the key, removing string quotes
            $this->$key = $match[2];
        }

        // throw if not all required properties were set
        if (is_null($this->keyId)) throw new \Exception("KeyId not found in signature header");
        if (is_null($this->signature)) throw new \Exception("Signature not found in signature header");

        // the headers should be stored as array
        $this->headers = explode(" ", $this->headers);
    }

    /**
     *  The key-ID getter
     *  @return string
     */
    public function keyId()
    {
        return $this->keyId;
    }

    /**
     *  Set the key-ID
     *  @param  string
     *  @return Signature
     */
    public function setKeyId($keyId)
    {
        // update the member
        $this->keyId = $keyId;

        // allow chaining
        return $this;
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
        foreach ($this->headers as $value)
        {
            // check if requested header is included
            if (strtolower($header) == strtolower($value)) return true;
        }

        // not found
        return false;
    }

    /**
     *  Add a header - you must add it in the same order as the signature string
     *  @param  name        name of the header
     *  @return Signature
     */
    public function addHeader($name)
    {
        // remove the header with the same key
        $this->removeHeader($name);

        // add a new header
        $this->headers[] = $name;

        // allow chaining
        return $this;
    }

    /**
     *  Remove a header
     *  @param  key
     *  @return Signature
     */
    public function removeHeader($key)
    {
        // remove from the array (filter the array and keep all other headers)
        $this->headers = array_filter($this->headers, function($header) use ($key) {

            return $header != $key;
        });

        // allow chaining
        return $this;
    }

    /**
     * Headers getter
     * @return Headers names array
     */
    public function headers()
    {
        // return current headers
        return $this->headers;
    }

    /**
     *  The algorithm getter
     *  @return     string
     */
    public function algorithm()
    {
        // return current algorithm
        return $this->algorithm;
    }

    /**
     *  The algorithm setter
     *  @param      string  $algorithm  The algorithm value to be set
     *  @return     Signature
     */
    public function setAlgorithm(string $algorithm)
    {
        // set it for provided value
        $this->algorithm = $algorithm;

        // allow chaining
        return $this;
    }

    /**
     *  Retrieve the signature
     *  @return string
     */
    public function signature()
    {
        // expose the signature
        return $this->signature;
    }

    /**
     *  Set the signature
     *  @param  string
     *  @return Signature
     */
    public function setSignature($signature)
    {
        // store the signature
        $this->signature = $signature;

        // allow chaining
        return $this;
    }

    /**
     *  Return the string representation of the header
     *  @return string
     */
    public function __toString()
    {
        // signature header created according to specification
        return implode(",", array(
            "keyId=\"".$this->keyId."\"",
            "algorithm=\"".strtolower($this->algorithm)."\"",
            "headers=\"".implode(" ", $this->headers)."\"",
            "signature=\"".$this->signature."\""
        ));
    }
}

