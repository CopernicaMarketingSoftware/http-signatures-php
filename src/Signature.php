<?php
/**
 *  Signature.php
 *
 *  Helper class to verify signed headers in accordance with draft-cavage-http-signatures
 *  version 10. Only does RSA for now.
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
    private $_keyId;

    /**
     *  The actual signature
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
    private $_signature;

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
    private $_headers;

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
    private $_algorithm;

    /**
     * Private key in text form
     */
    private $_private_key;

    /**
     * Public key in text form
     */
    private $_public_key;

    /**
     * Array for storing header objects.
     *
     * @var        array
     */
    private $_headers_arr = [];

    /**
     *  Constructor for the signature
     */
    function __construct()
    {
        if (in_array('HTTP_SIGNATURE', $_SERVER)) {
            $this->read($_SERVER['HTTP_SIGNATURE']);
        }
    }

    /**
     *  The key-ID
     *  @return string
     */
    public function keyId()
    {
        return $this->_keyId ? $this->_keyId : "";
    }

    /**
     *  Check if a specific header is included in the signature
     *  @param  string
     *  @return bool
     */
    public function contains($header)
    {
        return in_array($header, $this->headers);
    }

    /**
     * Adds a private key. It is required for signing a request.
     *
     * @param      string  $key    private key
     */
    public function addPrivateKey($key)
    {
        $this->_private_key = $key;
    }


    /**
     * Adds a public key. It is required for verification.
     *
     * @param      string  $key    public key
     */
    public function addPublicKey($key)
    {
        $this->_public_key = $key;
    }

    /**
     *  The algorithm
     *  @return string
     */
    public function algorithm(string $algorithm = null)
    {
        if($algorithm != null){
            // if(in_array($algorithm, \openssl_get_cipher_methods(true)))
                $this->_algorithm = $algorithm;
        }
        return $this->_algorithm ? $this->_algorithm : "";
    }

    /**
     * Getter for signature string
     */
    public function signatureString()
    {
        $signtureStr = new SignatureString($this->_headers_arr);
        return $signtureStr->signature();
    }

    /**
     *  The headers that are included in the signature
     *  @return array
     */
    public function headers(bool $as_array = false)
    {
        if($as_array){
            $result = [];
            foreach($this->_headers_arr as $header){
                if($header->key() !== "(request-target)" && $header->key() !== "host")
                    array_push($result, $header->key().": ".$header->value());
            }
            return $result;
        }
        return $this->_headers_arr;
    }

    /**
     *  The headers string for signature
     *  @return array
     */
    public function headersStr()
    {
        $str = "";
        foreach($this->_headers_arr as $header){
            $str .= $header->key()." ";
        }
        return trim($str);
    }

    /**
     * Generate signature header value
     *
     * @param      string  $signingKey  The signing key
     * @param      string  $message     Optional message
     */
    public function generate()
    {
        // sign message and save signature
        openssl_sign($this->signatureString(), $this->_signature, $this->_private_key, $this->_algorithm);

        // encode in base64 so it's readable
        $this->_signature = base64_encode($this->_signature);

        $this->signature = "keyId=\"".$this->keyId()."\",algorithm=\"".strtolower($this->algorithm());
        $this->signature .= "\",headers=\"".$this->headersStr()."\",signature=\"".$this->_signature."\"";

        return $this->signature;
    }

    /**
     * Read signature from header
     *
     * @param      string   $signature  The signature from request
     *
     * @return     boolean  true if everything ready for verification, false otherwise
     */
    public function read(string $signature)
    {
        // perform a regular expression to match as much as possible
        preg_match_all('/([a-zA-Z]*)="(.*?)"/', $signature, $matches, PREG_SET_ORDER);

        // parse the signature fields, splitting on ',' character
        foreach ($matches as $idx => $match)
        {
            // get the key and value
            $key = $match[1];

            // supported members
            if (!in_array( $key, ['keyId','signature','algorithm', 'headers'])) continue;

            // set the value in the key, removing string quotes
            $this->{"_".$key} = $match[2];
        }
        return true;
    }

    public function addHeader(string $key, string $value = "")
    {
        // check if header exists, then replace it
        foreach($this->_headers_arr as &$header){
            if($header->key() === $key){
                $header->value($value);
                return;
            }
        }
        // new header
        array_push($this->_headers_arr, new Header($key, $value));
    }

    /**
     *  Check if the signature is valid given a certain key
     *  @param  string      the key to check the signature
     *  @return bool
     */
    public function verify()
    {
        // explode the headers for testing
        $headers = explode(' ', $this->_headers);

        // verify if all headers are added
        foreach($this->_headers_arr as $header){
            if(in_array($header->key(), $headers) === false)
                return false;
        }

        // split algorithm in signing algorithm and hashing algorithm
        list($procedure, $hash) = explode('-', $this->_algorithm);

        if($this->_public_key === null)
            return false;

        // do we need the rsa algorithm?
        return openssl_verify($this->signatureString(), base64_decode($this->_signature), $this->_public_key, $hash);
    }
}

