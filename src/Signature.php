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
    private $keyId;

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
    private $signature;

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
     *  @var array
     */
    private $headers;

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
    private $algorithm;

    /**
     * Private key in text form
     */
    private $_private_key;

    /**
     * Public key in text form
     */
    private $_public_key;


    /**
     *  Constructor for the signature
     */
    function __construct()
    {

    }

    /**
     * Generate signature header
     *
     * @param      string  $signingKey  The signing key
     * @param      string  $message     Optional message
     */
    public function generate(string $target = null, string $method = null, string $message = null)
    {
        // create new signature string that will be used for signing
        $signatureString = new SignatureString($target, $method, $message);

        $this->headers = $signatureString->headers();

        // sign message and save signature
        openssl_sign($signatureString->signature(), $this->signature, $this->_private_key, "SHA256");

        // encode in base64 so it's readable
        $result = base64_encode($this->signature);

        $this->signature = "keyID=\"".$this->keyId."\",algorithm=\"".$this->algorithm."\",headers=\"";
        $this->signature .= $this->headers."\",signature=\"".$result."\"";

        return $this->signature;
    }

    /**
     * Read signature from header
     *
     * @param  line    Header field, e.g. keyId="...",algorithm="..." etc.
     */
    public function read(string $signature)
    {
        // perform a regular expression to match as much as possible
        preg_match_all('/([a-zA-Z]*)="(.*?)"/', $signature, $matches, PREG_SET_ORDER);

        // @todo parse the records better, being stateful with the quotation mark
        // parse the signature fields, splitting on ',' character
        foreach ($matches as $idx => $match)
        {
            // get the key and value
            $key = $match[1];

            // supported members
            if (!in_array(
                    $key,
                    array('keyId','signature','headers','algorithm')
                )
            ) continue;

            // set the value in the key, removing string quotes
            $this->{$key} = $match[2];
        }

        // explode the headers further
        $this->headers = explode(' ', $this->headers);

        // there are a couple of headers that must be included
        foreach (array('(request-target)','date','digest') as $header)
        {
            // is it included?
            if (!$this->contains($header)) throw new \Exception("header $header not included in signature");
        }
    }

    /**
     *  Utility function to reconstruct the signing body
     *  @return string
     */
    private function body()
    {
        // we start out empty
        $body = "";

        // append all relevant headers
        foreach ($this->headers as $header)
        {
            // @todo (request-target) is constructed in a different way

            // if the sign body is empty, don't post a newline
            if (!empty($body)) $body .= "\n";

            // the key in the server vars
            $key = 'HTTP_' . str_replace('-', '_', strtoupper($header));

            // add the header and its value to the sign body
            $body .= $header . ": " . $_SERVER[$key];
        }
    }

    /**
     *  The key-ID
     *  @return string
     */
    public function keyId()
    {
        return $this->keyId;
    }

    /**
     *  The headers that were included in the signature
     *  @return array
     */
    public function headers()
    {
        return $this->headers;
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
     * Adds a private key.
     *
     * @param      string  $key    private key
     */
    public function addPrivateKey($key)
    {
        $this->_private_key = $key;
    }


    /**
     * Adds a public key.
     *
     * @param      string  $key    public key
     */
    public function addPublicKey($key)
    {
        $this->_public_key = $key;
    }

    /**
     *  Check if the signature is valid given a certain key
     *  @param  string      the key to check the signature
     *  @return bool
     */
    public function verify()
    {
        // split algorithm in signing algorithm and hashing algorithm
        list($procedure, $hash) = explode('-', $this->algorithm);

        // do we need the rsa algorithm?
        if ($this->algorithm == 'rsa') return openssl_verify($this->body(), $this->signature, $key, $hash) == 1;

        // do we need the hmac algorithm?
        if ($this->algorithm == 'hmac') return hash_hmac($hash, $this->body(), $key) == $this->signature;

        // no match
        return false;
    }
}

