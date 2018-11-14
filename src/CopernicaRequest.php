<?php
/**
 * CopernicaRequest.php
 *
 * @copyright 2018 Copernica BV
 */

/**
 * Namespace definition
 */
namespace Copernica;

/**
 *  Dependencies
 */
require_once(__DIR__.'/NormalizedHeaders.php');
require_once(__DIR__.'/DkimKey.php');
require_once(__DIR__.'/Digest.php');
require_once(__DIR__.'/Verifier.php');

/**
 * Helper class for verifying Copernica signature from request
 */
class CopernicaRequest
{
    /**
     * Message headers
     */
    private $headers;

    /**
     * Message body
     */
    private $body;

    /**
     *  Default constructor
     *
     * @throws     Exception   (description)
     * @throws     \Exception  (description)
     */
    function __construct($headers, $copernicaId, $method, $location)
    {
        // get all request headers
        $this->headers = new NormalizedHeaders(apache_request_headers());

        // Copernica always send out requests with a digest header, if it is missing, something is wrong
        if (!$this->headers->hasHeader('digest'))
            throw new \Exception("Digest header is missing");

        // check if date header exists
        if (!$this->headers->hasHeader('date'))
            throw new \Exception("Date header is missing");

        // get the message datetime
        $date = new \DateTime($this->headers->getHeader('date'));

        // get current datetime
        $now = new \DateTime('now', $date->getTimezone());

        // check if message is no longer than 1 minute
        if ($now->getTimestamp() - $date->getTimestamp() > 60)
            throw new \Exception("request older than 1 minute");

        // check if Copernica header exists
        if (!$this->headers->hasHeader('x-copernica-id'))
            throw new \Exception("Copernica id header is missing");

        // new Digest instance for digest verification, Copernica request always include digest header
        $digest = new Digest($this->headers->getHeader('digest'));

        // get request body
        $this->body = file_get_contents('php://input');

        // check if digest matches
        if (!$digest->matches($this->body)) throw new \Exception('Digest header does not match body data');

        // new verifier instance (could throw if there is no signature at all inside the headers,
        // or if the signature is malformed)
        $verifier = new Verifier(
            $this->headers->getHeaders(),
            $method,
            $location
        );

        // check if the appropriate headers are included in the signature
        if (!$verifier->contains('Host'))
            throw new \Exception("Invalid signature: the Host header is not included in the signature");
        if (!$verifier->contains('Date'))
            throw new \Exception("Invalid signature: the Date header is not included in the signature");
        if (!$verifier->contains("Content-length"))
            throw new \Exception("Invalid signature: the Content-length header is not included in the signature");
        if (!$verifier->contains("Content-type"))
            throw new \Exception("Invalid signature: the Content-type header is not included in the signature");
        if (!$verifier->contains("Digest"))
            throw new \Exception("Invalid signature: the Digest header is not included in the signature");
        if (!$verifier->contains("x-nonce"))
            throw new \Exception("Invalid signature: the X-nonce header is not included in the signature");

        // can also check if value is correct
        if (!$verifier->contains('x-copernica-id', $copernicaId))
            throw new \Exception('invalid signature: the x-copernica-id header is not included in the signature or has an invalid value');

        // // check if the key-id refers to a key issued by Copernica
        if (!preg_match('/\.copernica\.com$/', $verifier->keyId())) throw new \Exception("call is not signed by copernica.com (but by someone else)");

        // get the dkim-key (could throw if the key could not be located in dns, or when it was malformed)
        $key = new DkimKey($verifier->keyId());

        // verify signature correctness
        if (!$verifier->verify(strval($key))) throw new \Exception('signature is invalid');
    }


    /**
     * Request body getter.
     *
     * @return     string  Request body.
     */
    public function getBody()
    {
        return $this->body;
    }

    /**
     * Gets the content of a provided case-insensitive header name.
     *
     * @return     <type>  The content type.
     */
    public function getHeader($name)
    {
        return $this->headers->getHeader($name);
    }
}
