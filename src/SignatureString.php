<?php

/**
$signing_string = "(request-target): post /foo
   host: example.org
   date: Tue, 07 Jun 2014 20:51:35 GMT
   digest: SHA-256=".$digest."
   content-length: 18";
**/

/**
 *  Namespace definition
 */
namespace Copernica;

/**
 *  Dependencies
 */
require_once(__DIR__.'/Digest.php');
/**
 *  Class definition
 */
class SignatureString
{
    /**
     * Target URL
     */
    private $_target;

    /**
     * Method of call
     */
    private $_method;

    /**
     * Headers in signature
     */
    private $_headers;

    /**
     * Generated signature string
     */
    private $_signature_string;

    /**
     * Constructor for the signature string
     *
     * @param      string      $target  The target URL
     * @param      string      $body    Optional message body
     *
     * @throws     \Exception  (description)
     */
    function __construct(string $target = null, $method = null, string $body = null)
    {
        // use current URL for validation
        $this->_target =  (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? "https" : "http") . "://$_SERVER[HTTP_HOST]$_SERVER[REQUEST_URI]";

        if ($target != null){
            // validate target URL if provided
            if (filter_var($target, FILTER_VALIDATE_URL) === false)
                throw new \Exception("Target in not a valid URL: ".$target);

            // save it if valid
            $this->_target = $target;
        }

        $this->_method = $method ? $method : $_SERVER['REQUEST_METHOD'];

        $this->generate($body);
    }

    /**
     * Target getter
     *
     * @return     string  Target's URL
     */
    private function _target()
    {
        return $this->_target;
    }

    /**
     * Target host getter
     *
     * @return     string  Target's host
     */
    private function _host()
    {
        return parse_url($this->_target)['host'] ?? null;
    }

    /**
     * Target URI getter
     *
     * @return     string  Target's URI
     */
    private function _uri()
    {
        return parse_url($this->_target)['path'] ?? null;
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

    /**
     * Headers getter
     *
     * @return     string  signature string headers
     */
    public function headers()
    {
        return $this->_headers;
    }

    /**
     * Generates signature string
     *
     * @param      string  $body   The body of message if available
     *
     * @return     array
     */
    public function generate(string $body = null)
    {
        // @todo missing method in (request-target)
        $result_arr = [
            "(request-target)"  => $this->_uri(),
            "host"              => $this->_host(),
            "date"              => \date(\DateTime::RFC822),
        ];

        // if message body is available, generate digest string
        if ($body != null) {
            $result_arr['digest'] = "SHA-256=".base64_encode(Digest::create($body));
            $result_arr['content-length'] = strlen($body);
        }

        // save headers used for signature string
        $this->_headers = implode(" ", array_keys($result_arr));

        // follow signature string creation
        $result = "";
        foreach($result_arr as $key => $value){
            $result .= $key.": ".$value."\n";
        }
        $this->_signature_string = trim($result);
        return $this->_signature_string;
    }
}

