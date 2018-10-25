<?php
/**
 *  WebHook.php
 *
 *  Class that can be used to handle incoming webcalls from copernica.com.
 *  If you use this class to handle incoming webcalls, all calls are automatically
 *  checked if they do indeed come from copernica.com, and not from someone
 *  else.
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
require_once(__DIR__.'/Signature.php');
require_once(__DIR__.'/Digest.php');
require_once(__DIR__.'/DkimKey.php');

/**
 *  Class definition
 */
class Webhook
{
    /**
     *  The request body
     *  @return string
     */
    private $body;


    /**
     *  Constructor for the security object
     *
     *  You need to pass in the hostname that the call is supposed to go to,
     *  the path to the script and your customer ID. Inside the constructor
     *  it is checked if the call is indeed sent to this script (and is not
     *  a reply attack). If something is wrong, an exception is thrown.
     *
     *  @param  string      hostname on which the call is running
     *  @param  string      path to the script
     *  @param  integer     customer ID, either account_<id> or environment_<id>
     *  @throws Exception
     */
    function __construct($hostname, $path, $customerID)
    {
        // Date header is mandatory
        if(!in_array("HTTP_DATE", $_SERVER)) throw new \Exception("No date header set.");

        // construct the signature
        $signature = new Signature();

        // add required headers

        // date header
        $signature->addHeader('date', $_SERVER['HTTP_DATE']);

        // Copernica's customer id
        $signature->addHeader('x_copernica_id', $_SERVER['HTTP_X_COPERNICA_ID']);

        // request method and target
        $signature->addHeader("(request-target)", $_SERVER['method']." ".$_SERVER['REQUEST_URI']);

        // request host
        $signature->addHeader('host', $_SERVER['HTTP_HOST']);

        // load the data
        $this->body = file_get_contents("php://stdin");

        // parse the digest
        $digest = new Digest($_SERVER['HTTP_DIGEST']);

        // if the digest doesn't match the data, we fail
        if (!$digest->matches($this->body)) throw new \Exception("message digest mismatch");

        // add digest as header
        $signature->addHeader('digest', $_SERVER['HTTP_DIGEST']);

        // get the dkim-key
        $key = new DkimKey($signature->keyId());

        // add set it for signature verification
        $signature->addPublicKey(strval($key));

        // verify the signature
        if (!$signature->verify()) throw new \Exception("signature is not valid");
    }

    /**
     *  Get access to the request body
     *  @return string
     */
    public function body()
    {
        return $this->body;
    }
}

