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
class WebHook
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
     *  @param  integer     customer ID
     *  @throws Exception
     */
    function __construct($hostname, $path, $customerID)
    {
        // parse the date @todo what if the header is not even set?
        $date = new DateTime($_SERVER['HTTP_DATE']);

        // discard anything that is more than 5 minutes old
        if ($date->getTimestamp() < time() - 300) throw new Exception("request older than 5 minutes");

        // the appropriate customer-ID must be included in the call @todo what if the header is not even set?
        if ($_SERVER['HTTP_X_COPERNICA_ID'] != $customerID) throw new Exception("request for invalid customer ID");
        
        // @todo check request path
        // @todo check host name

        // load the data
        $this->body = file_get_contents("php://stdin");
        
        // do we have a digest?
        if (!isset($_SERVER['HTTP_DIGEST'])) throw new Exception("message digest missing");
        
        // parse the digest
        $digest = new Digest($_SERVER['HTTP_DIGEST']);
        
        // if the digest doesn't match the data, we fail
        if (!$digest->matches($this->body)) throw new Exception("message digest mismatch");

        // construct the signature
        $signature = new Signature($_SERVER['HTTP_SIGNATURE']);
        
        // check if the appropriate headers are included in the signature
        if (!$signature->contains('host')) throw new Exception("hostname is not included in the signature");
        if (!$signature->contains('x-copernica-id')) throw new Exception("customer ID is not included in the signature");
        
        // check if the key-id refers to a key issued by copernica
        if (!preg_match('/\.copernica.com$/', $signature->keyId)) throw new Exception("call is not signed by copernica.com (but by someone else)");
        
        // get the dkim-key
        $key = new DkimKey($signature->keyId());
        
        // verify the signature
        if (!$signature->verify(strval($key))) throw new Exception("signature is not valid");
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

