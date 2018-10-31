<?php
/**
 *  DkimKey.php
 *
 *  Helper class to obtain a Dkim key from the DNS system
 *  and expose it in PEM format.
 *
 *  @author Michael van der Werve
 *  @copyright 2018 Copernica BV
 */

/**
 *  Namespace definition
 */
namespace Copernica;

/**
 *  Class that makes a DNS query to resolve a DKIM key and convert it
 *  to a valid OpenSSL key.
 */
class DkimKey
{
    /**
     *  The version
     *  @var string
     */
    private $version;

    /**
     *  The (decoded) key
     *  @var string
     */
    private $key;

    /**
     *  Constructor from an url
     *  @param url
     */
    function __construct($url)
    {
        // first, resolve all the records
        $records = dns_get_record($url, DNS_TXT);

        // loop over all records
        foreach ($records as $record)
        {
            // loop over entries in record
            foreach($record as $entry)
            {
                // check if dkim entry
                if(strpos($entry, "=") === false) continue;

                // object for the certificate
                $certificate = array();

                // we parse the certificate
                foreach (explode(";", $entry) as $tuple)
                {
                    // explode the key and value
                    list($key, $value) = explode('=', $tuple);

                    // set in the array
                    $certificate[$key] = $value;
                }

                // skip if not a dkim record
                if ($certificate['v'] != 'DKIM1') continue;

                // set the version
                $this->version = $certificate['v'];

                // decode the public key
                $this->key = "-----BEGIN PUBLIC KEY-----\n";
                $this->key .= $certificate['p']."\n";
                $this->key .= "-----END PUBLIC KEY-----\n";

                // leap out, we have a valid key and certificate
                return;
            }
        }

        // we didn't leap out, so either there are no records or
        // none of the records was actually valid, throw an error
        throw new \Exception("no valid dkim keys found at " . $url);
    }

    /**
     *  Get the key
     *  @return string
     */
    public function key()
    {
        return $this->key;
    }

    /**
     *  Cast to a string value
     *  @return string
     */
    public function __toString()
    {
        return $this->key;
    }
}
