<?php
/**
 * NormalizeHeaders.php
 *
 * @copyright 2018 Copernica BV
 */

/**
 * Namespace definition
 */
namespace Copernica;

/**
 * Helper class for handling headers with case-insensitive header name
 */
class NormalizedHeaders
{
    /**
     * @var array Map of all registered headers, as original name => value
     */
    private $headers = array();

    /**
     * @var array Map of lowercase header name => original name at registration
     */
    private $headerNames  = array();

    /**
     * Default constructor
     *
     * @param      <type>  $headers  The headers
     */
    function __construct($headers)
    {
        // iterate over headers
        foreach ($headers as $header => $value)
        {
            // normalize header name for searching
            $normalized = strtolower($header);

            // check if header already defined
            if (!$this->hasHeader($normalized))
            {
                // save original header name
                $this->headerNames[$normalized] = $header;

                // save header value
                $this->headers[$header] = $value;
            }
        }
    }

    /**
     * Retrieves all header values.
     *
     * While header names are not case-sensitive, getHeaders() will preserve the
     * exact case in which headers were originally specified.
     *
     * @return array All headers
     */
    public function getHeaders()
    {
        return $this->headers;
    }

    /**
     * Checks if a header exists by the given case-insensitive name.
     *
     * @param string $name Case-insensitive header field name.
     * @return bool Returns true if any header names match the given header
     *     name using a case-insensitive string comparison. Returns false if
     *     no matching header name is found in the message.
     */
    public function hasHeader($header)
    {
        return isset($this->headerNames[strtolower($header)]);
    }

    /**
     * Retrieves a message header value by the given case-insensitive name.
     *
     * This method returns an string of the header values of the given
     * case-insensitive header name.
     *
     * If the header does not appear in the message, this method MUST return an
     * empty string.
     *
     * @param $name     string Case-insensitive header field name.
     * @return          string An string values as provided for the given
     *    header. If the header does not appear in the message, this method MUST
     *    return an empty string.
     */
    public function getHeader($header)
    {
        // save case-insensitive header field name
        $header = strtolower($header);

        // check if header name is defined
        if (!isset($this->headerNames[$header]))
        {
            // return empty string if not
            return "";
        }

        // retrieve original header field name
        $header = $this->headerNames[$header];

        // return header value
        return $this->headers[$header];
    }

}
