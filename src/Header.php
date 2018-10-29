<?php
/**
 *  Header.php
 *
 *  Generic class for storing header as key and value pair.
 *
 *  @author Radek Brzezinski
 *  @copyright 2018 Copernica BV
 */


/**
 *  Namespace definition
 */
namespace Copernica;

/**
 *  Class definition
 */
class Header
{
    /**
     * Header key
     *
     * @var        string
     */
    private $_key;

    /**
     * Header value
     *
     * @var        string
     */
    private $_value;


    /**
     * Constructor
     *
     * @param      string  $key    The header key
     * @param      string  $value  The header value
     */
    function __construct(string $key, string $value)
    {
        $this->_key = $key;
        $this->_value = $value;
    }

    /**
     * Key getter and setter
     *
     * @param      string  $value  The value
     *
     * @return     string  Header key
     */
    public function key(string $value = null)
    {
        if ($value === null)
            return $this->_key;
        else
            return $this->_key = $value;
    }

    /**
     * Value getter and setter
     *
     * @param      string  $value  The value
     *
     * @return     string  Header value
     */
    public function value(string $value = null)
    {
        if ($value === null)
            return $this->_value;
        else
            return $this->_value = $value;
    }

    /**
     * Returns a string representation of the object.
     *
     * @return     string  String representation of the object.
     */
    public function __toString(){
        return "{$this->_key}: {$this->_value}";
    }
}
