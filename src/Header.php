<?php


/**
 *  Namespace definition
 */
namespace Copernica;

/**
 *  Class for headers management
 */
class Header
{
    private $_key;

    private $_value;

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
     * @return     <type>  ( description_of_the_return_value )
     */
    public function key(string $value = null)
    {
        if($value === null)
            return $this->_key;
        else
            return $this->_key = $value;
    }

    /**
     * Value getter and setter
     *
     * @param      string  $value  The value
     *
     * @return     <type>  ( description_of_the_return_value )
     */
    public function value(string $value = null)
    {
        if($value === null)
            return $this->_value;
        else
            return $this->_value = $value;
    }
}
