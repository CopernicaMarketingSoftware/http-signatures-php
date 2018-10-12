# Webhook security

If you use a PHP scripts to process webhooks from Copernica, you can use
the classes inside this repository to verify these incoming webhook
requests.

Copernica adds a digital signature to each outgoing webhook call. With
the classes inside this repository you can automatically check this 
signature. This prevents that your webhook handling script will ever
be fed with data that does not come from Copernica.com. 

## Installation

Package can be installed via composer cli, executing following line.

```
composer require copernica/webhook-security
```

## Usage

Below is an example script that verifies the message to be authentic, 
recent and from Copernica.

```
// Include the security header file
require_once('Copernica/Webhook.php');

// Construct the object. You need to pass the hostname on which the 
// calls are supposed to come in, the path name and your customer ID
// (which is an integer)
$webhook = new Copernica\Webhook("customername.com", "/path/to/script.php", 'account_1234');

// @todo process the actual data
$data = json_decode($webhook->body());
```
