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

```php
// Include the security header file
require_once('Copernica/Webhook.php');

// Construct the object. All headers will be filled in from $_SERVER variable
$webhook = new Copernica\Webhook();

// @todo process the actual data
$data = json_decode($webhook->body());
```

## Signing request

Below is an generic example script for singing a request using cURL.

```php
// read a content of a private key
$keyPriv = file_get_contents("test");

// new signature object with "date" header filled in
$sign = new Copernica\Signature();

// add private key
$sign->addPrivateKey($keyPriv);

// set signing method
$sign->algorithm("RSA-SHA256");

// add headers, order in which headers are added will be kept in signature
$sign->addHeader("(request-target)", "get /foo?param=value&pet=dog");
$sign->addHeader("host", "example.com");
$sign->addHeader("date", date(DateTime::RFC822));

// generate signature
$signature = $sign->generate();

// cURL request initialization
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL,"example.com/foo?param=value&pet=dog");
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

// get headers as array
$headers = $sign->headers(true);

// add signature header
array_push($headers, "signature: ".$signature);

// set request headers
curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);

// execute query
$server_output = curl_exec ($ch);

curl_close ($ch);

```
