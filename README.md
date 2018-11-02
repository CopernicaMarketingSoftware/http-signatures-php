# HTTP signatures for PHP

This is an implementation of signing HTTP messages from a draft by M. Cavage.
Full draft can be found under:
https://datatracker.ietf.org/doc/draft-cavage-http-signatures/. This library 
can be used for creating new signatures and verifying signatures created according 
to the draft specification.

All webhook calls from Copernica are signed using the algorithm from this
specification. If you use a PHP scripts to process webhooks from Copernica, 
you can therefore use the classes inside this repository to verify these 
incoming webhook requests. But the repository is useful for others as well,
if you want to either sign or verify HTTP requests.

## Installation

Package can be installed via composer cli, by executing the following command:

```
composer require copernica/webhook-security
```

## Verifying incoming requests

Below is an generic example script for verifying signatures. If you have a script
that processes incoming HTTP calls, and you want to verify that these calls
indeed come from the expected source (and that the request is not forged), you
have to take the following steps:

- Create an instance of the Copernica\Verifier class to extract the signature
from the HTTP headers.
- Check if the signature does indeed cover the HTTP headers that you expect
to appear in the signature. Copernica for example, always at least includes the 
digest, date, host and x-copernica-id headers in the signature. A signature
that does not cover these headers is by definition invalid.
- Read out the key-ID stored in the signature, and load the appropropriate key
from the key storage (Copernica stores the key in DNS, so you will have to
do a DNS lookup, but other parties may use a different technologies to
share public keys or passwords).
- Check if the signature is valid using the key loaded from storage.

In almost all cases, the signature also includes the "digest" header. To
verify the call, you must therefore also check if the message body of the
incoming HTTP request matches the digest header. To do this, this library
contains a Copernica\Digest class.

Note that the next example contains a _generic example_ useful for verifying
incoming requests from _any source_. A copernica-specific example can be found
further down in this README file.

```php
// Include the verifier header file
require_once('Copernica/Verifier.php');

// Include the optional digest verification header
require_once('Copernica/Digest.php');

// Include the optional header normalizer
require_once('Copernica/NormalizedHeaders.php');

try
{
    // get all request headers using helper class
    $headers = new Copernica\NormalizedHeaders(apache_request_headers());

    // new Digest instance for digest verification
    // it is highly recommended to verify digest for message content
    $digest = new Copernica\Digest($headers->getHeader('digest'));

    // get request body
    $body = file_get_contents('php://input');

    // check if digest matches
    if (!$digest->matches($body)) throw new Exception("Digest header mismatch");

    // new verifier instance
    $verifier = new Copernica\Verifier(
        $headers->getHeaders(),         // all available headers
        $_SERVER['REQUEST_METHOD'],     // optional request method
        $_SERVER['REQUEST_URI']         // optional request location
    );

    // check if headers is in a signature
    if (!$verifier->contains("digest")) throw new Exception("Signature does not contains digest");

    // pseudo function to get a public key using keyId provided
    $keyPub = $keyStorage->get($verifier->keyId());

    // verify signature correctness
    if (!$verifier->verify($keyPub)) throw new Exception("Signature verification failed");

    // message has been verified
    // @todo process message body
}
catch (Exception $exception)
{
    // the incoming webhook was invalid
    echo("Invalid webhook call: ".$exception->getMessage());

    // @todo add your own handling (like logging)
}
```

## Verifying Copernica signature

The signatures from Copernica must include the (request-target), host, date, content-length, 
content-type, digest and x-copernica-id headers. This last header contains your customer ID
that uses to ensure that the call is really dealing with your account. The public key to
verify the signature is stored in DNS in the same format as DKIM public keys (do check
if the key is really stored in the copernica.com domain!).

To make your verification script simpler, we have included a class in this library
that can be used for validating Copernica webhooks. It takes care of checking all
headers, comparing the customer-ID and fetching the key from DNS:

```php

require_once('Copernica/CopernicaRequest.php');

// an exception is thrown if the call did not come from Copernica or is invalid
try
{
    // check if this is a valid request from Copernica (it throws if it isn't)
    $result = new Copernica\CopernicaRequest(
        apache_request_headers(),   // available HTTP headers
        12345,                      // Copernica customer ID
        $_SERVER['REQUEST_METHOD'], // request method
        $_SERVER['REQUEST_URI']     // request location
    );

    // get the incoming body data
    $data = $result->getBody();

    // get the content-type
    $type = $result->getHeader('content-type');

    // message has been verified
    // @todo process message body
}
catch (Exception $exception)
{
    // the call did not come from Copernica
    // @todo add your own handling (like logging)
}

```

## Signing request

This library does not only contain the technology for verifying signatures, but
also for signing outgoing requests. This may be useful if you want to sign
your requests too. Below is an generic example script for singing a request 
using cURL.

```php
// Include the signer header file
require_once('Copernica/Signer.php');

// read a content of a private key
$keyPriv = file_get_contents("test");

// new signature object with "date" header filled in
$signer = new Copernica\Signer(
    $keyPriv,       // private key
    "test",         // keyId signature value
    "RSA-SHA256",   // algorithm signature value
    "POST",         // optional request method
    "/foo"          // optional request location
);

$body = '{"hello": "world"}';

// it is highly recommended to attach digest for message content verification
$digest = "md5=".base64_encode(hash("md5", $body, true));
$date = date(DateTime::RFC822);

// add headers, order in which headers are added will be kept in signature
// if method and location are provided to constructor first header will be (request-target)
$signer
    ->addHeader("host", "example.com")
    ->addHeader("date", $date)
    ->addHeader("digest", $digest);

// check if signature is generated
// signature needs to have a "Date" header as minimum requirements
if (strval($signer) == "") exit("Generated signature is empty, signature requires a \"Date\" as minimum.");

// set request headers and signature
$headers = [
    "Date: $date",
    "Digest: $digest",
    "Signature: $signer",
    "Host: example.com",
    "Content-Type: application/json",
    "Content-Length: ".strlen($body)
];

// cURL request initialization
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, "example.com/foo");
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLINFO_HEADER_OUT, true);
curl_setopt($ch, CURLOPT_POST, true);

// set headers for request
curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);

// set body for request
curl_setopt($ch, CURLOPT_POSTFIELDS, $body);

// execute query
$server_output = curl_exec($ch);

// close cURL
curl_close ($ch);

```
