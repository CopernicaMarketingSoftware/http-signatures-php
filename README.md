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

## Signing request

Below is an generic example script for singing a request using cURL.

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
// if request and method are provided to constructor first header will be (request-target)
$signer
    ->addHeader("host", "example.com")
    ->addHeader("date", $date)
    ->addHeader("digest", $digest);

// set request headers and signature
$headers = [
    "date: ".$date,
    "digest: ".$digest,
    "Signature: ".$signer,
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

## Verifying request

Below is an generic example script for verifying signature.

```php
// Include the verifier header file
require_once('Copernica/Verifier.php');

// Include the optional digest verification header
require_once('Copernica/Digest.php');

// get all request headers
$headers = apache_request_headers();

// new Digest instance for digest verification
// it is highly recommended to verify digest for message content
$digest = new Copernica\Digest($headers["digest"]);

// get request body
$body = file_get_contents('php://input');

// check if digest matches
if ($digest->matches($body))
{
    // new verifier instance
    $sign = new Copernica\Verifier(
        $headers,   // all available headers
        "POST",     // optional request method
        "/foo"      // optional request location
    );

    // pseudo function to get a public key using keyId provided
    $keyPub = $keyStorage->get($sign->keyId());

    // verify signature correctness
    if (!$sign->verify($keyPub))
    {
        return;
    }
}
```
