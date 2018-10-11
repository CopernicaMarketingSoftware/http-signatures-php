# Webhook security

Repository containing an example to verify request security, even if the message is being sent over a compromised channel.

## Usage

Below is an example script that verifies the message to be authentic, recent and from Copernica.

```
// include the security header file
require 'Security.php';

// construct the object. if this fails (throws), the channel is not secure.
$security = new Copernica\Security();
```
