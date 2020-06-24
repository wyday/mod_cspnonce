# mod_cspnonce

"mod_cspnonce" is an Apache2 module that makes it dead simple to add "nonce" values to the CSP (content security policy) headers.

## Example

### Server config

```
LoadModule headers_module modules/mod_headers.so
LoadModule cspnonce_module modules/mod_cspnonce.so

# add the CSP_NONCE to the "default-src"
Header add Content-Security-Policy "default-src 'self' 'nonce-%{CSP_NONCE}e';"
```

### Usage in your server-side script

Using the CSP nonce is as simple as loading the `CSP_NONCE` server variable using whatever method is available in your script language of choice. Here's a dead-simple example in PHP:

```
<?php

// access the CSP nonce from a script
$csp_nonce = $_SERVER['CSP_NONCE'];

?>
```

## Why not use `mod_unique_id`?

Becase that module doesn't create base64 values (`@` symbols are not valid), plus it's overly bloated and uses 90's era random number generation (i.e. it's not random at all -- it's just a bunch of numbers smushed together).
