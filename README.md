# mod_cspnonce

"mod_cspnonce" is an Apache2 module that makes it dead simple to add "nonce" values to the [CSP (`Content-Security-Policy`) headers](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy).

`nonce` values are a great way to enable CSP headers while still having dynamic scripts and styles in your web app. Here's an [example from MDN web docs showing a use of `nonce` with `script-src` CSP](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/script-src).

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

Or, a more realistic example:

```
<script nonce="<?= $_SERVER['CSP_NONCE'] ?>">
  var inline = 1;
</script>
```


## Why not use `mod_unique_id`?

Because `mod_unique_id` doesn't create base64 values (`@` symbols are not valid), plus it's overly bloated and uses 90's era random number generation (i.e. it's not random at all -- it's just a bunch of numbers smushed together).



## Building `mod_cspnonce`

On **Windows** you can use our pre-built binaries (see the Release tab on this github repository). Or you can load the .sln file in the latest Visual Studio and build it (note: the Apache headers and linker libraries need to be relative to wherever you clone this repository to -- see the library and header paths in the project file for exact details).

On **Unix (macOS, Linux, etc.)** you can use [the `apxs` utility provided with Apache](https://httpd.apache.org/docs/2.4/programs/apxs.html). The first step is typically installing the "development tools" for Apache Server. So, on Debian/Ubuntu, that might look like this:

```
sudo apt install apache2-dev
```

And on RedHat/CentOS that might look like this:

```
sudo yum install httpd-devel
```

Then, to compile & install the module, run `apxs` like so (note, you'll need to modify the path to wherever you cloned this repository to):

```
apxs -ci /your/path/to/mod_cspnonce.c
```
