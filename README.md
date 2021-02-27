<div align="center"><img src="https://letsencrypt.org/images/letsencrypt-logo-horizontal.svg"/></div>

# Letsencrypt
PHP SSL for [letsencrypt](https://letsencrypt.org) ACME v2.

Let’s Encrypt is a free, automated, and open certificate authority brought to you by the non-profit [Internet Security Research Group (ISRG)](https://www.abetterinternet.org).

`Only PHP client is provided here.`

Supporting RSA ECC

### Travis CI badge

[![Travis-ci](https://api.travis-ci.com/yakeing/php_letsencrypt.svg?branch=master&status=passed)](https://travis-ci.com/yakeing/php_letsencrypt)

### codecov badge

[![codecov](https://codecov.io/gh/yakeing/php_letsencrypt/branch/master/graph/badge.svg)](https://codecov.io/gh/yakeing/php_letsencrypt)

### Packagist badge

[![Version](http://img.shields.io/packagist/v/yakeing/php_letsencrypt.svg)](../../releases)
[![Downloads](http://img.shields.io/packagist/dt/yakeing/php_letsencrypt.svg)](https://packagist.org/packages/yakeing/php_letsencrypt/stats)

### Github badge

[![Downloads](https://badging.now.sh/github/downloads/yakeing/php_letsencrypt?icon=github)](../../)
[![Size](https://badging.now.sh/github/size/yakeing/php_letsencrypt?icon=github)](src)
[![tag](https://badging.now.sh/github/tag/yakeing/php_letsencrypt?icon=github)](../../releases)
[![license](https://badging.now.sh/static/label/license/555/MPL-2.0/fe7d37?icon=github)](LICENSE)
[![languages](https://badging.now.sh/static/label/language/555/PHP/34abef?icon=github)](../../search?l=php)

### Installation

Use [Composer](https://getcomposer.org) to install the library.
Of course, You can go to [Packagist](https://packagist.org/packages/yakeing/php_letsencrypt) to view.

```
    $ composer require yakeing/php_letsencrypt
```

### Initialization parameter

- [x] Sample：
```php
    $le = new letsencrypt();
    $option = array();
    $option['accountKey'] = '-----BEGIN PUBLIC KEY-----\nMIIBIjA....NjQIDAQA\n-----END PUBLIC KEY----';
```

### Get Directory

- [x] Sample：
```php
    echo $le->Directory();
```

### New Nonce

- [x] Sample：
```php
    echo $le->NewNonce();
```

### New User Registration

- [x] Sample：
```php
    //-----BEGIN PUBLIC KEY-----\nMIIBIjA....NjQIDAQA\n-----END PUBLIC KEY----
    $accountKey = $option['accountKey'];
    $userinfo = array('mailto:yakeing@github.com');

    $le->NewAccount($accountKey, $userinfo);
    $option['kid'] = $le->body['kid'];
```

### New Order

- [x] Sample：
```php
    //-----BEGIN PUBLIC KEY-----\nMIIBIjA....NjQIDAQA\n-----END PUBLIC KEY----
    $accountKey = $option['accountKey'];
    $domain = 'example.com';
    $kid = $option['kid']; //12345
    $type = 'dns';

    $le->NewOrder($accountKey, $domain, $kid, $type);
    $option['authorizations'] = $le->body['authorizations'][0];
    $option['finalize'] = $le->body['finalize'];
```

### Get challenges

- [x] Sample：
```php
    $jsonAuthz = file_get_contents($option['authorizations']); //array(.....)
    $authz = json_decode($jsonAuthz, true);
    foreach ($authz['challenges'] as $value) {
      if ('http-01' == $value['type']) {
        //$option['status'] = $value['status']; // valid
        $option['url'] = $value['url'];
        $option['token'] = $value['token'];
      }
    }
```

### Get Dns Txt

- [x] Sample：
```php
    //-----BEGIN PUBLIC KEY-----\nMIIBIjA....NjQIDAQA\n-----END PUBLIC KEY----
    $accountKey = $option['accountKey'];
    $token = $option['token']; //gDhhgh5Sdgf......fGDB0ceWadfg

    $ret = $le->GetDnsTxt($accountKey, $token);
    // FrZWluZ0BnaXR......odWIuY29tMFkwE
```

### Challenge 

- [x] Sample：
```php
    //-----BEGIN PUBLIC KEY-----\nMIIBIjA....NjQIDAQA\n-----END PUBLIC KEY----
    $accountKey = $option['accountKey'];
    $kid = $option['kid']; //12345
    $url = $option['url']; //https://~.api.letsencrypt.org/acme/authz-v3/*****
    $token = $option['token']; //gDhhgh5Sdgf......fGDB0ceWadfg
    $le->Challenge($accountKey, $kid, $url, $token);
    //$le->body['status'] == 'valid'
```

### Application for certificate issuance 

- [x] Sample：
```php
    //-----BEGIN PUBLIC KEY-----\nMIIBIjA....NjQIDAQA\n-----END PUBLIC KEY----
    $accountKey = $option['accountKey'];
    $kid = $option['kid']; //12345
    $finalizeUrl = $option['finalize']; //https://~.api.letsencrypt.org/acme/finalize/***/***';
    $csr = '-----BEGIN CERTIFICATE-----\nMIIEjjCCA3agAw....NjDNFu0Qg==-----END CERTIFICATE-----';
    $outCert = true;

    $le->GetCert($accountKey, $kid, $finalizeUrl, $csr, $outCert);
    $Cert = $le->body; //certificate
```

### Certificate revocation 

- [x] Sample：
```php
    $cerKey = '-----BEGIN PUBLIC KEY-----\nMIIBIjA....NjQIDAQA\n-----END PUBLIC KEY----';
    $Cert = '-----BEGIN CERTIFICATE-----\nMIIEA2agAw....HgdYhhE9gj\n==-----END CERTIFICATE-----';
    $reason = 0;

    $le->RevokeCert($cerKey, $cer, $reason);
```

### Domain name deauthorization

- [x] Sample：
```php
    //-----BEGIN PUBLIC KEY-----\nMIIBIjA....NjQIDAQA\n-----END PUBLIC KEY----
    $accountKey = $option['accountKey'];
    $kid = 'k6789';
    $authKid = 'd12345';

    $le->AuthzDeactivate($accountKey, $kid, $authKid);
```

### Change account communication key

- [x] Sample：
```php
    //-----BEGIN PUBLIC KEY-----\nMIIBIjA....NjQIDAQA\n-----END PUBLIC KEY----
    $accountKey = $option['accountKey'];
    $kid = $option['kid']; //12345
    $newAccountKey = '-----BEGIN PUBLIC KEY-----\nOIYGRjp8....ATy3ggQiyA\n-----END PUBLIC KEY----';;

    $le->KeyChange($accountKey, $kid, $newAccountKey);
```

### Account deactivation

- [x] Sample：
```php
    //-----BEGIN PUBLIC KEY-----\nMIIBIjA....NjQIDAQA\n-----END PUBLIC KEY----
    $accountKey = $option['accountKey'];
    $kid = $option['kid']; //12345

    $le->DeactivatedAccount($accountKey, $kid);
```

[Sponsor](https://github.com/yakeing/Documentation/blob/master/Sponsor/README.md)
---
If you've got value from any of the content which I have created, then I would very much appreciate your support by payment donate.

[![Sponsor](https://badging.now.sh/static/label/Sponsor/EA4AAA?icon=heart)](https://github.com/yakeing/Documentation/blob/master/Sponsor/README.md)

Author
---

weibo: [yakeing](https://weibo.com/yakeing)

twitter: [yakeing](https://twitter.com/yakeing)
