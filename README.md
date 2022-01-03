# DNS client for PHP

[![StyleCI](https://github.styleci.io/repos/442167162/shield?branch=master&style=flat)](https://github.styleci.io/repos/442167162?branch=master)
[![License](http://poser.pugx.org/sztyup/dns/license)](https://packagist.org/packages/sztyup/dns)

## Installation

The recommended way is by
[Composer](https://getcomposer.org/).

```bash
composer require sztyup/dns
```

#Usage

```php
$client = new \Sztyup\Dns\SecureClient();
$client->query('google.com', 'A');
```

## License

This package is available under the MIT License (MIT). Please see [License File](LICENSE) for more information.
