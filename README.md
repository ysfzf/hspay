# 火速付PHP-SDK

## 安装

```
composer require ycpfzf/hspay
```

## 使用

```php
use Ycpfzf\Hspay\Client;

//以下参数由火速付进件时提供
$host='https://pay.xxx.yyy';
$appkey='HS_123456';
$appsecret='xxxyyyzzz';
$privateKey='-----BEGIN PRIVATE KEY-----
 ...
-----END PRIVATE KEY-----';
$hsPublicKey='-----BEGIN PUBLIC KEY-----
 ...
-----END PUBLIC KEY-----';

$client = new Client($host,$appkey,$appsecret,$privateKey,$hsPublicKey);
$resp=$client->pay([
    'orderNo'=>'xxxx',
    'amount'=>0.15,
    'goodsName'=>'测试商品',
    'notifyUrl'=>'http://www.xxyy.com/notify',
    'payWay'=>'MINI_PROGRAM',
    'channel'=>'WECHAT',
    'appId'=>'wx4186a2a7fxxxx',
    'userId'=>'oKFYv5AEybpl5v2uw1lyyyyyy'
]);

print_r($resp);
```