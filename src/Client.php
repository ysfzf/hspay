<?php

namespace Ycpfzf\Hspay;

class Client
{
    protected $host;
    protected $appkey;
    protected $appsecret;
    protected $privateKey;
    protected $hsPublicKey;

    public function __construct($host,$appkey,$appsecret,$privateKey,$hsPublicKey)
    {
        $this->host=$host;
        $this->appkey=$appkey;
        $this->appsecret=$appsecret;
        $this->privateKey=$privateKey;
        $this->hsPublicKey=$hsPublicKey;
    }

    public function pay($order){
        return $this->request('/v1/pay',$order);
    }

    public function refund($order){
        return $this->request('/v1/refund',$order);
    }

    public function query($order){
        return $this->request('/v1/order',$order);
    }

    static public function generateKey($bit,$path)
    {
        if(!is_dir($path)){
            mkdir($path,0777,true);
        }
        $res = openssl_pkey_new([
            'private_key_bits' => $bit,
            'digest_alg' => 'sha256'
        ]);
        if (!$res) {
            throw new \Exception('创建openssl对象失败');
        }
        $privateKey = '';

        // 获取公钥和私钥
        if (openssl_pkey_export($res, $privateKey)) {
            $details = openssl_pkey_get_details($res);

            if ($details && isset($details['key'])) {
                $publicKey = $details['key'];
                file_put_contents($path.'/private.pem',$privateKey);
                file_put_contents($path.'/pubice.pem',$publicKey);
            } else {
                throw new \Exception('获取私钥信息失败');
            }
        } else {
            throw new \Exception('生成openssl证书失败');
        }
    }

    protected function getSignStr($jsonStr, $url, $tm){
        $signStr = sprintf("%s\n%s\n%s\n%s\n%s", $url, $this->appkey, $tm, $this->appsecret, $jsonStr);
        return  base64_encode($signStr);
    }

    protected function sign($jsonStr,$url,$tm){
        $privKeyId = openssl_pkey_get_private($this->privateKey);
        $signature = '';
        $signStr = $this->getSignStr($jsonStr, $url, $tm);
        openssl_sign($signStr, $signature, $privKeyId,OPENSSL_ALGO_SHA256);
        openssl_free_key($privKeyId);
        return base64_encode($signature);
    }

    protected function verifySign($respSign,$respBody, $url, $tm){
        $publicKey=openssl_pkey_get_public($this->hsPublicKey);
        $signStr = $this->getSignStr($respBody, $url, $tm);
        return openssl_verify($signStr,base64_decode($respSign),  $publicKey, OPENSSL_ALGO_SHA256);
    }

    protected function request($url, $param){
        $tm=time();
        $jsonStr=json_encode($param);
        $sign= $this->sign($jsonStr, $url, $tm);
        $respHeaders=[];
        $ch = curl_init();
        curl_setopt_array($ch,[
            CURLOPT_URL => $this->host.$url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_ENCODING => '',
            CURLOPT_MAXREDIRS => 10,
            CURLOPT_TIMEOUT => 10,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
            CURLOPT_CUSTOMREQUEST => 'POST',
            CURLOPT_HEADERFUNCTION=>function($curl,$header)use(&$respHeaders){
                $len=strlen($header);
                $headers=explode(':',$header,2);
                if(count($headers)<2){
                    return $len;
                }
                $respHeaders[strtolower($headers[0])]=trim($headers[1]);
                return $len;
            },
            CURLOPT_POSTFIELDS=> $jsonStr,
            CURLOPT_HTTPHEADER => [
                'Content-Type: application/json',
                'Content-Length: ' . strlen($jsonStr),
                'X-Hsp-Timestamp: ' . $tm,
                'X-Hsp-Appkey: ' . $this->appkey,
                'X-Hsp-Sign: ' . $sign,
            ]
        ]);

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        if($httpCode!==200){
            throw new \Exception('发送请求失败,请检查参数,http code:'.$httpCode);
        }
        $respSign=$respHeaders['x-hsp-sign']??'';
        $respTimestamp=$respHeaders['x-hsp-timestamp']??'';
        $check=false;
        if($respSign){
            $check=$this->verifySign($respSign,$response,$url,$respTimestamp);
        }
        $data=json_decode($response,true);
        $data['check']=$check;
        return $data;
    }
}