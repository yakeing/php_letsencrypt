<?php
/**
        * PHP SSL for letsencrypt.com  acme v02
        * @author http://weibo.com/yakeing
        * @version 3.0
        * note: Must support CURL and Openssl
        * note: Account Key Must be RSA 2048 | 4096 or ECDSA P-256 | P-384 Digital certificate
        * https://acme-staging-v02.api.letsencrypt.org staging
 **/
namespace php_letsencrypt;
class Letsencrypt{
    private $keyIdentifier = array();
    public $develop = false;
    public $body = '';
    public $nonce = 0;
    public $location = 0; //location frequency(301/302)
    public $termsUrl = 'https://letsencrypt.org/documents/LE-SA-v1.2-November-15-2017.pdf'; //protocol
    public $url = 'https://acme-v02.api.letsencrypt.org';

    //construct
    public function __construct(){
        extension_loaded('openssl') or die('Must support Openssl');
        extension_loaded('curl') or die('Must support Curl');
    }//END __construct

    //Directory
    public function Directory(){
        $ret = $this->Http($this->url.'/directory');
        $this->body = $ret['body'];
        if($ret['code'] != 200){
            return false;
        }
        return true;
    }//END directory

    //Obtaining credentials (0)
    public function NewNonce(){
        if(empty($this->nonce)){
            list($usec, $sec) = explode(' ',microtime());
            $ret = $this->Http($this->url.'/acme/new-nonce?request='.(string)((float)$sec+(float)$usec));
            if($ret['code'] == 0){
                return false;
            }
        }
        return $this->nonce;
    }//END newNonce

    //New User Registration Registered users can skip (1)
    //$userinfo =array('mailto:yakeing@github.com')
    public function NewAccount($accountKey, $userinfo){
        $keyId = $this->GetKeyId($accountKey);
        $ret = $this->SignMessagehttp($keyId, 'new-acct', array(
            'termsOfServiceAgreed' => true, 'resource' => 'new-acct', 'contact'=> $userinfo
        ));
        // 200 OK Already registered 2018/8/20 Back to detail
        //if($ret['code'] == 200 && preg_match('/^Location:\s?https:\/\/[^\/]+\/acme\/acct\/(\d+)\r\n/sm', $ret['header'], $kid)){
            // $ret = $this->SignMessagehttp($keyId, 'acct/'.$kid[1], array(
            //  'onlyReturnExisting' => true, 'resource' => 'account'
            // ), $kid[1]);
            // if($ret['code'] != 200){
            //  return false;
            // }
        $this->body = json_decode($ret['body'], true);
        // 200 OK Already registered
        // 201 - Created new user
        if($ret['code'] == 200 || $ret['code'] == 201){
            preg_match('/^Location:\s?https:\/\/[^\/]+\/acme\/acct\/(\d+)\r\n/sm', $ret['header'], $kid);
            $this->body['kid'] = $kid[1];
            return true;
        }
        return false;
    }//END newAccount

    //New Order
    //gmdate(DATE_RFC3339); <= PHP 5.1.3
    public function NewOrder($accountKey, $domain, $kid, $type='dns'){
        $keyId = $this->GetKeyId($accountKey);
        $identifiers = array();
        if(is_array($domain)){
            foreach ($domain as $value) {
                $identifiers[] = array('type' => $type, 'value' => $value);
            }
        }else{
            $identifiers[] = array('type' => $type, 'value' => $domain);
        }
        //$thisTime = time();
        $ret = $this->SignMessagehttp($keyId, 'new-order',array(
            'identifiers' => $identifiers,
            //'notBefore' => gmdate('Y-m-d\TH:i:s\Z', $thisTime),
            //'notAfter' => gmdate('Y-m-d\TH:i:s\Z', $thisTime+604800),
            'resource' => 'new-order'
        ), $kid);
        $this->body = json_decode($ret['body'], true);
        if($ret['code'] != 201){ //Domain name error exits directly
            return false;
        }
        if(preg_match('/^Location: (.*?)\r\n/sm', $ret['header'], $location)){
            $this->body['location'] = $location[1];
        }
        $this->body['sign'] = $this->PrivkeySign($keyId);
        return true;
    } //END newOrder

    //Get DNS Record value
    //dns-01 TXT value
    public function GetDnsTxt($accountKey, $token){
        $keyId = $this->GetKeyId($accountKey);
        $sign = $this->PrivkeySign($keyId);
        return $this->Base64Url(hash('sha256', $token.'.'.$sign, true));
    } //END GetDnsTxt

    //Challenge(3)
    //Re-authorization required for each test failure
    //http://{domain}/.well-known/acme-challenge/{token}
    //Wildcards can only be verified using DNS-01
    //_acme-challenge.example.org. 300 IN TXT "gfj9Xq...Rg85nM"
    public function Challenge($accountKey, $kid, $url, $token){
        $keyId = $this->GetKeyId($accountKey);
        $sign = $this->PrivkeySign($keyId);
        $ret = $this->SignMessagehttp($keyId, $url,
                array( 'keyAuthorization' => $token.'.'.$sign)
        , $kid);
        if($ret['code'] != 200){
                $this->body = $ret['body'];
                return false;
        }
     $body = json_decode($ret['body'], true);
     if($body['status'] == 'valid'){
            $this->body =$body;
         return true;
     }
        for($i=0; $i<=5; ++$i){
            $ret = $this->Http($url);
            if($ret === false) return false;
            $challengeBody = json_decode($ret['body'], true);
            //Verification failed
            if(!isset($challengeBody['status']) || $challengeBody['status'] == 'invalid'){
                $this->body = $challengeBody['error'];
                return false;
            }
            //Waiting for verification
            if($challengeBody['status'] == 'pending'){
             sleep(2);//Delay 2 seconds
             continue;
            //Verification passed
            }else if($challengeBody['status'] == 'valid'){
             $this->body = $challengeBody;
             return true;
             break;
            }
        }//for
        return false;
    }//END challenge

    //Application for certificate issuance (4)
    public function GetCert($accountKey, $kid, $finalizeUrl, $csr, $outCert=true){
        $keyId = $this->GetKeyId($accountKey);
        $csrContent = $this->ImplodePem($csr);
        $ret = $this->SignMessagehttp($keyId, $finalizeUrl,
            array( 'resource' => 'finalize', 'csr' => $csrContent), $kid);
        $finalizeBody = json_decode($ret['body'], true);
        if($ret['code'] != 200 || $finalizeBody['status'] !== 'valid'){
            $this->body = $finalizeBody;
            return false;
        }
        if($outCert === false){
            $this->body = $finalizeBody;
            return true;
        }
        $cert = $this->Http($finalizeBody['certificate']);
        $this->body = $cert['body'];
        if($cert['code'] != 200){
            return false;
        }
        return true;
    } //END getCert

    //Certificate revocation (5)
    /* reason Option
    0      unspecified                   未指明
    1      keyCompromise            key 妥协
    2      cACompromise             CA妥协
    3      affiliationChanged         从属关系改变
    4      superseded                    被取代
    5      cessationOfOperation    停止使用
    6      certificateHold               证书保留
    7      value 7 is not used         空 (不要使用这个选项)
    8      removeFromCRL            从CRL中删除
    9      privilegeWithdrawn       撤销特权
    10    aACompromise              AA妥协
    */
    //$Key  they can be signed with either an account key pair or the key pair in the certificate.
    //certificate key Example: "jwk": /* certificate's public key */ ($kid=false)
    //account key Example: "kid": "https://example.com/acme/acct/evOfKhNU60wg" ($kid=****)
    public function RevokeCert($Key, $cer, $reason=0, $kid=false){
        $keyId = $this->GetKeyId($Key);
        $csrContent = $this->ImplodePem($cer);
        if($reason < 0 && $reason > 10) $reason = 0;
        //{jwkKublicOn} Nonexistent
        $ret = $this->SignMessagehttp($keyId, 'revoke-cert',
            array('resource' => 'revoke-cert', 'certificate' => $csrContent, 'reason' => $reason),
            $kid);
        if($ret['code'] == 200 || $ret['code'] == 409){
            return true;
        }
        $this->body = $ret['body'];
        return false;
    }//END revokeCert

    //Domain name deauthorization
    //https://{url}/acme/challenge/{AuthKid}/1234
    //https://{url}/acme/authz-v3/{AuthKid}
    public function AuthzDeactivate($accountKey, $kid, $authKid){
        $keyId = $this->GetKeyId($accountKey);
        $ret = $this->SignMessagehttp($keyId, 'authz-v3/'.$authKid,
            array('resource' => 'authz-v3', 'status' => 'deactivated'), $kid);
        $this->body = $ret['body'];
        if($ret['code'] == 200 || $ret['code'] == 409){
            return true;
        }
     return false;
    }//END authzDeactivate

    // Change account communication key
    public function KeyChange($accountKey, $kid, $newAccountKey){
        $newKeyId = $this->GetKeyId($newAccountKey);
        $keyId = $this->GetKeyId($accountKey);
        $newKeyJWK = $this->JWK($newKeyId);
        $payload = $this->SignMessagehttp($newKeyId, 'key-change',
            array('account' => $this->url.'/acme/acct/'.$kid,'newKey' => $newKeyJWK), false, true);
        $payload['resource'] = 'keyChange';
        $ret = $this->SignMessagehttp($keyId, 'key-change', $payload, $kid);
        $this->body = $ret['body'];
        if($ret['code'] != 200){
            return false;
        }else{
            return true;
        }
    }//END keyChange

    //Account deactivation
    public function DeactivatedAccount($accountKey, $kid){
        $keyId = $this->GetKeyId($accountKey);
        $ret = $this->SignMessagehttp($keyId, 'authz-v3/'.$kid,
            array('resource' => 'authz-v3', 'status' => 'deactivated'), $kid); //valid
        $this->body = $ret['body'];
        if($ret['code'] != 200){
            return false;
        }else{
            return true;
        }
    }//END deactivatedAccount

    //transfer data
    private function Http($url, $data = false){
        $header = array(
            'Expect:', //Prevent return HTTP/1.1 100 Continue
            'Content-Type: application/jose+json'
        );
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HEADER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, $header);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
        if(0<$this->location){
            curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
            curl_setopt($ch, CURLOPT_AUTOREFERER, true);
            curl_setopt($ch, CURLOPT_MAXREDIRS, $this->location);
        }
        if(!empty($data)){
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
        }
        $output = curl_exec($ch);
        if ($output === false) {
            //throw new Exception('curl failed: '.curl_error($ch));
            return array(
                'code' => 0,
                'body' => 'curl failed: '.curl_error($ch)
            );
        }
        $httpCode = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $headerSize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
        $header = substr($output, 0, $headerSize-4);
        $response = trim(substr($output, $headerSize));
        curl_close($ch);
        if($this->develop){
            print_r("<pre>");
            echo "\n---------START------------\n";
            echo "\nURL: ".$url."\n";
            if(!empty($data)){
                echo "\nPOST:\n";
                var_dump($data);
            }
            echo "\nheader:\n";
            print_r($header);
            echo "\n\nreturn:\n";
            print_r($response);
            echo "\n---------NED------------\n";
        }
        if(preg_match('/^Replay-Nonce:\s?(.*?)\r\n/sm', $header, $newNonce)){
            $this->nonce = $newNonce[1];
        }else{
            $this->nonce = 0;
        }
        return array(
            'header' => $header,
            'code' => $httpCode,
            'body' => $response
        );
    }//END HTTP

    // Get the KEY resource
    private function GetKeyId($accountKey){
        $id = md5($accountKey);
        if(!isset($this->keyIdentifier[$id])){
            $this->keyIdentifier[$id] = openssl_pkey_get_private($accountKey);
        }
        return $this->keyIdentifier[$id];
    }//END getKeyId

    // URL 64-bit encoding
    private function Base64Url($str, $isEncode=true){
        if($isEncode) $str = base64_encode($str);
        return str_replace( array('+', '/', '='), array('-', '_', ''), $str);
    }//END base64Url

    //Splicing (Remove the head and tail stitching lines)
    private function ImplodePem($pem, $isbase64Url=true){
        $lines = array_map('trim',explode("\n",trim($pem)));
        $lines = array_slice($lines , 1, -1);
        $lines = implode('', $lines);
        if($isbase64Url) $lines = $this->Base64Url($lines, false);
        return $lines;
    }//END implodePem

    // JSON Web Key (RSA / ECC private key)
    private function JWK($keyId){
        $keyInfo = openssl_pkey_get_details($keyId);
        if(isset($keyInfo['rsa'])){
            $ret = array(
                'e' => $this->Base64Url($keyInfo['rsa']['e']),
                'kty' => 'RSA',
                'n' => $this->Base64Url($keyInfo['rsa']['n'])
            );
        }else{ // $keyInfo['ec']
            //$keyInfo['ec']["curve_name"] = prime256v1 / secp384r1 / secp521r1
            if($keyInfo['bits'] == 256 || $keyInfo['bits'] == 384){
                $crv = 'P-'.$keyInfo['bits'];
            }else{
                throw new Exception('ECDSA  Only accept prime256v1 or secp384r1 Your encryption length is '.$keyInfo['ec']["curve_name"].' ('.$keyInfo['bits'].')');
            }
            $keyStr = $this->ImplodePem($keyInfo['key'], false);
            $hexKey = base64_decode($keyStr);
            $pubLen = strlen($hexKey)-65;
            $pub = substr($hexKey, $pubLen); //public key(The last 65 characters)
            $pubText = substr($pub, 1); //Remove the pub compression label (04)
            $len = strlen($pubText)/2;
            list($keyX, $keyY) = str_split($pubText, $len);
            $x = $this->Base64Url($keyX); //43
            $y = $this->Base64Url($keyY); //43
            $ret = array('crv' => $crv, 'kty' => 'EC', 'x' => $x, 'y' => $y);
            if($this->develop){
                $priv = substr($hexKey, 0, $pubLen); //private key
                echo "\nECC priv:";
                var_dump(bin2hex($priv));
                echo "ECC pub:";
                var_dump(bin2hex($pub));
                echo "ECC len: ".$len."\n";
            }
        }
        return $ret; //ksort($ret);
    }//END JWK

    // Privkey Sign
    private function PrivkeySign($keyId){
        $jwk = $this->JWK($keyId);
        return $this->Base64Url(openssl_digest(json_encode($jwk), 'sha256', true));
    }//END privkeySign

    // Sign Message
    private function SignMessage($keyId, $message, $type){
        if(openssl_sign($message, $sign, $keyId, 'sha256')){// OPENSSL_ALGO_SHA256
            if($type == 'EC'){
                $hex = bin2hex($sign);
                $sequenceLength = hexdec(substr($hex, 2, 2)); //sequence Integer (Does not include labels and lengths)
                $integer = substr($hex, 4, $sequenceLength*2); //DER Integer
                $integerRPosition = hexdec(substr($integer,0, 2));//Integer R Position
                $integerRLength = hexdec(substr($integer,2, 2));//Integer R Length (20/21)
                $deviationR = ($integerRLength-32); //deviation R
                $r = substr($sign,$integerRPosition+$deviationR+2, 32);//Integer R
                $integerSBegin = $integerRPosition*2+$integerRLength*2;
                $integerSPosition = hexdec(substr($integer,$integerSBegin, 2));//Integer S Position
                $integerSLength = hexdec(substr($integer,$integerSBegin+2, 2));//Integer S Length (20/21)
                $deviationS = ($integerSLength-32); //deviation S
                $s = substr($sign,($integerSBegin/2)+$integerSPosition+$deviationS+2, 32);//Integer S
                $sign = $r.$s;
                if($this->develop){
                    echo "\nSignature hex:";
                    var_dump($hex);
                    $sequence = substr($hex, 0, 2); //Sequence tag 0x30
                    echo "Signature SEQUENCE: 0x".$sequence;
                    echo "\nSignature SEQUENCE Length:".$sequenceLength;
                    echo "\nSignature INTEGER:";
                    var_dump($integer);
                    echo "Signature R:";
                    var_dump(bin2hex($r));
                    echo "Signature S:";
                    var_dump(bin2hex($s));
                    echo "Sign Value:";
                    var_dump($this->Base64Url($sign));
                    echo "\n";
                }
            }
            return $this->Base64Url($sign);
        }
        return false;
    }//END signMessage

    // Sign Message transfer data
    private function SignMessagehttp($keyId, $url, $payload, $kid=false, $outRequest=false){
        if(strrpos(strtolower($url), 'http') !== 0){
            $url = $this->url.'/acme/'.$url;
        }
        $protected =  array('url' => $url);
        if(!$outRequest){
            $protected['nonce'] = $this->NewNonce();
        }
        //jwk Requests only for new accounts and revocation of certificate resources
        //kid Applies to all other requests
        if(is_bool($kid)){
            $protected['jwk'] = $this->JWK($keyId);
            $kty = $protected['jwk']['kty'];
        }else{
            $keyInfo = openssl_pkey_get_details($keyId);
            $kty = isset($keyInfo['rsa']) ?  'RSA' : 'EC';
            $protected['kid'] = $this->url.'/acme/acct/'.$kid;
        }
        if($kty == 'EC'){ //ECC
            $protected['alg'] = 'ES256';
        }else{ //RSA
            $protected['alg'] = 'RS256';
        }
        //$protected = array('nonce' => $nonce);
        //$header = array('alg' => $alg, 'jwk' => $jwk);
        //PHP 5.4 version str_replace('\\/', '/',  json_encode($payload));
        ksort($payload);
        ksort($protected);
        $payload64 = $this->Base64Url(json_encode($payload, JSON_UNESCAPED_SLASHES));
        $protected64 = $this->Base64Url(json_encode($protected, JSON_UNESCAPED_SLASHES));
        $sign = $this->SignMessage($keyId, $protected64.'.'.$payload64, $kty);
        $requestData = array(
            //'header' => $header,
            'protected' => $protected64,
            'payload' => $payload64,
            'signature' => $sign
        );
        if($this->develop){
            echo "\n\n----------------- POST Raw data : --------------------\n";
            $Data = array(
                //'header' => $header,
                'protected' => $payload,
                'payload' => $protected,
                'signature' => $sign
            );
            print_r($Data);
        }
        if($outRequest){
            return $requestData;
        }else{
            return $this->Http($url, json_encode($requestData));
        }
    }//END signMessageHttp

    //destruct
    public function __destruct(){
        foreach($this->keyIdentifier as $key){
            openssl_free_key($key);
            $this->nonce = 0;
        }
    } //END __destruct
}
