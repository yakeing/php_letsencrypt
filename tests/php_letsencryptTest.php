<?php
namespace php_letsencryptTest;
use php_letsencrypt;
use php_letsencrypt\Letsencrypt;
use PHPUnit\Framework\TestCase;
class php_letsencryptTest extends TestCase{
    public function testInitialization(){
        $le = new Letsencrypt();
        $le->location = 2;
        $le->url = 'https://acme-staging-v02.api.letsencrypt.org';
        $private = dirname(__FILE__).'/private.key';
        $ecc_domain = dirname(__FILE__).'/ecc_domain.csr';
        $ecc_private = dirname(__FILE__).'/ecc_private.key';
        $this->assertFileExists($private);
        $accountKey = file_get_contents($private);
        $this->assertFileExists($ecc_domain);
        $this->assertFileExists($ecc_private);
        $option = array(
            'csr' => $ecc_domain,
            'csrKey' => $ecc_private,
            'domain' => 'oauth.applinzi.com',
            'userinfo' => array('mailto:yakeing@github.com')
        );
        return array($le, $accountKey, $option);
    }

    /**
    * @depends testInitialization
    */
    public function testDirectory(array $args){
        list($le, $accountKey, $option) = $args;
        $Directory = $le->Directory();
        $this->assertTrue($Directory);
        return array($le, $accountKey, $option);
    }

    /**
    * @depends testDirectory
    */
    public function testNewAccount(array $args){
        list($le, $accountKey, $option) = $args;
        $NewAccount = $le->NewAccount($accountKey, $option['userinfo']);
        $this->assertTrue($NewAccount);
        //$this->assertEquals('10430142', $le->body['kid']);
        $option['kid'] = $le->body['kid'];
        return array($le, $accountKey, $option);
    }

    /**
    * @depends testNewAccount
    */
    public function testNewOrder(array $args){
        list($le, $accountKey, $option) = $args;
        $type = 'dns';
        $le->develop = true;
        $NewOrder_Multiple = $le->NewOrder($accountKey, array($option['domain']), $option['kid'], $type);
        $le->develop = false;
        $this->assertTrue($NewOrder_Multiple);
        $NewOrder = $le->NewOrder($accountKey, $option['domain'], $option['kid'], $type);
        $this->assertTrue($NewOrder);
        $option['authorizations'] = $le->body['authorizations'][0];
        $option['finalize'] = $le->body['finalize'];
        return array($le, $accountKey, $option);
    }

    /**
    * @depends testNewOrder
    */
    public function testAuthz(array $args){
        list($le, $accountKey, $option) = $args;
        $jsonAuthz = $le->GetAuthorizations($accountKey, $option['authorizations'], $option['kid']);
         $this->assertTrue($jsonAuthz);
        foreach ($le->body['body']['challenges'] as $value) {
            if ('http-01' == $value['type']) {
                $option['status'] = $value['status']; // valid
                $option['url'] = $value['url'];
                $option['token'] = $value['token'];
                break;
            }
        }
        $GetDnsTxt = $le->GetDnsTxt($accountKey, $option['token']);
        $this->assertTrue(is_string($GetDnsTxt));
        //$this->assertEquals('kpptQ58W......eGuEU', $GetDnsTxt);
        return array($le, $accountKey, $option);
    }


    /**
    * @depends testAuthz
    */
    public function testChallenge(array $args){
        list($le, $accountKey, $option) = $args;
        //if('valid' != $option['status']){
            $url = $option['url']; //$authz[0]['challenges']['url'] (http-01)
            $token = $option['token']; //$authz[0]['challenges']['token'] (http-01)
            $Challenge = $le->Challenge($accountKey, $option['kid'], $url, $token);
            $this->assertTrue($Challenge);
            $option['status'] = $le->body['status']; // valid
        //}
        $this->assertEquals('valid', $option['status']);
        return array($le, $accountKey, $option);
    }


    /**
    * @depends testChallenge
    */
    public function testGetCert(array $args){
        list($le, $accountKey, $option) = $args;
        $finalizeUrl = $option['finalize'];
        $csr = file_get_contents($option['csr']);
        $GetCert = $le->GetCert($accountKey, $option['kid'], $finalizeUrl, $csr);
        $this->assertTrue($GetCert);
        $Cert = strstr($le->body, '-----END', true);
        $option['Cert'] = $Cert.'-----END CERTIFICATE-----'; //certificate
        file_put_contents('/tmp/certificate.cer', $option['Cert']);
        return array($le, $accountKey, $option);
    }
    
    /**
    * @depends testGetCert
    */
    public function testAuthzDeactivate(array $args){
        list($le, $accountKey, $option) = $args;  
        $this->assertEquals(1, preg_match('/\/(\d+)$/', $option['authorizations'], $authKid));
        $AuthzDeactivate = $le->AuthzDeactivate($accountKey, $option['kid'], $authKid[1]);
        $this->assertTrue($AuthzDeactivate);
        return array($le, $accountKey, $option);
    }
    
    /**
    * @depends testAuthzDeactivate
    */
    public function testRevokeCert(array $args){
        list($le, $accountKey, $option) = $args;
        $csrKey = file_get_contents($option['csrKey']);
        $RevokeCert = $le->RevokeCert($csrKey, $option['Cert'], 5);
        $this->assertTrue($RevokeCert);
        $le->__destruct();
        return array($le, $accountKey, $option);
    }
  
    /*
    KeyChange($accountKey, $kid, $newAccountKey)
    DeactivatedAccount($accountKey, $kid)
    */
}
