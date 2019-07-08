#!/usr/bin/env python3
# coding=utf-8
# Author: shi2019624
"""
create_rsa_key() - 创建RSA密钥
my_encrypt_and_decrypt() - 测试加密解密功能
rsa_sign() & rsa_signverify() - 测试签名与验签功能
"""

import base64
import hashlib
import json
import re

from Crypto.Cipher import AES as _AES
from binascii import b2a_hex, a2b_hex

from Crypto.Hash import SHA1
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15


pubkey = '''MIGJAoGBAIJqqXE0mkNSMwsaXMuCUC5vpItkM/wfF+kfOqCR5y5VGlDg46Ug4dIU
YYdJFTJDkXXy8zMxxNZbMZrFX5tUcLwTSr3DWFR5S73niCfTXC3q8rc3zagP83RH
1luKt44ZkH/B5pbxzDyNQeNz+P03ijWlX69w5hSxTbG3m9dHAUQZAgMBAAE='''

privatekey = '''MIICXQIBAAKBgQCCaqlxNJpDUjMLGlzLglAub6SLZDP8HxfpHzqgkecuVRpQ4OOl
IOHSFGGHSRUyQ5F18vMzMcTWWzGaxV+bVHC8E0q9w1hUeUu954gn01wt6vK3N82o
D/N0R9ZbireOGZB/weaW8cw8jUHjc/j9N4o1pV+vcOYUsU2xt5vXRwFEGQIDAQAB
AoGARVISnKS8NnpzvTwXBOlQW05mZN0vMJ0KZZR+4iiLfDoqEcFn3zbaMYM5z+IN
zTjTEaHAmX6jxNiWRlERH4xDmz/45z0BUXe6/1zsLFk/NKW6QXaOHLBp3p26uRVU
dUXp9ItZch3iHZvpmUdwbj6DDUGwIWvt4IGAWkrxIHyxka0CQQDVqykO2B0EU39S
SgxHiEGE+l7nNVlT2faDUIPhtcmCt70sRwKhI+6Y+zmFxE2+3zwbDmG92dzskQCQ
Z0IcG1frAkEAnEEhgQC3cCy+mhinzCYhHNlUwmOP/ytOC/HQdTUpc1mGUizJHz+1
/iioHXJlkEceg8JuoSiCDlo0AYvgopM3CwJBALbM4aqegGzEFsjLKyhDzXI8VddP
UCYp8vozdzEyur0H/2OTOQ+t0yK0xGjKIo2rJRwsuLiZXKZUA/yHKwsq5ZMCQAVw
OuNLjBbqZ8PjQcvYM+TWJ54Qaw2dizzdML0zmXq7TfKEPofI5uOutJM5zREleIlr
dgBD8argNtkq7imaaBsCQQC60+SIibOUSbN/7sY5Q8oNQPTQAZFPRDOMc70sVh1U
ktKKxf7B/9tfDqYYx/w/BkxTH5skqqSVbGR3fiM81Wue'''


class RSA_AES:
    def __init__(self, key: str):
        """Init aes object used by encrypt or decrypt.
        AES/ECB/PKCS5Padding  same as aes in java default.
        """
        self.aes = _AES.new(bytes.fromhex(self.get_sha1prng_key(key)), _AES.MODE_ECB)

    @staticmethod
    def get_sha1prng_key(key: str) -> bytes:
        signature = hashlib.sha1(key.encode()).digest()
        signature = hashlib.sha1(signature).hexdigest().upper()[:32]
        return signature

    @staticmethod
    def padding(s: str) -> str:
        pad_num = 16 - len(s) % 16
        return s + pad_num * chr(pad_num)

    @staticmethod
    def unpadding(s):
        padding_num = ord(s[-1])
        return s[: -padding_num]

    def encrypt_to_hex(self, content_str):
        """
        使用AES进行加密
        :param content_str: 要加密的内容 str
        :return: 加密得到的16进制 hex
        """
        try:
            content_bytes = self.padding(content_str).encode()
            ciphertext_bytes = self.aes.encrypt(content_bytes)
        except Exception() as e:
            print('AES内容加密失败', e)
        return ciphertext_bytes.hex().upper()

    def decrypt_from_base64(self, ciphertext_bs64):
        """
        使用AES进行解密
        :param content_str: 加密得到的16进制 hex
        :return: 加密的内容 str
        """
        try:
            ciphertext_bytes = bytes.fromhex(ciphertext_bs64.lower())
            content_bytes = self.aes.decrypt(ciphertext_bytes)
            content_str = self.unpadding(content_bytes.decode())
        except Exception() as e:
            print('AES内容解密失败', e)
        return content_str


    def MD5_encrypt(self, content_text):
        """
        对加密内容进行md5加密
        :param content_text: 加密内容
        :return: 加密得到的16进制 hex
        """
        try:
            hl = hashlib.md5()
            hl.update(content_text.encode(encoding='utf-8'))
            md5 = hl.hexdigest()
        except Exception as e:
            print("MD5加密失败", e)
        return md5


    def rsa_sign(self, md5):
        """
        对md5加密内容进行签名， md5加密参数需要是字符串
        :param key: 私钥
        :param text: 需要签名的文本 bytes
        :return: base64编码的签名信息 bytes
        """
        try:
            private_key = RSA.importKey(base64.b64decode(privatekey))
            hash_obj = SHA1.new(md5.encode())
            signer = pkcs1_15.new(private_key)
            signature = signer.sign(hash_obj)
        except Exception as e:
            print("加签失败", e)
        return b2a_hex(signature).decode()


    def rsa_signverify(self, md5, signature):
        """
        验签方法
        :param key: 公钥
        :param text: 需要验签的文本 bytes
        :param signature: base64编码的签名信息 bytes
        :return: 验签结果 bool
        """
        public_key = RSA.importKey(base64.b64decode(pubkey))
        hash_obj = SHA1.new(md5.encode())
        verifier = pkcs1_15.new(public_key)
        try:
            verifier.verify(hash_obj, a2b_hex(signature.encode()))
            print('The signature is valid.')
            return True
        except (ValueError, TypeError):
            print('The signature is invalid.')

    def send_json(self, request_id, request_type, encrypt_massage):
        """
        加密加签发送
        :param request_type: 业务类型选择
        :param encrypt_massage: 要加密发送的内容
        :return: 加签json
        """
        content_text = self.SplitString("", request_id, request_type, encrypt_massage)
        md5 = self.MD5_encrypt(content_text)
        signature = self.rsa_sign(md5)
        result = self.SplitString(signature, request_id, request_type, encrypt_massage)
        return json.dumps(result)


    def get_decr_message(self, json_data):
        """
        对接收的字符串进行md5加密以及验签解密
        :param json_data: 获取的Java加密json字符串
        :return: 加签json
        """
        str1 = str(json_data)
        if "sign" in str1:
            dict_1 = json.loads(str1)
            signature = dict_1["head"]["sign"]
            encr_message = dict_1["body"]["encrypt_message"]
            ss = ''',"":""'''
            str_md5 = re.sub(r',?"sign":(["a-z0-9]*,?)', ss, str1)
            md5 = self.MD5_encrypt(str_md5)
            self.rsa_signverify(md5, signature)
            result = rsa_aes.decrypt_from_base64(encr_message)
            print("解密获取的内容：%s" % result)


    def SplitString(self, sign, request_id, request_type, encrypt_massage):
        """
         拼接返回报文字符串
        :param request_type: 业务类型选择
        :param encrypt_massage: 要加密发送的内容
        :return: 拼接的字符串
        """
        notSign = ',"":""'
        resString='{"head":{"partner":"'+DIANEI+'",'
        resString += '"response_id":"'+request_id+'",'
        resString += '"response_type":"'+request_type+'"'
        if (sign != "" and sign != ""):
            notSign=sign
            resString += ',"sign":"'+notSign+'"'
        resString += "},"
        resString += '"body":{"encrypt_message":"'+rsa_aes.encrypt_to_hex(str(encrypt_massage))+'"'
        resString += "}}"
        return resString


if __name__ == '__main__':

    PASSWORD = "123456"
    DIANEI = "diannei"
    request_id = "20190423202512345622"
    request_type = "Q1"
    encrypt_massage = {
        "certificate_no": "320621198902146578940",
        "auth_code": "12345623"
    }
    json_data = '{"head":{"partner":"diannei","request_id":"943f58915a5a479bb723f6b7fe9a8008","request_type":"Q1","sign":"796bf27ad880c72afe6a6555ff8ec74b35d0dff1e8493cdd1d426b4f6afc642b12c5faffe60452d07b5129fa80bb77a7973ca04c2a002c07aeb508abe28de6672125b8634d7662f7ee154f52b6749ee5a1886208b1b20fa523fba968d093263dc44419fb2c31da64b0a1f6dd38c6edf05274f800f3fdd22dfcea1e18bc6b7640"},"body":{"encrypt_message":"B524F3F4E45B312BFE43396D2D0924B6AEA5BFBA822E31CD58F2EA258C380609EA393CF027DBE55D82D7E405EA191189049BC99B40A6EF094E9CFFBF160E28E3CB53B966BB008522E33737F44C63B4E7"}}'

    rsa_aes = RSA_AES(PASSWORD)
    rsa_aes.send_json(request_id, request_type, encrypt_massage)
    rsa_aes.get_decr_message(json_data)
