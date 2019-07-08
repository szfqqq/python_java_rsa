package com.unidt.services;

import com.alibaba.fastjson.JSONObject;
import com.unidt.bean.rsa.RsaBean;
import com.unidt.helper.common.*;
import org.bouncycastle.jcajce.provider.symmetric.AES;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.RequestBody;


import java.util.*;

import static com.unidt.helper.common.AESHelper.*;
import static com.unidt.helper.common.DigitalSignature.attestation;
import static com.unidt.helper.common.DigitalSignature.signature;
import static com.unidt.helper.common.HttpRequestUtil.httpStringPostRequest;



@Service
public class RsaService {

    @Autowired
    KeyGenerater keyGenerater;





    /**
     *  确认是否可以上传影像请求
     * @param resBean
     * @return
     */
    public String  getCheckUpload(RsaBean resBean) {
        JSONObject doc = new JSONObject();
        JSONObject head = new JSONObject();
        JSONObject body = new JSONObject();
        String resStr = "";
        if (resBean == null || StringUtils.isEmpty(resBean.certificate_no)) {
            return ReturnResult.createResult(Constants.API_CODE_NOT_FOUND, "入参错误！").toJSONString();
        }
        String uuid = GetUUID32.getUUID32();

        head.put("partner", Constants.PARTNER);
        head.put("request_id", uuid);
        head.put("request_type", Constants.REQUEST_Q1);
        head.put(" ", "\\r\\n");

        JSONObject bosy_json = new JSONObject();
        bosy_json.put("certificate_no", resBean.certificate_no);
        bosy_json.put("auth_code", resBean.auth_code);
        String password = Constants.AES_PASSWORD;
        String resSign="";
        try {
//            System.out.println(bosy_json.getClass().toString());
//            System.out.println("00000000000");
//            System.out.println(bosy_json.toString().getClass().toString());
//            System.out.println("1111111111111");
//            System.out.println(password);
            byte[] encode = encrypt(bosy_json.toString(), password);
//            System.out.println(encode);
//            System.out.println("22222222222222");
//            System.out.println(encode.getClass().toString());
            String encrypt_message = parseByte2HexStr(encode);
//            System.out.println("33333333333333");
//            System.out.println(encrypt_message.getClass().toString());
            System.out.println("密文字符串：" + encrypt_message);
            body.put("encrypt_message", encrypt_message);
            doc.put("body", body);
            RsaBean rsaBean = new RsaBean();
            rsaBean.partner = Constants.PARTNER;
            rsaBean.request_id = uuid;
            rsaBean.request_type = Constants.REQUEST_Q1;
            rsaBean.encrypt_message = encrypt_message;
            String sign ="";
            String strSign = AESHelper.SplitString(sign,rsaBean);
//            System.out.println(strSign);
//            System.out.println(strSign.getClass().toString());
//            System.out.println(123456);
            String request_str = keyGenerater.hashKeyForDisk(strSign);
            System.out.println(request_str);
            System.out.println("2222222222222");
            sign = signature(request_str);
            System.out.println(sign);
            System.out.println("44444444444444444444");
            sign=",\"sign\":\""+sign+"\"";
            resSign= AESHelper.SplitString(sign,rsaBean);

        } catch (Exception e) {
            e.printStackTrace();
            return ReturnResult.createResult(Constants.API_CODE_FORBIDDEN, "调用异常！"+e).toJSONString();
        }
        System.out.println(resSign);
        System.out.println("333333333333333");
        return resSign;
    }




    /**
     *  确认是否可以上传影像请求
     * @param resBean
     * @return
     */
    public String  getResultSign(RsaBean resBean) {
        JSONObject doc = new JSONObject();
        JSONObject head = new JSONObject();
        JSONObject body = new JSONObject();
        String resStr = "";
        if (resBean == null || StringUtils.isEmpty(resBean.certificate_no)) {
            return ReturnResult.createResult(Constants.API_CODE_NOT_FOUND, "入参错误！").toJSONString();
        }
        String uuid = GetUUID32.getUUID32();

        head.put("partner", Constants.PARTNER);
        head.put("request_id", uuid);
        head.put("request_type", Constants.REQUEST_Q1);
        head.put(" ", " ");
        JSONObject bosy_json = new JSONObject();
        bosy_json.put("certificate_no", resBean.certificate_no);
        bosy_json.put("auth_code", resBean.auth_code);
        String password = Constants.AES_PASSWORD;
        String resSign = "";
        try {
            byte[] encode = encrypt(bosy_json.toString(), password);
            String encrypt_message = parseByte2HexStr(encode);
            System.out.println("密文字符串：" + encrypt_message);
           /* doc.put("head", head);
            body.put("encrypt_message", encrypt_message);
            doc.put("body", body);
            //改为全部加签
            String request_str = keyGenerater.hashKeyForDisk(doc.toString());
            String sign = signature(request_str);
            head.put("sign", sign);
            doc.put("head", head);
            RsaBean rsa = new RsaBean();
            rsa.head=head;
            rsa.body =body;*/

            String sign ="";
            RsaBean rsaBean = new RsaBean();
            rsaBean.partner =Constants.PARTNER;
            rsaBean.request_id = uuid;
            rsaBean.request_type = Constants.REQUEST_Q1;
            rsaBean.encrypt_message = encrypt_message;
            String strSign = AESHelper.SplitString(sign,rsaBean);
            String request_str = keyGenerater.hashKeyForDisk(strSign);
            sign =signature(request_str);
            sign=",\"sign\":\""+sign+"\"";
            resSign = AESHelper.SplitString(sign,rsaBean);
           // String result = this.set_userInfo(rsa);/*
            String url = Constants.SIMULATOR_PATH;
            System.out.println("上传验证接口"+url);
            String result = httpStringPostRequest(url,resSign);
            if (StringUtils.isEmpty(result)) {
                return ReturnResult.createResult(Constants.API_CODE_FORBIDDEN, "验证失败！").toJSONString();
            }
            //验证返回签名，然后解析报文秘闻encrypt_message
            JSONObject res_json = JSONObject.parseObject(result);
            if (res_json != null && res_json.get("head") != null) {
                // 获取输出结果中的加密内容，进行解密
                JSONObject head_json = JSONObject.parseObject(res_json.get("head").toString());
                JSONObject res_body = JSONObject.parseObject(res_json.get("body").toString());
                String res_sign = head_json.get("sign") == null ? "" : head_json.get("sign").toString();
                JSONObject check_json = head_json.fluentRemove("sign");
                JSONObject newSign = new JSONObject();
                newSign.put("head",check_json);
                newSign.put("body",res_json.get("body"));

                RsaBean reqBean = new RsaBean();
                reqBean.response_id = head_json.get("response_id").toString();
                reqBean.response_code = head_json.get("response_code").toString();
                reqBean.response_type =head_json.get("response_type").toString();
                reqBean.response_result =head_json.get("response_result").toString();
                reqBean.encrypt_message =  res_body.get("encrypt_message").toString();
                resSign = AESHelper.ResSplitString("",reqBean);
                System.out.println(resSign);
                String check_str = keyGenerater.hashKeyForDisk(resSign);
                System.out.println(res_sign);
                System.out.println(check_str);
                System.out.println("lalalalalalalaallalalalalalalallalalalalallalall");
                if (!attestation(res_sign, check_str)) {
                    System.out.println("验签失败");
                    return ReturnResult.createResult(Constants.API_CODE_FORBIDDEN, "验签失败！").toJSONString();
                } else {
                    System.out.println("验签成功");

                    if (res_body.get("encrypt_message") != null) {
                        String bodyStr = res_body.get("encrypt_message").toString();
                        //序列号
                        byte[] decode = parseHexStr2Byte(bodyStr);
                        //解密
                        byte[] decryptResult = decrypt(decode, password);
                        System.out.println("解密后：" + new String(decryptResult, "UTF-8")); //不转码会乱码
                        resStr = new String(decryptResult);
                        res_json = JSONObject.parseObject(resStr);
                        res_json.put("res_head", head_json);
                        //统一返回处理
                        return ReturnResult.createResult(Constants.API_CODE_OK, "接口调用成功！",res_json).toJSONString();
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
            return ReturnResult.createResult(Constants.API_CODE_FORBIDDEN, "调用异常！"+e).toJSONString();
        }

        return ReturnResult.createResult(Constants.API_CODE_FORBIDDEN, "接口曹祖异常返回").toJSONString();
    }

    /**
     * 审核结果
     * @param resBean
     * @return
     */
    public String get_upload(RsaBean resBean){
        JSONObject doc = new JSONObject();
        JSONObject head = new JSONObject();
        JSONObject body = new JSONObject();
        String resStr ="";
        if(resBean ==null||StringUtils.isEmpty(resBean.order_no)){
            return ReturnResult.createResult(Constants.API_CODE_NOT_FOUND, "入参错误！").toJSONString();
        }
        String uuid = GetUUID32.getUUID32();
        /*head.put("partner", Constants.PARTNER);
        head.put("request_id", uuid);
        head.put("request_type", resBean.request_type);
        head.put("", "");*/
        JSONObject bosy_json = new JSONObject();
        bosy_json.put("order_no",resBean.order_no);
        bosy_json.put("auth_code",resBean.audit_code);
        bosy_json.put("audit_result",resBean.audit_result);
        String password=Constants.AES_PASSWORD;
        byte[] encode = encrypt(bosy_json.toString(), password);
        String encrypt_message = parseByte2HexStr(encode);
        System.out.println("密文字符串：" + encrypt_message);
        doc.put("head", head);
        body.put("encrypt_message",encrypt_message);
        doc.put("body",body);
        String sign ="";
        String resSign= "";
        try{
            RsaBean rsaBean = new RsaBean();
            rsaBean.partner =Constants.PARTNER;
            rsaBean.request_id = uuid;
            rsaBean.request_type = resBean.request_type;
            rsaBean.encrypt_message = encrypt_message;
            String strSign = AESHelper.SplitString(sign,rsaBean);
            String request_str = keyGenerater.hashKeyForDisk(strSign.toString());
            sign =signature(request_str);
            sign =",\"sign\":\""+sign+"\"";
            resSign = AESHelper.SplitString(sign,rsaBean);

            head.put("sign",sign);
            doc.put("head",head);
            //封装好入参
            String url=Constants.CALLBACK_PATH;
            System.out.println("结果验证接口:"+url);
            String result = httpStringPostRequest(url,resSign);
            if(StringUtils.isEmpty(result)){
                return ReturnResult.createResult(Constants.API_CODE_FORBIDDEN,"验证失败！").toJSONString();
            }
            //验证返回签名，然后解析报文密文  encrypt_message
            JSONObject json = new JSONObject();
            //JSONObject   res_json = json.getJSONObject(result);
            JSONObject res_json = JSONObject.parseObject(result);

            if(json !=null&& res_json.get("head")!=null){
                // 获取输出结果中的加密内容，进行解密
               // JSONObject head_json = json.getJSONObject(res_json.get("head").toString());
                JSONObject newHead = new JSONObject();

                JSONObject head_json = JSONObject.parseObject(res_json.get("head").toString());
                JSONObject res_body = JSONObject.parseObject(res_json.get("body").toString());
                newHead.put("response_id",head_json.get("response_id"));
                newHead.put("response_type",head_json.get("response_type"));
                newHead.put("response_code",head_json.get("response_code"));
                newHead.put("response_result",head_json.get("response_result"));
                newHead.put("","");
                String res_sign = head_json.get("sign")==null?"": head_json.get("sign").toString();
                JSONObject check_json =  head_json.fluentRemove("sign");
                // String cnheck_str = keyGenerater.hashKeyForDisk(check_json.toString());

                RsaBean reqBean = new RsaBean();
                reqBean.response_id = head_json.get("response_id").toString();
                reqBean.response_code = head_json.get("response_code").toString();
                reqBean.response_type =head_json.get("response_type").toString();
                reqBean.response_result =head_json.get("response_result").toString();
                reqBean.encrypt_message =  res_body.get("encrypt_message").toString();
                resSign = AESHelper.ResSplitString("",reqBean);
                System.out.println(resSign);
                String check_str = keyGenerater.hashKeyForDisk(resSign.toString());

                if(!attestation(res_sign,check_str)){
                    System.out.println("验签失败");
                    return ReturnResult.createResult(Constants.API_CODE_FORBIDDEN,"验签失败！").toJSONString();
                }else {
                    System.out.println("验签成功");

                    if (res_body.get("encrypt_message") != null) {
                        String bodyStr = res_body.get("encrypt_message").toString();
                        //序列号
                        byte[] decode = parseHexStr2Byte(bodyStr);
                        //解密
                        byte[] decryptResult = decrypt(decode, password);
                        System.out.println("解密后：" + new String(decryptResult, "UTF-8")); //不转码会乱码
                        resStr = new String(decryptResult);
                        res_json = JSONObject.parseObject(resStr);
                        res_json.put("res_head", head_json);
                        //统一返回处理
                        return ReturnResult.createResult(Constants.API_CODE_OK, "接口调用成功！", res_json).toJSONString();
                    }
                }
            }
        }catch (Exception e){
            e.printStackTrace();
            return ReturnResult.createResult(Constants.API_CODE_FORBIDDEN, "调用异常！"+e).toJSONString();
        }
        return doc.toString();
    }

    /**
     * 审核结果
     * @param resBean
     * @return
     */
    public String submit_res(RsaBean resBean){
        JSONObject doc = new JSONObject();
        JSONObject head = new JSONObject();
        JSONObject body = new JSONObject();
        String resStr ="";
        if(resBean ==null||StringUtils.isEmpty(resBean.order_no)){
            return ReturnResult.createResult(Constants.API_CODE_NOT_FOUND, "入参错误！").toJSONString();
        }
        String uuid = GetUUID32.getUUID32();
        head.put("partner", Constants.PARTNER);
        head.put("request_id", uuid);
        head.put("request_type", resBean.request_type);
        head.put("", "");
        JSONObject bosy_json = new JSONObject();
        bosy_json.put("order_no",resBean.order_no);
        bosy_json.put("auth_code",resBean.audit_code);
        bosy_json.put("audit_result",resBean.audit_result);
        String resSign ="";
        try{
            String password=Constants.AES_PASSWORD;
            byte[] encode = encrypt(bosy_json.toString(), password);
            String encrypt_message = parseByte2HexStr(encode);
            System.out.println("密文字符串：" + encrypt_message);

           /* String request_str = keyGenerater.hashKeyForDisk(head.toString());
            String sign =signature(request_str);
            head.put("sign",sign);
            doc.put("head",head);
            body.put("encrypt_message",encrypt_message);
            doc.put("body",body);*/

            String sign ="";
            RsaBean rsaBean = new RsaBean();
            rsaBean.partner =Constants.PARTNER;
            rsaBean.request_id = uuid;
            rsaBean.request_type = resBean.request_type;
            rsaBean.encrypt_message = encrypt_message;
            String strSign = AESHelper.SplitString(sign,rsaBean);
            String request_str = keyGenerater.hashKeyForDisk(strSign.toString());
            String ss  =signature(request_str);
            sign =",\"sign\":\""+ss+"\"";
            resSign = AESHelper.SplitString(sign,rsaBean);

        }catch (Exception e){
            e.printStackTrace();
            return ReturnResult.createResult(Constants.API_CODE_FORBIDDEN, "调用异常！"+e).toJSONString();
        }
        return resSign;
    }


    public String set_userInfo(RsaBean resBean) throws Exception {

        JSONObject doc = new JSONObject();
        JSONObject newHead = new JSONObject();
        JSONObject newBody = new JSONObject();
        String password=Constants.AES_PASSWORD;
        String resStr ="";
        String  bodyStr ="";
        try{

            if(resBean.head!=null){
                // 获取输出结果中的加密内容，进行解密
                //JSONObject head_json = json.getJSONObject(resBean.head.toJSONString());
                JSONObject head_json =  resBean.head;
                String res_sign = head_json.get("sign")==null?"": head_json.get("sign").toString();
                JSONObject check_json =  head_json.fluentRemove("sign");

                JSONObject newSign = new JSONObject();
                newSign.put("head",check_json);
                newSign.put("body",resBean.body);
                String cnheck_str = keyGenerater.hashKeyForDisk(newSign.toString());
                if(!attestation(res_sign,cnheck_str)){
                    System.out.println("验签失败");
                    doc.put("msg","验签失败！");
                    doc.put("code",400);
                    return ReturnResult.createResult(Constants.API_CODE_FORBIDDEN,"验签失败！").toJSONString();
                }else{
                    doc.put("msg","验签成功！");
                    doc.put("code",200);
                    System.out.println("验签成功");
                    newHead.put("response_id",new Date().getTime());
                    newHead.put("response_type",Constants.REQUEST_Q1);
                    newHead.put("response_code","0");
                    newHead.put("response_result","成功");
                    newHead.put("","");
                    JSONObject bosy_json = new JSONObject();
                    bosy_json.put("auth_code","555666");
                    bosy_json.put("cust_name","通知");
                    bosy_json.put("spell_name","姓名");
                    bosy_json.put("certificate_no","1585456545");
                    bosy_json.put("cust_sex","1");
                    bosy_json.put("cust_birthday","2001-02-03");
                    bosy_json.put("hospital_name","shanghai");
                    bosy_json.put("hospital_spell_name","上海");
                    bosy_json.put("dicom_shoot_time",new Date().getTime());
                    bosy_json.put("order_no","20151513545");
                    bosy_json.put("is_can_upload","1");
                    byte[] encode = encrypt(bosy_json.toString(), password);
                    String encrypt_message = parseByte2HexStr(encode);
                    System.out.println("密文字符串：" + encrypt_message);
                    newBody.put("encrypt_message",encrypt_message);
                    doc.put("body",newBody);

                    String request_str = keyGenerater.hashKeyForDisk(newHead.toString());
                    String sign =signature(request_str);
                    newHead.put("sign",sign);
                    doc.put("head",newHead);
                }
                JSONObject res_body = resBean.body;
                if(res_body.get("encrypt_message")!=null){
                    bodyStr = res_body.get("encrypt_message").toString();
                    //resStr = keyGenerater.jieMi(bodyStr).toString();
                }
            }
            byte[] decode = parseHexStr2Byte(bodyStr);
            byte[] decryptResult = decrypt(decode, password);
            if(decryptResult!=null){
                resStr =new String(decryptResult, "UTF-8");
                System.out.println("解密后：" + resStr); //不转码会乱码
            }
           // resStr =new String(decryptResult, "UTF-8");
        }catch (Exception e){
            e.printStackTrace();
        }
        // System.out.println("解密后：" + new String(decryptResult, "UTF-8")); //不转码会乱码
        // return new String(decryptResult);
        return  doc.toString();
    }
}
