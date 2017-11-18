package com.yklis.util;

import java.util.Map;

public class CommFunction {
    
    /**
     * 加密字符串
     * @param aStr
     * @param aKey
     * @return
     */
    public static String enCryptStr(String aStr,String aKey){
        
        return DESUtil.EnCryptStr(aStr,aKey);
        
    }
    
    /**
     * 解密字符串
     * @param aStr
     * @param aKey
     * @return
     */
    public static String deCryptStr(String aStr,String aKey){
        
        return DESUtil.DeCryptStr(aStr,aKey);
        
    }    
    
    /**
     * 计算参数的签名值
     * @param inputParamMap
     * @param token
     * @return
     */
    public static String signCalc(Map<String, String[]> inputParamMap,String token){  
    	
    	return SignCheckUtil.signCalc(inputParamMap, token);
    }
    
    /**
     * 接口参数签名sign校验
     * @param inputParamMap
     * @param token
     * @return
     */
    public static boolean signCheck(Map<String, String[]> inputParamMap,String token){
    	
    	return SignCheckUtil.signCheck(inputParamMap, token);
    }
}
