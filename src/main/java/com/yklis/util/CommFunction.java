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
     * 接口参数签名sign校验
     * @param inputParamMap
     * @param token
     * @return
     */
    public static boolean signCheck(Map<String, String[]> inputParamMap,String token){
    	
    	return SignCheckUtil.signCheck(inputParamMap, token);
    }
}
