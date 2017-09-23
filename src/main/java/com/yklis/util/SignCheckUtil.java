package com.yklis.util;

import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.apache.log4j.Logger;
import org.springframework.util.DigestUtils;

import com.google.gson.Gson;

public class SignCheckUtil {
	
    //配置容器起动时候加载log4j配置文件
    //只要将log4j.properties放在classes下，tomcat启动的时候会自动加载log4j的配置信息，
    //在程式代码不再需要使用PropertyConfigurator.configure("log4j.properties")来加载，
    //如果用了它反而会出现上面的错误--Could not read configuration file [log4jj.properties]
    //PropertyConfigurator.configure("log4jj.properties");
    private static Logger logger = Logger.getLogger(SignCheckUtil.class);
    
    public static boolean signCheck(Map<String, String[]> inputParamMap,String token){        
        
        Gson gson = new Gson();
        logger.info("请求参数:"+gson.toJson(inputParamMap));
        
        List<Map.Entry<String,String[]>> list = new ArrayList<Map.Entry<String,String[]>>(inputParamMap.entrySet());
        
        try{
            //排序
            Collections.sort(list,new RequestParameterComparator());
        }catch(Exception e){
            logger.error("请求参数排序出错:"+e.toString());
        }
        
        //String signOrg = "";//null+"ABC"结果是nullABC
        StringBuilder sb1 = new StringBuilder();
        String signValue = null;
        
        for(Map.Entry<String,String[]> mapping:list){
            
            String paramKey = mapping.getKey(); 
            String[] paramValue = mapping.getValue();
            
            if(paramValue.length<=0){
                logger.info(paramKey+"的值为null");
                continue;
            }
            
            if((null==paramValue[0])||("".equals(paramValue[0]))){
                logger.info(paramKey+"的值为空字符串");
                continue;
            }
            
            if("sign".equalsIgnoreCase(paramKey)){
                signValue = paramValue[0];
                continue;
            }
            
            //signOrg=signOrg+paramKey+paramValue[0];
            sb1.append(paramKey);
            sb1.append(paramValue[0]);
            
        }
        
        StringBuilder sb2 = new StringBuilder();        
        //String signOrg = null;
        
        //计算md5之前确保接口与接入方的字符串编码一致
        try {
            String s1 = URLEncoder.encode(sb1.toString(), "utf-8");
            sb2.append(s1);
        } catch (Exception e) {            
            logger.error("URLEncoder.encode报错:"+e.toString());
        }
        
        //表示需要登录访问的接口
        if(null != token && !"".equals(token)){
            //signOrg=token+signOrg;
            sb2.insert(0, token);
        }
        
        logger.info("拼出来的字符串:"+sb2.toString());
        
        //如果signOrg为null,md5DigestAsHex方法将抛出异常
        //空字符串("")md5DigestAsHex的结果为d41d8cd98f00b204e9800998ecf8427e
        String signMD5 = DigestUtils.md5DigestAsHex(sb2.toString().getBytes());
        logger.info("signMD5:"+signMD5);
        
        if(signMD5.equalsIgnoreCase(signValue)) return true;
        
        return false;        
    }
    
    static class RequestParameterComparator implements Comparator<Map.Entry<String,String[]>> {
        
        private Logger logger = Logger.getLogger(this.getClass());
        
        @Override
        public int compare(Entry<String, String[]> o1, Entry<String, String[]> o2) {

            try{
                
                return o1.getKey().compareTo(o2.getKey());
                                                    
            }catch(Exception e){
                logger.error("RequestParameterComparator出错:"+e.toString());
                return 0;
            }
        }
 
    }
}
