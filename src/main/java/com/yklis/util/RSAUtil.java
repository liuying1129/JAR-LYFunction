package com.yklis.util;

import java.io.ByteArrayOutputStream;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class RSAUtil {
	
    /** 
     * * 生成新密钥对 * 
     *  
     * @return KeyPair * 
     * @throws EncryptException 
     */  
    public static KeyPair generateKeyPair() throws Exception {  
        try {  
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA", new BouncyCastleProvider());
            // 没什么好说的了，这个值关系到块加密的大小，可以更改，但是不要太大，否则效率会低  
            final int KEY_SIZE = 1024;
            keyPairGen.initialize(KEY_SIZE, new SecureRandom());  
            KeyPair keyPair = keyPairGen.generateKeyPair();
            return keyPair;  
        } catch (Exception e) {
            throw new Exception(e.getMessage());  
        }   
    }
    
    /** 
     * * 加密 * 
     *  
     * @param publicKey 
     *            加密的密钥 * 
     * @param data 
     *            待加密的明文数据 * 
     * @return 加密后的数据 * 
     * @throws Exception 
     */  
    public static byte[] encrypt(PublicKey publicKey, byte[] data) throws Exception {  
        try {  
            Cipher cipher = Cipher.getInstance("RSA");//第二参数,new BouncyCastleProvider()引起内存泄漏，去掉不影响
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);  
            int blockSize = cipher.getBlockSize();// 获得加密块大小，如：加密前数据为128个byte，而key_size=1024  
            // 加密块大小为127  
            // byte,加密后为128个byte;因此共有2个加密块，第一个127  
            // byte第二个为1个byte  
            int outputSize = cipher.getOutputSize(data.length);// 获得加密块加密后块大小  
            int leavedSize = data.length % blockSize;  
            int blocksSize = leavedSize != 0 ? data.length / blockSize + 1  
                    : data.length / blockSize;  
            byte[] raw = new byte[outputSize * blocksSize];  
            int i = 0;  
            while (data.length - i * blockSize > 0) {  
                if (data.length - i * blockSize > blockSize)  
                    cipher.doFinal(data, i * blockSize, blockSize, raw, i  
                            * outputSize);  
                else  
                    cipher.doFinal(data, i * blockSize, data.length - i  
                            * blockSize, raw, i * outputSize);  
                // 这里面doUpdate方法不可用，查看源代码后发现每次doUpdate后并没有什么实际动作除了把byte[]放到  
                // ByteArrayOutputStream中，而最后doFinal的时候才将所有的byte[]进行加密，可是到了此时加密块大小很可能已经超出了  
                // OutputSize所以只好用dofinal方法。  
  
                i++;  
            }  
            return raw;  
        } catch (Exception e) {  
            throw new Exception(e.getMessage());  
        }  
    }
    
    /** 
     * * 解密 * 
     *  
     * @param privateKey 
     *            解密的密钥 * 
     * @param raw 
     *            已经加密的数据 * 
     * @return 解密后的明文 * 
     * @throws Exception 
     */  
    public static byte[] decrypt(PrivateKey privateKey, byte[] raw) throws Exception {  
        try {  
            Cipher cipher = Cipher.getInstance("RSA");//第二参数,new BouncyCastleProvider()引起内存泄漏，去掉不影响
            cipher.init(Cipher.DECRYPT_MODE, privateKey);  
            int blockSize = cipher.getBlockSize();  
            ByteArrayOutputStream bout = new ByteArrayOutputStream(64);  
            int j = 0;  
  
            while (raw.length - j * blockSize > 0) {  
                bout.write(cipher.doFinal(raw, j * blockSize, blockSize));  
                j++;  
            }  
            return bout.toByteArray();  
        } catch (Exception e) {  
            throw new Exception(e.getMessage());  
        }  
    }
    
    /**
     * 解密 由js加密的字符串
     * 
     * @param privateKey
     * @param encryptData
     * @return 解密结果的字符串（未经url decode）
     * @throws Exception
     */
    public static String decryptDataFromJs(PrivateKey privateKey, String encryptData) throws Exception {
        byte[] en_data = Hex.decodeHex(encryptData.toCharArray());
        StringBuffer sb = new StringBuffer();
        sb.append(new String(RSAUtil.decrypt(privateKey, en_data)));
        return sb.reverse().toString();
    }
    
    /**
     * Hex转码，把Key转换成字符串
     * （用于存储与传播）
     * 
     * @param b
     * @return
     */
    public static String toHexString(byte[] b) {   
        StringBuilder sb = new StringBuilder(b.length * 2);   
        for (int i = 0; i < b.length; i++) {   
            sb.append(HEXCHAR[(b[i] & 0xf0) >>> 4]);   
            sb.append(HEXCHAR[b[i] & 0x0f]);   
        }   
        return sb.toString();   
    }
    
    private static byte[] toBytes(String s) {   
        byte[] bytes;   
        bytes = new byte[s.length() / 2];   
        for (int i = 0; i < bytes.length; i++) {   
            bytes[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2),   
                    16);   
        }   
        return bytes;   
    }
    
    /**
     * 读取经过hex转换的公钥，转换为可用的PublicKey object
     * 
     * @param publicKeyStr
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public static PublicKey readPublicKey(String publicKeyStr) throws NoSuchAlgorithmException, InvalidKeySpecException {
    	KeyFactory keyFactory = KeyFactory.getInstance("RSA", new BouncyCastleProvider());
    	X509EncodedKeySpec bobPubKeySpec = new X509EncodedKeySpec(toBytes(publicKeyStr));   
        PublicKey publicKey = keyFactory.generatePublic(bobPubKeySpec);
        return publicKey;
    }
    
    /**
     * 读取经过hex转换的私钥，转换为可用的PrivateKey object
     * 
     * @param pravateKeyStr
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public static PrivateKey readPrivateKey(String pravateKeyStr) throws NoSuchAlgorithmException, InvalidKeySpecException {
    	KeyFactory keyFactory = KeyFactory.getInstance("RSA", new BouncyCastleProvider());
        PKCS8EncodedKeySpec priPKCS8 = new PKCS8EncodedKeySpec(toBytes(pravateKeyStr));   
        PrivateKey privateKey = keyFactory.generatePrivate(priPKCS8);
        return privateKey;
    }
  
    private static char[] HEXCHAR = { '0', '1', '2', '3', '4', '5', '6', '7',   
            '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
    
    /**
     * 获取公钥的Modulus
     * 
     * @param publicKey
     * @return
     */
    public static String getModulus(RSAPublicKey publicKey){
    	return new String(Hex.encodeHex(publicKey.getModulus().toByteArray()));
    }
    
    /**
     * 获取公钥的Exponent
     * 
     * @param publicKey
     * @return
     */
    public static String getExponent(RSAPublicKey publicKey) {
    	return new String(Hex.encodeHex(publicKey.getPublicExponent().toByteArray()));
    }
}
