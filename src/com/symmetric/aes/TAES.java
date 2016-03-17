package com.symmetric.aes;

import java.security.Key;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * jdk和bc实现AES加密
 * @author yys
 *
 */
public class TAES {

	private final static String AES = "AES";
	private final static String BC = "BC";
	
	//jdk生成key
	public static Key getJdkAES() throws Exception{
		KeyGenerator keyGenerator = KeyGenerator.getInstance(AES);
		keyGenerator.init(128);
		SecretKey secretKey = keyGenerator.generateKey();
		byte[] bytekey = secretKey.getEncoded();
		
		//key转换
		Key key = new SecretKeySpec(bytekey,AES);
		return key;
	}
	
	//jdk实现AES加密
	public static String jdkAESEncryption(Key key,String data) throws Exception{
		Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE,key);
		byte[] result = cipher.doFinal(data.getBytes());
		return Hex.encodeHexString(result);
	}
	
	//jdk实现AES解密
	public static String jdkAESDecrypt(Key key,String data) throws Exception{
		Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE,key);
		byte[] result = cipher.doFinal(Hex.decodeHex(data.toCharArray()));
		return new String(result);
	}
	
	//bc生成key
	public static Key getBcAES() throws Exception{
		//bc实现需要加上这个就是
		Security.addProvider(new BouncyCastleProvider());
		
		KeyGenerator keyGenerator = KeyGenerator.getInstance(AES,BC);
		keyGenerator.init(128);
		SecretKey secretKey = keyGenerator.generateKey();
		byte[] bytekey = secretKey.getEncoded();
		
		//key转换
		Key key = new SecretKeySpec(bytekey,AES);
		return key;
	}
	
	//jdk实现AES加密
	public static String bcAESEncryption(Key key,String data) throws Exception{
		Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE,key);
		byte[] result = cipher.doFinal(data.getBytes());
		return Hex.encodeHexString(result);
	}
	
	//jdk实现AES解密
	public static String bcAESDecrypt(Key key,String data) throws Exception{
		Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE,key);
		byte[] result = cipher.doFinal(Hex.decodeHex(data.toCharArray()));
		return new String(result);
	}
	
	public static void main(String[] args) {
		try{
			
			//jdk加密
			String str = "this is AES";
			Key key = getJdkAES();
			String rs = jdkAESEncryption(key, str);
			System.out.println("jsk AES 加密："+rs);
			//rs是加密后的结果
			rs = jdkAESDecrypt(key, rs);
			System.out.println("jdk AES 解密："+rs);
			
			//BC加密
			Key key2 = getJdkAES();
			String rs2 = jdkAESEncryption(key2, str);
			System.out.println("jsk AES 加密："+rs2);
			//rs是加密后的结果
			rs2 = jdkAESDecrypt(key2, rs2);
			System.out.println("jdk AES 解密："+rs2);
			
		}catch (Exception e) {
			e.printStackTrace();
		}
	}
	
}
