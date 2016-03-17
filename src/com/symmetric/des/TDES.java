package com.symmetric.des;

import java.security.Key;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * jdk和BC实现DES加密
 * @author yys
 *
 */
public class TDES {
	
	private final static String DES = "DES";
	private final static String BC = "BC";

	//jdk DES生成key
	public static Key getJdkDESKey() throws Exception{
		//生成key
		KeyGenerator keyGenerator = KeyGenerator.getInstance(DES);
		keyGenerator.init(56);
		SecretKey secretKey= keyGenerator.generateKey();
		byte[] byteKey = secretKey.getEncoded();
		
		//key转换
		DESKeySpec desKeySpec = new DESKeySpec(byteKey);
		SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(DES);
		Key convertSecretKey =secretKeyFactory.generateSecret(desKeySpec);
		
		return convertSecretKey;
	}
	
	//jdkDES加密
	public static String jdkDESEncryption(Key key,String data) throws Exception{
		Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE,key);
		byte[] result = cipher.doFinal(data.getBytes());
		return Hex.encodeHexString(result);
	}
	
	//jdkDES解密
	public static String jdkDESDecrypt(Key key,String data) throws Exception{
		Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE,key);
		byte[] result = cipher.doFinal(Hex.decodeHex(data.toCharArray()));
		return new String(result,"UTF-8");
	}
	
	//bcDES生成key
	public static Key getBcDESKey() throws Exception{
		Security.addProvider(new BouncyCastleProvider());
		//生成key
		KeyGenerator keyGenerator = KeyGenerator.getInstance(DES,BC);
		
		keyGenerator.init(56);
		SecretKey secretKey= keyGenerator.generateKey();
		byte[] byteKey = secretKey.getEncoded();
		
		//key转换
		DESKeySpec desKeySpec = new DESKeySpec(byteKey);
		SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(DES);
		Key convertSecretKey =secretKeyFactory.generateSecret(desKeySpec);
		
		return convertSecretKey;
	}
	
	//bcDES加密
	public static String bcDESEncryption(Key key,String data) throws Exception{
		Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE,key);
		byte[] result = cipher.doFinal(data.getBytes());
		return Hex.encodeHexString(result);
	}
	
	//bcDES解密
	public static String bcDESDecrypt(Key key,String data) throws Exception{
		Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE,key);
		byte[] result = cipher.doFinal(Hex.decodeHex(data.toCharArray()));
		return new String(result);
	}
	
	public static void main(String[] args) {
		try {
			String data = "hello world";
			//必须用加密的key才可以解密
			Key key = getJdkDESKey();
			String rs = jdkDESEncryption(key,data);
			System.out.println("jdkDES加密："+rs);
			rs = jdkDESDecrypt(key,rs);
			System.out.println("jdkDES解密："+rs);
			
			
			Key key2 = getBcDESKey();
			String bc = bcDESEncryption(key2,data);
			System.out.println("bcDES加密："+bc);
			bc = bcDESDecrypt(key2,bc);
			System.out.println("bcDES解密："+bc);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
