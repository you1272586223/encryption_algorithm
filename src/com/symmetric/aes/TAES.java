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
 * jdk��bcʵ��AES����
 * @author yys
 *
 */
public class TAES {

	private final static String AES = "AES";
	private final static String BC = "BC";
	
	//jdk����key
	public static Key getJdkAES() throws Exception{
		KeyGenerator keyGenerator = KeyGenerator.getInstance(AES);
		keyGenerator.init(128);
		SecretKey secretKey = keyGenerator.generateKey();
		byte[] bytekey = secretKey.getEncoded();
		
		//keyת��
		Key key = new SecretKeySpec(bytekey,AES);
		return key;
	}
	
	//jdkʵ��AES����
	public static String jdkAESEncryption(Key key,String data) throws Exception{
		Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE,key);
		byte[] result = cipher.doFinal(data.getBytes());
		return Hex.encodeHexString(result);
	}
	
	//jdkʵ��AES����
	public static String jdkAESDecrypt(Key key,String data) throws Exception{
		Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE,key);
		byte[] result = cipher.doFinal(Hex.decodeHex(data.toCharArray()));
		return new String(result);
	}
	
	//bc����key
	public static Key getBcAES() throws Exception{
		//bcʵ����Ҫ�����������
		Security.addProvider(new BouncyCastleProvider());
		
		KeyGenerator keyGenerator = KeyGenerator.getInstance(AES,BC);
		keyGenerator.init(128);
		SecretKey secretKey = keyGenerator.generateKey();
		byte[] bytekey = secretKey.getEncoded();
		
		//keyת��
		Key key = new SecretKeySpec(bytekey,AES);
		return key;
	}
	
	//jdkʵ��AES����
	public static String bcAESEncryption(Key key,String data) throws Exception{
		Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE,key);
		byte[] result = cipher.doFinal(data.getBytes());
		return Hex.encodeHexString(result);
	}
	
	//jdkʵ��AES����
	public static String bcAESDecrypt(Key key,String data) throws Exception{
		Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE,key);
		byte[] result = cipher.doFinal(Hex.decodeHex(data.toCharArray()));
		return new String(result);
	}
	
	public static void main(String[] args) {
		try{
			
			//jdk����
			String str = "this is AES";
			Key key = getJdkAES();
			String rs = jdkAESEncryption(key, str);
			System.out.println("jsk AES ���ܣ�"+rs);
			//rs�Ǽ��ܺ�Ľ��
			rs = jdkAESDecrypt(key, rs);
			System.out.println("jdk AES ���ܣ�"+rs);
			
			//BC����
			Key key2 = getJdkAES();
			String rs2 = jdkAESEncryption(key2, str);
			System.out.println("jsk AES ���ܣ�"+rs2);
			//rs�Ǽ��ܺ�Ľ��
			rs2 = jdkAESDecrypt(key2, rs2);
			System.out.println("jdk AES ���ܣ�"+rs2);
			
		}catch (Exception e) {
			e.printStackTrace();
		}
	}
	
}
