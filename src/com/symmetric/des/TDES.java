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
 * jdk��BCʵ��DES����
 * @author yys
 *
 */
public class TDES {
	
	private final static String DES = "DES";
	private final static String BC = "BC";

	//jdk DES����key
	public static Key getJdkDESKey() throws Exception{
		//����key
		KeyGenerator keyGenerator = KeyGenerator.getInstance(DES);
		keyGenerator.init(56);
		SecretKey secretKey= keyGenerator.generateKey();
		byte[] byteKey = secretKey.getEncoded();
		
		//keyת��
		DESKeySpec desKeySpec = new DESKeySpec(byteKey);
		SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(DES);
		Key convertSecretKey =secretKeyFactory.generateSecret(desKeySpec);
		
		return convertSecretKey;
	}
	
	//jdkDES����
	public static String jdkDESEncryption(Key key,String data) throws Exception{
		Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE,key);
		byte[] result = cipher.doFinal(data.getBytes());
		return Hex.encodeHexString(result);
	}
	
	//jdkDES����
	public static String jdkDESDecrypt(Key key,String data) throws Exception{
		Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE,key);
		byte[] result = cipher.doFinal(Hex.decodeHex(data.toCharArray()));
		return new String(result,"UTF-8");
	}
	
	//bcDES����key
	public static Key getBcDESKey() throws Exception{
		Security.addProvider(new BouncyCastleProvider());
		//����key
		KeyGenerator keyGenerator = KeyGenerator.getInstance(DES,BC);
		
		keyGenerator.init(56);
		SecretKey secretKey= keyGenerator.generateKey();
		byte[] byteKey = secretKey.getEncoded();
		
		//keyת��
		DESKeySpec desKeySpec = new DESKeySpec(byteKey);
		SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(DES);
		Key convertSecretKey =secretKeyFactory.generateSecret(desKeySpec);
		
		return convertSecretKey;
	}
	
	//bcDES����
	public static String bcDESEncryption(Key key,String data) throws Exception{
		Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE,key);
		byte[] result = cipher.doFinal(data.getBytes());
		return Hex.encodeHexString(result);
	}
	
	//bcDES����
	public static String bcDESDecrypt(Key key,String data) throws Exception{
		Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE,key);
		byte[] result = cipher.doFinal(Hex.decodeHex(data.toCharArray()));
		return new String(result);
	}
	
	public static void main(String[] args) {
		try {
			String data = "hello world";
			//�����ü��ܵ�key�ſ��Խ���
			Key key = getJdkDESKey();
			String rs = jdkDESEncryption(key,data);
			System.out.println("jdkDES���ܣ�"+rs);
			rs = jdkDESDecrypt(key,rs);
			System.out.println("jdkDES���ܣ�"+rs);
			
			
			Key key2 = getBcDESKey();
			String bc = bcDESEncryption(key2,data);
			System.out.println("bcDES���ܣ�"+bc);
			bc = bcDESDecrypt(key2,bc);
			System.out.println("bcDES���ܣ�"+bc);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
