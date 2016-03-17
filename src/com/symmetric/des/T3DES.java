package com.symmetric.des;

import java.security.Key;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * jdk��bcʵ��3DES����
 * @author Administrator
 *
 */
public class T3DES {
	
	private final static String DESEDE = "DESede";
	private final static String BC = "BC";

	//jdk3DES����key
	public static Key getJdkThreeKey() throws Exception{
		KeyGenerator keyGenerator = KeyGenerator.getInstance(DESEDE);
		//������112����168����new SecureRandom()
		//keyGenerator.init(new SecureRandom());
		keyGenerator.init(168);
		SecretKey secretKey = keyGenerator.generateKey();
		byte[] bytekey = secretKey.getEncoded();
		
		//keyת��
		DESedeKeySpec deSedeKeySpec = new DESedeKeySpec(bytekey);
		SecretKeyFactory factory = SecretKeyFactory.getInstance(DESEDE);
		return factory.generateSecret(deSedeKeySpec);
	}
	
	//jdk3DES����
	public static String jdkThreeDESEncryption(Key key,String data) throws Exception{
		Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE,key);
		byte[] result = cipher.doFinal(data.getBytes());
		return Hex.encodeHexString(result);
	}
	
	//jdk3DES����
	public static String jdkThreeDESDecrypt(Key key,String data) throws Exception{
		Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE,key);
		byte[] result = cipher.doFinal(Hex.decodeHex(data.toCharArray()));
		return new String(result);
	}
	
	//bc3DES����key
	public static Key getBcThreeKey() throws Exception{
		Security.addProvider(new BouncyCastleProvider());
		KeyGenerator keyGenerator = KeyGenerator.getInstance(DESEDE,BC);
		//������112����168����new SecureRandom()
		//keyGenerator.init(new SecureRandom());
		keyGenerator.init(168);
		SecretKey secretKey = keyGenerator.generateKey();
		byte[] bytekey = secretKey.getEncoded();
		
		//keyת��
		DESedeKeySpec deSedeKeySpec = new DESedeKeySpec(bytekey);
		SecretKeyFactory factory = SecretKeyFactory.getInstance(DESEDE);
		return factory.generateSecret(deSedeKeySpec);
	}
	
	//bc3DES����
	public static String bcThreeDESEncryption(Key key,String data) throws Exception{
		Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE,key);
		byte[] result = cipher.doFinal(data.getBytes());
		return Hex.encodeHexString(result);
	}
	
	//bc3DES����
	public static String bcThreeDESDecrypt(Key key,String data) throws Exception{
		Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE,key);
		byte[] result = cipher.doFinal(Hex.decodeHex(data.toCharArray()));
		return new String(result);
	}
	
	public static void main(String[] args) {
		try{
			String str = "hello world";
			Key key = getJdkThreeKey();
			String rs = jdkThreeDESEncryption(key,str);
			System.out.println("JDK 3DES���ܣ�"+rs);
			//rs�Ǽ��ܺ������
			rs = jdkThreeDESDecrypt(key,rs);
			System.out.println("JDK3 DES���ܣ�"+rs);
			
			Key key2 = getBcThreeKey();
			String rs2 = jdkThreeDESEncryption(key2,str);
			System.out.println("BC 3DES���ܣ�"+rs2);
			//rs2�Ǽ��ܺ������
			rs2 = jdkThreeDESDecrypt(key2,rs2);
			System.out.println("BC DES���ܣ�"+rs2);
		}catch (Exception e) {
			e.printStackTrace();
		}
	}
	
}
