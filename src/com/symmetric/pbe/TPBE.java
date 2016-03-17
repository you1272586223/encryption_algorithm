package com.symmetric.pbe;

import java.security.Key;
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * jdk��bcʵ��PBE����
 * @author yys
 *
 */
public class TPBE {

	public final static String PBE = "PBEWITHMD5andDES";
	public final static String BC = "BC";
	public final static String src = "this is PBE";
	
	//jdkʵ��PBE����
	public static void jdkPBE(){
		try{
			//��ʼ����
			SecureRandom random = new SecureRandom();
			byte[] bt = random.generateSeed(8);
			
			//���ɿ������Կ
			String password = "yys";
			PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray());
			SecretKeyFactory factory = SecretKeyFactory.getInstance(PBE);
			Key key = factory.generateSecret(pbeKeySpec);
			
			//����
			PBEParameterSpec parameterSpec = new PBEParameterSpec(bt,100);
			Cipher cipher = Cipher.getInstance(PBE);
			cipher.init(Cipher.ENCRYPT_MODE,key,parameterSpec);
			byte[] result = cipher.doFinal(src.getBytes());
			System.out.println("jdk PBE���ܣ�"+Hex.encodeHexString(result));
			
			//����
			cipher.init(Cipher.DECRYPT_MODE,key,parameterSpec);
			result = cipher.doFinal(result);
			System.out.println("jdk PBE���ܣ�"+new String(result));
		}catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	//BCʵ��PBE����
	public static void bcPBE(){
		try{
			Security.addProvider(new BouncyCastleProvider());
			//��ʼ����
			SecureRandom random = new SecureRandom();
			byte[] bt = random.generateSeed(8);
			
			//���ɿ������Կ
			String password = "yys";
			PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray());
			SecretKeyFactory factory = SecretKeyFactory.getInstance(PBE,BC);
			Key key = factory.generateSecret(pbeKeySpec);
			
			//����
			PBEParameterSpec parameterSpec = new PBEParameterSpec(bt,100);
			Cipher cipher = Cipher.getInstance(PBE);
			cipher.init(Cipher.ENCRYPT_MODE,key,parameterSpec);
			byte[] result = cipher.doFinal(src.getBytes());
			System.out.println("BC PBE���ܣ�"+Hex.encodeHexString(result));
			
			//����
			cipher.init(Cipher.DECRYPT_MODE,key,parameterSpec);
			result = cipher.doFinal(result);
			System.out.println("BC PBE���ܣ�"+new String(result));
		}catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	
	public static void main(String[] args) {
		jdkPBE();
		bcPBE();
	}

}
