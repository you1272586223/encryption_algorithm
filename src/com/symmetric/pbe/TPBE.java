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
 * jdk和bc实现PBE加密
 * @author yys
 *
 */
public class TPBE {

	public final static String PBE = "PBEWITHMD5andDES";
	public final static String BC = "BC";
	public final static String src = "this is PBE";
	
	//jdk实现PBE加密
	public static void jdkPBE(){
		try{
			//初始化盐
			SecureRandom random = new SecureRandom();
			byte[] bt = random.generateSeed(8);
			
			//生成口令和秘钥
			String password = "yys";
			PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray());
			SecretKeyFactory factory = SecretKeyFactory.getInstance(PBE);
			Key key = factory.generateSecret(pbeKeySpec);
			
			//加密
			PBEParameterSpec parameterSpec = new PBEParameterSpec(bt,100);
			Cipher cipher = Cipher.getInstance(PBE);
			cipher.init(Cipher.ENCRYPT_MODE,key,parameterSpec);
			byte[] result = cipher.doFinal(src.getBytes());
			System.out.println("jdk PBE加密："+Hex.encodeHexString(result));
			
			//解密
			cipher.init(Cipher.DECRYPT_MODE,key,parameterSpec);
			result = cipher.doFinal(result);
			System.out.println("jdk PBE解密："+new String(result));
		}catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	//BC实现PBE加密
	public static void bcPBE(){
		try{
			Security.addProvider(new BouncyCastleProvider());
			//初始化盐
			SecureRandom random = new SecureRandom();
			byte[] bt = random.generateSeed(8);
			
			//生成口令和秘钥
			String password = "yys";
			PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray());
			SecretKeyFactory factory = SecretKeyFactory.getInstance(PBE,BC);
			Key key = factory.generateSecret(pbeKeySpec);
			
			//加密
			PBEParameterSpec parameterSpec = new PBEParameterSpec(bt,100);
			Cipher cipher = Cipher.getInstance(PBE);
			cipher.init(Cipher.ENCRYPT_MODE,key,parameterSpec);
			byte[] result = cipher.doFinal(src.getBytes());
			System.out.println("BC PBE加密："+Hex.encodeHexString(result));
			
			//解密
			cipher.init(Cipher.DECRYPT_MODE,key,parameterSpec);
			result = cipher.doFinal(result);
			System.out.println("BC PBE解密："+new String(result));
		}catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	
	public static void main(String[] args) {
		jdkPBE();
		bcPBE();
	}

}
