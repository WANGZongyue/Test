package rsa.coder;

import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.*;
import java.util.*;

/*
*
*
*/
public class RSAcoder
{
	private static final String KEY_ALGORITHM="rsa";
	private static final String SIGNATURE_ALGORITHM="md5withrsa";
	private static final String PUBLIC_KEY="RSAPublickey";
	private static final String PRIVATE_KEY="RSAPrivatekey";
	private static final int KEY_SIZE=512;
	
	public static Map<String,Object> initKey() throws Exception
	{
		KeyPairGenerator keyPairGenerator=KeyPairGenerator.getInstance(KEY_ALGORITHM);
		keyPairGenerator.initialize(KEY_SIZE);
		KeyPair keyPair=keyPairGenerator.generateKeyPair();
		RSAPublicKey publicKey=(RSAPublicKey) keyPair.getPublic();
		RSAPrivateKey privateKey=(RSAPrivateKey) keyPair.getPrivate();
		Map<String,Object> keyMap=new HashMap<String,Object>(2);
		keyMap.put(PUBLIC_KEY, publicKey);
		keyMap.put(PRIVATE_KEY, privateKey);
		return keyMap;
	}
	
	public static byte[] getPublicKey(Map<String,Object> keyMap)
	{
		Key key=(Key) keyMap.get(PUBLIC_KEY);
		return key.getEncoded();
	}
	
	public static byte[] getPrivateKey(Map<String,Object> keyMap)
	{
		Key key=(Key) keyMap.get(PRIVATE_KEY);
		return key.getEncoded();
	}
	
	public static byte[] sign(byte[] data,byte[] privateKey) throws Exception
	{
		PKCS8EncodedKeySpec pkcs8encodespec=new PKCS8EncodedKeySpec(privateKey);
		KeyFactory keyFactory=KeyFactory.getInstance(KEY_ALGORITHM);
		PrivateKey priKey=keyFactory.generatePrivate(pkcs8encodespec);
		Signature signature=Signature.getInstance(SIGNATURE_ALGORITHM);
		signature.initSign(priKey);
		signature.update(data);
		return signature.sign();
	}
	
	public static boolean verify(byte[] data,byte[] sign,byte[] publicKey) throws Exception
	{
		X509EncodedKeySpec x509encodedkeyspec=new X509EncodedKeySpec(publicKey);
		KeyFactory keyFactory=KeyFactory.getInstance(KEY_ALGORITHM);
		PublicKey pubKey=keyFactory.generatePublic(x509encodedkeyspec);
		Signature signature=Signature.getInstance(SIGNATURE_ALGORITHM);
		signature.initVerify(pubKey);
		signature.update(data);
		return signature.verify(sign);
	}
}
