package rsa.coder;

import static org.junit.Assert.*;
import Format.Hex;
import java.util.Map;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public class RSAcoderTest
{
	private static Map<String,Object> keyMap;
	private static byte[] privateKey;
	private static byte[] publicKey;
	
	@Before
	public void setUp() throws Exception
	{
		keyMap=RSAcoder.initKey();
		privateKey=RSAcoder.getPrivateKey(keyMap);
		publicKey=RSAcoder.getPublicKey(keyMap);
		System.out.println("private key:");
		System.out.println(Hex.byte2hex(privateKey));
		System.out.println("public key:");
		System.out.println(Hex.byte2hex(publicKey));
	}

	@After
	public void tearDown() throws Exception
	{
	}

	@Test
	public void testSign() throws Exception
	{
		byte[] data="abc".getBytes();
		byte[] sign=RSAcoder.sign(data, privateKey);
		System.out.println("sign:");
		System.out.println(Hex.byte2hex(sign));
		boolean status=RSAcoder.verify(data, sign, publicKey);
		assertTrue(status);
	}

}
