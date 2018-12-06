package mitm2DES;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map.Entry;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

public class MitMAttackDES {
	
	private static final int MAX_KEY_VALUE = new BigInteger("11111111111111111111", 2).intValue();

	public static void main(String[] args) throws GeneralSecurityException {
		byte[] plaintext = "My secret text".getBytes();
		byte[] verifyPlaintext = "My verifying text".getBytes();
		int key1Int = 42;
		int key2Int = 1337;
		byte[] key1Bytes = convertToBytesZeroPadded(key1Int);
		byte[] key2Bytes = convertToBytesZeroPadded(key2Int);
		SecretKeySpec key1 = new SecretKeySpec(key1Bytes, "DES");
		SecretKeySpec key2 = new SecretKeySpec(key2Bytes, "DES");
		
	    byte[] ciphertext = doubleEncrypt(key1, key2, plaintext);
	    byte[] verifyCiphertext = doubleEncrypt(key1, key2, verifyPlaintext);
//	    plaintext = doubleDecrypt(key1, key2, ciphertext);
	    
	    System.out.println("Meet in the middle attack on double-DES with 20 bit keys");
	    System.out.println("Plaintext: \t\t" + DatatypeConverter.printHexBinary(plaintext));
	    System.out.println("Ciphertext: \t\t" + DatatypeConverter.printHexBinary(ciphertext));
	    System.out.println("Verifing plaintext: \t" + DatatypeConverter.printHexBinary(verifyPlaintext));
	    System.out.println("Verifing ciphertext: \t" + DatatypeConverter.printHexBinary(verifyCiphertext));
	    System.out.println("Key 1 as int: \t\t" + key1Int);
	    System.out.println("Key 2 as int: \t\t" + key2Int);
	    
	    long startTime = System.nanoTime();	    
	    mitm(plaintext, ciphertext, verifyPlaintext, verifyCiphertext);	    
	    long endTime = System.nanoTime();
	    double totalTime = (endTime - startTime) * Math.pow(10, -9);
	    System.out.println("Execution time in sec: \t" + totalTime);
	}
	
	private static void mitm(byte[] plaintext, byte[] ciphertext, byte[] verifyPlaintext, byte[] verifyCiphertext) throws GeneralSecurityException {
		HashMap<Integer, String> encrypted = new HashMap<Integer, String>();
		HashMap<Integer, String> decrypted = new HashMap<Integer, String>();
		HashMap<String, ArrayList<Integer>> key1Candidates = new HashMap<String, ArrayList<Integer>>();
		HashMap<String, ArrayList<Integer>> key2Candidates = new HashMap<String, ArrayList<Integer>>();
		List<Entry<Integer, Integer>> keyPairs = new ArrayList<>();
		
		Cipher cipher = Cipher.getInstance("DES");
		for (int i = 0; i <= MAX_KEY_VALUE; i++) {
			byte[] keyBytes = convertToBytesZeroPadded(i);
			SecretKeySpec key = new SecretKeySpec(keyBytes, "DES");
			
			// Encryption
			cipher.init(Cipher.ENCRYPT_MODE, key);
			encrypted.put(i, new String(cipher.doFinal(plaintext)));
			
			// Decryption
			try {
				cipher.init(Cipher.DECRYPT_MODE, key);
				decrypted.put(i, new String(cipher.doFinal(ciphertext)));
			} catch (BadPaddingException e) {
				// Will happen on "bad" keys. Should be treated as wrong key. Source: https://stackoverflow.com/a/8053459/6840994
			}			
		}
		
		HashSet<String> commonValues = new HashSet<String>(encrypted.values());
		commonValues.retainAll(decrypted.values());
		if (commonValues.isEmpty()) {
			throw new Error("Could not find the keys.");
		}
				
		for (int i = 0; i <= MAX_KEY_VALUE; i++) {
			if (commonValues.contains(encrypted.get(i))) {
				if (key1Candidates.containsKey(encrypted.get(i))) {					
					key1Candidates.get(encrypted.get(i)).add(i);				
				} else {
					ArrayList<Integer> list = new ArrayList<Integer>();
					list.add(i);
					key1Candidates.put(encrypted.get(i), list);
				}
			}
			
			if (commonValues.contains(decrypted.get(i))) {
				if (key2Candidates.containsKey(decrypted.get(i))) {					
					key2Candidates.get(decrypted.get(i)).add(i);				
				} else {
					ArrayList<Integer> list = new ArrayList<Integer>();
					list.add(i);
					key2Candidates.put(decrypted.get(i), list);
				}
			}
		}	
		
		System.out.println("Candidates for key 1:\t" + Arrays.toString(key1Candidates.values().toArray()));
		System.out.println("Candidates for key 2:\t" + Arrays.toString(key2Candidates.values().toArray()));
		
	    String verifyCipherString = DatatypeConverter.printHexBinary(verifyCiphertext);
		for (String com : commonValues) {
			for (int i : key1Candidates.get(com)) {
				byte[] key1Bytes = convertToBytesZeroPadded(i);
				SecretKeySpec key1 = new SecretKeySpec(key1Bytes, "DES");
				for (int j : key2Candidates.get(com)) {
					byte[] key2Bytes = convertToBytesZeroPadded(j);
					SecretKeySpec key2 = new SecretKeySpec(key2Bytes, "DES");
					byte[] testCiphertext = doubleEncrypt(key1, key2, verifyPlaintext);
					
					if (DatatypeConverter.printHexBinary(testCiphertext).equals(verifyCipherString)) {
						Entry<Integer, Integer> pair = new AbstractMap.SimpleEntry<>(i, j);
						keyPairs.add(pair);
					}
				}
			}
		}
		
		System.out.println("Key pair(s) (in int format) verified on second plaintext-ciphertext pair:");
		System.out.println(Arrays.toString(keyPairs.toArray()));
	}

	private static byte[] doubleEncrypt(SecretKeySpec key1, SecretKeySpec key2, byte[] plaintext) {
		byte[] ciphertext = null;
		try {
			Cipher cipher = Cipher.getInstance("DES");
			
			// Round 1
			cipher.init(Cipher.ENCRYPT_MODE, key1);
			ciphertext = cipher.doFinal(plaintext);
		
			// Round 2
			cipher.init(Cipher.ENCRYPT_MODE, key2);
			ciphertext = cipher.doFinal(ciphertext);
			
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
		}

		return ciphertext;		
	}
	
	private static byte[] doubleDecrypt(SecretKeySpec key1, SecretKeySpec key2, byte[] ciphertext) {
		byte[] plaintext = null;
		try {
			Cipher cipher = Cipher.getInstance("DES");
			
			// Round 2
			cipher.init(Cipher.DECRYPT_MODE, key2);
			plaintext = cipher.doFinal(ciphertext);

			// Round 1
			cipher.init(Cipher.DECRYPT_MODE, key1);
			plaintext = cipher.doFinal(plaintext);
			
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
		}
		
		return plaintext;
	}
	
	private static byte[] convertToBytesZeroPadded(int val) {
		return DatatypeConverter.parseHexBinary(String.format("%1$05X", val).concat("00000000000"));
	}
}
