package rainbowTableAES;
import java.io.BufferedWriter;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

public class AESRainbowTable {
    private static byte[] keyPadded = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    private static byte[] plaintext = {(byte) 0xf3, (byte) 0x3c, (byte) 0xcd, (byte) 0x08,	0x44, (byte) 0xc6, (byte) 0x5d, (byte) 0xf2,
    		(byte) 0x81, (byte) 0x27, (byte) 0xc3, (byte) 0x73, (byte) 0xec, (byte) 0xba, (byte) 0xfb, (byte) 0xe6};
    private static HashMap<String, String> rainbowTable = new HashMap<String, String>();
    private static HashSet<String> keyRegister = new HashSet<String>();
    private static int t = 1000; // Number of columns
    private static int m = (int) Math.pow(2, 8); 
    private static int rows = m * t; // Number of rows
    private static int divisor = (int) Math.pow(2, 24);
    private static ArrayList<Integer> pointList = new ArrayList<Integer>();

    public static void main(String[] args) throws GeneralSecurityException {
    	// Read RainbowTable if it exists, else generate it    	
    	try {
			readRainbowTable();
			System.out.println("Reading rainbow table from file");
		} catch (Exception e) {
			System.out.println("Generating rainbow table");
			generateRainbowTable();
		}
    	
    	System.out.println("Number of rows without duplicate endpoints in rainbow table: " + rainbowTable.size());
    	
    	for (int i = 0; i < 1000; i++) {    		
    		test(false);
    	}
    }
    
    private static void test(boolean knownStartPoint) throws GeneralSecurityException {
    	Random random = new Random();
    	byte[] key = new byte[3];
    	String testCipher = "";
    	
    	if (knownStartPoint) {    		
	    	String startKey = "";
	    	// Find valid start point
	    	while (!rainbowTable.containsValue(startKey)) {
				random.nextBytes(key);
				startKey = DatatypeConverter.printHexBinary(key);
	    	}		
	    	testCipher = DatatypeConverter.printHexBinary(aes(key));
	    	
	    	// Find related end point
	    	byte[] tempcipher = null;
			for (int j = 1; j <= t; j++) {
		    	int chipherInt = (Integer.parseInt(DatatypeConverter.printHexBinary(aes(key)), 16) + j) % divisor;
		    	tempcipher = Arrays.copyOfRange(ByteBuffer.allocate(4).putInt(chipherInt).array(), 1, 4);
		    	key = tempcipher;
	    	}
    	
    	} else {
			random.nextBytes(key);
			testCipher = DatatypeConverter.printHexBinary(key);
    	}
		
    	System.out.println("Test cipher: " + testCipher);
    	String resKey = getKey(testCipher);
    	if (resKey == null) {
    		System.err.println("Key could not be found in rainbow table.");
    	} else {
    		String cipher = DatatypeConverter.printHexBinary(aes(DatatypeConverter.parseHexBinary(resKey)));
    		if (cipher.equals(testCipher)) {
				System.out.println("Test succeed! Key: " + resKey);
				
			} else {
				System.err.println("Shit! A wrong key was found: " + resKey);
			}
    	}
    }
    
    private static String getKey(String orgCipher) throws GeneralSecurityException {    	    	    	
    	for (int i = t; i > 0; i--) {
			String cipher = orgCipher;
	    	for (int j = i; j <= t; j++) {	    		
	    		int nextKeyInt = (Integer.parseInt(cipher, 16) + j) % divisor;
	    		byte[] nextKeyBytes = Arrays.copyOfRange(ByteBuffer.allocate(4).putInt(nextKeyInt).array(), 1, 4);

	    		if (j != t) {
	    			cipher = DatatypeConverter.printHexBinary(aes(nextKeyBytes));
	    		} else {
	    			cipher = DatatypeConverter.printHexBinary(nextKeyBytes);	    			
	    		}
	    	}
	    	
    		if (rainbowTable.containsKey(cipher)) {    	    	
    			String startKey = rainbowTable.get(cipher);
    	    	byte[] keyHexBytes = DatatypeConverter.parseHexBinary(startKey);

    	    	for (int k = 1; k < i; k++) {
    	    		cipher = DatatypeConverter.printHexBinary(aes(keyHexBytes));
    	    		int nextKeyInt = (Integer.parseInt(cipher, 16) + k) % divisor;
    	    		keyHexBytes = Arrays.copyOfRange(ByteBuffer.allocate(4).putInt(nextKeyInt).array(), 1, 4);
    	    	}
    	    	
    	    	cipher = DatatypeConverter.printHexBinary(aes(keyHexBytes));
	    		if (cipher.equals(orgCipher)) {
	    			return DatatypeConverter.printHexBinary(keyHexBytes);
	    		}
        	}
    	}	
    	return null;
    }
    
    private static void generateRainbowTable() throws GeneralSecurityException {
    	byte[] key = new byte[3];
    	byte[] cipher = new byte[3];
    	byte[] startPoint = new byte[3];
    	String cipherStr = null;
    	Random random = new Random();
    	HashSet<String> chainKeys = new HashSet<String>();
    	
    	for (int i = 0; i < rows; i++) {
			random.nextBytes(startPoint);
			chainKeys.clear();
			key = startPoint;
			
			for (int j = 1; j <= t; j++) {
				chainKeys.add(DatatypeConverter.printHexBinary(key));
				cipherStr = DatatypeConverter.printHexBinary(aes(key));
		    	int chipherInt = (Integer.parseInt(cipherStr, 16) + j) % divisor;
		    	cipher = Arrays.copyOfRange(ByteBuffer.allocate(4).putInt(chipherInt).array(), 1, 4);
		    	cipherStr = DatatypeConverter.printHexBinary(cipher);		    	
		    	key = cipher;
	    	}
			
			if (!rainbowTable.containsKey(cipherStr)) {
	    		rainbowTable.put(cipherStr, DatatypeConverter.printHexBinary(startPoint));
	    		keyRegister.addAll(chainKeys);
	    	}
			
    		if (i % m == 0) {
    			System.out.println("Row: " + i + ", Points: " + keyRegister.size());
    			pointList.add(keyRegister.size());
    		}
    	}
		savePointList();
		saveRainbowTable();
    }

    private static void savePointList() {
		try {
			BufferedWriter pointsFile = new BufferedWriter(new FileWriter("points.txt"));
			for (Integer points : pointList) {
				pointsFile.write(points.toString());
			    pointsFile.newLine();
			}
			pointsFile.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
    }
    
    private static void saveRainbowTable() {
		try {
			FileOutputStream tableFile = new FileOutputStream("RainbowTable");
			ObjectOutputStream objectOut = new ObjectOutputStream(tableFile);
			objectOut.writeObject(rainbowTable);
			objectOut.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
    }
    
    @SuppressWarnings("unchecked")
	private static void readRainbowTable() throws Exception {
    	FileInputStream tableFile = new FileInputStream("RainbowTable");
		ObjectInputStream objectIn = new ObjectInputStream(tableFile);
		rainbowTable = (HashMap<String, String>) objectIn.readObject();
		objectIn.close();    
	}
    
    private static byte[] aes(byte[] key) throws GeneralSecurityException {
    	keyPadded[0] = key[0];
    	keyPadded[1] = key[1];
    	keyPadded[2] = key[2];
        SecretKeySpec secretKey = new SecretKeySpec(keyPadded, "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return Arrays.copyOfRange(cipher.doFinal(plaintext), 0, 3);
    }    
}

