import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.*;

public class RainbowTable {
	
	// This is the data structure to use for the rainbow table, mapping end of chains to beginning of chains.
	Map<String, String> lastToFirst;
	static ArrayList<String> passwds;
	
	public MessageDigest message_digest = null;
	BigInteger bi;

	byte[] res;
	final int NUM_CHARACTERS = 4;
	char[] characters = new char[]{'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'};
	BigInteger passwordSpaceSize;
	BigInteger charactersLength;
	
	int chainLength;
	int numRows;
	String passwd = "abcd";
	
	public RainbowTable(int numChains, int chainLength) {
		this.numRows = numChains;
		this.chainLength = chainLength;
		passwordSpaceSize = new BigInteger(""+ ((int)Math.pow(characters.length, NUM_CHARACTERS))); // number of possible passwords
		charactersLength = new BigInteger(""+characters.length);
		passwds = new ArrayList<String>();
		lastToFirst = new Hashtable<String,String>();
		try {
			message_digest = MessageDigest.getInstance("MD5"); // using MD5 hash functionn
			
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}				
		generatePasswords(passwds, characters, "", characters.length, NUM_CHARACTERS);
		//System.out.println("Size of possible passwords: " + passwds.size());
		String filename = "table" + numChains+"x"+chainLength+".txt";
		if(!readFromFile(filename)) {
			long startTime = System.currentTimeMillis();
			buildTable(numChains, chainLength);
			System.out.println("Building table took: " + ((double)(System.currentTimeMillis()-startTime)/1000) + " s");
			startTime = System.currentTimeMillis();
			getAverageLookupTime(100);
			writeToFile(filename);
		}
		else{
			System.out.println("File created");
		}
		
	}
	
	// change to random index
	private void buildTable(int numchains, int chainlength) {
		// TODO: Build the rainbow table using hash and reduce methods
		Integer chain = 0;
		int index = 0;
		String initialpassword;
		String hash;
		
		Random rand = new Random();
		while(chain < numchains){
			initialpassword = reduce(chain.toString(),0);
			String lastpassword = initialpassword;
			hash = hash(lastpassword);
			if (!lastToFirst.containsKey(initialpassword)){
				for (int i = 0; i < chainlength; i++){
					hash = hash(lastpassword);
					lastpassword = reduce(hash,i);
				}
				if (!lastToFirst.containsValue(hash)){
					lastToFirst.put(hash,initialpassword);
				}
			}
			chain++;
		}
		
	}
	
	
	private static void generatePasswords(ArrayList<String> perms, char [] charSet, String prefix, int length, int k){
		if (k == 0){
            perms.add(prefix);
            return;
        }
        else{
            for (int i = 0; i < length; i++){
                String newString = prefix + charSet[i];
                generatePasswords(perms,charSet,newString,length,k-1);
            }
        }
		
	}
	
	
	/**
	 * Looks up a known password by lookup up its hash value.
	 * Useful for testing the table.
	 */
	
	public String lookupPwd(String pwd, int chainlength) {
		return lookup(hash(pwd),chainlength);
	}
	
	public void getAverageLookupTime(int numpasswords){
		double sum = 0.0;
		double average;
		double starttime;
		double endtime;
		String lookupresult;
		int numvalid = 0;
		
		for (int i = 0; i < numpasswords; i++){
			Integer num = (Integer) i;
			String passwd = reduce(num.toString(),0);
			starttime = System.currentTimeMillis();
			lookupresult = lookupPwd(passwd, this.chainLength);
			if (lookupresult != null){
				numvalid++;
			}
			endtime = (double) (System.currentTimeMillis() - starttime)/1000;
			System.out.println("Lookup time: " + (double) (System.currentTimeMillis() - starttime)/1000 + " result: " + lookupresult);
			//sum += endtime;
		}
		//average =  sum/numpasswords;
		//System.out.println("Average lookup time: " + average);
		System.out.println("Number of valid passwords: " + numvalid);
		//System.out.println("Percentage success: " + (double)((numvalid/numpasswords) * 100));
	}
	
	/**
	 * Note, this is not truly a "random" string. It simply reduces the given string to
	 * a password and looks up that password.
	 */
	public String lookupRandomString(String randomString,int chainlength) {
		return lookup(reduce(randomString, 0),chainlength);
	}
	
	public String lookup(String originalhash, int chainlength) {
		//TODO: Lookup a given hash in the rainbow table.
		// Return null if the password is not found
		/*
		1.) reduce originalhash, hash that result chainlength times: write function
		    that does this starting from last reduce function: should return a hash value
		2.) check if keyset contains this hash value
		3.) If it does, get the value of that key which is the initial password and 
		    construct chain from this.
	    4.) If any hash in this chain matches the originalhash, then the password is also
	        in this chain and should be returned
		*/
		String hashToFind = null;
		for (int i = chainlength - 1; i >= 0; i--){
			hashToFind = lookupChain(originalhash, i, chainlength - 1);
			if (lastToFirst.keySet().contains(hashToFind)){
				String initialpasswd = lastToFirst.get(hashToFind);
				String chainHash;
				for (int j = 0; j < chainlength; j++){
					chainHash = hash(initialpasswd);
					if (originalhash.equals(chainHash)){
						return initialpasswd;
					}
					initialpasswd = reduce(chainHash,j);
				}
			}
			
			
		}
		
		return null;
	}
	
	/* 
	 * Function computes the reduced password and checks if the hash of thet
	 * password matches any of the keys in the table. Start and end are the 
	 * indices of the reduce functions
	 */
	
	public String lookupChain(String originalhash, int start, int end){
		String reduce = null;
		String hash = originalhash;
		for (int i = start; i < end; i++){
			reduce = reduce(hash,i);
			hash = hash(reduce);
		}
		return hash;
	}

	/**
	 * Returns the String representation of the hash of the given password.
	 * message_digest is initialized to md5, so this will be the md5 hash if 
	 * nothing is changed.
	 */
	private String hash(String passwd) {
		try {
			res = message_digest.digest(passwd.getBytes("US-ASCII"));
			bi = new BigInteger(1, res);
			return String.format("%0" + (res.length * 2) + "x", bi);
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		return null;
	}
	

	/**
	 * This method reduces a hash to a password in the password space.
	 * The method will (likely) return a different password depending on the subscript passed in.
	 * It is deterministic (i.e. same input will lead to the same output).
	 */
	private String reduce(String hash, int subscript) {
		try {
			hash += subscript;
			res = message_digest.digest(hash.getBytes("US-ASCII"));
			bi = (new BigInteger(res)).mod(passwordSpaceSize);
			StringBuilder pwd = new StringBuilder();
			for(int i=0; i<NUM_CHARACTERS; i++) {
				pwd.append(characters[bi.mod(charactersLength).intValue()]);
				bi = bi.divide(charactersLength);
			}
			return pwd.toString();
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		return null;
	}
	
	/**
	 * This method simply writes the lastToFirst map to a file so it can be read later.
	 * The file just has each key/value pair on its own line
	 * 
	 */
	private void writeToFile(String filename) {
		File f = new File(filename);
		try {
			BufferedWriter bw = new BufferedWriter(new FileWriter(f));
			for (String key : lastToFirst.keySet()) {
				bw.write(key + " " + lastToFirst.get(key) + "\n");
			}
			bw.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	/**
	 * This method reads a file of key/value pairs into the lastToFirst map.
	 * 
	 */
	private boolean readFromFile(String filename) {
		File f = new File(filename);
		if (!f.exists()) {
			System.out.println("File does not exist yet, building file");
			return false;
		}
		try {
			BufferedReader br = new BufferedReader(new FileReader(f));
			String line = null;
			String[] pair;
			while ((line = br.readLine()) != null) {
				pair = line.split("\\s");
				if (pair.length != 2) {
					System.err.println("Invalid format in table file: " + line);
					continue;
				}
				lastToFirst.put(pair[0], pair[1]);
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
		return true;
	}
}
