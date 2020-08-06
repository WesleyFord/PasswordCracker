import java.util.Scanner;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;


public class PasswordCracker {
		
	//A seven char word from /usr/share/dict/words (Linux or Mac) which gets the first
	//letter capitalized and a 1-digit number appended
	public static void ruleOne(File passwordFile, MessageDigest digest, PrintWriter writer, File wordListFile) throws FileNotFoundException {
		String encrypted;
		String fileLine;
		String[] splitLine;
		String word;
		Scanner passwords = new Scanner(passwordFile);
		
		//Runs this rule until all passwords have been tried.
		while (passwords.hasNext()) {
			Scanner wordlist = new Scanner(wordListFile);
			//Gets next password in the file
			fileLine = passwords.nextLine();
			splitLine = fileLine.split(":");
			
			//Gets the value of the encrypted password that we're searching for
			encrypted = splitLine[1];
			Boolean found = false;
			//Runs until there are no more words in the wordlist or until the correct password is found.
			while (wordlist.hasNext() && found == false) {
				//Gets the new word to try
				word = wordlist.next();
				//Checks to ensure that the word is exactly 7 characters long
				if (word.length() == 7) {
					//Runs through every possible value to append to the string
					for (int i = 0; i < 10; i++) {
						//Capitalizes the first letter
						String newWord = word.substring(0, 1).toUpperCase() + word.substring(1) + "" + i;
						
						//Generates the SHA-256 hashed value of the password we have generated
						byte[] byteWord = digest.digest(newWord.getBytes(StandardCharsets.UTF_8));
						BigInteger tempNum = new BigInteger(1, byteWord);
						String hashedWord = String.format("%064x", tempNum);
						
						//If the hashed word matches the password's encrypted hash, print the password
						//to the console and to the output file and break the loops back to get the next password
						if (hashedWord.compareTo(encrypted) == 0) {
							found = true;
							System.out.println(encrypted + ":" + newWord);
							writer.println(encrypted + ":" + newWord);
							break;
						}
					}
				
					if (found == true) {
						break;
					}		
				}
			}
			wordlist.close();
		}
		passwords.close();
	}
	
	//A four digit password with at least one of the following special characters in the
	//beginning: *, ~, !, #
	public static void ruleTwo(File passwordFile, MessageDigest digest, PrintWriter writer, File wordListFile) throws FileNotFoundException {
		String encrypted;
		String fileLine;
		String[] splitLine;
		Scanner passwords = new Scanner(passwordFile);
		//Loops until all passwords have been attempted
		while (passwords.hasNext()) {
			//Gets the line in password file and the encrypted password we are looking for
			fileLine = passwords.nextLine();
			splitLine = fileLine.split(":");
			boolean found = false;
			encrypted = splitLine[1];
			
			//Loops through all possible 4-digit combinations of numbers
			for (int i = 0; i < 9999; i++) {
				//I developed a Python script to generate a list of all combinations of the 4 symbols,
				//which is much faster than looping through each combination and removing duplicates (256+ times
				//vs 64).
				String[] symbols = {"!", "#", "*", "~", "!#", "!*", "!~", "#!", "#*", "#~", "*!",
									"*#", "*~", "~!", "~#", "~*", "!#*", "!#~", "!*#", "!*~", "!~#",
									"!~*", "#!~", "#!*", "#*~", "#*!", "#~*", "#~!", "*!#", "*!~", "*#!", 
									"*#~", "*~!", "*~#", "~!*", "~!#", "~#*", "~#!", "~*#", "~*!", "!#*~", 
									"!#~*", "!~#*", "!~*#", "!*#~", "!*~#", "#!~*", "#!*~", "#~*!", "#~!*", 
									"#*~!", "#*!~", "~!#*", "~!*#", "~#*!", "~#!*", "~*#!", "~*!#", "*~!#", 
									"*~#!", "*!#~", "*!~#", "*#!~", "*#~!"};
				//Format the number with padded zeroes to make it 4 digits
				String passNum = String.format("%04d", i);
				String thisPass;
				
				//Loop through every combination of symbols
				for (int j = 0; j < symbols.length; j++) {
					//Puts a combination of symbols at the front of the generated number
					thisPass = symbols[j] + passNum;
					
					//Generates a SHA-256 encryption key for the number and symbol combination 
					//and checks it against the given password encryption.
					byte[] byteWord = digest.digest(thisPass.getBytes(StandardCharsets.UTF_8));
					BigInteger tempNum = new BigInteger(1, byteWord);
					String hashedWord = String.format("%064x", tempNum);

					//If the two match, exit the loops and print to the console and output file.
					if (hashedWord.compareTo(encrypted) == 0) {
						found = true;
						System.out.println(encrypted + ":" + thisPass);
						writer.println(encrypted + ":" + thisPass);
						break;
					}	
				}
				if (found == true) break;
			}
		}
		passwords.close();
	}
	
	//A five char word from /usr/share/dict/words with the letter 'a' in it which gets replaced
	//with the special character @ and the character �l� is substituted by the number �1�. All combinations 
	public static void ruleThree(File passwordFile, MessageDigest digest, PrintWriter writer, File wordListFile) throws FileNotFoundException {
		String encrypted;
		Scanner passwords = new Scanner(passwordFile);
		//Loops through until there are no passwords left to try
		while (passwords.hasNextLine()) {
			//Gets the password line from the file and retrieves the encrypted password.
			String fileLine = passwords.nextLine();
			String[] splitLine = fileLine.split(":");
			encrypted = splitLine[1];
			Scanner wordlist = new Scanner(wordListFile);
			String word;
			Boolean found = false;
			
			//Scans through the wordlist file until the wordlist runs out of combinations or 
			//the password is found
			while(wordlist.hasNextLine() && found == false) {
				word = wordlist.nextLine();
				String temp = word;
				//Checks that the password is exactly 5 characters long
				if (word.length() == 5) {
					//Loops through and tries 4 combinations of replacement, including no replacement:
					for (int i = 0; i < 4; i++) {
						//Replace a's with @
						if (i == 1) {
							temp = word.replaceAll("a", "@");
							temp = temp.replaceAll("A", "@");
						}
						//Replace l's with 1's
						if (i == 2) {
							temp = word.replaceAll("l", "1");
							temp = temp.replaceAll("L", "1");	
						}
						//Replace a's with @ and l's with 1's	
						if (i == 3) {
							temp = word.replaceAll("a", "@");
							temp = temp.replaceAll("A", "@");
							temp = temp.replaceAll("l", "1");
							temp = temp.replaceAll("L", "1");
						}
						
						//Generate a SHA-256 encryption of the password to try
						byte[] byteWord = digest.digest(temp.getBytes(StandardCharsets.UTF_8));
						BigInteger tempNum = new BigInteger(1, byteWord);
						String hashedWord = String.format("%064x", tempNum);
						
						//Check the encryption of the password we are trying against the given encrypted value
						//If the two are a match, exit the loops to the next password and print to the console
						//and to the output file
						if (hashedWord.compareTo(encrypted) == 0) {
							found = true;
							System.out.println(encrypted + ":" + temp);
							writer.println(encrypted + ":" + temp);
							break;
						}	
					}
				}
			} 
			wordlist.close();
		}
		passwords.close();
	}
	
	//Any number that is made with digits up to 6 digits length.
	public static void ruleFour(File passwordFile, MessageDigest digest, PrintWriter writer, File wordListFile) throws FileNotFoundException {
		String encrypted;
		Scanner passwords = new Scanner(passwordFile);
		//Loop through the passwords list until there are no more passwords to try.
		while (passwords.hasNextLine()) {
			//Get the encrypted password we are trying to crack
			String fileLine = passwords.nextLine();
			String[] splitLine = fileLine.split(":");
			encrypted = splitLine[1];
			String numberPassword;
			//Loop through all numbers between 0 and 999999 to get all 6-digit numbers.
			for (int i = 0; i < 999999; i++) {
				//Pad the number to the left with zeroes if it would normally be under 6 digits
				numberPassword = String.format("%06d", i);
				
				//Generate a SHA-256 encryption for the number we are trying as the password
				byte[] byteNum = digest.digest(numberPassword.getBytes(StandardCharsets.UTF_8));	
				BigInteger tempNum = new BigInteger(1, byteNum);
				String hashedNum = String.format("%064x", tempNum);
				
				//If the two SHA keys match, print the password values to the console and output file 
				//and exit the for loop.
				if (hashedNum.compareTo(encrypted) == 0) {
					System.out.println(encrypted + ":" + numberPassword);
					writer.println(encrypted + ":" + numberPassword);
					break;
				}
				
			}
		}
		passwords.close();
	}
	
	//Any number of chars single word from /usr/share/dict/words (Linux or Mac)
	public static void ruleFive(File passwordFile, MessageDigest digest, PrintWriter writer, File wordListFile) throws FileNotFoundException {
		String encrypted;
		String word;
		Scanner passwords = new Scanner(passwordFile);
		//Loop through until there are no more passwords to try to crack
		while (passwords.hasNextLine()) {
			Scanner wordlist = new Scanner(wordListFile);
			//Get the encrypted value of the password we are trying to crack
			String fileLine = passwords.nextLine();
			String[] splitLine = fileLine.split(":");
			encrypted = splitLine[1];
			
			//Loop through the entire wordlist
			while (wordlist.hasNext()) {
				word = wordlist.nextLine();
				//For each word, generate a SHA-256 key 
				byte[] byteWord = digest.digest(word.getBytes(StandardCharsets.UTF_8));
				BigInteger tempNum = new BigInteger(1, byteWord);
				String hashedWord = String.format("%064x", tempNum);
				
				//Check the generated SHA key against the one provided in the password file.
				//Exit the wordlist loop and print the password to the output file and to the console.
				if (hashedWord.compareTo(encrypted) == 0) {
					System.out.println(encrypted + ":" + word);
					writer.println(encrypted + ":" + word);
					break;
				}
			}
			wordlist.close();
		}
		passwords.close();
	}

	
	public static void main(String args[]) throws NoSuchAlgorithmException, FileNotFoundException {
		Scanner keyboard = new Scanner(System.in);
		MessageDigest digest = MessageDigest.getInstance("SHA-256");
		
		//Create an output file that we can print to
		PrintWriter writer = new PrintWriter("crackedPasswords.txt");
		
		//Get the wordlist and password file paths from the user.
		System.out.print("Please enter the path to the password file you would like to crack: ");
		
		File passwordFile = new File(keyboard.next());
		
		System.out.print("Please enter the path to the word file you would like to use: ");
		
		File wordListFile = new File(keyboard.next());
		
		//Get the rule number that the user would like to follow or quit if they type q or quit.
		System.out.println("Please enter the number of the password rule you would like to crack or type q or quit to exit: ");
		System.out.println("1: Seven character word with the first letter capitalized and one digit appended");
		System.out.println("2: A four digit password with a symbol (*, ~, !, #) at the beginning");
		System.out.println("3: A five character word with 'a' replaced by @ and 'l' replaced by 1");
		System.out.println("4: Any word made with digits up to six digits length");
		System.out.println("5: A word of any length");
		System.out.print("Which rule would you like to crack? ");
		
		Boolean isValid = false;
		//Loops until the user enters a valid rule value or quits the program. Runs the appropriate method
		//for the desired rule value.
		while (isValid == false) {
			String ruleToFollow = keyboard.next();
			if (ruleToFollow.toLowerCase().compareTo("q") == 0 || ruleToFollow.toLowerCase().compareTo("quit") == 0) break;
			else if (ruleToFollow.compareTo("1") == 0) {
				ruleOne(passwordFile, digest, writer, wordListFile);
				isValid = true;
			}
			else if (ruleToFollow.compareTo("2") == 0) {
				ruleTwo(passwordFile, digest, writer, wordListFile);
				isValid = true;
			}
			else if (ruleToFollow.compareTo("3") == 0) {
				ruleThree(passwordFile, digest, writer, wordListFile);
				isValid = true;
			}
			else if (ruleToFollow.compareTo("4") == 0) {
				ruleFour(passwordFile, digest, writer, wordListFile);
				isValid = true;
			}
			else if (ruleToFollow.compareTo("5") == 0) {
				ruleFive(passwordFile, digest, writer, wordListFile);
				isValid = true;
			}
			else System.out.print("That is not a valid rule number. Please try again or type q or quit to exit: ");
		}
		writer.close();
		keyboard.close();			
	}
}
