import java.util.HashMap;
import java.util.Map;

public class CaesarCipher {
    private int shift;
    private Map<Character, Character> encryptionMap;
    private Map<Character, Character> decryptionMap;

    public CaesarCipher(int shift) {
        this.shift = shift;
        this.encryptionMap = createEncryptionMap(shift);
        this.decryptionMap = createDecryptionMap(shift);
    }

    // Create the encryption map based on the shift value
    private Map<Character, Character> createEncryptionMap(int shift) {
        Map<Character, Character> map = new HashMap<>();
        for (char c = 'a'; c <= 'z'; c++) {
            // Calculate the encrypted character based on the shift
            char encryptedChar = (char) ('a' + (c - 'a' + shift) % 26);
            map.put(c, encryptedChar);
        }
        return map;
    }

    // Create the decryption map based on the shift value
    private Map<Character, Character> createDecryptionMap(int shift) {
        Map<Character, Character> map = new HashMap<>();
        for (char c = 'a'; c <= 'z'; c++) {
            // Calculate the decrypted character based on the shift
            char decryptedChar = (char) ('a' + (c - 'a' - shift + 26) % 26);
            map.put(c, decryptedChar);
        }
        return map;
    }

    // Encrypt the message using the encryption map
    public String encrypt(String message) {
        StringBuilder encryptedMessage = new StringBuilder();
        for (char c : message.toCharArray()) {
            if (Character.isLetter(c)) {
                char encryptedChar = encryptionMap.get(Character.toLowerCase(c));
                encryptedMessage.append(Character.isUpperCase(c) ? Character.toUpperCase(encryptedChar) : encryptedChar);
            } else {
                encryptedMessage.append(c);
            }
        }
        return encryptedMessage.toString();
    }

    // Decrypt the encrypted message using the decryption map
    public String decrypt(String encryptedMessage) {
        StringBuilder decryptedMessage = new StringBuilder();
        for (char c : encryptedMessage.toCharArray()) {
            if (Character.isLetter(c)) {
                char decryptedChar = decryptionMap.get(Character.toLowerCase(c));
                decryptedMessage.append(Character.isUpperCase(c) ? Character.toUpperCase(decryptedChar) : decryptedChar);
            } else {
                decryptedMessage.append(c);
            }
        }
        return decryptedMessage.toString();
    }

    public static void main(String[] args) {
        int shift = 3;
        CaesarCipher cipher = new CaesarCipher(shift);

        String message = "Hello, World!";
        System.out.println("Original Message: " + message);

        String encryptedMessage = cipher.encrypt(message);
        System.out.println("Encrypted Message: " + encryptedMessage);

        String decryptedMessage = cipher.decrypt(encryptedMessage);
        System.out.println("Decrypted Message: " + decryptedMessage);
    }
}







