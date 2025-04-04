import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class Main {

    private static final String ALGORITHM = "AES";
    private static final String CIPHER_MODE = "AES/GCM/NoPadding";
    private static final int KEY_SIZE = 256;
    private static final int GCM_TAG_LENGTH = 128;
    private static final int IV_SIZE = 12;

    public static SecretKey generateKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM);
        keyGen.init(KEY_SIZE);
        return keyGen.generateKey();
    }

    public static byte[] generateIV() {
        byte[] iv = new byte[IV_SIZE];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    public static String encrypt(String data, SecretKey key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance(CIPHER_MODE);
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        byte[] encrypted = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }

    public static String decrypt(String encryptedData, SecretKey key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance(CIPHER_MODE);
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, spec);
        byte[] decoded = Base64.getDecoder().decode(encryptedData);
        byte[] decrypted = cipher.doFinal(decoded);
        return new String(decrypted);
    }

    static class UniversalSwitch {
        private final Map<String, SecretKey> keyStore = new HashMap<>();

        public void registerDevice(String deviceId, SecretKey key) {
            keyStore.put(deviceId, key);
        }

        public String sendData(String deviceId, String data) throws Exception {
            SecretKey key = keyStore.get(deviceId);
            if (key == null) throw new IllegalArgumentException("Device not registered.");
            byte[] iv = generateIV();
            String encrypted = encrypt(data, key, iv);
            return Base64.getEncoder().encodeToString(iv) + ":" + encrypted; // IV:CipherText
        }

        public String receiveData(String deviceId, String payload) throws Exception {
            SecretKey key = keyStore.get(deviceId);
            if (key == null) throw new IllegalArgumentException("Device not registered.");
            String[] parts = payload.split(":");
            byte[] iv = Base64.getDecoder().decode(parts[0]);
            String encrypted = parts[1];
            return decrypt(encrypted, key, iv);
        }
    }

    public static void main(String[] args) {
        try {
            UniversalSwitch switchDevice = new UniversalSwitch();
            String legacyDeviceId = "LEGACY-DEVICE-001";

            SecretKey deviceKey = generateKey();
            switchDevice.registerDevice(legacyDeviceId, deviceKey);

            String originalData = "Sensor=75;Status=ACTIVE";
            String payload = switchDevice.sendData(legacyDeviceId, originalData);
            System.out.println("Encrypted Payload: " + payload);

            String decrypted = switchDevice.receiveData(legacyDeviceId, payload);
            System.out.println("Decrypted Data: " + decrypted);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
