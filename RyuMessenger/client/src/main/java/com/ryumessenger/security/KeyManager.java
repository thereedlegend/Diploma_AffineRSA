package com.ryumessenger.security;

import java.io.File;
import java.io.FileReader;
import java.math.BigInteger;
import java.nio.file.Path;
import java.security.*;
import javax.crypto.interfaces.DHPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.*;
import java.util.Map;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;

import com.ryumessenger.util.Logger;

/**
 * Управляет ключами клиента: RSA для асимметричного шифрования и DH для обмена секретами
 */
public class KeyManager {
    private static final String USER_DATA_DIR = "user_data";
    private static final String RSA_PRIVATE_KEY_FILE = "user_RSA_private.pem";
    private static final String RSA_PUBLIC_KEY_FILE = "user_RSA_public.pem";
    private static final String DH_PRIVATE_KEY_FILE = "user_DH_private.pem";
    private static final String DH_PUBLIC_KEY_FILE = "user_DH_public.pem";
    
    // Ключи RSA
    private KeyPair rsaKeyPair;
    private BigInteger serverRsaPublicKeyN;
    private BigInteger serverRsaPublicKeyE;
    
    // Параметры аффинного шифра сервера
    private Map<String, Object> serverAffineParams;
    
    // Ключи DH
    private KeyPair dhKeyPair;
    private BigInteger dhServerPublicKey;
    private byte[] dhSharedSecret;
    
    // DH параметры (должны быть согласованы с сервером)
    private static final BigInteger DH_P = new BigInteger("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF", 16);
    private static final BigInteger DH_G = BigInteger.valueOf(2);
    
    static {
        Security.addProvider(new BouncyCastleProvider());
    }
    
    public KeyManager() {
        ensureUserDataDir();
        // Инициализация ключей при создании экземпляра
        try {
            initRSAKeys();
            initDHKeys();
        } catch (Exception e) {
            String errorMessage = "Критическая ошибка при инициализации ключей в KeyManager: " + e.getMessage();
            Logger.error(errorMessage, e);
            throw new RuntimeException(errorMessage, e);
        }
    }
    
    /**
     * Гарантирует, что директория user_data существует
     */
    private void ensureUserDataDir() {
        File userDataDir = new File(USER_DATA_DIR);
        if (!userDataDir.exists()) {
            userDataDir.mkdirs();
            Logger.info("Создана директория для хранения ключей пользователя: " + userDataDir.getAbsolutePath());
        }
    }
    
    /**
     * Загружает или генерирует RSA-ключи клиента
     */
    public void initRSAKeys() throws Exception {
        File privateKeyFile = new File(USER_DATA_DIR, RSA_PRIVATE_KEY_FILE);
        File publicKeyFile = new File(USER_DATA_DIR, RSA_PUBLIC_KEY_FILE);
        
        if (privateKeyFile.exists() && publicKeyFile.exists()) {
            // Загружаем существующие ключи
            rsaKeyPair = loadRSAKeysFromPEM();
            Logger.info("Ключи RSA успешно загружены из PEM-файлов.");
        } else {
            // Генерируем новые ключи
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            rsaKeyPair = keyGen.generateKeyPair();
            
            // Сохраняем ключи
            saveRSAKeysToPEM();
            Logger.info("Сгенерированы новые RSA ключи и сохранены в формате PEM.");
        }
    }
    
    /**
     * Загружает или генерирует ключи DH клиента
     */
    public void initDHKeys() throws Exception {
        File privateKeyFile = new File(USER_DATA_DIR, DH_PRIVATE_KEY_FILE);
        File publicKeyFile = new File(USER_DATA_DIR, DH_PUBLIC_KEY_FILE);
        
        if (privateKeyFile.exists() && publicKeyFile.exists()) {
            // Загружаем существующие ключи
            dhKeyPair = loadDHKeysFromPEM();
            Logger.info("Ключи DH успешно загружены из PEM-файлов.");
        } else {
            // Генерируем новые ключи
            DHParameterSpec dhParams = new DHParameterSpec(DH_P, DH_G);
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");
            keyGen.initialize(dhParams);
            dhKeyPair = keyGen.generateKeyPair();
            
            // Сохраняем ключи
            saveDHKeysToPEM();
            Logger.info("Сгенерированы новые DH ключи и сохранены в формате PEM.");
        }
    }
    
    /**
     * Сохраняет RSA ключи в PEM-файлы
     */
    private void saveRSAKeysToPEM() throws Exception {
        // Сохраняем приватный ключ
        savePEMKey(new File(USER_DATA_DIR, RSA_PRIVATE_KEY_FILE), "RSA PRIVATE KEY", rsaKeyPair.getPrivate().getEncoded());
        
        // Сохраняем публичный ключ
        savePEMKey(new File(USER_DATA_DIR, RSA_PUBLIC_KEY_FILE), "RSA PUBLIC KEY", rsaKeyPair.getPublic().getEncoded());
        
        Logger.info("RSA ключи сохранены в PEM-формате: " + 
                   Path.of(USER_DATA_DIR, RSA_PUBLIC_KEY_FILE) + ", " + 
                   Path.of(USER_DATA_DIR, RSA_PRIVATE_KEY_FILE));
    }
    
    /**
     * Сохраняет DH ключи в PEM-файлы
     */
    private void saveDHKeysToPEM() throws Exception {
        // Сохраняем приватный ключ
        savePEMKey(new File(USER_DATA_DIR, DH_PRIVATE_KEY_FILE), "DH PRIVATE KEY", dhKeyPair.getPrivate().getEncoded());
        
        // Сохраняем публичный ключ
        savePEMKey(new File(USER_DATA_DIR, DH_PUBLIC_KEY_FILE), "DH PUBLIC KEY", dhKeyPair.getPublic().getEncoded());
        
        Logger.info("DH ключи сохранены в PEM-формате: " + 
                   Path.of(USER_DATA_DIR, DH_PUBLIC_KEY_FILE) + ", " + 
                   Path.of(USER_DATA_DIR, DH_PRIVATE_KEY_FILE));
    }
    
    /**
     * Сохраняет ключ в формате PEM
     */
    private void savePEMKey(File file, String type, byte[] encoded) throws Exception {
        try (PemWriter pemWriter = new PemWriter(new java.io.FileWriter(file))) {
            PemObject pemObject = new PemObject(type, encoded);
            pemWriter.writeObject(pemObject);
        }
    }
    
    /**
     * Загружает RSA ключи из PEM-файлов
     */
    private KeyPair loadRSAKeysFromPEM() throws Exception {
        PublicKey publicKey = loadPublicKeyFromPEM(new File(USER_DATA_DIR, RSA_PUBLIC_KEY_FILE), "RSA");
        PrivateKey privateKey = loadPrivateKeyFromPEM(new File(USER_DATA_DIR, RSA_PRIVATE_KEY_FILE), "RSA");
        return new KeyPair(publicKey, privateKey);
    }
    
    /**
     * Загружает DH ключи из PEM-файлов
     */
    private KeyPair loadDHKeysFromPEM() throws Exception {
        PublicKey publicKey = loadPublicKeyFromPEM(new File(USER_DATA_DIR, DH_PUBLIC_KEY_FILE), "DH");
        PrivateKey privateKey = loadPrivateKeyFromPEM(new File(USER_DATA_DIR, DH_PRIVATE_KEY_FILE), "DH");
        return new KeyPair(publicKey, privateKey);
    }
    
    /**
     * Загружает публичный ключ из PEM-файла
     */
    private PublicKey loadPublicKeyFromPEM(File file, String algorithm) throws Exception {
        byte[] encoded = readPEMFile(file);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
        return keyFactory.generatePublic(keySpec);
    }
    
    /**
     * Загружает приватный ключ из PEM-файла
     */
    private PrivateKey loadPrivateKeyFromPEM(File file, String algorithm) throws Exception {
        byte[] encoded = readPEMFile(file);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
        return keyFactory.generatePrivate(keySpec);
    }
    
    /**
     * Читает содержимое PEM-файла
     */
    private byte[] readPEMFile(File file) throws Exception {
        try (PemReader pemReader = new PemReader(new FileReader(file))) {
            PemObject pemObject = pemReader.readPemObject();
            return pemObject.getContent();
        }
    }
    
    /**
     * Устанавливает публичный RSA-ключ сервера
     */
    public void setServerRSAPublicKey(BigInteger n, BigInteger e) {
        this.serverRsaPublicKeyN = n;
        this.serverRsaPublicKeyE = e;
        Logger.info(String.format("KeyManager: Публичный RSA ключ сервера установлен: n=%s..., e=%s",
                (n != null ? n.toString().substring(0, Math.min(10, n.toString().length())) + "..." : "null"),
                (e != null ? e.toString() : "null")));
    }
    
    /**
     * Устанавливает параметры аффинного шифра сервера
     */
    public void setServerAffineParams(Map<String, Object> affineParams) {
        this.serverAffineParams = affineParams;
        Logger.info("KeyManager: Аффинные параметры сервера установлены: " + affineParams);
    }
    
    /**
     * Устанавливает публичный DH-ключ сервера и вычисляет общий секрет
     */
    public void setServerDHPublicKey(BigInteger dhPublicKey) throws Exception {
        this.dhServerPublicKey = dhPublicKey;
        
        if (dhKeyPair == null || dhKeyPair.getPrivate() == null) {
            Logger.error("KeyManager: DHKeyPair клиента не инициализирован перед установкой DH ключа сервера.");
            throw new IllegalStateException("Клиентский DHKeyPair не инициализирован.");
        }
        
        KeyFactory keyFactory = KeyFactory.getInstance("DH");
        DHPublicKeySpec keySpec = new DHPublicKeySpec(dhPublicKey, DH_P, DH_G);
        PublicKey serverPublicKeyObj = keyFactory.generatePublic(keySpec);
        
        KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
        keyAgreement.init(dhKeyPair.getPrivate());
        keyAgreement.doPhase(serverPublicKeyObj, true);
        
        this.dhSharedSecret = keyAgreement.generateSecret();
        Logger.info("KeyManager: Вычислен общий DH-секрет с сервером. Длина: " + (dhSharedSecret != null ? dhSharedSecret.length : 0));
    }
    
    /**
     * Возвращает компоненты публичного RSA-ключа клиента (n, e)
     */
    public BigInteger[] getClientRSAPublicKeyComponents() {
        if (rsaKeyPair == null || !(rsaKeyPair.getPublic() instanceof RSAPublicKey)) {
             Logger.error("KeyManager: RSAKeyPair клиента не инициализирован или публичный ключ не является RSAPublicKey.");
            return null; 
        }
        RSAPublicKey publicKey = (RSAPublicKey) rsaKeyPair.getPublic();
        return new BigInteger[] { publicKey.getModulus(), publicKey.getPublicExponent() };
    }
    
    /**
     * Возвращает приватный RSA-ключ клиента
     */
    public PrivateKey getClientRSAPrivateKey() {
        return (rsaKeyPair != null) ? rsaKeyPair.getPrivate() : null;
    }
    
    /**
     * Возвращает публичный RSA-ключ клиента
     */
    public PublicKey getClientRSAPublicKey() {
        return rsaKeyPair != null ? rsaKeyPair.getPublic() : null;
    }
    
    /**
     * Возвращает Y-компоненту публичного DH-ключа клиента (BigInteger)
     */
    public BigInteger getClientDHPublicKeyY() {
        if (dhKeyPair == null || !(dhKeyPair.getPublic() instanceof DHPublicKey)) {
           Logger.error("KeyManager: DHKeyPair клиента не инициализирован или публичный ключ не является DHPublicKey.");
           return null;
        }
        DHPublicKey publicKey = (DHPublicKey) dhKeyPair.getPublic();
        return publicKey.getY();
    }
    
    /**
     * Возвращает общий DH-секрет, вычисленный с сервером
     */
    public byte[] getDHSharedSecret() {
        if (dhSharedSecret == null) {
            Logger.warn("Попытка получить DH общий секрет, но он еще не вычислен (равен null).");
        }
        return dhSharedSecret;
    }
    
    /**
     * Проверяет, доступен ли публичный ключ DH сервера.
     */
    public boolean isServerDHPublicKeyAvailable() {
        return this.dhServerPublicKey != null;
    }
    
    /**
     * Возвращает публичный RSA-ключ сервера, собранный из компонентов
     */
    public PublicKey getServerRSAPublicKey() throws Exception {
        if (serverRsaPublicKeyN == null || serverRsaPublicKeyE == null) {
            Logger.warn("KeyManager: Публичный ключ RSA сервера не установлен (n или e is null).");
            return null; // Или выбросить исключение, если это критично
        }
        
        RSAPublicKeySpec keySpec = new RSAPublicKeySpec(serverRsaPublicKeyN, serverRsaPublicKeyE);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(keySpec);
    }
    
    /**
     * Возвращает параметры аффинного шифра сервера
     */
    public Map<String, Object> getServerAffineParams() {
        return serverAffineParams;
    }
} 