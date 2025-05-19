package com.ryumessenger.security;

import java.io.File;
import java.io.FileReader;
import java.math.BigInteger;
import java.nio.file.Path;
import java.security.*;
import javax.crypto.interfaces.DHPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.*;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;

import com.ryumessenger.util.Logger;
import java.nio.file.Paths;

/**
 * Управляет ключами клиента: RSA для асимметричного шифрования и DH для обмена секретами
 */
public class KeyManager implements AutoCloseable {
    private static final String USER_DATA_DIR = "user_data";
    private static final String RSA_PRIVATE_KEY_FILE = "user_RSA_private.pem";
    private static final String RSA_PUBLIC_KEY_FILE = "user_RSA_public.pem";
    private static final String DH_PRIVATE_KEY_FILE = "user_DH_private.pem";
    private static final String DH_PUBLIC_KEY_FILE = "user_DH_public.pem";
    
    // Ключи RSA
    private KeyPair rsaKeyPair;
    private BigInteger serverRsaPublicKeyN;
    private BigInteger serverRsaPublicKeyE;
    
    // Ключи DH
    private KeyPair dhKeyPair;
    private BigInteger dhServerPublicKeyY;
    private byte[] dhSharedSecret;
    
    // Пути к файлам
    private String userDataDirectoryPath;
    
    // DH параметры (должны быть согласованы с сервером)
    private BigInteger clientDhP;
    private BigInteger clientDhG;
    private boolean dhParametersSet = false;
    
    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
            Logger.info("BouncyCastle provider added.");
        } else {
            Logger.info("BouncyCastle provider already registered.");
        }
    }
    
    public KeyManager() {
        this(".");
    }

    public KeyManager(String baseDir) {
        this.userDataDirectoryPath = Paths.get(baseDir, USER_DATA_DIR).toString();
        
        File userDataDir = new File(userDataDirectoryPath);
        if (!userDataDir.exists()) {
            userDataDir.mkdirs();
            Logger.info("Создана директория для хранения ключей: " + userDataDir.getAbsolutePath());
        }
        
        try {
            initRSAKeys();
        } catch (Exception e) {
            Logger.error("Ошибка инициализации RSA ключей клиента: " + e.getMessage(), e);
            throw new RuntimeException("Не удалось инициализировать RSA ключи клиента", e);
        }
    }

    @Override
    public void close() {
        // Нет необходимости в очистке - нет чувствительных данных в памяти
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
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
            keyGen.initialize(2048, new SecureRandom());
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
        if (!dhParametersSet || clientDhP == null || clientDhG == null) {
            Logger.warn("Попытка инициализировать DH ключи клиента до установки DH параметров P и G от сервера. Инициализация отложена.");
            return;
        }

        File privateKeyFile = new File(USER_DATA_DIR, DH_PRIVATE_KEY_FILE);
        File publicKeyFile = new File(USER_DATA_DIR, DH_PUBLIC_KEY_FILE);
        
        if (privateKeyFile.exists() && publicKeyFile.exists()) {
            try {
                dhKeyPair = loadDHKeysFromPEM();
                Logger.info("Ключи DH клиента успешно загружены из PEM-файлов.");
                
                DHPublicKey pubKey = (DHPublicKey) dhKeyPair.getPublic();
                if (!pubKey.getParams().getP().equals(clientDhP) || !pubKey.getParams().getG().equals(clientDhG)) {
                    Logger.warn("Загруженные DH ключи клиента используют другие параметры P,G, чем текущие от сервера. Перегенерация.");
                    throw new GeneralSecurityException("DH параметры загруженного ключа не совпадают с серверными.");
                }
            } catch (Exception e) {
                Logger.warn("Не удалось загрузить или валидировать существующие DH ключи клиента (возможно, из-за смены P,G сервера): " + e.getMessage() + ". Будут сгенерированы новые.");
                generateAndSaveNewDHKeys();
            }
        } else {
            generateAndSaveNewDHKeys();
        }
    }
    
    private void generateAndSaveNewDHKeys() throws Exception {
        DHParameterSpec dhParams = new DHParameterSpec(clientDhP, clientDhG, 0);
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH", "BC");
        keyGen.initialize(dhParams);
        dhKeyPair = keyGen.generateKeyPair();
        
        saveDHKeysToPEM();
        Logger.info("Сгенерированы новые DH ключи клиента и сохранены в формате PEM.");
    }
    
    /**
     * Сохраняет RSA ключи в PEM-файлы
     */
    private void saveRSAKeysToPEM() throws Exception {
        // Сохраняем приватный ключ
        savePEMKey(new File(USER_DATA_DIR, RSA_PRIVATE_KEY_FILE), "PRIVATE KEY", rsaKeyPair.getPrivate().getEncoded());
        
        // Сохраняем публичный ключ
        savePEMKey(new File(USER_DATA_DIR, RSA_PUBLIC_KEY_FILE), "PUBLIC KEY", rsaKeyPair.getPublic().getEncoded());
        
        Logger.info("RSA ключи сохранены в PEM-формате: " + 
                   Path.of(USER_DATA_DIR, RSA_PUBLIC_KEY_FILE) + ", " + 
                   Path.of(USER_DATA_DIR, RSA_PRIVATE_KEY_FILE));
    }
    
    /**
     * Сохраняет DH ключи в PEM-файлы
     */
    private void saveDHKeysToPEM() throws Exception {
        // Сохраняем приватный ключ
        savePEMKey(new File(USER_DATA_DIR, DH_PRIVATE_KEY_FILE), "PRIVATE KEY", dhKeyPair.getPrivate().getEncoded());
        
        // Сохраняем публичный ключ
        savePEMKey(new File(USER_DATA_DIR, DH_PUBLIC_KEY_FILE), "PUBLIC KEY", dhKeyPair.getPublic().getEncoded());
        
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
        if (!dhParametersSet || clientDhP == null || clientDhG == null) {
            throw new IllegalStateException("DH параметры (P, G) должны быть установлены от сервера перед загрузкой DH ключей клиента.");
        }
        PrivateKey privateKey = loadPrivateKeyFromPEM(new File(USER_DATA_DIR, DH_PRIVATE_KEY_FILE), "DH");
        PublicKey publicKey = loadPublicKeyFromPEM(new File(USER_DATA_DIR, DH_PUBLIC_KEY_FILE), "DH");

        if (publicKey instanceof DHPublicKey) {
            DHPublicKey dhPubKey = (DHPublicKey) publicKey;
            DHParameterSpec params = dhPubKey.getParams();
            if (!params.getP().equals(clientDhP) || !params.getG().equals(clientDhG)) {
                 Logger.error("Параметры P,G загруженного DH публичного ключа клиента (" + params.getP().toString().substring(0,10) + "...," + params.getG() + ") " +
                             "не совпадают с текущими параметрами от сервера (" + clientDhP.toString().substring(0,10) + "...," + clientDhG + ").");
                throw new GeneralSecurityException("Параметры DH загруженного ключа клиента не совпадают с текущими параметрами от сервера.");
            }
        } else {
             throw new GeneralSecurityException("Загруженный публичный ключ DH имеет неверный тип.");
        }
        return new KeyPair(publicKey, privateKey);
    }
    
    /**
     * Загружает публичный ключ из PEM-файла
     */
    private PublicKey loadPublicKeyFromPEM(File file, String algorithm) throws Exception {
        byte[] encoded = readPEMFile(file);

        // Логирование для отладки
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < Math.min(encoded.length, 16); i++) {
            sb.append(String.format("%02X ", encoded[i]));
        }
        Logger.info("loadPublicKeyFromPEM: Reading from file: " + file.getAbsolutePath());
        Logger.info("loadPublicKeyFromPEM: Algorithm: " + algorithm);
        Logger.info("loadPublicKeyFromPEM: Encoded key length: " + encoded.length);
        Logger.info("loadPublicKeyFromPEM: First " + Math.min(encoded.length, 16) + " bytes of encoded key: " + sb.toString().trim());

        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
        return keyFactory.generatePublic(keySpec);
    }
    
    /**
     * Загружает приватный ключ из PEM-файла
     */
    private PrivateKey loadPrivateKeyFromPEM(File file, String algorithm) throws Exception {
        byte[] encoded = readPEMFile(file);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
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
     * Устанавливает публичный ключ DH сервера и вычисляет общий секрет
     */
    public synchronized void setServerDHPublicKey(BigInteger serverDhY) throws Exception {
        if (!dhParametersSet || clientDhP == null || clientDhG == null) {
            throw new IllegalStateException("DH параметры клиента (P, G) должны быть установлены перед установкой публичного ключа DH сервера.");
        }
        if (dhKeyPair == null) {
            Logger.warn("DH ключевая пара клиента не инициализирована при попытке установить ключ DH сервера. Попытка инициализации...");
            initDHKeys();
            if (dhKeyPair == null) {
                 throw new IllegalStateException("DH ключевая пара клиента не может быть инициализирована. Проверьте установку P и G.");
            }
        }
        
        this.dhServerPublicKeyY = serverDhY;
        Logger.info("Публичный ключ DH сервера установлен: Y_server=" + serverDhY.toString().substring(0, Math.min(10,serverDhY.toString().length())) + "...");
        
        KeyFactory keyFactory = KeyFactory.getInstance("DH", "BC");
        DHPublicKeySpec dhPublicKeySpec = new DHPublicKeySpec(serverDhY, clientDhP, clientDhG);
        PublicKey serverDHPublicKey = keyFactory.generatePublic(dhPublicKeySpec);
        
        KeyAgreement keyAgreement = KeyAgreement.getInstance("DH", "BC");
        keyAgreement.init(dhKeyPair.getPrivate());
        keyAgreement.doPhase(serverDHPublicKey, true);
        
        this.dhSharedSecret = keyAgreement.generateSecret();
        Logger.info("Общий секрет DH успешно сгенерирован. Длина: " + (dhSharedSecret != null ? dhSharedSecret.length * 8 : "null") + " бит.");
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
        if (dhKeyPair == null) {
            Logger.warn("Попытка получить Y клиента, но DH ключевая пара не инициализирована.");
            if (dhParametersSet) {
                try {
                    initDHKeys();
                } catch (Exception e) {
                     Logger.error("Не удалось инициализировать DH ключи при попытке получить Y клиента: " + e.getMessage(), e);
                     return null;
                }
            }
            if (dhKeyPair == null) return null;
        }
        DHPublicKey dhPublicKey = (DHPublicKey) dhKeyPair.getPublic();
        return dhPublicKey.getY();
    }
    
    /**
     * Возвращает общий DH-секрет, вычисленный с сервером
     */
    public byte[] getDHSharedSecret() {
        if (dhSharedSecret == null) {
             Logger.warn("Попытка получить общий секрет DH, но он еще не сгенерирован.");
        }
        return dhSharedSecret;
    }
    
    /**
     * Проверяет, доступен ли публичный ключ DH сервера.
     */
    public boolean isServerDHPublicKeyAvailable() {
        return dhServerPublicKeyY != null;
    }
    
    /**
     * Возвращает публичный RSA-ключ сервера, собранный из компонентов
     */
    public PublicKey getServerRSAPublicKey() throws Exception {
        if (serverRsaPublicKeyN == null || serverRsaPublicKeyE == null) {
            Logger.warn("KeyManager: Публичный ключ RSA сервера не установлен (n или e is null).");
            return null;
        }
        
        RSAPublicKeySpec keySpec = new RSAPublicKeySpec(serverRsaPublicKeyN, serverRsaPublicKeyE);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(keySpec);
    }

    public void setDHParameters(BigInteger p, BigInteger g) {
        if (p == null || g == null) {
            Logger.error("Попытка установить нулевые DH параметры P или G.");
            throw new IllegalArgumentException("DH параметры P и G не могут быть null.");
        }
        this.clientDhP = p;
        this.clientDhG = g;
        this.dhParametersSet = true;
        Logger.info("DH параметры клиента установлены: P=" + p.toString().substring(0, Math.min(10,p.toString().length())) + "..., G=" + g.toString());

        try {
            initDHKeys();
        } catch (Exception e) {
            Logger.error("Ошибка инициализации DH ключей клиента после установки параметров: " + e.getMessage(), e);
            throw new RuntimeException("Не удалось инициализировать DH ключи клиента", e);
        }
    }

    public boolean areDHParametersSet() {
        return this.dhParametersSet;
    }

    /**
     * Возвращает PEM представление публичного ключа DH клиента.
     * Необходимо для отправки на сервер или другому клиенту.
     */
    public String getClientDHPublicKeyAsPEM() throws Exception {
        if (dhKeyPair == null) {
            initDHKeys();
            if (dhKeyPair == null) {
                 throw new IllegalStateException("Не удалось инициализировать/получить DH ключи клиента.");
            }
        }
        File tempFile = File.createTempFile("temp_client_dh_pub", ".pem");
        tempFile.deleteOnExit();
        savePEMKey(tempFile, "PUBLIC KEY", dhKeyPair.getPublic().getEncoded());
        
        String pemString = new String(java.nio.file.Files.readAllBytes(tempFile.toPath()));
        tempFile.delete();
        return pemString;
    }
    
    public BigInteger getClientDhP() {
        return clientDhP;
    }

    public BigInteger getClientDhG() {
        return clientDhG;
    }

    /**
     * Возвращает DH KeyPair клиента.
     * Может вернуть null, если ключи не инициализированы.
     */
    public KeyPair getDhKeyPair() {
        // Попытка инициализировать, если еще не сделано и параметры есть
        if (dhKeyPair == null && dhParametersSet) {
            try {
                initDHKeys();
            } catch (Exception e) {
                Logger.error("KeyManager: Не удалось инициализировать DH ключи при попытке получить KeyPair: " + e.getMessage(), e);
                return null;
            }
        }
        return dhKeyPair;
    }

    /**
     * Возвращает объект приватного RSA ключа клиента.
     * @return java.security.PrivateKey или null, если ключи не инициализированы.
     */
    public java.security.PrivateKey getRsaPrivateKeyObject() {
        if (rsaKeyPair != null) {
            return rsaKeyPair.getPrivate();
        }
        // Можно добавить попытку загрузки или генерации, если rsaKeyPair == null
        // Logger.warn("KeyManager: Попытка получить объект приватного RSA ключа, но rsaKeyPair не инициализирован.");
        return null;
    }

    /**
     * Возвращает объект публичного RSA ключа клиента.
     * @return java.security.PublicKey или null, если ключи не инициализированы.
     */
    public java.security.PublicKey getRsaPublicKeyObject() {
        if (rsaKeyPair != null) {
            return rsaKeyPair.getPublic();
        }
        return null;
    }
} 