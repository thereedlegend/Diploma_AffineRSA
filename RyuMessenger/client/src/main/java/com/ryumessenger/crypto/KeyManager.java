package com.ryumessenger.crypto;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.security.KeyFactory;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

public class KeyManager {
    private RSA.KeyPair clientRsaKeyPair;
    private AffineCipher clientAffineCipher; // Общий афинный шифр (вместо разных для языков)
    private String keysDirectoryPath;
    private String keysFilePath;
    private String userDataDirectoryPath;
    private String rsaPublicPemPath;
    private String rsaPrivatePemPath;

    // Поля для хранения публичного ключа RSA сервера и его аффинных параметров
    private RSA.PublicKey serverRsaPublicKey;
    private JSONObject serverAffineParamsJson;

    // Используем DiffieHellman для обмена ключами
    private DiffieHellman diffieHellman;

    public KeyManager(String baseDir) {
        this.keysDirectoryPath = Paths.get(baseDir, CryptoConstants.KEYS_DIR_NAME).toString();
        this.keysFilePath = Paths.get(this.keysDirectoryPath, CryptoConstants.CLIENT_KEYS_FILE_NAME).toString();
        
        // Новая директория user_data для PEM-файлов
        this.userDataDirectoryPath = Paths.get(baseDir, "user_data").toString();
        this.rsaPublicPemPath = Paths.get(this.userDataDirectoryPath, "user_RSA_public.pem").toString();
        this.rsaPrivatePemPath = Paths.get(this.userDataDirectoryPath, "user_RSA_private.pem").toString();
        
        this.diffieHellman = new DiffieHellman(); // Инициализируем DH с параметрами по умолчанию
        loadOrGenerateKeys();
    }

    private void loadOrGenerateKeys() {
        // Создаем директорию user_data, если ее нет
        File userDataDir = new File(userDataDirectoryPath);
        if (!userDataDir.exists()) {
            if (!userDataDir.mkdirs()) {
                System.err.println("Ошибка: Не удалось создать директорию user_data: " + userDataDirectoryPath);
            }
        }
        
        // Сначала пытаемся загрузить ключи из PEM-файлов
        if (tryLoadKeysFromPem()) {
            System.out.println("Ключи RSA успешно загружены из PEM-файлов.");
        } else {
            // Если не получилось, пробуем загрузить из старого формата JSON
            File keysDir = new File(keysDirectoryPath);
            if (!keysDir.exists()) {
                if (!keysDir.mkdirs()) {
                    System.err.println("Ошибка: Не удалось создать директорию ключей: " + keysDirectoryPath);
                    generateNewKeys(); // Генерируем новые ключи
                    return;
                }
            }

            File keysFile = new File(keysFilePath);
            if (keysFile.exists()) {
                try {
                    String content = new String(Files.readAllBytes(Paths.get(keysFilePath)));
                    JSONObject json = new JSONObject(content);

                    JSONObject rsaPubKeyJson = json.getJSONObject("rsa_public_key");
                    BigInteger n_pub = new BigInteger(rsaPubKeyJson.getString("n"));
                    BigInteger e_pub = new BigInteger(rsaPubKeyJson.getString("e"));
                    RSA.PublicKey publicKey = new RSA.PublicKey(n_pub, e_pub);

                    JSONObject rsaPrivKeyJson = json.getJSONObject("rsa_private_key");
                    BigInteger n_priv = new BigInteger(rsaPrivKeyJson.getString("n"));
                    BigInteger d_priv = new BigInteger(rsaPrivKeyJson.getString("d"));
                    RSA.PrivateKey privateKey = new RSA.PrivateKey(n_priv, d_priv);
                    
                    if (!n_pub.equals(n_priv)) {
                        throw new JSONException("RSA public and private key N mismatch.");
                    }
                    this.clientRsaKeyPair = new RSA.KeyPair(publicKey, privateKey);

                    // Загружаем параметры афинного шифра для ASCII
                    JSONObject affineParamsJson = json.getJSONObject("affine_cipher");
                    
                    // Пытаемся загрузить массив коэффициентов b
                    int[] bValues;
                    if (affineParamsJson.has("b_values")) {
                        JSONArray bValuesArray = affineParamsJson.getJSONArray("b_values");
                        bValues = new int[bValuesArray.length()];
                        for (int i = 0; i < bValuesArray.length(); i++) {
                            bValues[i] = bValuesArray.getInt(i);
                        }
                    } else {
                        // Для обратной совместимости - используем одно значение b для всех позиций
                        int b = affineParamsJson.getInt("b");
                        JSONArray aValuesArray = affineParamsJson.getJSONArray("a_values");
                        bValues = new int[aValuesArray.length()];
                        for (int i = 0; i < aValuesArray.length(); i++) {
                            bValues[i] = b;
                        }
                    }
                    
                    // Загружаем массив коэффициентов a
                    JSONArray aValuesArray = affineParamsJson.getJSONArray("a_values");
                    int[] aValues = new int[aValuesArray.length()];
                    for (int i = 0; i < aValuesArray.length(); i++) {
                        aValues[i] = aValuesArray.getInt(i);
                    }
                    
                    clientAffineCipher = new AffineCipher(aValues, bValues);
                    
                    System.out.println("Ключи клиента загружены из: " + keysFilePath);
                    
                    // Сохраняем ключи в PEM-формате для будущего использования
                    saveToPem();

                } catch (IOException | JSONException | NumberFormatException | NullPointerException e) {
                    System.err.println("Ошибка при загрузке ключей клиента: " + e.getMessage() + ". Генерирую новые ключи.");
                    e.printStackTrace();
                    generateNewKeys();
                }
            } else {
                System.out.println("Файл ключей клиента не найден. Генерирую новые ключи.");
                generateNewKeys();
            }
        }
    }

    /**
     * Пытается загрузить ключи RSA из PEM-файлов
     * @return true, если загрузка успешна, false в противном случае
     */
    private boolean tryLoadKeysFromPem() {
        File publicKeyFile = new File(rsaPublicPemPath);
        File privateKeyFile = new File(rsaPrivatePemPath);
        
        if (!publicKeyFile.exists() || !privateKeyFile.exists()) {
            return false;
        }
        
        try {
            // Загрузка публичного ключа
            String publicKeyPem = new String(Files.readAllBytes(publicKeyFile.toPath()));
            RSA.PublicKey publicKey = parsePemPublicKey(publicKeyPem);
            
            // Загрузка приватного ключа
            String privateKeyPem = new String(Files.readAllBytes(privateKeyFile.toPath()));
            RSA.PrivateKey privateKey = parsePemPrivateKey(privateKeyPem);
            
            if (publicKey != null && privateKey != null) {
                // Проверка, что ключи парные (имеют одинаковые модули)
                if (publicKey.n.equals(privateKey.n)) {
                    this.clientRsaKeyPair = new RSA.KeyPair(publicKey, privateKey);
                    
                    // Загрузили RSA ключи, теперь нужно загрузить параметры афинного шифра
                    // Для этого все равно используем JSON-файл
                    File keysFile = new File(keysFilePath);
                    if (keysFile.exists()) {
                        String content = new String(Files.readAllBytes(Paths.get(keysFilePath)));
                        JSONObject json = new JSONObject(content);
                        JSONObject affineParamsJson = json.getJSONObject("affine_cipher");
                        
                        // Пытаемся загрузить массив коэффициентов b
                        int[] bValues;
                        if (affineParamsJson.has("b_values")) {
                            JSONArray bValuesArray = affineParamsJson.getJSONArray("b_values");
                            bValues = new int[bValuesArray.length()];
                            for (int i = 0; i < bValuesArray.length(); i++) {
                                bValues[i] = bValuesArray.getInt(i);
                            }
                        } else {
                            // Для обратной совместимости - используем одно значение b для всех позиций
                            int b = affineParamsJson.getInt("b");
                            JSONArray aValuesArray = affineParamsJson.getJSONArray("a_values");
                            bValues = new int[aValuesArray.length()];
                            for (int i = 0; i < aValuesArray.length(); i++) {
                                bValues[i] = b;
                            }
                        }
                        
                        // Загружаем массив коэффициентов a
                        JSONArray aValuesArray = affineParamsJson.getJSONArray("a_values");
                        int[] aValues = new int[aValuesArray.length()];
                        for (int i = 0; i < aValuesArray.length(); i++) {
                            aValues[i] = aValuesArray.getInt(i);
                        }
                        
                        clientAffineCipher = new AffineCipher(aValues, bValues);
                    } else {
                        // Если JSON-файл не найден, генерируем новый афинный шифр
                        this.clientAffineCipher = AffineCipher.createWithRandomKeys(16);
                        saveKeys(); // Сохраняем для будущего использования
                    }
                    
                    return true;
                }
            }
        } catch (IOException | JSONException e) {
            System.err.println("Ошибка при загрузке ключей из PEM-файлов: " + e.getMessage());
        }
        
        return false;
    }
    
    /**
     * Парсит публичный ключ RSA из PEM-формата
     */
    private RSA.PublicKey parsePemPublicKey(String pemContent) {
        try {
            // Удаляем заголовок, подвал и все пробельные символы
            String base64Content = pemContent
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");
            
            // Декодируем Base64 в массив байтов
            byte[] data = Base64.getDecoder().decode(base64Content);
            
            // Простой метод парсинга для нашего специального PEM-формата
            // В реальном приложении нужно использовать библиотеку для ASN.1 DER-декодирования
            String dataStr = new String(data);
            String[] parts = dataStr.split("\\|");
            
            if (parts.length == 2) {
                BigInteger n = new BigInteger(parts[0]);
                BigInteger e = new BigInteger(parts[1]);
                return new RSA.PublicKey(n, e);
            }
        } catch (Exception e) {
            System.err.println("Ошибка при парсинге PEM-публичного ключа: " + e.getMessage());
        }
        return null;
    }
    
    /**
     * Парсит приватный ключ RSA из PEM-формата
     */
    private RSA.PrivateKey parsePemPrivateKey(String pemContent) {
        try {
            // Удаляем заголовок, подвал и все пробельные символы
            String base64Content = pemContent
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
            
            // Декодируем Base64 в массив байтов
            byte[] data = Base64.getDecoder().decode(base64Content);
            
            // Простой метод парсинга для нашего специального PEM-формата
            String dataStr = new String(data);
            String[] parts = dataStr.split("\\|");
            
            if (parts.length == 2) {
                BigInteger n = new BigInteger(parts[0]);
                BigInteger d = new BigInteger(parts[1]);
                return new RSA.PrivateKey(n, d);
            }
        } catch (Exception e) {
            System.err.println("Ошибка при парсинге PEM-приватного ключа: " + e.getMessage());
        }
        return null;
    }
    
    /**
     * Сохраняет RSA ключи в PEM-формате
     */
    private void saveToPem() {
        if (clientRsaKeyPair == null) {
            System.err.println("Нет RSA ключей для сохранения в PEM-формате.");
            return;
        }
        
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");

            // Сохраняем публичный ключ в стандартном X.509 PEM формате
            RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(clientRsaKeyPair.publicKey.n, clientRsaKeyPair.publicKey.e);
            java.security.PublicKey javaPublicKey = keyFactory.generatePublic(publicKeySpec);
            byte[] x509EncodedPublicKey = javaPublicKey.getEncoded();
            
            try (PemWriter pemWriter = new PemWriter(new FileWriter(rsaPublicPemPath))) {
                PemObject pemObject = new PemObject("PUBLIC KEY", x509EncodedPublicKey);
                pemWriter.writeObject(pemObject);
            }

            // Сохраняем приватный ключ в стандартном PKCS#8 PEM формате
            RSAPrivateKeySpec privateKeySpec = new RSAPrivateKeySpec(clientRsaKeyPair.privateKey.n, clientRsaKeyPair.privateKey.d);
            java.security.PrivateKey javaPrivateKey = keyFactory.generatePrivate(privateKeySpec);
            byte[] pkcs8EncodedPrivateKey = javaPrivateKey.getEncoded();

            try (PemWriter pemWriter = new PemWriter(new FileWriter(rsaPrivatePemPath))) {
                PemObject pemObject = new PemObject("PRIVATE KEY", pkcs8EncodedPrivateKey);
                pemWriter.writeObject(pemObject);
            }
            
            System.out.println("RSA ключи сохранены в СТАНДАРТНОМ PEM-формате: " + rsaPublicPemPath + ", " + rsaPrivatePemPath);
        } catch (Exception e) { // Ловим более общий Exception, так как KeyFactory и другие могут бросать разные ошибки
            System.err.println("Ошибка при сохранении RSA ключей в стандартном PEM-формате: " + e.getMessage());
            e.printStackTrace(); // Для детальной отладки
        }
    }

    private void generateNewKeys() {
        RSA rsa = new RSA();
        this.clientRsaKeyPair = rsa.generateKeys(CryptoConstants.RSA_KEY_SIZE_BITS);

        // Генерируем афинный шифр с ASCII алфавитом и 16 разными коэффициентами 'a' и 'b'
        this.clientAffineCipher = AffineCipher.createWithRandomKeys(16);

        saveKeys();
        saveToPem(); // Дополнительно сохраняем в PEM-формате
    }

    private void saveKeys() {
        JSONObject json = new JSONObject();
        try {
            JSONObject rsaPubKeyJson = new JSONObject();
            rsaPubKeyJson.put("n", clientRsaKeyPair.publicKey.n.toString());
            rsaPubKeyJson.put("e", clientRsaKeyPair.publicKey.e.toString());
            json.put("rsa_public_key", rsaPubKeyJson);

            JSONObject rsaPrivKeyJson = new JSONObject();
            rsaPrivKeyJson.put("n", clientRsaKeyPair.privateKey.n.toString());
            rsaPrivKeyJson.put("d", clientRsaKeyPair.privateKey.d.toString());
            json.put("rsa_private_key", rsaPrivKeyJson);

            // Сохраняем параметры афинного шифра
            JSONObject affineParamsJson = new JSONObject();
            
            // Сохраняем массив коэффициентов a
            JSONArray aValuesArray = new JSONArray();
            for (int a : clientAffineCipher.getAValues()) {
                aValuesArray.put(a);
            }
            affineParamsJson.put("a_values", aValuesArray);
            
            // Сохраняем массив коэффициентов b
            JSONArray bValuesArray = new JSONArray();
            for (int b : clientAffineCipher.getBValues()) {
                bValuesArray.put(b);
            }
            affineParamsJson.put("b_values", bValuesArray);
            
            // Для обратной совместимости также сохраняем первый коэффициент b
            affineParamsJson.put("b", clientAffineCipher.getB());
            
            // Сохраняем количество разных a и модуль (ASCII)
            affineParamsJson.put("key_length", clientAffineCipher.getKeyLength());
            affineParamsJson.put("m", 256); // ASCII
            
            json.put("affine_cipher", affineParamsJson);

            try (FileWriter file = new FileWriter(keysFilePath)) {
                file.write(json.toString(4)); // 4 for nice formatting
                file.flush();
                System.out.println("Client keys saved to: " + keysFilePath);
            } catch (IOException e) {
                System.err.println("Error saving client keys: " + e.getMessage());
                e.printStackTrace();
            }
        } catch (JSONException e) {
            System.err.println("Error constructing JSON for keys: " + e.getMessage());
            e.printStackTrace();
        }
    }

    public RSA.PublicKey getClientRsaPublicKey() {
        return clientRsaKeyPair != null ? clientRsaKeyPair.publicKey : null;
    }
    
    public RSA.PrivateKey getClientRsaPrivateKey() {
        return clientRsaKeyPair != null ? clientRsaKeyPair.privateKey : null;
    }

    public RSA.KeyPair getClientRsaKeyPair() {
        return clientRsaKeyPair;
    }

    public AffineCipher getAffineCipher() {
        return clientAffineCipher;
    }
    
    /**
     * Для обратной совместимости со старым кодом, который использовал языковые шифры
     */
    public AffineCipher getAffineCipher(String lang) {
        return clientAffineCipher; // Теперь возвращаем один универсальный шифр независимо от языка
    }

    public void setServerRsaPublicKey(String nStr, String eStr) {
        try {
            BigInteger n = new BigInteger(nStr);
            BigInteger e = new BigInteger(eStr);
            this.serverRsaPublicKey = new RSA.PublicKey(n, e);
            System.out.println("KeyManager: Публичный RSA ключ сервера установлен: n=" + nStr.substring(0,10) + "..., e=" + eStr);
        } catch (NumberFormatException ex) {
            System.err.println("KeyManager: Ошибка парсинга компонентов RSA ключа сервера: " + ex.getMessage());
            this.serverRsaPublicKey = null;
        }
    }

    public RSA.PublicKey getServerRsaPublicKey() {
        return serverRsaPublicKey;
    }

    public void setServerAffineParams(JSONObject affineParamsJson) {
        this.serverAffineParamsJson = affineParamsJson;
        System.out.println("KeyManager: Аффинные параметры сервера установлены: " + affineParamsJson.toString());
    }

    public JSONObject getServerAffineParamsJson() {
        return serverAffineParamsJson;
    }

    public String getKeysDirectoryPath() {
        return keysDirectoryPath;
    }
    
    /**
     * Возвращает путь к директории user_data
     */
    public String getUserDataDirectoryPath() {
        return userDataDirectoryPath;
    }
    
    /**
     * Возвращает открытый ключ Диффи-Хеллмана для обмена с сервером
     */
    public BigInteger getDiffieHellmanPublicKey() {
        return diffieHellman.getPublicKey();
    }
    
    /**
     * Вычисляет общий секрет Диффи-Хеллмана на основе открытого ключа сервера
     * @param serverPublicKey Открытый ключ сервера
     * @return AffineCipher, созданный из общего секрета
     */
    public AffineCipher computeSharedAffineCipher(BigInteger serverPublicKey, int keyLength) {
        try {
            BigInteger sharedSecret = diffieHellman.computeSharedSecret(serverPublicKey);
            return DiffieHellman.createAffineCipher(sharedSecret, keyLength);
        } catch (Exception e) {
            System.err.println("Ошибка при вычислении общего секрета Диффи-Хеллмана: " + e.getMessage());
            // Возвращаем локальный афинный шифр в случае ошибки
            return clientAffineCipher;
        }
    }

    /**
     * Инициализирует общий секрет Диффи-Хеллмана и подготавливает зашифрованный пакет 
     * для отправки получателю с использованием RSA шифрования.
     * 
     * @param recipientPublicKey Публичный ключ RSA получателя
     * @param keyLength Длина ключа (количество разных коэффициентов a и b)
     * @return Зашифрованный пакет с общим секретом для отправки или null при ошибке
     */
    public String initializeAndEncryptSharedSecret(RSA.PublicKey recipientPublicKey, int keyLength) {
        if (recipientPublicKey == null) {
            System.err.println("Не указан публичный ключ RSA получателя");
            return null;
        }
        
        try {
            // Генерируем новый экземпляр Диффи-Хеллмана для этого получателя
            DiffieHellman recipientSpecificDH = new DiffieHellman();
            
            // Используем собственный приватный ключ DH для вычисления общего секрета
            // Это эмуляция - в реальном протоколе DH общий секрет вычисляется после обмена публичными ключами
            BigInteger fakeOtherPublicKey = BigInteger.valueOf(123456789); // Для демонстрации
            BigInteger sharedSecret = recipientSpecificDH.computeSharedSecret(fakeOtherPublicKey);
            
            // Создаем EncryptionService для шифрования общего секрета
            EncryptionService encryptionService = 
                new EncryptionService(this);
            
            // Шифруем общий секрет публичным ключом RSA получателя
            String encryptedPackage = 
                encryptionService.prepareEncryptedSharedSecretPackage(sharedSecret, recipientPublicKey);
            
            System.out.println("Общий секрет инициализирован и зашифрован для получателя");
            
            return encryptedPackage;
        } catch (Exception e) {
            System.err.println("Ошибка при инициализации и шифровании общего секрета: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }
    
    /**
     * Получает общий секрет из зашифрованного пакета и создает AffineCipher на его основе.
     * 
     * @param encryptedPackage Зашифрованный пакет с общим секретом
     * @param keyLength Длина ключа (количество разных коэффициентов a и b)
     * @return AffineCipher, созданный на основе расшифрованного общего секрета, или null при ошибке
     */
    public AffineCipher processEncryptedSharedSecretAndCreateCipher(String encryptedPackage, int keyLength) {
        if (encryptedPackage == null || encryptedPackage.isEmpty()) {
            System.err.println("Пустой зашифрованный пакет с общим секретом");
            return null;
        }
        
        try {
            // Создаем EncryptionService для расшифровки общего секрета
            EncryptionService encryptionService = 
                new EncryptionService(this);
            
            // Расшифровываем пакет и получаем общий секрет
            BigInteger sharedSecret = 
                encryptionService.processEncryptedSharedSecretPackage(encryptedPackage);
            
            if (sharedSecret == null) {
                System.err.println("Не удалось получить общий секрет из пакета");
                return null;
            }
            
            // Создаем AffineCipher на основе полученного общего секрета
            AffineCipher sharedCipher = DiffieHellman.createAffineCipher(sharedSecret, keyLength);
            
            System.out.println("Создан AffineCipher на основе полученного общего секрета");
            
            return sharedCipher;
        } catch (Exception e) {
            System.err.println("Ошибка при обработке зашифрованного общего секрета: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }
} 