package com.ryumessenger.crypto;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

import org.json.JSONException;
import org.json.JSONObject;

public class KeyManager {
    private RSA.KeyPair clientRsaKeyPair;
    private Map<String, AffineCipher> clientAffineCiphers; // Ключ - язык ("ru", "en")
    private String keysDirectoryPath;
    private String keysFilePath;

    // Поля для хранения публичного ключа RSA сервера и его аффинных параметров
    private RSA.PublicKey serverRsaPublicKey;
    private JSONObject serverAffineParamsJson; // Храним JSON объект как есть или парсим в Map<String, Map<String, Integer>>

    public KeyManager(String baseDir) {
        this.keysDirectoryPath = Paths.get(baseDir, CryptoConstants.KEYS_DIR_NAME).toString();
        this.keysFilePath = Paths.get(this.keysDirectoryPath, CryptoConstants.CLIENT_KEYS_FILE_NAME).toString();
        this.clientAffineCiphers = new HashMap<>();
        loadOrGenerateKeys();
    }

    private void loadOrGenerateKeys() {
        File keysDir = new File(keysDirectoryPath);
        if (!keysDir.exists()) {
            if (!keysDir.mkdirs()) {
                System.err.println("Ошибка: Не удалось создать директорию ключей: " + keysDirectoryPath);
                // В UI нужно будет показать ошибку и, возможно, закрыть приложение
                generateNewKeys(); // Попытаться сгенерировать в текущей директории как fallback? Или просто ошибка.
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

                JSONObject affineParamsJsonOuter = json.getJSONObject("affine_params");
                for (String langKey : affineParamsJsonOuter.keySet()) {
                    JSONObject params = affineParamsJsonOuter.getJSONObject(langKey);
                    AffineCipher.Language affineLang;
                    if ("ru".equalsIgnoreCase(langKey)) {
                        affineLang = AffineCipher.Language.RUSSIAN;
                    } else if ("en".equalsIgnoreCase(langKey)) {
                        affineLang = AffineCipher.Language.ENGLISH;
                    } else {
                        System.err.println("Неизвестный язык в файле ключей: " + langKey + ". Пропускаю.");
                        continue;
                    }
                    AffineCipher cipher = new AffineCipher(params.getInt("a"), params.getInt("b"), affineLang);
                    clientAffineCiphers.put(langKey, cipher);
                }
                System.out.println("Ключи клиента загружены из: " + keysFilePath);
                if (!clientAffineCiphers.containsKey("ru") || !clientAffineCiphers.containsKey("en")) {
                    System.err.println("Внимание: отсутствуют аффинные ключи для одного или нескольких языков. Перегенерирую.");
                    generateNewKeys(); // Если не все ключи на месте, лучше перегенерировать
                }

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

    private void generateNewKeys() {
        RSA rsa = new RSA();
        this.clientRsaKeyPair = rsa.generateKeys(CryptoConstants.RSA_KEY_SIZE_BITS);

        this.clientAffineCiphers.clear();
        AffineCipher affineRu = AffineCipher.createWithRandomKeys(AffineCipher.Language.RUSSIAN);
        this.clientAffineCiphers.put("ru", affineRu);

        AffineCipher affineEn = AffineCipher.createWithRandomKeys(AffineCipher.Language.ENGLISH);
        this.clientAffineCiphers.put("en", affineEn);

        saveKeys();
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

            JSONObject affineParamsJsonOuter = new JSONObject();
            for (Map.Entry<String, AffineCipher> entry : clientAffineCiphers.entrySet()) {
                JSONObject params = new JSONObject();
                params.put("a", entry.getValue().getKeyA());
                params.put("b", entry.getValue().getKeyB());
                params.put("m", entry.getValue().getModulus());
                affineParamsJsonOuter.put(entry.getKey(), params);
            }
            json.put("affine_params", affineParamsJsonOuter);

            try (FileWriter file = new FileWriter(keysFilePath)) {
                file.write(json.toString(4)); // 4 for nice formatting
                file.flush();
                System.out.println("Client keys saved to: " + keysFilePath);
            } catch (IOException e) {
                System.err.println("Error saving client keys: " + e.getMessage());
                e.printStackTrace();
                // Что делать, если сохранить не удалось? Возможно, работать без сохранения,
                // но тогда при следующем запуске ключи будут новые.
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

    public AffineCipher getAffineCipher(String lang) {
        return clientAffineCiphers.get(lang.toLowerCase());
    }
    
    public Map<String, AffineCipher> getAllAffineCiphers() {
        return clientAffineCiphers;
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
        // Здесь можно добавить логику для парсинга affineParamsJson в более удобную структуру,
        // например, Map<String, Map<String, Integer>> для каждого языка.
        // Пример:
        // serverAffineParams = new HashMap<>();
        // for (String lang : affineParamsJson.keySet()) {
        //     JSONObject params = affineParamsJson.getJSONObject(lang);
        //     Map<String, Integer> langParams = new HashMap<>();
        //     langParams.put("a", params.getInt("a"));
        //     langParams.put("b", params.getInt("b"));
        //     langParams.put("m", params.getInt("m"));
        //     serverAffineParams.put(lang, langParams);
        // }
        System.out.println("KeyManager: Аффинные параметры сервера установлены: " + affineParamsJson.toString());
    }

    public JSONObject getServerAffineParamsJson() {
        return serverAffineParamsJson;
    }

    public String getKeysDirectoryPath() {
        return keysDirectoryPath;
    }
} 