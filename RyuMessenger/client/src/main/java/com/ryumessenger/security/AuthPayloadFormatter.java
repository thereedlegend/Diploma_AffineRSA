package com.ryumessenger.security;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import com.fasterxml.jackson.databind.ObjectMapper;
import javax.crypto.Cipher;
import com.ryumessenger.security.EnhancedAffineCipher.AffineCipherParams;
import com.ryumessenger.util.Logger;

/**
 * Класс для формирования зашифрованных payload для регистрации и аутентификации с использованием RSA и аффинного шифра.
 */
public class AuthPayloadFormatter {
    private final KeyManager keyManager;
    private final EnhancedAffineCipher affineCipher;
    private final ObjectMapper objectMapper = new ObjectMapper();
    
    public AuthPayloadFormatter(KeyManager keyManager, EnhancedAffineCipher affineCipher) {
        this.keyManager = keyManager;
        this.affineCipher = affineCipher;
    }
    
    /**
     * Формирует зашифрованный payload для регистрации пользователя
     */
    public String formatRegistrationPayload(String username, String password, String tag, String displayName, String clientDhPublicKeyY) {
        try {
            String encryptedPassword = this.affineCipher.encrypt(password);
            AffineCipherParams cipherParams = this.affineCipher.getParams(password.length());
            
            Map<String, Object> rsaEncryptedData = new HashMap<>();
            rsaEncryptedData.put("cipher_text", encryptedPassword);
            rsaEncryptedData.put("affine_params", cipherParams);
            rsaEncryptedData.put("dh_public_key", clientDhPublicKeyY);
            
            String jsonToEncrypt = objectMapper.writeValueAsString(rsaEncryptedData);
            
            PublicKey serverPublicKey = keyManager.getServerRSAPublicKey();
            if (serverPublicKey == null) {
                Logger.error("RSA публичный ключ сервера не установлен в KeyManager. Невозможно зашифровать payload.");
                throw new RuntimeException("RSA ключ сервера отсутствует.");
            }
            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaCipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);
            
            String encryptedPayload = encryptRSAChunked(jsonToEncrypt, rsaCipher);
            
            Logger.info("Сформирован RSA-зашифрованный payload (содержащий аффинно-зашифрованный пароль) для регистрации пользователя " + username);
            return encryptedPayload;
            
        } catch (Exception e) {
            Logger.error("Ошибка при формировании payload для регистрации: " + e.getMessage(), e);
            throw new RuntimeException("Не удалось сформировать payload для регистрации", e);
        }
    }
    
    /**
     * Формирует зашифрованный payload для аутентификации пользователя
     */
    public String formatLoginPayload(String username, String password, String clientDhPublicKeyY) {
        try {
            String encryptedPassword = this.affineCipher.encrypt(password);
            AffineCipherParams cipherParams = this.affineCipher.getParams(password.length());
            
            Map<String, Object> payload = new HashMap<>();
            payload.put("cipher_text", encryptedPassword);
            payload.put("affine_params", cipherParams);
            payload.put("dh_public_key", clientDhPublicKeyY);
            
            String jsonToEncrypt = objectMapper.writeValueAsString(payload);
            
            PublicKey serverPublicKey = keyManager.getServerRSAPublicKey();
            if (serverPublicKey == null) {
                Logger.error("RSA публичный ключ сервера не установлен в KeyManager. Невозможно зашифровать payload.");
                throw new RuntimeException("RSA ключ сервера отсутствует.");
            }
            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaCipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);
            
            String encryptedPayload = encryptRSAChunked(jsonToEncrypt, rsaCipher);
            
            Logger.info("Сформирован RSA-зашифрованный payload (содержащий аффинно-зашифрованный пароль) для аутентификации пользователя " + username);
            return encryptedPayload;
            
        } catch (Exception e) {
            Logger.error("Ошибка при формировании payload для аутентификации: " + e.getMessage(), e);
            throw new RuntimeException("Не удалось сформировать payload для аутентификации", e);
        }
    }
    
    /**
     * Шифрует строку с помощью RSA по частям (чанкам), т.к. длина блока RSA ограничена
     */
    private String encryptRSAChunked(String plainText, Cipher cipher) throws Exception {
        byte[] plainBytes = plainText.getBytes(StandardCharsets.UTF_8);
        
        // Определяем максимальный размер блока для шифрования (обычно RSA-2048 = 245 байт)
        int maxBlockSize = 245;
        int totalLength = plainBytes.length;
        int blocksCount = (int) Math.ceil((double)totalLength / maxBlockSize);
        
        StringBuilder result = new StringBuilder();
        result.append(blocksCount).append(":");
        
        for (int i = 0; i < blocksCount; i++) {
            int offset = i * maxBlockSize;
            int length = Math.min(maxBlockSize, totalLength - offset);
            
            byte[] block = new byte[length];
            System.arraycopy(plainBytes, offset, block, 0, length);
            
            byte[] encryptedBlock = cipher.doFinal(block);
            String encryptedBase64 = Base64.getEncoder().encodeToString(encryptedBlock);
            
            if (i > 0) {
                result.append(".");
            }
            result.append(encryptedBase64);
        }
        
        return result.toString();
    }
    
    /**
     * Формирует объект с зашифрованным payload для отправки на сервер при регистрации
     */
    public Map<String, Object> createRegistrationRequest(String username, String password, String tag, String displayName) {
        Map<String, Object> request = new HashMap<>();
        request.put("username", username);
        request.put("tag", tag);
        request.put("display_name", displayName);
        
        BigInteger[] rsaComponents = keyManager.getClientRSAPublicKeyComponents();
        if (rsaComponents != null && rsaComponents.length >= 2) {
            request.put("rsa_public_key_n", rsaComponents[0].toString());
            request.put("rsa_public_key_e", rsaComponents[1].toString());
        } else {
            Logger.error("Не удалось получить компоненты RSA ключа клиента для запроса регистрации.");
            return null;
        }
        
        String clientDhPublicKeyY = keyManager.getClientDHPublicKeyY().toString();
        request.put("encrypted_password_payload", formatRegistrationPayload(username, password, tag, displayName, clientDhPublicKeyY));
        return request;
    }
    
    /**
     * Формирует объект с зашифрованным payload для отправки на сервер при аутентификации
     */
    public Map<String, Object> createLoginRequest(String username, String password) {
        Map<String, Object> request = new HashMap<>();
        request.put("username", username);
        String clientDhPublicKeyY = keyManager.getClientDHPublicKeyY().toString();
        request.put("encrypted_login_payload", formatLoginPayload(username, password, clientDhPublicKeyY));
        
        return request;
    }

    /**
     * Формирует зашифрованный payload для смены пароля.
     * Внутренний JSON содержит current_password_details и new_password_details,
     * каждый из которых содержит cipher_text и affine_params.
     * Также включает dh_public_key клиента.
     * Весь этот JSON шифруется RSA ключом сервера.
     */
    public String formatChangePasswordPayload(String currentPassword, String newPassword, String clientDhPublicKeyY) {
        try {
            // Шифруем текущий пароль
            String encryptedCurrentPassword = this.affineCipher.encrypt(currentPassword);
            AffineCipherParams currentPasswordParams = this.affineCipher.getParams(currentPassword.length());
            Map<String, Object> currentPasswordDetails = new HashMap<>();
            currentPasswordDetails.put("cipher_text", encryptedCurrentPassword);
            currentPasswordDetails.put("affine_params", currentPasswordParams);

            // Шифруем новый пароль
            String encryptedNewPassword = this.affineCipher.encrypt(newPassword);
            AffineCipherParams newPasswordParams = this.affineCipher.getParams(newPassword.length());
            Map<String, Object> newPasswordDetails = new HashMap<>();
            newPasswordDetails.put("cipher_text", encryptedNewPassword);
            newPasswordDetails.put("affine_params", newPasswordParams);

            // Формируем основной payload для RSA шифрования
            Map<String, Object> rsaEncryptedData = new HashMap<>();
            rsaEncryptedData.put("current_password_payload", currentPasswordDetails);
            rsaEncryptedData.put("new_password_payload", newPasswordDetails);
            rsaEncryptedData.put("dh_public_key", clientDhPublicKeyY);

            String jsonToEncrypt = objectMapper.writeValueAsString(rsaEncryptedData);

            PublicKey serverPublicKey = keyManager.getServerRSAPublicKey();
            if (serverPublicKey == null) {
                Logger.error("RSA публичный ключ сервера не установлен. Невозможно зашифровать payload для смены пароля.");
                throw new RuntimeException("RSA ключ сервера отсутствует для смены пароля.");
            }
            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaCipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);

            String encryptedPayload = encryptRSAChunked(jsonToEncrypt, rsaCipher);

            Logger.info("Сформирован RSA-зашифрованный payload для смены пароля.");
            return encryptedPayload;

        } catch (Exception e) {
            Logger.error("Ошибка при формировании payload для смены пароля: " + e.getMessage(), e);
            throw new RuntimeException("Не удалось сформировать payload для смены пароля", e);
        }
    }
} 