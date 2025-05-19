package com.ryumessenger.model;

import org.json.JSONObject;

// Простая модель пользователя (в основном для хранения публичных данных)
public class User {
    private int id;
    private String username;
    private String tag;
    private String displayName;
    private String rsaPublicKeyN;
    private String rsaPublicKeyE;

    public User(JSONObject json) {
        this.id = json.getInt("id");
        // Если поле username отсутствует, используем поле tag вместо него
        if (json.has("username")) {
            this.username = json.getString("username");
        } else if (json.has("tag")) {
            this.username = json.getString("tag");
        } else {
            this.username = "";
            System.err.println("User model: Поля username и tag не найдены в JSON: " + json.toString());
        }
        this.tag = json.optString("tag", "");
        this.displayName = json.optString("display_name", json.optString("displayName", this.username));
        
        if (json.has("rsa_public_key") && json.get("rsa_public_key") instanceof JSONObject) {
            JSONObject rsaKeyJson = json.getJSONObject("rsa_public_key");
            this.rsaPublicKeyN = rsaKeyJson.optString("n", null);
            this.rsaPublicKeyE = rsaKeyJson.optString("e", null);
        } else {
            this.rsaPublicKeyN = json.optString("rsaPublicKeyN", null);
            this.rsaPublicKeyE = json.optString("rsaPublicKeyE", null);
             if (this.rsaPublicKeyN == null || this.rsaPublicKeyE == null) {
                System.err.println("User model: RSA public key parts not found or in unexpected format in JSON: " + json.toString());
            }
        }
    }

    // Конструктор для создания пользователя из отдельных полей
    public User(int id, String username, String displayName, String tag) {
        this.id = id;
        this.username = username;
        this.displayName = displayName;
        this.tag = tag;
        this.rsaPublicKeyN = null;
        this.rsaPublicKeyE = null;
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getTag() {
        return tag;
    }

    public void setTag(String tag) {
        this.tag = tag;
    }

    public String getDisplayName() {
        return displayName;
    }

    public void setDisplayName(String displayName) {
        this.displayName = displayName;
    }

    public String getRsaPublicKeyN() {
        return rsaPublicKeyN;
    }

    public void setRsaPublicKeyN(String rsaPublicKeyN) {
        this.rsaPublicKeyN = rsaPublicKeyN;
    }

    public String getRsaPublicKeyE() {
        return rsaPublicKeyE;
    }

    public void setRsaPublicKeyE(String rsaPublicKeyE) {
        this.rsaPublicKeyE = rsaPublicKeyE;
    }

    @Override
    public String toString() {
        return displayName + (tag != null && !tag.isEmpty() ? " [@" + tag + "]" : "");
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        User user = (User) o;
        return id == user.id;
    }

    @Override
    public int hashCode() {
        return Integer.hashCode(id);
    }
} 