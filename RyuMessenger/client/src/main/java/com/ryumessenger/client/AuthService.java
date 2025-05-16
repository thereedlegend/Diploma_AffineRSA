package com.ryumessenger.client;

import org.json.JSONObject;

public class AuthService {
    private final ApiClient apiClient;

    public AuthService(ApiClient apiClient) {
        this.apiClient = apiClient;
    }

    public JSONObject login(String username, String password) throws Exception {
        JSONObject data = new JSONObject();
        data.put("username", username);
        data.put("password", password);
        return apiClient.post("/auth/login", data);
    }

    public JSONObject register(String username, String password) throws Exception {
        JSONObject data = new JSONObject();
        data.put("username", username);
        data.put("password", password);
        return apiClient.post("/auth/register", data);
    }
} 