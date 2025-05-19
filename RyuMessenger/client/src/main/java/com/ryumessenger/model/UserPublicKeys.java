package com.ryumessenger.model;

import java.math.BigInteger;

public class UserPublicKeys {
    private final BigInteger rsaModulus; // n
    private final BigInteger rsaExponent; // e
    // DH P и G предполагаются глобальными, получаемыми отдельно.
    private final BigInteger dhPublicKeyY;

    public UserPublicKeys(BigInteger rsaModulus, BigInteger rsaExponent, BigInteger dhPublicKeyY) {
        this.rsaModulus = rsaModulus;
        this.rsaExponent = rsaExponent;
        this.dhPublicKeyY = dhPublicKeyY;
    }

    public BigInteger getRsaModulus() { return rsaModulus; }
    public BigInteger getRsaExponent() { return rsaExponent; }
    public BigInteger getDhPublicKeyY() { return dhPublicKeyY; }
} 