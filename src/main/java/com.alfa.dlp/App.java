package com.alfa.dlp;

import com.google.cloud.kms.v1.KeyRing;

public class App {

    public static void main(String[] args) {
        final KeyRing keyRing = CloudKeyManagement.getOrCreateKeyRing("my-keyring");
        final com.google.cloud.kms.v1.CryptoKey cryptoKey = CloudKeyManagement.getOrCreateCryptoKey(keyRing, "my-key");
        final String message = "My name is fernando and my email is alfafc@gmail.com, this is really nice!";

        final String value = DataLossPreventionHandler.deidentifyContentWithRegexPattern(cryptoKey, "[0-9]*", message);
        System.err.println(value);
        System.err.println(DataLossPreventionHandler.reidentifyContent(cryptoKey, value));

        System.exit(0);
    }
}