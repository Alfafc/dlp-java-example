package com.alfa.dlp;

import com.google.cloud.kms.v1.*;
import com.google.protobuf.ByteString;

import static com.alfa.dlp.GoogleCredentials.APPLICATION_NAME;

public class CloudKeyManagement {

    private static final String PROJECT_LOCATION = "global";

    /**
     * Create or get key ring
     * You need to give this permissions to the account
     * https://cloud.google.com/kms/docs/reference/permissions-and-roles?hl=es-419
     */
    static KeyRing getOrCreateKeyRing(final String keyRingId) {

        try (final KeyManagementServiceClient client = GoogleCredentials.buildKMS()) {

            try {
                return client.getKeyRing(KeyRingName.newBuilder().
                        setProject(APPLICATION_NAME).
                        setLocation(PROJECT_LOCATION).
                        setKeyRing(keyRingId).
                        build());
            } catch (final Exception ignored) {
            }

            final String parent = LocationName.format(APPLICATION_NAME, PROJECT_LOCATION);
            return client.createKeyRing(parent, keyRingId, KeyRing.newBuilder().build());
        } catch (final Exception e) {
            throw new RuntimeException("Problems creating keyring [" + keyRingId + "]: " + e.getMessage(), e);
        }
    }

    /**
     * Creates or get crypto key
     */
    static CryptoKey getOrCreateCryptoKey(final KeyRing keyRing, final String cryptoKeyId) {

        try (final KeyManagementServiceClient client = GoogleCredentials.buildKMS()) {

            try {
                final String keyRingName = keyRing.getName().substring(keyRing.getName().lastIndexOf("/") + 1);
                return client.getCryptoKey(CryptoKeyName.newBuilder().
                        setProject(APPLICATION_NAME).
                        setLocation(PROJECT_LOCATION).
                        setKeyRing(keyRingName).
                        setCryptoKey(cryptoKeyId).
                        build());
            } catch (final Exception ignored) {
            }


            final CryptoKey cryptoKey = CryptoKey.newBuilder()
                    .setPurpose(CryptoKey.CryptoKeyPurpose.ENCRYPT_DECRYPT)
                    .build();

            return client.createCryptoKey(keyRing.getName(), cryptoKeyId, cryptoKey);
        } catch (final Exception e) {
            throw new RuntimeException("Problems creating cryptokey [" + cryptoKeyId + "] using [" + keyRing.getName() + "]: " + e.getMessage(), e);
        }
    }

    /**
     * Encrypt plain text
     */
    static ByteString encrypt(final CryptoKey cryptoKey, final String plaintext) {

        try (final KeyManagementServiceClient client = GoogleCredentials.buildKMS()) {

            return client.
                    encrypt(
                            EncryptRequest.newBuilder().
                                    setName(cryptoKey.getName()).
                                    setPlaintext(ByteString.copyFrom(plaintext.getBytes())).
                                    build()
                    ).getCiphertext();
        } catch (final Exception e) {
            throw new RuntimeException("Problems encrypting using [" + cryptoKey.getName() + "]: " + e.getMessage(), e);
        }
    }

    /**
     * Decrypt previous encrypted text
     */
    public static ByteString decrypt(final CryptoKey cryptoKey, final ByteString cipherText) {

        try (final KeyManagementServiceClient client = GoogleCredentials.buildKMS()) {

            return client.
                    decrypt(
                            DecryptRequest.newBuilder().
                                    setName(cryptoKey.getName()).
                                    setCiphertext(cipherText).
                                    build()
                    ).getPlaintext();

        } catch (final Exception e) {
            throw new RuntimeException("Problems decrypting using [" + cryptoKey.getName() + "]: " + e.getMessage(), e);
        }
    }
}
