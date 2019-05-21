package com.alfa.dlp;

import com.google.api.gax.core.CredentialsProvider;
import com.google.api.gax.core.FixedCredentialsProvider;
import com.google.auth.oauth2.ServiceAccountCredentials;
import com.google.cloud.ServiceOptions;
import com.google.cloud.dlp.v2.DlpServiceClient;
import com.google.cloud.dlp.v2.DlpServiceSettings;
import com.google.cloud.kms.v1.KeyManagementServiceClient;
import com.google.cloud.kms.v1.KeyManagementServiceSettings;

import java.io.FileInputStream;

final class GoogleCredentials {

    static final String APPLICATION_NAME = ServiceOptions.getDefaultProjectId();
    private static final String DLP_ENCRYPT_FILE = "/credentials.json";

    static KeyManagementServiceClient buildKMS() {
        try {
            final CredentialsProvider credentialsProvider = FixedCredentialsProvider.create(ServiceAccountCredentials.fromStream(new FileInputStream(DLP_ENCRYPT_FILE)));

            return KeyManagementServiceClient.create(
                    KeyManagementServiceSettings.
                            newBuilder().
                            setCredentialsProvider(credentialsProvider).
                            build());
        } catch (final Exception exception) {
            throw new RuntimeException(exception.getMessage(), exception);
        }
    }

    static DlpServiceClient buildDLP() {

        try {
            final CredentialsProvider credentialsProvider = FixedCredentialsProvider.create(ServiceAccountCredentials.fromStream(new FileInputStream(DLP_ENCRYPT_FILE)));

            return DlpServiceClient.create(
                    DlpServiceSettings.
                            newBuilder().
                            setCredentialsProvider(credentialsProvider).
                            build());
        } catch (final Exception exception) {
            throw new RuntimeException(exception.getMessage(), exception);
        }
    }
}
