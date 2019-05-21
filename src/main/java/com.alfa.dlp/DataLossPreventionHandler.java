package com.alfa.dlp;

import com.google.cloud.dlp.v2.DlpServiceClient;
import com.google.privacy.dlp.v2.*;
import com.google.protobuf.ByteString;
import org.apache.commons.lang3.StringUtils;

import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static com.alfa.dlp.GoogleCredentials.APPLICATION_NAME;

class DataLossPreventionHandler {

    private static final String SURROGATE_HARDCODED_STRING = "_VALUE_";
    private static final Pattern SURROGATE_PATTERN_LENGTH = Pattern.compile("\\(([0-9]*)\\):.*");

    static String deidentifyContentWithRegexPattern(final com.google.cloud.kms.v1.CryptoKey cryptoKeyForWrapping, final String pattern, final String message) {

        return commonIdentifyContent(cryptoKeyForWrapping, message, pattern, (dlpServiceClient, inspectConfig, deidentifyConfig, contentItem) -> {

            final DeidentifyContentRequest request = DeidentifyContentRequest.newBuilder().
                    setParent(ProjectName.format(APPLICATION_NAME)).
                    setDeidentifyConfig(deidentifyConfig).
                    setInspectConfig(inspectConfig).
                    setItem(contentItem).
                    build();

            final DeidentifyContentResponse response = dlpServiceClient.deidentifyContent(request);
            return response.getItem().getValue();
        });
    }

    static String reidentifyContent(final com.google.cloud.kms.v1.CryptoKey cryptoKeyForWrapping, final String message) {

        if (StringUtils.isBlank(message))
            return message;

        return Arrays.stream(message.split(SURROGATE_HARDCODED_STRING))//.parallel()
                .map(content -> {

                    final Matcher matcher = SURROGATE_PATTERN_LENGTH.matcher(content);
                    if (!matcher.matches()) return content;

                    final int beginIndex = matcher.group(1).length() + 3;
                    final String realContent = content.substring(0, beginIndex + Integer.parseInt(matcher.group(1)));

                    final String replaceValue = commonIdentifyContent(cryptoKeyForWrapping, SURROGATE_HARDCODED_STRING + realContent, ".*", (dlpServiceClient, inspectConfig, deidentifyConfig, contentItem) -> {

                        final ReidentifyContentRequest request = ReidentifyContentRequest.newBuilder().
                                setParent(ProjectName.format(APPLICATION_NAME)).
                                setReidentifyConfig(deidentifyConfig).
                                setInspectConfig(inspectConfig).
                                setItem(contentItem).
                                build();

                        final ReidentifyContentResponse response = dlpServiceClient.reidentifyContent(request);
                        return response.getItem().getValue();
                    });
                    return content.replace(realContent, replaceValue);
                })
                .collect(Collectors.joining());
    }

    private static String commonIdentifyContent(final com.google.cloud.kms.v1.CryptoKey cryptoKeyForWrapping, final String message,
                                                final String pattern, final DLPContent dlpDelegate) {
        try (final DlpServiceClient dlpServiceClient = GoogleCredentials.buildDLP()) {
            final ContentItem contentItem = ContentItem.newBuilder().setValue(message).build();

            // Create the format-preserving encryption (FPE) configuration
            final ByteString wrappedKey = CloudKeyManagement.encrypt(cryptoKeyForWrapping, "AkL3IOdnj1j2k4of");
            final KmsWrappedCryptoKey kmsWrappedCryptoKey = KmsWrappedCryptoKey.newBuilder().
                    setWrappedKey(wrappedKey).
                    setCryptoKeyName(cryptoKeyForWrapping.getName()).
                    build();

            final CryptoKey cryptoKey = CryptoKey.newBuilder().
                    setKmsWrapped(kmsWrappedCryptoKey).
                    build();

            final InfoType surrogateInfoType = InfoType.newBuilder().setName(SURROGATE_HARDCODED_STRING).build();

            final CryptoDeterministicConfig cryptoReplaceFfxFpeConfig = CryptoDeterministicConfig.newBuilder().
                    setCryptoKey(cryptoKey).
                    setSurrogateInfoType(surrogateInfoType).
                    build();

            // Create the deidentification transformation configuration
            final PrimitiveTransformation primitiveTransformation = PrimitiveTransformation.newBuilder().
                    setCryptoDeterministicConfig(cryptoReplaceFfxFpeConfig).
                    build();

            final InfoTypeTransformations.InfoTypeTransformation infoTypeTransformationObject = InfoTypeTransformations.InfoTypeTransformation.
                    newBuilder().
                    setPrimitiveTransformation(primitiveTransformation).
                    build();

            final InfoTypeTransformations infoTypeTransformationArray = InfoTypeTransformations.newBuilder().
                    addTransformations(infoTypeTransformationObject).
                    build();

            // Create the deidentification request object
            final DeidentifyConfig deidentifyConfig = DeidentifyConfig.newBuilder().
                    setInfoTypeTransformations(infoTypeTransformationArray).
                    build();

            final CustomInfoType.Regex regex = CustomInfoType.Regex.newBuilder().
                    setPattern(pattern).
                    build();

            final CustomInfoType customInfoType = CustomInfoType.newBuilder().
                    setInfoType(surrogateInfoType).
                    setSurrogateType(CustomInfoType.SurrogateType.newBuilder().build()).
                    setLikelihood(Likelihood.VERY_LIKELY).
                    setRegex(regex).
                    build();

            // uncomment these lines and the line after in inspecConfig builder,
            // to use default info types instead of custom regex

//            final List<InfoType> infoTypes = new ArrayList<>();
////            // See https://cloud.google.com/dlp/docs/infotypes-reference for complete list of info types
//            for (String typeName : new String[]{"PHONE_NUMBER", "EMAIL_ADDRESS", "CREDIT_CARD_NUMBER"}) {
//                infoTypes.add(InfoType.newBuilder().setName(typeName).build());
//            }

            final InspectConfig inspectConfig = InspectConfig.newBuilder().
//                    addInfoTypes(infoTypes).
        addCustomInfoTypes(customInfoType).
                            build();

            return dlpDelegate.apply(dlpServiceClient, inspectConfig, deidentifyConfig, contentItem);
        } catch (Exception e) {
            throw new RuntimeException("Error in re/deidentifying with format-preserving encryption (FPE): " + e.getMessage(), e);
        }
    }

    private interface DLPContent {

        String apply(final DlpServiceClient dlpServiceClient, final InspectConfig inspectConfig, final DeidentifyConfig deidentifyConfig,
                     final ContentItem contentItem);

    }
}
