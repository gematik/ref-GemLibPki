/*
 * Copyright (c) 2021 gematik GmbH
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *    http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.gematik.pki.certificate;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import de.gematik.pki.error.ErrorCode;
import de.gematik.pki.exception.GemPkiException;
import de.gematik.pki.tsl.TslInformationProvider;
import de.gematik.pki.tsl.TslReader;
import de.gematik.pki.tsl.TspInformationProvider;
import de.gematik.pki.tsl.TspServiceSubset;
import de.gematik.pki.utils.CertificateProvider;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;


/**
 * Dieser Test arbeitet ausschließlich mit einem Zertifikatsprofil (SMCB). Andere Profile zu testen wäre vermutlich
 * akademisch.
 */
@Slf4j(topic = "UNITTEST")
class CertificateVerificationTest {

    private static final String FILE_NAME_TSL_DEFAULT = "tsls/valid/TSL_default.xml";
    private static final String FILE_NAME_TSL_ALT_CA = "tsls/valid/TSL_altCA.xml";
    private static final String FILE_NAME_TSL_ALT_CA_REVOKED = "tsls/valid/TSL_altCA_revoked.xml";
    private static ZonedDateTime DATETIME_TO_CHECK;
    private final CertificateProfile certificateProfile = CertificateProfile.C_HCI_AUT_ECC;
    private String productType;
    private CertificateVerification certificateVerification;
    private X509Certificate VALID_X509_EE_CERT;
    private X509Certificate VALID_X509_EE_CERT_ALT_CA;
    private X509Certificate VALID_X509_ISSUER_CERT;

    @BeforeEach
    @SneakyThrows
    void setUp() {
        VALID_X509_EE_CERT = CertificateProvider
            .getX509Certificate("src/test/resources/certificates/GEM.SMCB-CA10/valid/DrMedGunther.pem");
        VALID_X509_EE_CERT_ALT_CA = CertificateProvider.getX509Certificate(
            "src/test/resources/certificates/GEM.SMCB-CA33/DrMedGuntherKZV.pem");
        VALID_X509_ISSUER_CERT = CertificateProvider
            .getX509Certificate("src/test/resources/certificates/GEM.SMCB-CA10/GEM.SMCB-CA10_TEST-ONLY.pem");
        DATETIME_TO_CHECK = ZonedDateTime.parse("2020-11-20T15:00:00Z");
        productType = "IDP";
        certificateVerification = buildCertificateVerififier(certificateProfile);
    }

    private CertificateVerification buildCertificateVerififier(
        final CertificateProfile certificateProfile) throws GemPkiException {
        return buildCertificateVerififier(FILE_NAME_TSL_DEFAULT, certificateProfile, VALID_X509_EE_CERT);
    }

    private CertificateVerification buildCertificateVerififier(final String tslFilename,
        final CertificateProfile certificateProfile, final X509Certificate x509EeCert) throws GemPkiException {

        final TspServiceSubset tspServiceSubset = new TspInformationProvider(new TslInformationProvider(
            new TslReader().getTrustServiceStatusList(tslFilename).orElseThrow()).getTspServices(), productType)
            .getTspServiceSubset(x509EeCert);

        return CertificateVerification.builder()
            .productType(productType)
            .tspServiceSubset(tspServiceSubset)
            .certificateProfile(certificateProfile)
            .x509EeCert(x509EeCert)
            .build();
    }

    @Test
    void verifyCertificateEndEntityNull() {
        assertThatThrownBy(
            () -> buildCertificateVerififier(FILE_NAME_TSL_DEFAULT, certificateProfile, null))
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("x509EeCert");
    }

    @Test
    void verifyCertificateProfileNull() {
        assertThatThrownBy(() -> buildCertificateVerififier(FILE_NAME_TSL_DEFAULT, null,
            VALID_X509_EE_CERT))
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("certificateProfile");
    }

    @Test
    void verifyTspProfileNull() {
        assertThatThrownBy(() -> buildCertificateVerififier(null, certificateProfile,
            VALID_X509_EE_CERT))
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("tslFilename");
    }

    @Test
    void verifySignatureIssuerNull() {
        assertThatThrownBy(() -> certificateVerification.verifySignature(null))
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("x509IssuerCert");
    }

    @Test
    void verifySignatureValid() {
        assertDoesNotThrow(() -> certificateVerification.verifySignature(VALID_X509_ISSUER_CERT));
    }

    @Test
    void verifySignatureNotValid() throws IOException {
        final X509Certificate invalidx509EeCert = CertificateProvider.getX509Certificate(
            "src/test/resources/certificates/GEM.SMCB-CA10/invalid/DrMedGunther_invalid-signature.pem");
        assertThatThrownBy(
            () -> buildCertificateVerififier(FILE_NAME_TSL_ALT_CA, certificateProfile, invalidx509EeCert)
                .verifySignature(VALID_X509_ISSUER_CERT))
            .isInstanceOf(GemPkiException.class)
            .hasMessageContaining(ErrorCode.SE_1024.getErrorMessage(productType));
    }

    @Test
    void verifyValidityReferenceDateNull() {
        assertThatThrownBy(() -> certificateVerification.verifyValidity(null))
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("referenceDate");
    }

    @Test
    void verifyValidityCertificateExpired() throws IOException {
        final X509Certificate expiredEeCert = CertificateProvider.getX509Certificate(
            "src/test/resources/certificates/GEM.SMCB-CA10/invalid/DrMedGunther_expired.pem");
        assertThatThrownBy(
            () -> buildCertificateVerififier(FILE_NAME_TSL_DEFAULT, certificateProfile, expiredEeCert)
                .verifyValidity(DATETIME_TO_CHECK))
            .isInstanceOf(GemPkiException.class)
            .hasMessageContaining(ErrorCode.SE_1021.name());
    }

    @Test
    void verifyValidityCertificateNotYetValid() throws IOException {
        final X509Certificate notYetValidEeCert = CertificateProvider.getX509Certificate(
            "src/test/resources/certificates/GEM.SMCB-CA10/invalid/DrMedGunther_not-yet-valid.pem");
        assertThatThrownBy(
            () -> buildCertificateVerififier(FILE_NAME_TSL_DEFAULT, certificateProfile, notYetValidEeCert)
                .verifyValidity(DATETIME_TO_CHECK))
            .isInstanceOf(GemPkiException.class)
            .hasMessageContaining(ErrorCode.SE_1021.name());
    }

    @Test
    void verifyValidityCertificateValid() {
        assertDoesNotThrow(() -> certificateVerification.verifyValidity(DATETIME_TO_CHECK));
    }

    @Test
    void verifyKeyUsageValid() {
        assertDoesNotThrow(() -> certificateVerification.verifyKeyUsage());
    }

    @Test
    void verifyKeyUsageMissingInCertificate() throws IOException {
        final X509Certificate missingKeyUsagex509EeCert = CertificateProvider.getX509Certificate(
            "src/test/resources/certificates/GEM.SMCB-CA10/invalid/DrMedGunther_missing-keyusage.pem");
        assertThatThrownBy(
            () -> buildCertificateVerififier(FILE_NAME_TSL_DEFAULT, certificateProfile,
                missingKeyUsagex509EeCert)
                .verifyKeyUsage())
            .isInstanceOf(GemPkiException.class)
            .hasMessageContaining(ErrorCode.SE_1016.name()); //WRONG_KEYUSAGE
    }

    @Test
    void verifyKeyUsageInvalidInCertificate() throws IOException {
        final X509Certificate invalidKeyUsagex509EeCert = CertificateProvider.getX509Certificate(
            "src/test/resources/certificates/GEM.SMCB-CA10/invalid/DrMedGunther_invalid-keyusage.pem");
        assertThatThrownBy(
            () -> buildCertificateVerififier(FILE_NAME_TSL_DEFAULT, certificateProfile,
                invalidKeyUsagex509EeCert)
                .verifyKeyUsage())
            .isInstanceOf(GemPkiException.class)
            .hasMessageContaining(ErrorCode.SE_1016.getErrorMessage(productType)); //WRONG_KEYUSAGE
    }

    @Test
    void verifyNotAllKeyUsagesPresentInCert() {
        assertThatThrownBy(
            () -> buildCertificateVerififier(CertificateProfile.C_HCI_AUT_RSA).verifyKeyUsage())
            .isInstanceOf(GemPkiException.class)
            .hasMessageContaining(ErrorCode.SE_1016.getErrorMessage(productType));
    }

    @Test
    void verifyToManyKeyUsagesPresentInCert() throws IOException {
        final X509Certificate validHbaAutEcc = CertificateProvider.getX509Certificate(
            "src/test/resources/certificates/GEM.HBA-CA13/GüntherOtís.pem");
        assertThatThrownBy(
            () -> buildCertificateVerififier(FILE_NAME_TSL_DEFAULT, CertificateProfile.C_HCI_AUT_ECC,
                validHbaAutEcc)
                .verifyKeyUsage())
            .isInstanceOf(GemPkiException.class)
            .hasMessageContaining(ErrorCode.SE_1016.getErrorMessage(productType));
    }

    @Test
    void verifyExtendedKeyUsageValid() {
        assertDoesNotThrow(() -> certificateVerification.verifyExtendedKeyUsage());
    }

    @Test
    void verifyNotAllExtendedKeyUsagesPresentInCert() {
        assertThatThrownBy(
            () -> buildCertificateVerififier(CertificateProfile.C_HP_AUT_ECC).verifyExtendedKeyUsage())
            .isInstanceOf(GemPkiException.class)
            .hasMessageContaining(ErrorCode.SE_1017.getErrorMessage(productType));
    }

    @Test
    void verifyToManyExtendedKeyUsagesPresentInCert() throws IOException {
        final X509Certificate validHbaAutEcc = CertificateProvider.getX509Certificate(
            "src/test/resources/certificates/GEM.HBA-CA13/GüntherOtís.pem");
        assertThatThrownBy(
            () -> buildCertificateVerififier(FILE_NAME_TSL_DEFAULT, CertificateProfile.C_HCI_AUT_ECC,
                validHbaAutEcc)
                .verifyExtendedKeyUsage())
            .isInstanceOf(GemPkiException.class)
            .hasMessageContaining(ErrorCode.SE_1017.getErrorMessage(productType));
    }

    @Test
    void verifyExtendedKeyUsageMissingInCertificate() throws IOException {
        final X509Certificate missingExtKeyUsagex509EeCert = CertificateProvider.getX509Certificate(
            "src/test/resources/certificates/GEM.SMCB-CA10/invalid/DrMedGunther_missing-extKeyUsage.pem");
        assertThatThrownBy(
            () -> buildCertificateVerififier(FILE_NAME_TSL_DEFAULT, certificateProfile,
                missingExtKeyUsagex509EeCert)
                .verifyExtendedKeyUsage())
            .isInstanceOf(GemPkiException.class)
            .hasMessageContaining(ErrorCode.SE_1017.name()); //WRONG_EXT_KEYUSAGE
    }

    @Test
    void verifyExtendedKeyUsageInvalidInCertificate() throws IOException {
        final X509Certificate invalidExtendedKeyUsageEeCert = CertificateProvider.getX509Certificate(
            "src/test/resources/certificates/GEM.SMCB-CA10/invalid/DrMedGunther_invalid-ext-keyusage.pem");
        assertThatThrownBy(
            () -> buildCertificateVerififier(FILE_NAME_TSL_DEFAULT, certificateProfile,
                invalidExtendedKeyUsageEeCert)
                .verifyExtendedKeyUsage())
            .isInstanceOf(GemPkiException.class)
            .hasMessageContaining(ErrorCode.SE_1017.getErrorMessage(productType));
    }

    @Test
    void verifyIssuerServiceStatusInaccord() {
        assertDoesNotThrow(() -> buildCertificateVerififier(FILE_NAME_TSL_ALT_CA, certificateProfile,
            VALID_X509_EE_CERT_ALT_CA).verifyIssuerServiceStatus());
    }

    /**
     * Timestamp "notBefore" of VALID_X509_EE_CERT_ALT_CA is before StatusStartingTime of TSPService (issuer of
     * VALID_X509_EE_CERT_ALT_CA) in TSL FILE_NAME_TSL_ALT_CA_REVOKED
     */
    @Test
    void verifyIssuerServiceStatusRevokedLater() {
        final String tslAltCaRevokedLater = "tsls/valid/TSL_altCA_revokedLater.xml";
        assertDoesNotThrow(() -> buildCertificateVerififier(tslAltCaRevokedLater,
            certificateProfile, VALID_X509_EE_CERT_ALT_CA)
            .verifyIssuerServiceStatus());
    }

    /**
     * Timestamp "notBefore" of VALID_X509_EE_CERT_ALT_CA is after StatusStartingTime of TSPService (issuer of
     * VALID_X509_EE_CERT_ALT_CA) in TSL FILE_NAME_TSL_ALT_CA_REVOKED
     */
    @Test
    void verifyIssuerServiceStatusRevoked() {
        assertThatThrownBy(() -> buildCertificateVerififier(FILE_NAME_TSL_ALT_CA_REVOKED,
            certificateProfile, VALID_X509_EE_CERT_ALT_CA)
            .verifyIssuerServiceStatus())
            .isInstanceOf(GemPkiException.class)
            .hasMessageContaining(ErrorCode.SE_1036.getErrorMessage(productType));
    }


    @Test
    void multipleCertificateProfilesMultipleCertTypesInEe() throws IOException {
        final X509Certificate eeMultipleCertTypes = CertificateProvider.getX509Certificate(
            "src/test/resources/certificates/GEM.SMCB-CA9/Aschoffsche_Apotheke_twoCertTypes.pem");
        assertDoesNotThrow(() -> buildCertificateVerififier(FILE_NAME_TSL_DEFAULT,
            certificateProfile, eeMultipleCertTypes).verifyCertificateType());
    }

    @Test
    void verifyCertificateProfileMissingPolicyId() throws IOException {
        final X509Certificate missingPolicyId = CertificateProvider
            .getX509Certificate(
                "src/test/resources/certificates/GEM.SMCB-CA10/invalid/DrMedGunther_missing-policyId.pem");
        assertThatThrownBy(
            () -> buildCertificateVerififier(FILE_NAME_TSL_DEFAULT, certificateProfile, missingPolicyId)
                .verifyCertificateType())
            .isInstanceOf(GemPkiException.class)
            .hasMessageContaining(ErrorCode.SE_1033.getErrorMessage(productType));
    }

    @Test
    void verifyCertificateProfileMissingCertType() throws IOException {
        final X509Certificate missingCertType = CertificateProvider
            .getX509Certificate(
                "src/test/resources/certificates/GEM.SMCB-CA10/invalid/DrMedGunther_missing-certificate-type.pem");
        assertThatThrownBy(
            () -> buildCertificateVerififier(FILE_NAME_TSL_DEFAULT, certificateProfile, missingCertType)
                .verifyCertificateType())
            .isInstanceOf(GemPkiException.class)
            .hasMessageContaining(ErrorCode.SE_1033.getErrorMessage(productType));
    }

    @Test
    void verifyCertificateProfileInvalidCertType() throws IOException {
        final X509Certificate invalidCertType = CertificateProvider
            .getX509Certificate(
                "src/test/resources/certificates/GEM.SMCB-CA10/invalid/DrMedGunther_invalid-certificate-type.pem");
        assertThatThrownBy(
            () -> buildCertificateVerififier(FILE_NAME_TSL_DEFAULT, certificateProfile, invalidCertType)
                .verifyCertificateType())
            .isInstanceOf(GemPkiException.class)
            .hasMessageContaining(ErrorCode.SE_1018.getErrorMessage(productType));
    }

    @Test
    void verifyCertificateProfileWrongServiceInfoExtInTsl() {
        final String tslAltCaWrongServiceExtension = "tsls/defect/TSL_defect_altCA_wrong-srvInfoExt.xml";

        assertThatThrownBy(
            () -> buildCertificateVerififier(tslAltCaWrongServiceExtension, certificateProfile,
                VALID_X509_EE_CERT_ALT_CA)
                .verifyCertificateType())
            .isInstanceOf(GemPkiException.class)
            .hasMessageContaining(ErrorCode.SE_1061.getErrorMessage(productType));
    }

}
