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

import static de.gematik.pki.certificate.SingleCertificateVerificationWorker.SVCSTATUS_INACCORD;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import de.gematik.pki.error.ErrorCode;
import de.gematik.pki.exception.GemPkiException;
import de.gematik.pki.tsl.TslInformationProvider;
import de.gematik.pki.tsl.TslReader;
import de.gematik.pki.tsl.TspService;
import de.gematik.pki.utils.CertificateProvider;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.stream.Collectors;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;


/**
 * Dieser Test arbeitet ausschließlich mit einem Zertifikatsprofil (SMCB). Andere Profile zu testen wäre vermutlich
 * akademisch.
 */
@Slf4j(topic = "UNITTEST")
class SingleCertificateVerificationWorkerTest {

    private static final String FILE_NAME_TSL_DEFAULT = "tsls/valid/TSL_default.xml";
    private static final String FILE_NAME_TSL_ALT_CA = "tsls/valid/TSL_altCA.xml";
    private static final String FILE_NAME_TSL_ALT_CA_REVOKED = "tsls/valid/TSL_altCA_revoked.xml";
    private static ZonedDateTime DATETIME_TO_CHECK;
    private final CertificateProfile certificateProfile = CertificateProfile.C_HCI_AUT_ECC;
    private String productType;
    private SingleCertificateVerificationWorker singleCertificateVerificationWorker;
    private X509Certificate VALID_EE_CERT;
    private X509Certificate VALID_EE_CERT_ALT_CA;
    private X509Certificate VALID_ISSUER_CERT;

    @BeforeEach
    void setUp() throws IOException {
        VALID_EE_CERT = CertificateProvider
            .getX509Certificate("src/test/resources/certificates/GEM.SMCB-CA10/valid/DrMedGunther.pem");
        VALID_EE_CERT_ALT_CA = CertificateProvider.getX509Certificate(
            "src/test/resources/certificates/GEM.SMCB-CA33/DrMedGuntherKZV.pem");
        VALID_ISSUER_CERT = CertificateProvider
            .getX509Certificate("src/test/resources/certificates/GEM.SMCB-CA10/GEM.SMCB-CA10_TEST-ONLY.pem");
        DATETIME_TO_CHECK = ZonedDateTime.parse("2020-11-20T15:00:00Z");
        productType = "IDP";
        singleCertificateVerificationWorker = buildCertificateChecker(certificateProfile);
    }

    private SingleCertificateVerificationWorker buildCertificateChecker(final CertificateProfile certificateProfile) {
        return buildCertificateChecker(FILE_NAME_TSL_DEFAULT, certificateProfile, VALID_EE_CERT);
    }

    private SingleCertificateVerificationWorker buildCertificateChecker(final String tslFilename,
        final CertificateProfile certificateProfile, final X509Certificate eeCert) {

        final List<TspService> tspServiceList = new TslInformationProvider(
            new TslReader().getTrustServiceStatusList(tslFilename).orElseThrow())
            .getTspServices();

        return SingleCertificateVerificationWorker.builder()
            .productType(productType)
            .tspServiceList(tspServiceList)
            .certificateProfile(certificateProfile)
            .x509EeCert(eeCert)
            .build();
    }

    @Test
    void verifyCertificateEndEntityNull() {
        assertThatThrownBy(() -> buildCertificateChecker(FILE_NAME_TSL_DEFAULT, certificateProfile, null))
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("x509EeCert");
    }

    @Test
    void verifyCertificateProfileNull() {
        assertThatThrownBy(() -> buildCertificateChecker(FILE_NAME_TSL_DEFAULT, null, VALID_EE_CERT))
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("certificateProfile");
    }

    @Test
    void verifyTspProfileNull() {
        assertThatThrownBy(() -> buildCertificateChecker(null, certificateProfile, VALID_EE_CERT))
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("tslFilename");
    }

    @Test
    void verifySignatureIssuerNull() {
        assertThatThrownBy(() -> singleCertificateVerificationWorker.verifySignature(null))
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("issuer");
    }

    @Test
    void verifySignatureValid() {
        assertDoesNotThrow(() -> singleCertificateVerificationWorker.verifySignature(VALID_ISSUER_CERT));
    }

    @Test
    void verifySignatureNotValid() throws IOException {
        final X509Certificate invalidEeCert = CertificateProvider.getX509Certificate(
            "src/test/resources/certificates/GEM.SMCB-CA10/invalid/DrMedGunther_invalid-signature.pem");
        assertThatThrownBy(() -> buildCertificateChecker(FILE_NAME_TSL_ALT_CA, certificateProfile, invalidEeCert)
            .verifySignature(VALID_ISSUER_CERT))
            .isInstanceOf(GemPkiException.class)
            .hasMessageContaining(ErrorCode.SE_1024.getErrorMessage(productType));
    }

    @Test
    void verifyValidityReferenceDateNull() {
        assertThatThrownBy(() -> singleCertificateVerificationWorker.verifyValidity(null))
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("referenceDate");
    }

    @Test
    void verifyValidityCertificateExpired() throws IOException {
        final X509Certificate expiredEeCert = CertificateProvider.getX509Certificate(
            "src/test/resources/certificates/GEM.SMCB-CA10/invalid/DrMedGunther_expired.pem");
        assertThatThrownBy(() -> buildCertificateChecker(FILE_NAME_TSL_DEFAULT, certificateProfile, expiredEeCert)
            .verifyValidity(DATETIME_TO_CHECK))
            .isInstanceOf(GemPkiException.class)
            .hasMessageContaining(ErrorCode.SE_1021.name());
    }

    @Test
    void verifyValidityCertificateNotYetValid() throws IOException {
        final X509Certificate notYetValidEeCert = CertificateProvider.getX509Certificate(
            "src/test/resources/certificates/GEM.SMCB-CA10/invalid/DrMedGunther_not-yet-valid.pem");
        assertThatThrownBy(() -> buildCertificateChecker(FILE_NAME_TSL_DEFAULT, certificateProfile, notYetValidEeCert)
            .verifyValidity(DATETIME_TO_CHECK))
            .isInstanceOf(GemPkiException.class)
            .hasMessageContaining(ErrorCode.SE_1021.name());
    }

    @Test
    void verifyValidityCertificateValid() {
        assertDoesNotThrow(() -> singleCertificateVerificationWorker.verifyValidity(DATETIME_TO_CHECK));
    }

    @Test
    void verifyKeyUsageValid() {
        assertDoesNotThrow(() -> singleCertificateVerificationWorker.verifyKeyUsage());
    }

    @Test
    void verifyKeyUsageMissingInCertificate() throws IOException {
        final X509Certificate missingKeyUsageEeCert = CertificateProvider.getX509Certificate(
            "src/test/resources/certificates/GEM.SMCB-CA10/invalid/DrMedGunther_missing-keyusage.pem");
        assertThatThrownBy(
            () -> buildCertificateChecker(FILE_NAME_TSL_DEFAULT, certificateProfile, missingKeyUsageEeCert)
                .verifyKeyUsage())
            .isInstanceOf(GemPkiException.class)
            .hasMessageContaining(ErrorCode.SE_1016.name()); //WRONG_KEYUSAGE
    }

    @Test
    void verifyKeyUsageInvalidInCertificate() throws IOException {
        final X509Certificate invalidKeyUsageEeCert = CertificateProvider.getX509Certificate(
            "src/test/resources/certificates/GEM.SMCB-CA10/invalid/DrMedGunther_invalid-keyusage.pem");
        assertThatThrownBy(
            () -> buildCertificateChecker(FILE_NAME_TSL_DEFAULT, certificateProfile, invalidKeyUsageEeCert)
                .verifyKeyUsage())
            .isInstanceOf(GemPkiException.class)
            .hasMessageContaining(ErrorCode.SE_1016.getErrorMessage(productType)); //WRONG_KEYUSAGE
    }

    @Test
    void verifyNotAllKeyUsagesPresentInCert() {
        assertThatThrownBy(() -> buildCertificateChecker(CertificateProfile.C_HCI_AUT_RSA).verifyKeyUsage())
            .isInstanceOf(GemPkiException.class)
            .hasMessageContaining(ErrorCode.SE_1016.getErrorMessage(productType));
    }

    @Test
    void verifyToManyKeyUsagesPresentInCert() throws IOException {
        final X509Certificate validHbaAutEcc = CertificateProvider.getX509Certificate(
            "src/test/resources/certificates/GEM.HBA-CA13/GüntherOtís.pem");
        assertThatThrownBy(
            () -> buildCertificateChecker(FILE_NAME_TSL_DEFAULT, CertificateProfile.C_HCI_AUT_ECC, validHbaAutEcc)
                .verifyKeyUsage())
            .isInstanceOf(GemPkiException.class)
            .hasMessageContaining(ErrorCode.SE_1016.getErrorMessage(productType));
    }

    @Test
    void verifyExtendedKeyUsageValid() {
        assertDoesNotThrow(() -> singleCertificateVerificationWorker.verifyExtendedKeyUsage());
    }

    @Test
    void verifyNotAllExtendedKeyUsagesPresentInCert() {
        assertThatThrownBy(() -> buildCertificateChecker(CertificateProfile.C_HP_AUT_ECC).verifyExtendedKeyUsage())
            .isInstanceOf(GemPkiException.class)
            .hasMessageContaining(ErrorCode.SE_1017.getErrorMessage(productType));
    }

    @Test
    void verifyToManyExtendedKeyUsagesPresentInCert() throws IOException {
        final X509Certificate validHbaAutEcc = CertificateProvider.getX509Certificate(
            "src/test/resources/certificates/GEM.HBA-CA13/GüntherOtís.pem");
        assertThatThrownBy(
            () -> buildCertificateChecker(FILE_NAME_TSL_DEFAULT, CertificateProfile.C_HCI_AUT_ECC, validHbaAutEcc)
                .verifyExtendedKeyUsage())
            .isInstanceOf(GemPkiException.class)
            .hasMessageContaining(ErrorCode.SE_1017.getErrorMessage(productType));
    }

    @Test
    void verifyExtendedKeyUsageMissingInCertificate() throws IOException {
        final X509Certificate missingExtKeyUsageEeCert = CertificateProvider.getX509Certificate(
            "src/test/resources/certificates/GEM.SMCB-CA10/invalid/DrMedGunther_missing-extKeyUsage.pem");
        assertThatThrownBy(
            () -> buildCertificateChecker(FILE_NAME_TSL_DEFAULT, certificateProfile, missingExtKeyUsageEeCert)
                .verifyExtendedKeyUsage())
            .isInstanceOf(GemPkiException.class)
            .hasMessageContaining(ErrorCode.SE_1017.name()); //WRONG_EXT_KEYUSAGE
    }

    @Test
    void verifyExtendedKeyUsageInvalidInCertificate() throws IOException {
        final X509Certificate invalidExtendedKeyUsageEeCert = CertificateProvider.getX509Certificate(
            "src/test/resources/certificates/GEM.SMCB-CA10/invalid/DrMedGunther_invalid-ext-keyusage.pem");
        assertThatThrownBy(
            () -> buildCertificateChecker(FILE_NAME_TSL_DEFAULT, certificateProfile, invalidExtendedKeyUsageEeCert)
                .verifyExtendedKeyUsage())
            .isInstanceOf(GemPkiException.class)
            .hasMessageContaining(ErrorCode.SE_1017.getErrorMessage(productType));
    }

    @Test
    void verifyGetIntendedExtendedKeyUsages() {
        final List<String> listOne = singleCertificateVerificationWorker
            .getIntendedExtendedKeyUsagesFromCertificateProfile(certificateProfile);
        final List<String> listTwo = List.of(ExtendedKeyUsage.ID_KP_CLIENTAUTH).stream().map(ExtendedKeyUsage::getOid)
            .collect(Collectors.toList());
        assertThat(listOne.containsAll(listTwo)).isTrue();
        assertThat(listTwo.containsAll(listOne)).isTrue();
    }

    @Test
    void verifyGetIntendedExtendedKeyUsagesFailed() {
        final List<String> listOne = singleCertificateVerificationWorker
            .getIntendedExtendedKeyUsagesFromCertificateProfile(certificateProfile);
        final List<String> listTwo = List.of(ExtendedKeyUsage.ID_KP_CLIENTAUTH, ExtendedKeyUsage.ID_KP_EMAILPROTECTION)
            .stream().map(ExtendedKeyUsage::getOid)
            .collect(Collectors.toList());
        assertThat(listOne.containsAll(listTwo)).isFalse();
        assertThat(listTwo.containsAll(listOne)).isTrue();
    }

    @Test
    void verifyGetIntendedExtendedKeyUsagesCertificateProfileNull() {
        assertThatThrownBy(
            () -> singleCertificateVerificationWorker.getIntendedExtendedKeyUsagesFromCertificateProfile(null))
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("certificateProfile");
    }

    @Test
    void verifyGetIntendedKeyUsages() {
        final List<Integer> listOne = singleCertificateVerificationWorker.getIntendedKeyUsagesFromCertificateProfile(
            certificateProfile)
            .stream().map(KeyUsage::getBit).collect(Collectors.toList());
        final List<Integer> listTwo = List.of(KeyUsage.DIGITAL_SIGNATURE)
            .stream().map(KeyUsage::getBit)
            .collect(Collectors.toList());
        assertThat(listOne.containsAll(listTwo)).isTrue();
        assertThat(listTwo.containsAll(listOne)).isTrue();
    }

    @Test
    void verifyGetIntendedKeyUsagesFailed() {
        final List<Integer> listOne = singleCertificateVerificationWorker.getIntendedKeyUsagesFromCertificateProfile(
            certificateProfile)
            .stream().map(KeyUsage::getBit).collect(Collectors.toList());
        final List<Integer> listTwo = List.of(KeyUsage.DIGITAL_SIGNATURE, KeyUsage.NON_REPUDIATION)
            .stream().map(KeyUsage::getBit)
            .collect(Collectors.toList());
        assertThat(listOne.containsAll(listTwo)).isFalse();
        assertThat(listTwo.containsAll(listOne)).isTrue();
    }

    @Test
    void verifyGetIntendedKeyUsagesCertificateProfileNull() {
        assertThatThrownBy(() -> singleCertificateVerificationWorker.getIntendedKeyUsagesFromCertificateProfile(null))
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("certificateProfile");
    }

    @Test
    void verifyGetIssuerCertificateValidEE() {
        assertDoesNotThrow(() -> singleCertificateVerificationWorker.getIssuerCertificate());
    }

    @Test
    void verifyGetIssuerCertificateExtractionError() {
        final String tslAltCaBroken = "tsls/defect/TSL_defect_altCA_broken.xml";
        assertThatThrownBy(() -> buildCertificateChecker(tslAltCaBroken, certificateProfile,
            VALID_EE_CERT_ALT_CA).performCertificateChecks())
            .isInstanceOf(GemPkiException.class)
            .hasMessageContaining(ErrorCode.TE_1002.name());
    }

    @Test
    void verifyGetIssuerCertificateMissing() {
        assertThatThrownBy(() -> buildCertificateChecker(FILE_NAME_TSL_DEFAULT, certificateProfile,
            VALID_EE_CERT_ALT_CA).performCertificateChecks())
            .isInstanceOf(GemPkiException.class)
            .hasMessageContaining(ErrorCode.TE_1027.name());
    }

    @Test
    void verifyIssuerServiceStatusInaccord() {
        assertDoesNotThrow(() -> buildCertificateChecker(FILE_NAME_TSL_ALT_CA, certificateProfile,
            VALID_EE_CERT_ALT_CA)
            .verifyIssuerServiceStatus());
    }

    @Test
    void verifyGetIssuerTspServiceMissingAki() throws IOException {
        final X509Certificate invalidEeCert = CertificateProvider.getX509Certificate(
            "src/test/resources/certificates/GEM.SMCB-CA10/invalid/DrMedGunther_missing-authorityKeyId.pem");
        assertThatThrownBy(() -> buildCertificateChecker(FILE_NAME_TSL_DEFAULT, certificateProfile, invalidEeCert)
            .getIssuerTspService())
            .isInstanceOf(GemPkiException.class)
            .hasMessageContaining(ErrorCode.SE_1023.getErrorMessage(productType));
    }

    /**
     * Timestamp "notBefore" of VALID_EE_CERT_ALT_CA is before StatusStartingTime of TSPService (issuer of
     * VALID_EE_CERT_ALT_CA) in TSL FILE_NAME_TSL_ALT_CA_REVOKED
     */
    @Test
    void verifyIssuerServiceStatusRevokedLater() {
        final String tslAltCaRevokedLater = "tsls/valid/TSL_altCA_revokedLater.xml";
        assertDoesNotThrow(() -> buildCertificateChecker(tslAltCaRevokedLater,
            certificateProfile, VALID_EE_CERT_ALT_CA)
            .verifyIssuerServiceStatus());
    }

    /**
     * Timestamp "notBefore" of VALID_EE_CERT_ALT_CA is after StatusStartingTime of TSPService (issuer of
     * VALID_EE_CERT_ALT_CA) in TSL FILE_NAME_TSL_ALT_CA_REVOKED
     */
    @Test
    void verifyIssuerServiceStatusRevoked() {
        assertThatThrownBy(() -> buildCertificateChecker(FILE_NAME_TSL_ALT_CA_REVOKED,
            certificateProfile, VALID_EE_CERT_ALT_CA)
            .verifyIssuerServiceStatus())
            .isInstanceOf(GemPkiException.class)
            .hasMessageContaining(ErrorCode.SE_1036.getErrorMessage(productType));
    }


    @Test
    void multipleCertificateProfiles_multipleCertTypesInEe() throws IOException {
        final X509Certificate eeMultipleCertTypes = CertificateProvider.getX509Certificate(
            "src/test/resources/certificates/GEM.SMCB-CA9/Aschoffsche_Apotheke_twoCertTypes.pem");
        assertDoesNotThrow(() -> buildCertificateChecker(FILE_NAME_TSL_DEFAULT, certificateProfile, eeMultipleCertTypes)
            .performCertificateChecks());
    }

    @Test
    void verifyGetCertificateProfileMissingPolicyId() throws IOException {
        final X509Certificate missingPolicyId = CertificateProvider
            .getX509Certificate(
                "src/test/resources/certificates/GEM.SMCB-CA10/invalid/DrMedGunther_missing-policyId.pem");
        assertThatThrownBy(() -> buildCertificateChecker(FILE_NAME_TSL_DEFAULT, certificateProfile, missingPolicyId)
            .performCertificateChecks())
            .isInstanceOf(GemPkiException.class)
            .hasMessageContaining(ErrorCode.SE_1033.getErrorMessage(productType));
    }

    @Test
    void verifyGetCertificateProfileMissingCertType() throws IOException {
        final X509Certificate missingCertType = CertificateProvider
            .getX509Certificate(
                "src/test/resources/certificates/GEM.SMCB-CA10/invalid/DrMedGunther_missing-certificate-type.pem");
        assertThatThrownBy(() -> buildCertificateChecker(FILE_NAME_TSL_DEFAULT, certificateProfile, missingCertType)
            .performCertificateChecks())
            .isInstanceOf(GemPkiException.class)
            .hasMessageContaining(ErrorCode.SE_1033.getErrorMessage(productType));
    }

    @Test
    void verifyGetCertificateProfileInvalidCertType() throws IOException {
        final X509Certificate invalidCertType = CertificateProvider
            .getX509Certificate(
                "src/test/resources/certificates/GEM.SMCB-CA10/invalid/DrMedGunther_invalid-certificate-type.pem");
        assertThatThrownBy(() -> buildCertificateChecker(FILE_NAME_TSL_DEFAULT, certificateProfile, invalidCertType)
            .verifyCertificateType())
            .isInstanceOf(GemPkiException.class)
            .hasMessageContaining(ErrorCode.SE_1018.getErrorMessage(productType));
    }

    @Test
    void verifyGetCertificateProfileWrongServiceInfoExtInTsl() {
        final String tslAltCaWrongServiceExtension = "tsls/defect/TSL_defect_altCA_wrong-srvInfoExt.xml";

        assertThatThrownBy(
            () -> buildCertificateChecker(tslAltCaWrongServiceExtension, certificateProfile,
                VALID_EE_CERT_ALT_CA)
                .performCertificateChecks())
            .isInstanceOf(GemPkiException.class)
            .hasMessageContaining(ErrorCode.SE_1061.getErrorMessage(productType));
    }

    @Test
    void verifyGetCertificateAuthorityServiceStatus() throws GemPkiException {
        final TspService tspService = singleCertificateVerificationWorker.getIssuerTspService();
        final String serviceStatus = singleCertificateVerificationWorker
            .getCertificateAuthorityServiceStatus(tspService);
        assertThat(serviceStatus).isEqualTo(SVCSTATUS_INACCORD);
    }

    @Test
    void verifyServiceSupplyPointValid() throws GemPkiException {
        assertThat(singleCertificateVerificationWorker.getServiceSupplyPointFromEeCertificate())
            .isEqualTo("http://ocsp-sim01-test.gem.telematik-test:8080/ocsp/OCSPSimulator/TSL_default-seq1");
    }

    @Test
    void verifyServiceSupplyPointMissing() {
        final String tslAltCaMissingSsp = "tsls/defect/TSL_defect_altCA_missingSsp.xml";
        assertThatThrownBy(() -> buildCertificateChecker(tslAltCaMissingSsp, certificateProfile,
            VALID_EE_CERT_ALT_CA)
            .getServiceSupplyPointFromEeCertificate())
            .isInstanceOf(GemPkiException.class)
            .hasMessageContaining(ErrorCode.TE_1026.getErrorMessage(productType));
    }

    @Test
    void verifyGetCertificateAuthorityServiceStatusTspServiceNull() {
        assertThatThrownBy(() -> singleCertificateVerificationWorker.getCertificateAuthorityServiceStatus(null))
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("tspService");
    }
}
