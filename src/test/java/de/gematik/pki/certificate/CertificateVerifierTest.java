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

import static de.gematik.pki.certificate.CertificateVerifier.SVCSTATUS_INACCORD;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import de.gematik.pki.error.ErrorCode;
import de.gematik.pki.exception.GemPkiException;
import de.gematik.pki.tsl.TSLInformationProvider;
import de.gematik.pki.tsl.TslReader;
import de.gematik.pki.utils.CertificateProvider;
import de.gematik.pki.utils.VariableSource;
import eu.europa.esig.jaxb.tsl.TSPServiceType;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.stream.Collectors;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ArgumentsSource;


/**
 * Dieser Test arbeitet ausschließlich mit einem Zertifikatsprofil (SMCB). Andere Profile zu testen wäre vermutlich
 * akademisch.
 */
@Slf4j(topic = "UNITTEST")
@DisplayName("Certificate Verification Test Using Valid and Invalid Certificates")
class CertificateVerifierTest {

    private String productType;
    private CertificateVerifier certificateVerifier;
    private X509Certificate VALID_EE_CERT;
    private X509Certificate VALID_EE_CERT_ALT_CA;
    private X509Certificate VALID_ISSUER_CERT;
    private static ZonedDateTime DATETIME_TO_CHECK;
    private static final String FILE_NAME_TSL_DEFAULT = "tsls/valid/TSL_default.xml";
    private static final String FILE_NAME_TSL_ALT_CA = "tsls/valid/TSL_altCA.xml";
    private static final String FILE_NAME_TSL_ALT_CA_REVOKED = "tsls/valid/TSL_altCA_revoked.xml";
    private final CertificateProfiles certificateProfile = CertificateProfiles.C_HCI_AUT_ECC;
    private final List<CertificateProfiles> certificateProfiles = List.of(certificateProfile);

    @BeforeEach
    void setUp() throws IOException {
        VALID_EE_CERT = CertificateProvider
            .getX509Certificate("src/test/resources/GEM.SMCB-CA10/valid/DrMedGunther.pem");
        VALID_EE_CERT_ALT_CA = CertificateProvider.getX509Certificate(
            "src/test/resources/GEM.SMCB-CA33/DrMedGuntherKZV.pem");
        VALID_ISSUER_CERT = CertificateProvider
            .getX509Certificate("src/test/resources/GEM.SMCB-CA10/GEM.SMCB-CA10_TEST-ONLY.pem");
        DATETIME_TO_CHECK = ZonedDateTime.parse("2020-11-20T15:00:00Z");
        productType = "IDP";
        certificateVerifier = buildCertificateChecker(FILE_NAME_TSL_DEFAULT, certificateProfiles);
    }

    private CertificateVerifier buildCertificateChecker(final String tslFilenameIdentifier,
        final List<CertificateProfiles> certificateProfile) {

        final List<TSPServiceType> tspServiceTypeList = new TSLInformationProvider(
            new TslReader().getTrustStatusListType(tslFilenameIdentifier).orElseThrow())
            .getTspServices();

        return CertificateVerifier.builder()
            .productType(productType)
            .tspServiceTypeList(tspServiceTypeList)
            .certificateProfiles(certificateProfile)
            .build();
    }

    @Test
    void verifyPerformTucPki18ChecksValid() {
        assertDoesNotThrow(() -> certificateVerifier.performTucPki18Checks(VALID_EE_CERT));
    }

    @ParameterizedTest
    @ArgumentsSource(CertificateProvider.class)
    @VariableSource(value = "invalid")
    void verifyPerformTucPki18ChecksInvalid(final X509Certificate cert) {
        assertThatThrownBy(() -> certificateVerifier.performTucPki18Checks(cert))
            .as("Test invalid certificates")
            .isInstanceOf(GemPkiException.class);
    }

    @Test
    void verifySignatureEndEntityNull() {
        assertThatThrownBy(() -> certificateVerifier.verifySignature(null, VALID_ISSUER_CERT))
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("x509EeCert");
    }

    @Test
    void verifySignatureIssuerNull() {
        assertThatThrownBy(() -> certificateVerifier.verifySignature(VALID_EE_CERT, null))
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("issuer");
    }

    @Test
    void verifySignatureValid() {
        assertDoesNotThrow(() -> certificateVerifier.verifySignature(VALID_EE_CERT, VALID_ISSUER_CERT));
    }

    @Test
    void verifySignatureNotValid() throws IOException {
        final X509Certificate invalidEeCert = CertificateProvider.getX509Certificate(
            "src/test/resources/GEM.SMCB-CA10/invalid/DrMedGunther_invalid-signature.pem");
        assertThatThrownBy(() -> certificateVerifier.verifySignature(invalidEeCert, VALID_ISSUER_CERT))
            .isInstanceOf(GemPkiException.class)
            .hasMessageContaining(ErrorCode.SE_1024.getErrorMessage(productType));
    }

    @Test
    void verifyValidityCertificateNull() {
        assertThatThrownBy(() -> certificateVerifier.verifyValidity(null, DATETIME_TO_CHECK))
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("x509EeCert");
    }

    @Test
    void verifyValidityReferenceDateNull() {
        assertThatThrownBy(() -> certificateVerifier.verifyValidity(VALID_EE_CERT, null))
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("referenceDate");
    }

    @Test
    void verifyValidityCertificateExpired() throws IOException {
        final X509Certificate expiredEeCert = CertificateProvider.getX509Certificate(
            "src/test/resources/GEM.SMCB-CA10/invalid/DrMedGunther_expired.pem");

        assertThatThrownBy(() -> certificateVerifier.verifyValidity(expiredEeCert, DATETIME_TO_CHECK))
            .isInstanceOf(GemPkiException.class)
            .hasMessageContaining(ErrorCode.SE_1021.name());
    }

    @Test
    void verifyValidityCertificateNotYetValid() throws IOException {
        final X509Certificate notYetValidEeCert = CertificateProvider.getX509Certificate(
            "src/test/resources/GEM.SMCB-CA10/invalid/DrMedGunther_not-yet-valid.pem");

        assertThatThrownBy(() -> certificateVerifier.verifyValidity(notYetValidEeCert, DATETIME_TO_CHECK))
            .isInstanceOf(GemPkiException.class)
            .hasMessageContaining(ErrorCode.SE_1021.name());
    }

    @Test
    void verifyValidityCertificateValid() {
        assertDoesNotThrow(() -> certificateVerifier.verifyValidity(VALID_EE_CERT, DATETIME_TO_CHECK));
    }

    @Test
    void verifyKeyUsageValid() {
        assertDoesNotThrow(() -> certificateVerifier.verifyKeyUsage(VALID_EE_CERT));
    }

    @Test
    void verifyKeyUsageCertificateNull() {
        assertThatThrownBy(() -> certificateVerifier.verifyKeyUsage(null))
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("x509EeCert");
    }

    @Test
    void verifyKeyUsageMissingInCertificate() throws IOException {
        final X509Certificate missingKeyUsageEeCert = CertificateProvider.getX509Certificate(
            "src/test/resources/GEM.SMCB-CA10/invalid/DrMedGunther_missing-keyusage.pem");
        assertThatThrownBy(() -> certificateVerifier.verifyKeyUsage(missingKeyUsageEeCert))
            .isInstanceOf(GemPkiException.class)
            .hasMessageContaining(ErrorCode.SE_1016.name()); //WRONG_KEYUSAGE
    }

    @Test
    void verifyKeyUsageInvalidInCertificate() throws IOException {
        final X509Certificate invalidKeyUsageEeCert = CertificateProvider.getX509Certificate(
            "src/test/resources/GEM.SMCB-CA10/invalid/DrMedGunther_invalid-keyusage.pem");
        assertThatThrownBy(() -> certificateVerifier.verifyKeyUsage(invalidKeyUsageEeCert))
            .isInstanceOf(GemPkiException.class)
            .hasMessageContaining(ErrorCode.SE_1016.getErrorMessage(productType)); //WRONG_KEYUSAGE
    }

    @Test
    void verifyExtendedKeyUsageValid() {
        assertDoesNotThrow(() -> certificateVerifier.verifyExtendedKeyUsage(VALID_EE_CERT));
    }

    @Test
    void verifyExtendedKeyUsageInvalidInCertificate() throws IOException {
        final X509Certificate invalidExtendedKeyUsageEeCert = CertificateProvider.getX509Certificate(
            "src/test/resources/GEM.SMCB-CA10/invalid/DrMedGunther_invalid-ext-keyusage.pem");
        assertThatThrownBy(() -> certificateVerifier.verifyExtendedKeyUsage(invalidExtendedKeyUsageEeCert))
            .isInstanceOf(GemPkiException.class)
            .hasMessageContaining(ErrorCode.SE_1017.getErrorMessage(productType));
    }

    @Test
    void verifyGetIntendedExtendedKeyUsages() {
        final List<String> listOne = certificateVerifier
            .getIntendedExtendedKeyUsagesFromCertificateProfile(certificateProfile);
        final List<String> listTwo = List.of(ExtendedKeyUsage.ID_KP_CLIENTAUTH).stream().map(ExtendedKeyUsage::getOid)
            .collect(Collectors.toList());
        assertThat(listOne.containsAll(listTwo)).isTrue();
        assertThat(listTwo.containsAll(listOne)).isTrue();
    }

    @Test
    void verifyGetIntendedExtendedKeyUsagesFailed() {
        final List<String> listOne = certificateVerifier
            .getIntendedExtendedKeyUsagesFromCertificateProfile(certificateProfile);
        final List<String> listTwo = List.of(ExtendedKeyUsage.ID_KP_CLIENTAUTH, ExtendedKeyUsage.ID_KP_EMAILPROTECTION)
            .stream().map(ExtendedKeyUsage::getOid)
            .collect(Collectors.toList());
        assertThat(listOne.containsAll(listTwo)).isFalse();
        assertThat(listTwo.containsAll(listOne)).isTrue();
    }

    @Test
    void verifyGetIntendedKeyUsages() {
        final List<Integer> listOne = certificateVerifier.getIntendedKeyUsagesFromCertificateProfile(
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
        final List<Integer> listOne = certificateVerifier.getIntendedKeyUsagesFromCertificateProfile(
            certificateProfile)
            .stream().map(KeyUsage::getBit).collect(Collectors.toList());
        final List<Integer> listTwo = List.of(KeyUsage.DIGITAL_SIGNATURE, KeyUsage.NON_REPUDIATION)
            .stream().map(KeyUsage::getBit)
            .collect(Collectors.toList());
        assertThat(listOne.containsAll(listTwo)).isFalse();
        assertThat(listTwo.containsAll(listOne)).isTrue();
    }

    @Test
    void verifyGetIssuerCertificateValidEE() {
        assertDoesNotThrow(() -> certificateVerifier.getIssuerCertificate(VALID_EE_CERT));
    }

    @Test
    void verifyIssuerServiceStatusInaccord() {
        assertDoesNotThrow(() -> buildCertificateChecker(FILE_NAME_TSL_ALT_CA,
            certificateProfiles).verifyIssuerServiceStatus(VALID_EE_CERT_ALT_CA));
    }

    @Test
    void verifyGetIssuerTspServiceMissingAki() throws IOException {
        final X509Certificate invalidEeCert = CertificateProvider.getX509Certificate(
            "src/test/resources/GEM.SMCB-CA10/invalid/DrMedGunther_missing-authorityKeyId.pem");
        assertThatThrownBy(() -> certificateVerifier.getIssuerTspService(invalidEeCert))
            .isInstanceOf(GemPkiException.class).hasMessageContaining(ErrorCode.SE_1023.getErrorMessage(
            productType));
    }

    /**
     * Timestamp "notBefore" of VALID_EE_CERT_ALT_CA is before StatusStartingTime of TSPService (issuer of
     * VALID_EE_CERT_ALT_CA) in TSL FILE_NAME_TSL_ALT_CA_REVOKED
     */
    @Test
    void verifyIssuerServiceStatusRevokedLater() {
        final String tslAltCaRevokedLater = "tsls/valid/TSL_altCA_revokedLater.xml";
        assertDoesNotThrow(() -> buildCertificateChecker(tslAltCaRevokedLater,
            certificateProfiles).verifyIssuerServiceStatus(VALID_EE_CERT_ALT_CA));
    }

    /**
     * Timestamp "notBefore" of VALID_EE_CERT_ALT_CA is after StatusStartingTime of TSPService (issuer of
     * VALID_EE_CERT_ALT_CA) in TSL FILE_NAME_TSL_ALT_CA_REVOKED
     */
    @Test
    void verifyIssuerServiceStatusRevoked() {
        assertThatThrownBy(() -> buildCertificateChecker(FILE_NAME_TSL_ALT_CA_REVOKED,
            certificateProfiles).verifyIssuerServiceStatus(VALID_EE_CERT_ALT_CA)).isInstanceOf(GemPkiException.class)
            .hasMessageContaining(ErrorCode.SE_1036.getErrorMessage(productType));
    }

    @Test
    void verifyGetCertificateProfileValid() {
        assertDoesNotThrow(
            () -> certificateProfiles.contains(certificateVerifier.getVerifiedCertificateProfile(
                VALID_EE_CERT)));
    }

    @Test
    void verifyGetCertificateProfileMissingPolicyId() throws IOException {
        final X509Certificate missingPolicyId = CertificateProvider
            .getX509Certificate(
                "src/test/resources/GEM.SMCB-CA10/invalid/DrMedGunther_missing-policyId.pem");
        assertThatThrownBy(() -> certificateProfiles.contains(certificateVerifier.getVerifiedCertificateProfile(
            missingPolicyId)))
            .isInstanceOf(GemPkiException.class)
            .hasMessageContaining(ErrorCode.SE_1033.getErrorMessage(productType));
    }

    @Test
    void verifyGetCertificateProfileMissingCertType() throws IOException {
        final X509Certificate missingCertType = CertificateProvider
            .getX509Certificate(
                "src/test/resources/GEM.SMCB-CA10/invalid/DrMedGunther_missing-certificate-type.pem");
        assertThatThrownBy(() -> certificateProfiles.contains(certificateVerifier.getVerifiedCertificateProfile(
            missingCertType)))
            .isInstanceOf(GemPkiException.class)
            .hasMessageContaining(ErrorCode.SE_1033.getErrorMessage(productType));
    }

    @Test
    void verifyGetCertificateProfileInvalidCertType() throws IOException {
        final X509Certificate invalidCertType = CertificateProvider
            .getX509Certificate(
                "src/test/resources/GEM.SMCB-CA10/invalid/DrMedGunther_invalid-certificate-type.pem");
        assertThatThrownBy(() -> certificateProfiles.contains(certificateVerifier.getVerifiedCertificateProfile(
            invalidCertType)))
            .isInstanceOf(GemPkiException.class)
            .hasMessageContaining(ErrorCode.SE_1018.getErrorMessage(productType));
    }

    @Test
    void verifyGetCertificateProfileWrongServiceInfoExtInTsl() {
        final String tslAltCaWrongServiceExtension = "tsls/defect/TSL_defect_altCA_wrong-srvInfoExt.xml";
        assertThatThrownBy(() -> buildCertificateChecker(tslAltCaWrongServiceExtension, certificateProfiles)
            .getVerifiedCertificateProfile(VALID_EE_CERT_ALT_CA))
            .isInstanceOf(GemPkiException.class)
            .hasMessageContaining(ErrorCode.SE_1061.getErrorMessage(productType));
    }

    @Test
    void verifyGetCertificateAuthorityServiceStatus() throws GemPkiException {
        final TSPServiceType tspServiceType = certificateVerifier.getIssuerTspService(VALID_EE_CERT);
        final String serviceStatus = certificateVerifier.getCertificateAuthorityServiceStatus(tspServiceType);
        assertThat(serviceStatus).isEqualTo(SVCSTATUS_INACCORD);
    }

    @Test
    void verifyServiceSupplyPointValid() throws GemPkiException {
        assertThat(certificateVerifier.getServiceSupplyPointFromEeCertificate(VALID_EE_CERT))
            .isEqualTo("http://ocsp-sim01-test.gem.telematik-test:8080/ocsp/OCSPSimulator/TSL_default-seq1");
    }

    @Test
    void verifyServiceSupplyPointMissing() {
        final String tslAltCaMissingSsp = "tsls/defect/TSL_defect_altCA_missingSsp.xml";
        assertThatThrownBy(() -> buildCertificateChecker(tslAltCaMissingSsp, certificateProfiles)
            .getServiceSupplyPointFromEeCertificate(VALID_EE_CERT_ALT_CA))
            .isInstanceOf(GemPkiException.class)
            .hasMessageContaining(ErrorCode.TE_1026.getErrorMessage(productType));
    }
}
