/*
 * Copyright (c) 2022 gematik GmbH
 * 
 * Licensed under the Apache License, Version 2.0 (the License);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an 'AS IS' BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.gematik.pki.certificate;

import static de.gematik.pki.TestConstants.FILE_NAME_TSL_DEFAULT;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import de.gematik.pki.error.ErrorCode;
import de.gematik.pki.exception.GemPkiException;
import de.gematik.pki.tsl.TslInformationProvider;
import de.gematik.pki.tsl.TslReader;
import de.gematik.pki.tsl.TspInformationProvider;
import de.gematik.pki.tsl.TspServiceSubset;
import de.gematik.pki.utils.CertificateProvider;
import de.gematik.pki.utils.ResourceReader;
import java.io.IOException;
import java.security.cert.X509Certificate;
import lombok.NonNull;
import lombok.SneakyThrows;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class CertificateProfileVerificationTest {

    private final CertificateProfile certificateProfile = CertificateProfile.C_HCI_AUT_ECC;
    private String productType;
    private CertificateProfileVerification certificateProfileVerification;
    private X509Certificate validX509EeCert;
    private X509Certificate validX509EeCertAltCa;

    @BeforeEach
    @SneakyThrows
    void setUp() {
        validX509EeCert = CertificateProvider
            .getX509Certificate(ResourceReader.getFilePathFromResources("certificates/GEM.SMCB-CA10/valid/DrMedGunther.pem"));
        validX509EeCertAltCa = CertificateProvider.getX509Certificate(
            ResourceReader.getFilePathFromResources("certificates/GEM.SMCB-CA33/DrMedGuntherKZV.pem"));
        productType = "IDP";
        certificateProfileVerification = buildCertificateProfileVerifier(certificateProfile);
    }

    private CertificateProfileVerification buildCertificateProfileVerifier(
        final CertificateProfile certificateProfile) throws GemPkiException, IOException {
        return buildCertificateProfileVerifier(FILE_NAME_TSL_DEFAULT, certificateProfile, validX509EeCert);
    }

    private CertificateProfileVerification buildCertificateProfileVerifier(@NonNull final String tslFilename,
        final CertificateProfile certificateProfile, final X509Certificate x509EeCert) throws GemPkiException, IOException {

        final TspServiceSubset tspServiceSubset = new TspInformationProvider(new TslInformationProvider(
            TslReader.getTsl(ResourceReader.getFilePathFromResources(tslFilename)).orElseThrow()).getTspServices(),
            productType)
            .getTspServiceSubset(x509EeCert);

        return CertificateProfileVerification.builder()
            .productType(productType)
            .tspServiceSubset(tspServiceSubset)
            .certificateProfile(certificateProfile)
            .x509EeCert(x509EeCert)
            .build();
    }

    @Test
    void verifyCertificateProfileNull() {
        assertThatThrownBy(() -> buildCertificateProfileVerifier(FILE_NAME_TSL_DEFAULT, null,
            validX509EeCert))
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("certificateProfile");
    }

    @Test
    void verifyTspProfileNull() {
        assertThatThrownBy(() -> buildCertificateProfileVerifier(null, certificateProfile,
            validX509EeCert))
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("tslFilename");
    }

    @Test
    void verifyKeyUsageValid() {
        assertDoesNotThrow(() -> certificateProfileVerification.verifyKeyUsage());
    }

    @SneakyThrows
    @Test
    void verifyKeyUsageMissingInCertificate() throws IOException {
        final X509Certificate missingKeyUsagex509EeCert = CertificateProvider.getX509Certificate(
            "src/test/resources/certificates/GEM.SMCB-CA10/invalid/DrMedGunther_missing-keyusage.pem");
        final var verifier = buildCertificateProfileVerifier(FILE_NAME_TSL_DEFAULT, certificateProfile,
            missingKeyUsagex509EeCert);
        assertThatThrownBy(verifier::verifyKeyUsage)
            .isInstanceOf(GemPkiException.class)
            .hasMessageContaining(ErrorCode.SE_1016.name()); //WRONG_KEYUSAGE
    }

    @SneakyThrows
    @Test
    void verifyKeyUsageInvalidInCertificate() throws IOException {
        final X509Certificate invalidKeyUsagex509EeCert = CertificateProvider.getX509Certificate(
            "src/test/resources/certificates/GEM.SMCB-CA10/invalid/DrMedGunther_invalid-keyusage.pem");
        final var verifier = buildCertificateProfileVerifier(FILE_NAME_TSL_DEFAULT, certificateProfile, invalidKeyUsagex509EeCert);
        assertThatThrownBy(verifier::verifyKeyUsage)
            .isInstanceOf(GemPkiException.class)
            .hasMessageContaining(ErrorCode.SE_1016.getErrorMessage(productType)); //WRONG_KEYUSAGE
    }

    @SneakyThrows
    @Test
    void verifyNotAllKeyUsagesPresentInCert() {
        final var verifier = buildCertificateProfileVerifier(CertificateProfile.C_HCI_AUT_RSA);
        assertThatThrownBy(verifier::verifyKeyUsage)
            .isInstanceOf(GemPkiException.class)
            .hasMessageContaining(ErrorCode.SE_1016.getErrorMessage(productType));
    }

    @SneakyThrows
    @Test
    void verifyToManyKeyUsagesPresentInCert() throws IOException {
        final X509Certificate validHbaAutEcc = CertificateProvider.getX509Certificate(
            "src/test/resources/certificates/GEM.HBA-CA13/GüntherOtís.pem");
        final var verifier = buildCertificateProfileVerifier(FILE_NAME_TSL_DEFAULT, CertificateProfile.C_HCI_AUT_ECC, validHbaAutEcc);
        assertThatThrownBy(verifier::verifyKeyUsage)
            .isInstanceOf(GemPkiException.class)
            .hasMessageContaining(ErrorCode.SE_1016.getErrorMessage(productType));
    }

    @Test
    void verifyExtendedKeyUsageValid() {
        assertDoesNotThrow(() -> certificateProfileVerification.verifyExtendedKeyUsage());
    }

    @SneakyThrows
    @Test
    void verifyNotAllExtendedKeyUsagesPresentInCert() {
        final var verifier = buildCertificateProfileVerifier(CertificateProfile.C_HP_AUT_ECC);
        assertThatThrownBy(verifier::verifyExtendedKeyUsage)
            .isInstanceOf(GemPkiException.class)
            .hasMessageContaining(ErrorCode.SE_1017.getErrorMessage(productType));
    }

    @SneakyThrows
    @Test
    void verifyToManyExtendedKeyUsagesPresentInCert() throws IOException {
        final X509Certificate validHbaAutEcc = CertificateProvider.getX509Certificate(
            "src/test/resources/certificates/GEM.HBA-CA13/GüntherOtís.pem");
        final var verifier = buildCertificateProfileVerifier(FILE_NAME_TSL_DEFAULT, CertificateProfile.C_HCI_AUT_ECC, validHbaAutEcc);
        assertThatThrownBy(verifier::verifyExtendedKeyUsage)
            .isInstanceOf(GemPkiException.class)
            .hasMessageContaining(ErrorCode.SE_1017.getErrorMessage(productType));
    }

    @SneakyThrows
    @Test
    void verifyExtendedKeyUsageMissingInCertificate() throws IOException {
        final X509Certificate missingExtKeyUsagex509EeCert = CertificateProvider.getX509Certificate(
            "src/test/resources/certificates/GEM.SMCB-CA10/invalid/DrMedGunther_missing-extKeyUsage.pem");
        final var verifier = buildCertificateProfileVerifier(FILE_NAME_TSL_DEFAULT, certificateProfile, missingExtKeyUsagex509EeCert);
        assertThatThrownBy(verifier::verifyExtendedKeyUsage)
            .isInstanceOf(GemPkiException.class)
            .hasMessageContaining(ErrorCode.SE_1017.name()); //WRONG_EXT_KEYUSAGE
    }

    @SneakyThrows
    @Test
    void verifyExtendedKeyUsageInvalidInCertificate() throws IOException {
        final X509Certificate invalidExtendedKeyUsageEeCert = CertificateProvider.getX509Certificate(
            "src/test/resources/certificates/GEM.SMCB-CA10/invalid/DrMedGunther_invalid-ext-keyusage.pem");
        final var verifier = buildCertificateProfileVerifier(FILE_NAME_TSL_DEFAULT, certificateProfile, invalidExtendedKeyUsageEeCert);
        assertThatThrownBy(verifier::verifyExtendedKeyUsage)
            .isInstanceOf(GemPkiException.class)
            .hasMessageContaining(ErrorCode.SE_1017.getErrorMessage(productType));
    }

    @Test
    void multipleCertificateProfilesMultipleCertTypesInEe() throws IOException {
        final X509Certificate eeMultipleCertTypes = CertificateProvider.getX509Certificate(
            "src/test/resources/certificates/GEM.SMCB-CA9/Aschoffsche_Apotheke_twoCertTypes.pem");
        assertDoesNotThrow(() -> buildCertificateProfileVerifier(FILE_NAME_TSL_DEFAULT,
            certificateProfile, eeMultipleCertTypes).verifyCertificateType());
    }

    @SneakyThrows
    @Test
    void verifyCertificateProfileMissingPolicyId() throws IOException {
        final X509Certificate missingPolicyId = CertificateProvider
            .getX509Certificate("src/test/resources/certificates/GEM.SMCB-CA10/invalid/DrMedGunther_missing-policyId.pem");
        final var verifier = buildCertificateProfileVerifier(FILE_NAME_TSL_DEFAULT, certificateProfile, missingPolicyId);
        assertThatThrownBy(verifier::verifyCertificateType)
            .isInstanceOf(GemPkiException.class)
            .hasMessageContaining(ErrorCode.SE_1033.getErrorMessage(productType));
    }

    @SneakyThrows
    @Test
    void verifyCertificateProfileMissingCertType() throws IOException {
        final X509Certificate missingCertType = CertificateProvider
            .getX509Certificate("src/test/resources/certificates/GEM.SMCB-CA10/invalid/DrMedGunther_missing-certificate-type.pem");
        final var verifier = buildCertificateProfileVerifier(FILE_NAME_TSL_DEFAULT, certificateProfile, missingCertType);
        assertThatThrownBy(verifier::verifyCertificateType)
            .isInstanceOf(GemPkiException.class)
            .hasMessageContaining(ErrorCode.SE_1033.getErrorMessage(productType));
    }

    @SneakyThrows
    @Test
    void verifyCertificateProfileInvalidCertType() throws IOException {
        final X509Certificate invalidCertType = CertificateProvider
            .getX509Certificate("src/test/resources/certificates/GEM.SMCB-CA10/invalid/DrMedGunther_invalid-certificate-type.pem");
        final var verifier = buildCertificateProfileVerifier(FILE_NAME_TSL_DEFAULT, certificateProfile, invalidCertType);
        assertThatThrownBy(verifier::verifyCertificateType)
            .isInstanceOf(GemPkiException.class)
            .hasMessageContaining(ErrorCode.SE_1018.getErrorMessage(productType));
    }

    @SneakyThrows
    @Test
    void verifyCertificateProfileWrongServiceInfoExtInTsl() {
        final String tslAltCaWrongServiceExtension = "tsls/defect/TSL_defect_altCA_wrong-srvInfoExt.xml";
        final var verifier = buildCertificateProfileVerifier(tslAltCaWrongServiceExtension, certificateProfile, validX509EeCertAltCa);
        assertThatThrownBy(verifier::verifyCertificateType)
            .isInstanceOf(GemPkiException.class)
            .hasMessageContaining(ErrorCode.SE_1061.getErrorMessage(productType));
    }

}
