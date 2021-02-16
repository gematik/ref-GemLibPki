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
import de.gematik.pki.tsl.TspService;
import de.gematik.pki.utils.CertificateProvider;
import de.gematik.pki.utils.VariableSource;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.List;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ArgumentsSource;


@Slf4j(topic = "UNITTEST")
class CertificateVerifierTest {

    private CertificateVerifier certificateVerifier;
    private X509Certificate VALID_EE_CERT;
    private static final String FILE_NAME_TSL_DEFAULT = "tsls/valid/TSL_default.xml";
    private final CertificateProfile certificateProfile = CertificateProfile.C_HCI_AUT_ECC;
    private final List<CertificateProfile> certificateProfiles = List.of(certificateProfile);

    @BeforeEach
    void setUp() throws IOException {
        VALID_EE_CERT = CertificateProvider
            .getX509Certificate("src/test/resources/certificates/GEM.SMCB-CA10/valid/DrMedGunther.pem");
        certificateVerifier = buildCertificateChecker(certificateProfiles);
    }

    private CertificateVerifier buildCertificateChecker(final List<CertificateProfile> certificateProfiles) {

        final List<TspService> tspServiceList = new TslInformationProvider(
            new TslReader().getTrustServiceStatusList(FILE_NAME_TSL_DEFAULT).orElseThrow())
            .getTspServices();

        return CertificateVerifier.builder()
            .productType("IDP")
            .tspServiceList(tspServiceList)
            .certificateProfiles(certificateProfiles)
            .build();
    }

    @Test
    void verifyPerformTucPki18ChecksValid() {
        assertDoesNotThrow(() -> certificateVerifier.performTucPki18Checks(VALID_EE_CERT));
    }

    @Test
    void verifyEgkAutEccCertValid() {
        assertDoesNotThrow(() -> buildCertificateChecker(List.of(CertificateProfile.C_CH_AUT_ECC))
            .performTucPki18Checks(CertificateProvider
                .getX509Certificate("src/test/resources/certificates/GEM.EGK-CA10/JunaFuchs.pem")));
    }

    @Test
    void verifyHbaAutEccCertValid() {
        assertDoesNotThrow(() -> buildCertificateChecker(List.of(CertificateProfile.C_HP_AUT_ECC))
            .performTucPki18Checks(CertificateProvider
                .getX509Certificate("src/test/resources/certificates/GEM.HBA-CA13/GüntherOtís.pem")));
    }

    @Test
    void verifySmcbAutRsaCertValid() {
        assertDoesNotThrow(() -> buildCertificateChecker(List.of(CertificateProfile.C_HCI_AUT_RSA))
            .performTucPki18Checks(CertificateProvider
                .getX509Certificate("src/test/resources/certificates/GEM.SMCB-CA24-RSA/AschoffscheApotheke.pem")));
    }

    @Test
    void verifyNotEveryKeyUsagePresent() {
        assertThatThrownBy(() -> certificateVerifier.performTucPki18Checks(CertificateProvider
            .getX509Certificate("src/test/resources/certificates/GEM.SMCB-CA24-RSA/AschoffscheApotheke.pem")))
            .isInstanceOf(GemPkiException.class)
            .hasMessageContaining(ErrorCode.SE_1016.name());
    }

    @Test
    void multipleCertificateProfiles_shouldSelectCorrectOne() {
        assertDoesNotThrow(() -> buildCertificateChecker(List.of(
            CertificateProfile.C_TSL_SIG_ECC, CertificateProfile.C_HCI_AUT_RSA, CertificateProfile.C_HCI_AUT_ECC
        )).performTucPki18Checks(VALID_EE_CERT));
    }

    @Test
    void multipleCertificateProfiles_shouldThrowKeyUsageError() throws IOException {
        final X509Certificate eeWrongKeyUsage = CertificateProvider
            .getX509Certificate(
                "src/test/resources/certificates/GEM.SMCB-CA10/invalid/DrMedGunther_invalid-keyusage.pem");
        assertThatThrownBy(
            () -> buildCertificateChecker(List.of(CertificateProfile.C_HCI_AUT_ECC, CertificateProfile.C_HP_AUT_ECC
            )).performTucPki18Checks(eeWrongKeyUsage))
            .isInstanceOf(GemPkiException.class)
            .hasMessageContaining(ErrorCode.SE_1016.name());
    }

    @Test
    void multipleCertificateProfiles_shouldThrowCertTypeError() throws IOException {
        final X509Certificate eeWrongKeyUsage = CertificateProvider
            .getX509Certificate(
                "src/test/resources/certificates/GEM.SMCB-CA10/invalid/DrMedGunther_invalid-certificate-type.pem");
        assertThatThrownBy(
            () -> buildCertificateChecker(List.of(CertificateProfile.C_HCI_AUT_ECC, CertificateProfile.C_HP_AUT_ECC
            )).performTucPki18Checks(eeWrongKeyUsage))
            .isInstanceOf(GemPkiException.class)
            .hasMessageContaining(ErrorCode.SE_1018.name());
    }

    @Test
    void verifyCertNull() {
        assertThatThrownBy(() -> certificateVerifier.performTucPki18Checks(null))
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("x509EeCert");
    }

    @Test
    void verifyCertProfilesNull() {
        assertThatThrownBy(() -> buildCertificateChecker(null))
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("certificateProfiles");
    }

    @Test
    void verifyCertProfilesEmpty() {
        assertThatThrownBy(() -> buildCertificateChecker(List.of()).performTucPki18Checks(VALID_EE_CERT))
            .isInstanceOf(GemPkiException.class)
            .hasMessageContaining(ErrorCode.UNKNOWN.name());
    }

    @ParameterizedTest
    @ArgumentsSource(CertificateProvider.class)
    @VariableSource(value = "invalid")
    void verifyPerformTucPki18ChecksInvalid(final X509Certificate cert) {
        assertThatThrownBy(() -> certificateVerifier.performTucPki18Checks(cert))
            .as("Test invalid certificates")
            .isInstanceOf(GemPkiException.class);
    }

}
