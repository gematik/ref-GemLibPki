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

package de.gematik.pki.tsl;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import de.gematik.pki.error.ErrorCode;
import de.gematik.pki.exception.GemPkiException;
import de.gematik.pki.utils.CertificateProvider;
import de.gematik.pki.utils.ResourceReader;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Optional;
import lombok.SneakyThrows;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class TspInformationProviderTest {

    private static final String FILE_NAME_TSL_DEFAULT = "tsls/valid/TSL_default.xml";
    private static final String FILE_NAME_TSL_ALT_CA_BROKEN = "tsls/defect/TSL_defect_altCA_broken.xml";
    private String productType;
    private TspInformationProvider tspInformationProvider;
    private X509Certificate VALID_X509_EE_CERT;
    private X509Certificate VALID_X509_EE_CERT_ALT_CA;


    @BeforeEach
    @SneakyThrows
    void setUp() {
        productType = "IDP";
        final Optional<TrustStatusListType> tsl = TslReader
            .getTsl(ResourceReader.getFilePathFromResources(FILE_NAME_TSL_DEFAULT));
        final TslInformationProvider tslInformationProvider = new TslInformationProvider(tsl.orElseThrow());
        tspInformationProvider = new TspInformationProvider(tslInformationProvider.getTspServices(),
            productType);
        VALID_X509_EE_CERT = CertificateProvider
            .getX509Certificate("src/test/resources/certificates/GEM.SMCB-CA10/valid/DrMedGunther.pem");
        VALID_X509_EE_CERT_ALT_CA = CertificateProvider.getX509Certificate(
            "src/test/resources/certificates/GEM.SMCB-CA33/DrMedGuntherKZV.pem");
    }

    @SneakyThrows
    @Test
    void generateTspServiceSubsetValidEE() {
        assertDoesNotThrow(() -> tspInformationProvider
            .getTspServiceSubset(VALID_X509_EE_CERT));
    }

    @SneakyThrows
    @Test
    void generateTspServiceSubsetIssuerCertificateExtractionError() {
        final Optional<TrustStatusListType> tslAltCaBroken = TslReader
            .getTsl(ResourceReader.getFilePathFromResources(FILE_NAME_TSL_ALT_CA_BROKEN));
        assertThatThrownBy(
            () -> new TspInformationProvider(
                new TslInformationProvider(tslAltCaBroken.orElseThrow()).getTspServices(),
                productType)
                .getTspServiceSubset(VALID_X509_EE_CERT_ALT_CA))
            .isInstanceOf(GemPkiException.class)
            .hasMessageContaining(ErrorCode.TE_1002.name());
    }

    @Test
    void generateTspServiceSubsetIssuerCertificateMissing() {
        assertThatThrownBy(() -> tspInformationProvider.getTspServiceSubset(VALID_X509_EE_CERT_ALT_CA))
            .isInstanceOf(GemPkiException.class)
            .hasMessageContaining(ErrorCode.TE_1027.name());
    }

    @Test
    void generateTspServiceSubsetMissingAki() throws IOException {
        final X509Certificate invalidx509EeCert = CertificateProvider.getX509Certificate(
            "src/test/resources/certificates/GEM.SMCB-CA10/invalid/DrMedGunther_missing-authorityKeyId.pem");
        assertThatThrownBy(() -> tspInformationProvider.getTspServiceSubset(invalidx509EeCert))
            .isInstanceOf(GemPkiException.class)
            .hasMessageContaining(ErrorCode.SE_1023.getErrorMessage(productType));
    }

    @Test
    void generateTspServiceSubsetServiceSupplyPointValid() throws GemPkiException {
        assertThat(tspInformationProvider.getTspServiceSubset(VALID_X509_EE_CERT).getServiceSupplyPoint())
            .isEqualTo("http://ocsp-sim01-test.gem.telematik-test:8080/ocsp/OCSPSimulator/TSL_default-seq1");
    }

    @Test
    void generateTspServiceSubsetServiceSupplyPointMissing() throws GemPkiException, IOException {
        final Optional<TrustStatusListType> tslAltCaMissingSsp = TslReader
            .getTsl(ResourceReader.getFilePathFromResources("tsls/defect/TSL_defect_altCA_missingSsp.xml"));

        assertThatThrownBy(() -> new TspInformationProvider(
            new TslInformationProvider(tslAltCaMissingSsp.orElseThrow()).getTspServices(),
            productType).getTspServiceSubset(VALID_X509_EE_CERT_ALT_CA).getServiceSupplyPoint())
            .isInstanceOf(GemPkiException.class)
            .hasMessageContaining(ErrorCode.TE_1026.getErrorMessage(productType));
    }
}
