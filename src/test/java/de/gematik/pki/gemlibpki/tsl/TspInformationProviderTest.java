/*
 * Copyright 2025, gematik GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * ******
 *
 * For additional notes and disclaimer from gematik and in case of changes by gematik find details in the "Readme" file.
 */

package de.gematik.pki.gemlibpki.tsl;

import static de.gematik.pki.gemlibpki.TestConstants.VALID_X509_EE_CERT_ALT_CA;
import static de.gematik.pki.gemlibpki.TestConstants.VALID_X509_EE_CERT_SMCB;
import static de.gematik.pki.gemlibpki.utils.TestUtils.assertNonNullParameter;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import de.gematik.pki.gemlibpki.error.ErrorCode;
import de.gematik.pki.gemlibpki.exception.GemPkiException;
import de.gematik.pki.gemlibpki.utils.TestUtils;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;
import java.security.cert.X509Certificate;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class TspInformationProviderTest {

  private String productType;
  private TspInformationProvider tspInformationProvider;

  @BeforeEach
  void setUp() {
    productType = "IDP";
    final TslInformationProvider tslInformationProvider =
        new TslInformationProvider(TestUtils.getDefaultTslUnsigned());
    tspInformationProvider =
        new TspInformationProvider(tslInformationProvider.getTspServices(), productType);
  }

  @Test
  void generateTspServiceSubsetValidEE() {
    assertDoesNotThrow(
        () -> tspInformationProvider.getIssuerTspServiceSubset(VALID_X509_EE_CERT_SMCB));
  }

  @Test
  void getIssuerTspServiceSubsetNonNull() {
    assertNonNullParameter(
        () -> tspInformationProvider.getIssuerTspServiceSubset(null), "x509EeCert");
    assertNonNullParameter(() -> tspInformationProvider.getIssuerTspService(null), "x509EeCert");
  }

  @Test
  void generateTspServiceSubsetIssuerCertificateExtractionError() {
    final TrustStatusListType tslAltCaBroken =
        TestUtils.getTslUnsigned("tsls/ecc/defect/TSL_defect_altCA_broken.xml");
    assertThatThrownBy(
            () ->
                new TspInformationProvider(
                        new TslInformationProvider(tslAltCaBroken).getTspServices(), productType)
                    .getIssuerTspServiceSubset(VALID_X509_EE_CERT_ALT_CA))
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.TE_1002_TSL_CERT_EXTRACTION_ERROR.getErrorMessage(productType));
  }

  @Test
  void generateTspServiceSubsetIssuerCertificateMissing() {
    assertThatThrownBy(
            () -> tspInformationProvider.getIssuerTspServiceSubset(VALID_X509_EE_CERT_ALT_CA))
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.TE_1027_CA_CERT_MISSING.getErrorMessage(productType));
  }

  @Test
  void generateTspServiceSubsetMissingAki() {
    final X509Certificate invalidx509EeCert =
        TestUtils.readCert("GEM.SMCB-CA10/invalid/DrMedGunther_missing-authorityKeyId.pem");
    assertThatThrownBy(() -> tspInformationProvider.getIssuerTspServiceSubset(invalidx509EeCert))
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.SE_1023_AUTHORITYKEYID_DIFFERENT.getErrorMessage(productType));
  }

  @Test
  void generateTspServiceSubsetServiceSupplyPointValid() throws GemPkiException {
    assertThat(
            tspInformationProvider
                .getIssuerTspServiceSubset(VALID_X509_EE_CERT_SMCB)
                .getServiceSupplyPoint())
        .isEqualTo("http://127.0.0.1:8083/ocsp/60");
  }

  @Test
  void generateTspServiceSubsetServiceSupplyPointMissing() {
    final TrustStatusListType tslAltCaMissingSsp =
        TestUtils.getTslUnsigned("tsls/ecc/defect/TSL_defect_altCA_missingSsp.xml");

    assertThatThrownBy(
            () ->
                new TspInformationProvider(
                        new TslInformationProvider(tslAltCaMissingSsp).getTspServices(),
                        productType)
                    .getIssuerTspServiceSubset(VALID_X509_EE_CERT_ALT_CA))
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.TE_1026_SERVICESUPPLYPOINT_MISSING.getErrorMessage(productType));
  }

  @Test
  void generateTspServiceSubsetServiceSupplyPointMissing2() {
    final TrustStatusListType tslAltCaMissingSsp =
        TestUtils.getTslUnsigned("tsls/ecc/defect/TSL_defect_altCA_missingSsp2.xml");

    assertThatThrownBy(
            () ->
                new TspInformationProvider(
                        new TslInformationProvider(tslAltCaMissingSsp).getTspServices(),
                        productType)
                    .getIssuerTspServiceSubset(VALID_X509_EE_CERT_ALT_CA))
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.TE_1026_SERVICESUPPLYPOINT_MISSING.getErrorMessage(productType));
  }

  @Test
  void verifyGetIssuerTspService() {
    assertDoesNotThrow(() -> tspInformationProvider.getIssuerTspService(VALID_X509_EE_CERT_SMCB));
  }
}
