/*
 * Copyright (Change Date see Readme), gematik GmbH
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
 * *******
 *
 * For additional notes and disclaimer from gematik and in case of changes by gematik find details in the "Readme" file.
 */

package de.gematik.pki.gemlibpki.commons.tsl;

import static de.gematik.pki.gemlibpki.commons.utils.CertReader.readX509;
import static de.gematik.pki.gemlibpki.commons.utils.TestUtils.assertNonNullParameter;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import de.gematik.pki.gemlibpki.commons.utils.TestUtils;
import eu.europa.esig.trustedlist.jaxb.tsl.TSPServiceType;
import java.security.cert.X509Certificate;
import org.junit.jupiter.api.Test;

class TspServiceTest {

  @Test
  void toString_whenServiceIsNonQes_thenContainsTestOnly() {
    final TspService tspService =
        new TslInformationProvider(TestUtils.getDefaultTslUnsignedNonQes())
            .getTspServices()
            .getFirst();
    assertThat(tspService.toString()).contains("TEST-ONLY");
  }

  @Test
  void toString_whenServiceIsQes_thenContainsBaPrefix() {
    final TspService tspService =
        new TslInformationProvider(TestUtils.getDefaultTslUnsignedQes())
            .getTspServices()
            .getFirst();
    assertThat(tspService.toString()).contains("BA-");
  }

  @Test
  void getFirstX509Certificate_whenServiceContainsCertificate_thenReturnsCertificate() {
    final TspService tspService = getFirstTspService();

    assertThat(tspService.getFirstX509Certificate())
        .isEqualTo(getCertificateFromTspService(tspService));
  }

  @Test
  void getFirstX509Certificate_whenServiceIsMalformed_thenThrowsException() {
    assertThatThrownBy(() -> new TspService(new TSPServiceType()).getFirstX509Certificate())
        .isInstanceOf(NullPointerException.class);
  }

  @Test
  void hasServiceTypeIdentifier_whenArgumentIsNull_thenThrowsOnNullParameter() {
    assertNonNullParameter(
        () -> getFirstTspService().hasServiceTypeIdentifier(null), "serviceTypeIdentifier");
  }

  @Test
  void hasServiceTypeIdentifier_whenIdentifierMatches_thenReturnsTrue() {
    assertThat(getOcspTspService().hasServiceTypeIdentifier(TslConstants.STI_OCSP)).isTrue();
  }

  @Test
  void hasServiceTypeIdentifier_whenIdentifierDoesNotMatch_thenReturnsFalse() {
    assertThat(getOcspTspService().hasServiceTypeIdentifier(TslConstants.STI_QC)).isFalse();
  }

  @Test
  void isOcspService_whenServiceIsOcsp_thenReturnsTrue() {
    assertThat(getOcspTspService().isOcspService()).isTrue();
  }

  @Test
  void isOcspService_whenServiceIsNotOcsp_thenReturnsFalse() {
    assertThat(getQcTspService().isOcspService()).isFalse();
  }

  @Test
  void containsCertificate_whenArgumentIsNull_thenThrowsOnNullParameter() {
    assertNonNullParameter(() -> getFirstTspService().containsCertificate(null), "certificate");
  }

  @Test
  void containsCertificate_whenServiceContainsCertificate_thenReturnsTrue() {
    final TspService tspService = getFirstTspService();
    final X509Certificate certificate = getCertificateFromTspService(tspService);

    assertThat(tspService.containsCertificate(certificate)).isTrue();
  }

  @Test
  void containsCertificate_whenServiceDoesNotContainCertificate_thenReturnsFalse() {
    final X509Certificate otherCertificate = TestUtils.readCertQes("ocsp/OcspSigner57Qes.pem");

    assertThat(getFirstTspService().containsCertificate(otherCertificate)).isFalse();
  }

  @Test
  void containsCertificate_whenServiceIsMalformed_thenReturnsFalse() {
    final TspService tspService = new TspService(new TSPServiceType());

    assertThat(tspService.containsCertificate(getCertificateFromTspService(getFirstTspService())))
        .isFalse();
  }

  private TspService getFirstTspService() {
    return new TslInformationProvider(TestUtils.getDefaultTslUnsignedNonQes())
        .getTspServices().stream()
            .filter(
                tspService ->
                    tspService.getTspServiceType().getServiceInformation() != null
                        && tspService
                                .getTspServiceType()
                                .getServiceInformation()
                                .getServiceDigitalIdentity()
                            != null
                        && tspService
                                .getTspServiceType()
                                .getServiceInformation()
                                .getServiceDigitalIdentity()
                                .getDigitalId()
                            != null
                        && !tspService
                            .getTspServiceType()
                            .getServiceInformation()
                            .getServiceDigitalIdentity()
                            .getDigitalId()
                            .isEmpty()
                        && tspService
                                .getTspServiceType()
                                .getServiceInformation()
                                .getServiceDigitalIdentity()
                                .getDigitalId()
                                .getFirst()
                                .getX509Certificate()
                            != null)
            .findFirst()
            .orElseThrow();
  }

  private TspService getOcspTspService() {
    return new TslInformationProvider(TestUtils.getDefaultTslUnsignedNonQes())
        .getTspServices().stream()
            .filter(tspService -> tspService.hasServiceTypeIdentifier(TslConstants.STI_OCSP))
            .findFirst()
            .orElseThrow();
  }

  private TspService getQcTspService() {
    return new TslInformationProvider(TestUtils.getDefaultTslUnsignedQes())
        .getTspServices().stream()
            .filter(tspService -> tspService.hasServiceTypeIdentifier(TslConstants.STI_QC))
            .findFirst()
            .orElseThrow();
  }

  private X509Certificate getCertificateFromTspService(final TspService tspService) {
    return readX509(
        tspService
            .getTspServiceType()
            .getServiceInformation()
            .getServiceDigitalIdentity()
            .getDigitalId()
            .getFirst()
            .getX509Certificate());
  }
}
