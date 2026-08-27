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

package de.gematik.pki.gemlibpki.ti10.ocsp;

import static de.gematik.pki.gemlibpki.commons.TestConstants.PRODUCT_TYPE;
import static de.gematik.pki.gemlibpki.commons.TestConstantsQes.VALID_ISSUER_CERT_QES_DEFAULT_CA;
import static de.gematik.pki.gemlibpki.commons.TestConstantsQes.VALID_X509_EE_CERT_QES;
import static de.gematik.pki.gemlibpki.commons.TestConstantsQes.X509_EE_CERT_QES_NO_OCSP_IN_TSL;
import static org.assertj.core.api.Assertions.assertThat;

import de.gematik.pki.gemlibpki.commons.tsl.TslInformationProvider;
import de.gematik.pki.gemlibpki.commons.utils.TestUtils;
import org.junit.jupiter.api.Test;

class TucPki030OcspTransceiverFactoryTest {

  @Test
  void determineOcspSsp_whenQesCertificateHasOcspServiceInTsl_thenReturnsTslOcspUrl()
      throws Exception {
    final TucPki030OcspTransceiverFactory factory =
        new TucPki030OcspTransceiverFactory(
            PRODUCT_TYPE,
            VALID_ISSUER_CERT_QES_DEFAULT_CA,
            new TslInformationProvider(TestUtils.getDefaultTslUnsignedNonQes()).getTspServices(),
            10,
            false);
    assertThat(factory.determineOcspSsp(VALID_X509_EE_CERT_QES))
        .isEqualTo("http://ehca-testref.komp-ca.telematik-test:8080/status/ecc-qocsp");
  }

  @Test
  void
      determineOcspSsp_whenTslOcspServiceIsMissing_variantOtherTsl_thenReturnsAuthorityInformationAccessUrl()
          throws Exception {
    final TucPki030OcspTransceiverFactory factory =
        new TucPki030OcspTransceiverFactory(
            PRODUCT_TYPE,
            VALID_ISSUER_CERT_QES_DEFAULT_CA,
            new TslInformationProvider(TestUtils.getTslUnsigned("tsls/nonqes/TI/TSL-PU.xml"))
                .getTspServices(),
            10,
            false);
    final String ocspUrl = factory.determineOcspSsp(VALID_X509_EE_CERT_QES);
    assertThat(ocspUrl).isEqualTo("http://ehca.gematik.de/ecc-qocsp");
  }

  @Test
  void
      determineOcspSsp_whenTslOcspServiceIsMissing_variantOtherAia_thenReturnsAuthorityInformationAccessUrl()
          throws Exception {
    final TucPki030OcspTransceiverFactory factory =
        new TucPki030OcspTransceiverFactory(
            PRODUCT_TYPE,
            VALID_ISSUER_CERT_QES_DEFAULT_CA,
            new TslInformationProvider(TestUtils.getDefaultTslUnsignedNonQes()).getTspServices(),
            10,
            false);
    final String ocspUrl = factory.determineOcspSsp(X509_EE_CERT_QES_NO_OCSP_IN_TSL);
    assertThat(ocspUrl).isEqualTo("http://ehca.gematik.de/ecc");
  }
}
