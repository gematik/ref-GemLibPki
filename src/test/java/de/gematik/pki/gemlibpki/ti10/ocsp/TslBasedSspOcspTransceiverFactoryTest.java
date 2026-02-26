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

import static de.gematik.pki.gemlibpki.commons.TestConstants.FILE_NAME_TSL_ECC_DEFAULT;
import static de.gematik.pki.gemlibpki.commons.TestConstants.PRODUCT_TYPE;
import static de.gematik.pki.gemlibpki.commons.TestConstants.VALID_X509_EE_CERT_SMCB;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import de.gematik.pki.gemlibpki.commons.exception.GemPkiException;
import de.gematik.pki.gemlibpki.commons.ocsp.OcspTransceiver;
import de.gematik.pki.gemlibpki.commons.tsl.TslInformationProvider;
import de.gematik.pki.gemlibpki.commons.tsl.TspInformationProvider;
import de.gematik.pki.gemlibpki.commons.tsl.TspService;
import de.gematik.pki.gemlibpki.commons.tsl.TspServiceSubset;
import de.gematik.pki.gemlibpki.commons.utils.TestUtils;
import java.security.cert.X509Certificate;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class TslBasedSspOcspTransceiverFactoryTest {

  private final X509Certificate eeCert = VALID_X509_EE_CERT_SMCB;
  private TslBasedSspOcspTransceiverFactory factory;

  @BeforeEach
  void setup() throws GemPkiException {

    final List<TspService> tspServices =
        new TslInformationProvider(TestUtils.getTslUnsigned(FILE_NAME_TSL_ECC_DEFAULT))
            .getTspServices();
    final TspServiceSubset tspServiceSubset =
        new TspInformationProvider(tspServices, PRODUCT_TYPE).getIssuerTspServiceSubset(eeCert);

    final int TIMEOUT = 5;
    final boolean TOLERATE_FAILURE = false;
    factory =
        new TslBasedSspOcspTransceiverFactory(PRODUCT_TYPE, tspServices, TIMEOUT, TOLERATE_FAILURE);
  }

  @Test
  void shouldCreateTransceiverWithCorrectValues() throws Exception {
    final OcspTransceiver transceiver = factory.create(eeCert);
    assertNotNull(transceiver);
  }
}
