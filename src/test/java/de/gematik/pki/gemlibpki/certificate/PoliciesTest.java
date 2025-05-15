/*
 * Copyright (Date see Readme), gematik GmbH
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

package de.gematik.pki.gemlibpki.certificate;

import static de.gematik.pki.gemlibpki.TestConstants.MISSING_CERT_TYPE;
import static de.gematik.pki.gemlibpki.TestConstants.VALID_X509_EE_CERT_SMCB;
import static de.gematik.pki.gemlibpki.utils.TestUtils.assertNonNullParameter;
import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import org.junit.jupiter.api.Test;

class PoliciesTest {

  @Test
  void getPolicyOids() throws IOException {
    assertThat(new Policies(VALID_X509_EE_CERT_SMCB).getPolicyOids())
        .contains(CertificateType.CERT_TYPE_SMC_B_AUT.getOid());
  }

  @Test
  void policiesCertNull() {
    assertNonNullParameter(() -> new Policies(null), "x509EeCert");
  }

  @Test
  void getPolicyOidsEmpty() throws IOException {
    assertThat(new Policies(MISSING_CERT_TYPE).getPolicyOids()).isEmpty();
  }
}
