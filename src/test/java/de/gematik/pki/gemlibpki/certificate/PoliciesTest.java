/*
 * Copyright 2023 gematik GmbH
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
 */

package de.gematik.pki.gemlibpki.certificate;

import static de.gematik.pki.gemlibpki.utils.TestUtils.assertNonNullParameter;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import de.gematik.pki.gemlibpki.utils.TestUtils;
import java.io.IOException;
import java.security.cert.X509Certificate;
import org.junit.jupiter.api.Test;

class PoliciesTest {

  @Test
  void getPolicyOids() throws IOException {
    final X509Certificate policyOids = TestUtils.readCert("GEM.SMCB-CA10/valid/DrMedGunther.pem");
    assertThat(new Policies(policyOids).getPolicyOids())
        .contains(CertificateType.CERT_TYPE_SMC_B_AUT.getOid());
  }

  @Test
  void policiesCertNull() {
    assertNonNullParameter(() -> new Policies(null), "x509EeCert");
  }

  @Test
  void getPolicyOidsMissing() {
    final X509Certificate missingPolicyId =
        TestUtils.readCert("GEM.SMCB-CA10/invalid/DrMedGunther_missing-policyId.pem");
    assertThatThrownBy(() -> new Policies(missingPolicyId))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void getPolicyOidsEmpty() throws IOException {
    final X509Certificate emptyPolicyId =
        TestUtils.readCert("GEM.SMCB-CA10/invalid/DrMedGunther_missing-certificate-type.pem");
    assertThat(new Policies(emptyPolicyId).getPolicyOids()).isEmpty();
  }
}
