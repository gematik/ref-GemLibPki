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

package de.gematik.pki.gemlibpki.certificate;

import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;
import lombok.NonNull;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.cert.X509CertificateHolder;

/**
 * Class to abstract the policy extension of a certificate. This class works with a parameterized
 * variable for the certificate in its constructor.
 */
public class Policies {

  private static final String FILTER_OUT_NOT_DESIRED_POLICY_OID = "1.2.276.0.76.4.163";
  private final PolicyInformation[] policyExtensions;

  public Policies(@NonNull final X509Certificate x509EeCert)
      throws CertificateEncodingException, IOException {
    policyExtensions =
        CertificatePolicies.fromExtensions(
                new X509CertificateHolder(x509EeCert.getEncoded()).getExtensions())
            .getPolicyInformation();
  }

  /**
   * Reading policy oid's
   *
   * @return Non duplicate list of policy oid's belonging to class member policyExtensions. Filters
   *     out non desired oid's.
   */
  public Set<String> getPolicyOids() {
    return Arrays.stream(policyExtensions)
        .filter(i -> !i.getPolicyIdentifier().getId().equals(FILTER_OUT_NOT_DESIRED_POLICY_OID))
        .map(policyInformation -> policyInformation.getPolicyIdentifier().getId())
        .collect(Collectors.toSet());
  }
}
