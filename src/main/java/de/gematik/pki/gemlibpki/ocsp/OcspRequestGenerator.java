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

package de.gematik.pki.gemlibpki.ocsp;

import static de.gematik.pki.gemlibpki.utils.GemlibPkiUtils.setBouncyCastleProvider;

import de.gematik.pki.gemlibpki.exception.GemPkiRuntimeException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import lombok.AccessLevel;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

/** Class to support OCSP related data */
@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
public final class OcspRequestGenerator {

  /**
   * Generates an OCSP request using BouncyCastle.
   *
   * @param x509EeCert end-entity certificate
   * @param x509IssuerCert issuer of end-entity certificate
   * @return OCSP request for a single certificate
   */
  public static OCSPReq generateSingleOcspRequest(
      @NonNull final X509Certificate x509EeCert, @NonNull final X509Certificate x509IssuerCert) {
    setBouncyCastleProvider();
    final JcaDigestCalculatorProviderBuilder digestCalculatorProviderBuilder =
        new JcaDigestCalculatorProviderBuilder();

    try {
      final DigestCalculatorProvider digestCalculatorProvider =
          digestCalculatorProviderBuilder.build();

      final DigestCalculator digestCalculator =
          digestCalculatorProvider.get(CertificateID.HASH_SHA1);

      final CertificateID id =
          new CertificateID(
              digestCalculator,
              new JcaX509CertificateHolder(x509IssuerCert),
              x509EeCert.getSerialNumber());

      final OCSPReqBuilder ocspReqBuilder = new OCSPReqBuilder();
      ocspReqBuilder.addRequest(id);
      return ocspReqBuilder.build();
    } catch (final OperatorCreationException | CertificateEncodingException | OCSPException e) {
      throw new GemPkiRuntimeException("Generieren des OCSP Requests fehlgeschlagen.", e);
    }
  }
}
