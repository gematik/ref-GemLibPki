/*
 * Copyright (c) 2023 gematik GmbH
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

package de.gematik.pki.gemlibpki.tsl;

import de.gematik.pki.gemlibpki.exception.GemPkiRuntimeException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Optional;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.apache.xml.security.signature.XMLSignatureException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import xades4j.XAdES4jException;
import xades4j.providers.CertificateValidationProvider;
import xades4j.providers.impl.PKIXCertificateValidationProvider;
import xades4j.verification.XAdESVerificationResult;
import xades4j.verification.XadesVerificationProfile;
import xades4j.verification.XadesVerifier;

/** Class to validate a TSL by checking its signature */
@Slf4j
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class TslValidator {

  /**
   * Check signature of given TSL (mathematically and against trust anchor).
   *
   * @param tsl the tsl to check
   * @param trustAnchor the tsl trust anchor certificate (issuer of signing certificate)
   * @return true if signature is valid, otherwise false
   */
  public static boolean checkSignature(
      @NonNull final Document tsl, @NonNull final X509Certificate trustAnchor) {
    try {
      final Optional<XAdESVerificationResult> xvr = getVerificationResult(tsl, trustAnchor);
      if (xvr.isEmpty()) {
        return false;
      }

      return xvr.get().getXmlSignature().checkSignatureValue(xvr.get().getValidationCertificate());
    } catch (final XAdES4jException
        | NoSuchAlgorithmException
        | XMLSignatureException
        | NoSuchProviderException
        | CertificateException
        | KeyStoreException e) {
      log.info("TSL signature verification failed.");
      return false;
    } catch (final IOException e) {
      throw new GemPkiRuntimeException("TSL signature verification failed.", e);
    }
  }

  /**
   * Check signature of given TSL (mathematically and against trust anchor).
   *
   * @param tsl the tsl to check
   * @param trustAnchor the tsl trust anchor certificate (issuer of signing certificate)
   * @return true if signature is valid, otherwise false
   */
  public static boolean checkSignature(
      final byte @NonNull [] tsl, @NonNull final X509Certificate trustAnchor) {
    return checkSignature(TslConverter.bytesToDoc(tsl), trustAnchor);
  }

  private static Optional<XAdESVerificationResult> getVerificationResult(
      final Document tsl, final X509Certificate trustAnchor)
      throws XAdES4jException, NoSuchAlgorithmException, NoSuchProviderException,
          CertificateException, KeyStoreException, IOException {
    final KeyStore trustAnchorStore = KeyStore.getInstance(KeyStore.getDefaultType());
    trustAnchorStore.load(null);
    trustAnchorStore.setCertificateEntry(
        trustAnchor.getSubjectX500Principal().getName(), trustAnchor);
    final CertificateValidationProvider certValidator =
        PKIXCertificateValidationProvider.builder(trustAnchorStore)
            .certPathBuilderProvider(BouncyCastleProvider.PROVIDER_NAME)
            .checkRevocation(false)
            .build();
    final XadesVerificationProfile profile = new XadesVerificationProfile(certValidator);
    final XadesVerifier verifier = profile.newVerifier();
    final Element signature = TslUtils.getSignature(tsl);
    if (signature == null) {
      return Optional.empty();
    }
    return Optional.of(verifier.verify(signature, null));
  }
}
