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

import de.gematik.pki.gemlibpki.commons.exception.GemPkiRuntimeException;
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
import org.apache.xml.security.Init;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.signature.XMLSignatureException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
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
   * Checks the signature of a given TSL (mathematically and against a given trust anchor).
   *
   * @param tslToVerify the tsl to check
   * @param trustAnchor the tsl trust anchor certificate (issuer of signing certificate)
   * @return true if the signature is valid, otherwise false
   */
  public static boolean checkNonQesTslSignatureWithTrustAnchor(
      final byte @NonNull [] tslToVerify, @NonNull final X509Certificate trustAnchor) {
    return checkNonQesTslSignatureWithTrustAnchor(
        TslConverter.bytesToDoc(tslToVerify), trustAnchor);
  }

  /**
   * Checks the signature of a given TSL (mathematically and against a given trust anchor).
   *
   * @param tslToVerify the tsl to check
   * @param trustAnchor the tsl trust anchor certificate (issuer of signing certificate)
   * @return true if the signature is valid, otherwise false
   */
  public static boolean checkNonQesTslSignatureWithTrustAnchor(
      @NonNull final Document tslToVerify, @NonNull final X509Certificate trustAnchor) {
    try {
      final Optional<XAdESVerificationResult> xvr = getVerificationResult(tslToVerify, trustAnchor);
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

  private static Optional<XAdESVerificationResult> getVerificationResult(
      final Document tsl, final X509Certificate trustAnchor)
      throws XAdES4jException,
          NoSuchAlgorithmException,
          NoSuchProviderException,
          CertificateException,
          KeyStoreException,
          IOException {
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

  /**
   * Validates the signature of a given QES TSL (mathematically). The signer's public key is taken
   * from the signer certificate in the TSL signature element.
   *
   * @param tsl the tsl to check
   * @return true if the signature is valid, otherwise false
   */
  public static boolean checkQesTslSignatureWithTslBasedTrust(@NonNull final Document tsl) {

    try {
      Init.init();

      final Element signatureElement = TslUtils.getSignature(tsl);

      registerIds(tsl);

      final XMLSignature xmlSignature = new XMLSignature(signatureElement, "");

      final KeyInfo keyInfo = xmlSignature.getKeyInfo();
      if (keyInfo == null) {
        return false;
      }

      final X509Certificate cert = keyInfo.getX509Certificate();
      if (cert == null) {
        return false;
      }

      return xmlSignature.checkSignatureValue(cert);

    } catch (final Exception e) {
      return false;
    }
  }

  /**
   * Validates the signature of a given QES TSL (mathematically). The signer's public key is taken
   * from the signer certificate in the TSL signature element.
   *
   * @param tsl the tsl to check
   * @return true if the signature is valid, otherwise false
   */
  public static boolean checkQesTslSignatureWithTslBasedTrust(final byte @NonNull [] tsl) {
    return checkQesTslSignatureWithTslBasedTrust(TslConverter.bytesToDoc(tsl));
  }

  private static void registerIds(final Document doc) {
    /*
    - Id="..." is in DOM not ID
    - setIdAttribute("Id", true) registers it as ID
    - is just Metainformation in DOM
    - signature stays as is
    */

    // Root-Element (Reference URI="")
    final Element root = doc.getDocumentElement();
    if (root.hasAttribute("Id")) {
      root.setIdAttribute("Id", true);
    }
    if (root.hasAttribute("ID")) {
      root.setIdAttribute("ID", true);
    }

    // ds:Signature @Id
    final NodeList signatures =
        doc.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Signature");
    for (int i = 0; i < signatures.getLength(); i++) {
      final Element sig = (Element) signatures.item(i);
      if (sig.hasAttribute("Id")) {
        sig.setIdAttribute("Id", true);
      }
    }

    // xades:SignedProperties @Id
    final NodeList signedProps =
        doc.getElementsByTagNameNS("http://uri.etsi.org/01903/v1.3.2#", "SignedProperties");
    for (int i = 0; i < signedProps.getLength(); i++) {
      final Element sp = (Element) signedProps.item(i);
      if (sp.hasAttribute("Id")) {
        sp.setIdAttribute("Id", true);
      }
    }
  }
}
