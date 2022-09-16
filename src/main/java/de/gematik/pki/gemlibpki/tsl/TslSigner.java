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

package de.gematik.pki.gemlibpki.tsl;

import static de.gematik.pki.gemlibpki.utils.GemlibPkiUtils.setBouncyCastleProvider;
import static org.apache.xml.security.signature.XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256_MGF1;

import de.gematik.pki.gemlibpki.exception.GemPkiRuntimeException;
import de.gematik.pki.gemlibpki.utils.P12Container;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import xades4j.XAdES4jException;
import xades4j.algorithms.EnvelopedSignatureTransform;
import xades4j.algorithms.ExclusiveCanonicalXMLWithoutComments;
import xades4j.production.BasicSignatureOptions;
import xades4j.production.DataObjectReference;
import xades4j.production.SignatureAlgorithms;
import xades4j.production.SignedDataObjects;
import xades4j.production.XadesBesSigningProfile;
import xades4j.production.XadesSigner;
import xades4j.properties.DataObjectDesc;
import xades4j.properties.DataObjectFormatProperty;
import xades4j.providers.KeyingDataProvider;
import xades4j.providers.impl.DirectKeyingDataProvider;
import xades4j.utils.XadesProfileResolutionException;

/** Class for signing tsl DOM Document structures */
@Slf4j
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class TslSigner {

  static {
    setBouncyCastleProvider();
  }
  /**
   * Signs a given tsl
   *
   * @param tsl The tsl to sign
   * @param tslSigner {@link P12Container} with x509certificate a key (RSA/ECC) for signature
   */
  public static void sign(@NonNull final Document tsl, @NonNull final P12Container tslSigner) {

    final Element elemToSign = getTslWithoutSignature(tsl);
    final KeyingDataProvider kdp =
        new DirectKeyingDataProvider(tslSigner.getCertificate(), tslSigner.getPrivateKey());
    final XadesSigner xSigner;
    try {
      xSigner =
          new XadesBesSigningProfile(kdp)
              .withSignatureAlgorithms(
                  new SignatureAlgorithms()
                      .withSignatureAlgorithm("RSA", ALGO_ID_SIGNATURE_RSA_SHA256_MGF1)
                      .withCanonicalizationAlgorithmForSignature(
                          new ExclusiveCanonicalXMLWithoutComments())
                      .withCanonicalizationAlgorithmForTimeStampProperties(
                          new ExclusiveCanonicalXMLWithoutComments()))
              .withBasicSignatureOptions(
                  new BasicSignatureOptions().includeIssuerSerial(false).includeSubjectName(false))
              .newSigner();

      final DataObjectDesc dod =
          new DataObjectReference("")
              .withTransform(new EnvelopedSignatureTransform())
              .withTransform(new ExclusiveCanonicalXMLWithoutComments())
              .withDataObjectFormat(new DataObjectFormatProperty("text/xml", ""));
      xSigner.sign(new SignedDataObjects(dod), elemToSign);
    } catch (final XadesProfileResolutionException e) {
      throw new GemPkiRuntimeException("Fehler beim erstellen des XAdES Profil Objektes.", e);
    } catch (final XAdES4jException e) {
      throw new GemPkiRuntimeException("Fehler bei erstellen der XAdES Signatur.", e);
    }
  }

  private static Element getTslWithoutSignature(final Document tsl) {
    final Element signature = TslUtils.getSignature(tsl);
    if (signature != null) {
      final Element elemToSign = (Element) signature.getParentNode();
      elemToSign.removeChild(signature);
      return elemToSign;
    } else {
      return tsl.getDocumentElement();
    }
  }
}
