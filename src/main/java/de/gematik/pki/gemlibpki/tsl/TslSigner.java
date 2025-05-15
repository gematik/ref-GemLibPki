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

package de.gematik.pki.gemlibpki.tsl;

import static de.gematik.pki.gemlibpki.utils.GemLibPkiUtils.setBouncyCastleProvider;
import static org.apache.xml.security.signature.XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256_MGF1;

import de.gematik.pki.gemlibpki.exception.GemPkiRuntimeException;
import de.gematik.pki.gemlibpki.utils.P12Container;
import lombok.Builder;
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
@Builder
public final class TslSigner {

  static {
    setBouncyCastleProvider();
  }

  @NonNull final Document tslToSign;
  @NonNull final P12Container tslSignerP12;
  @Builder.Default private final boolean checkSignerKeyUsage = true;
  @Builder.Default private final boolean checkSignerValidity = true;

  /** Signs a given tsl */
  public void sign() {

    if (!checkSignerKeyUsage) {
      log.info("WARNING! TSL is signed without signerKeyUsage check due to user request.");
    }

    if (!checkSignerValidity) {
      log.info("WARNING! TSL is signed without signerValidityCheck check due to user request.");
    }

    final Element elementToSign = getTslWithoutSignature(tslToSign);

    final KeyingDataProvider keyingDataProvider =
        new DirectKeyingDataProvider(tslSignerP12.getCertificate(), tslSignerP12.getPrivateKey());

    try {

      final SignatureAlgorithms signatureAlgorithms =
          new SignatureAlgorithms()
              .withSignatureAlgorithm("RSA", ALGO_ID_SIGNATURE_RSA_SHA256_MGF1)
              .withCanonicalizationAlgorithmForSignature(new ExclusiveCanonicalXMLWithoutComments())
              .withCanonicalizationAlgorithmForTimeStampProperties(
                  new ExclusiveCanonicalXMLWithoutComments());

      final BasicSignatureOptions basicSignatureOptions =
          new BasicSignatureOptions()
              .includeIssuerSerial(false)
              .includeSubjectName(false)
              .checkKeyUsage(checkSignerKeyUsage)
              .checkCertificateValidity(checkSignerValidity);

      final XadesSigner xadesSigner =
          new XadesBesSigningProfile(keyingDataProvider)
              .withSignatureAlgorithms(signatureAlgorithms)
              .withBasicSignatureOptions(basicSignatureOptions)
              .newSigner();

      final DataObjectDesc dataObjectDesc =
          new DataObjectReference("")
              .withTransform(new EnvelopedSignatureTransform())
              .withTransform(new ExclusiveCanonicalXMLWithoutComments())
              .withDataObjectFormat(new DataObjectFormatProperty("text/xml"));

      xadesSigner.sign(new SignedDataObjects(dataObjectDesc), elementToSign);

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
