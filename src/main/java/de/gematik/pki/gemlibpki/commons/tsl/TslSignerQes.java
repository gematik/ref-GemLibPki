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

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.token.SignatureTokenConnection;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;
import java.security.KeyStore.PasswordProtection;
import lombok.Builder;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.w3c.dom.Document;

@Slf4j
@Builder
public class TslSignerQes {

  @NonNull final Document tslToSign;
  final byte @NonNull [] tslSignerP12;
  final String tslSignerP12Password;

  public DSSDocument sign() {

    // create DSSDocument
    final DSSDocument inputDocument =
        new InMemoryDocument(TslConverter.docToBytes(tslToSign), "tsl.xml");

    // signature parameter
    final XAdESSignatureParameters params = new XAdESSignatureParameters();
    params.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
    params.setSignaturePackaging(SignaturePackaging.ENVELOPED);
    params.setDigestAlgorithm(DigestAlgorithm.SHA256);
    params.setEncryptionAlgorithm(EncryptionAlgorithm.RSASSA_PSS);

    // Token
    try (final SignatureTokenConnection token =
        new Pkcs12SignatureToken(
            tslSignerP12, new PasswordProtection(tslSignerP12Password.toCharArray()))) {

      // set Signing-Certificate
      final DSSPrivateKeyEntry keyEntry = token.getKeys().getFirst();
      params.setSigningCertificate(keyEntry.getCertificate());
      params.setCertificateChain(keyEntry.getCertificateChain());

      // XAdES Service
      final XAdESService service = new XAdESService(new CommonCertificateVerifier());

      // DSS‑6.x Signatur-Flow
      final ToBeSigned dataToSign = service.getDataToSign(inputDocument, params);
      final SignatureValue signatureValue =
          token.sign(dataToSign, params.getDigestAlgorithm(), keyEntry);

      return service.signDocument(inputDocument, params, signatureValue);
    }
  }
}
