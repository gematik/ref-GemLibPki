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

import static de.gematik.pki.gemlibpki.commons.TestConstants.P12_PASSWORD;
import static org.assertj.core.api.Assertions.assertThat;

import de.gematik.pki.gemlibpki.commons.utils.GemLibPkiUtils;
import de.gematik.pki.gemlibpki.commons.utils.TestUtils;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import java.nio.file.Path;
import javax.xml.crypto.dsig.XMLSignature;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;

class TslSignerQesTest {

  public static final String SIGNER_PATH_QES =
      "tsl_signer/Pseudo_German_Trusted_List_Signer_13.p12";

  private static final byte[] TSL_SIGNER_QES = TestUtils.readP12QesAsBytes(SIGNER_PATH_QES);
  private final TslSignerQes.TslSignerQesBuilder tslSignerBuilder = TslSignerQes.builder();

  @BeforeEach
  public void setup() {
    GemLibPkiUtils.setBouncyCastleProvider();
  }

  @Test
  void sign_whenExistingSignatureIsRemoved_thenAddsSingleSignature() {
    final Path destFile = Path.of("target/resignedTslQes.xml");
    final Document tslQesWithoutSignatureBlock = TestUtils.getDefaultTslAsDocQes();
    TslUtils.removeExistingXmlSignatures(tslQesWithoutSignatureBlock);
    final TslSignerQes tslSignerQes =
        tslSignerBuilder
            .tslSignerP12(TSL_SIGNER_QES)
            .tslSignerP12Password(P12_PASSWORD)
            .tslToSign(tslQesWithoutSignatureBlock)
            .build();
    final DSSDocument signedDssDocument = tslSignerQes.sign();
    final byte[] signedXmlBytes = DSSUtils.toByteArray(signedDssDocument);
    final Document signedTslQes = TslConverter.bytesToDoc(signedXmlBytes);
    assertThat(signedTslQes.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature").getLength())
        .isEqualTo(1);
    TslWriter.write(signedTslQes, destFile);
  }
}
