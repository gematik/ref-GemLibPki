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

import static de.gematik.pki.gemlibpki.commons.utils.TestUtils.assertNonNullParameter;
import static org.assertj.core.api.Assertions.assertThat;

import de.gematik.pki.gemlibpki.commons.utils.TestUtils;
import java.nio.file.Path;
import javax.xml.crypto.dsig.XMLSignature;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;

class TslUtilsTest {

  @Test
  void tslUtilsMethods_whenRequiredArgumentsAreNull_thenThrowsOnNullParameter() {
    assertNonNullParameter(() -> TslUtils.tslDownloadUrlMatchesOid(null), "oid");

    assertNonNullParameter(() -> TslUtils.createJaxbElement(null), "tslUnsigned");

    assertNonNullParameter(() -> TslUtils.getSignature(null), "tsl");
  }

  @Test
  void removeExistingXmlSignatures_whenDocumentContainsSignature_thenRemovesSignature() {
    final Path destFile = Path.of("target/TslWithoutSignatureBlock.xml");
    final Document tslQes = TestUtils.getDefaultTslAsDocQes();

    assertThat(
            tslQes.getElementsByTagName("Signature").getLength()
                + tslQes.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature").getLength())
        .isEqualTo(1);

    TslUtils.removeExistingXmlSignatures(tslQes);

    // signature block should be removed from tsl
    TslWriter.write(tslQes, destFile);

    assertThat(
            tslQes.getElementsByTagName("Signature").getLength()
                + tslQes.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature").getLength())
        .isZero();
  }
}
