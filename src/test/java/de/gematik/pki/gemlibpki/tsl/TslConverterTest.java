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

import static de.gematik.pki.gemlibpki.TestConstants.FILE_NAME_TSL_ECC_DEFAULT;
import static de.gematik.pki.gemlibpki.utils.ResourceReader.getFilePathFromResources;
import static de.gematik.pki.gemlibpki.utils.XmlCompare.documentsAreEqual;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import de.gematik.pki.gemlibpki.utils.GemlibPkiUtils;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;

class TslConverterTest {

  private static final Path TSL_PATH = getFilePathFromResources(FILE_NAME_TSL_ECC_DEFAULT);

  @Test
  void tslToDoc() {
    final TrustStatusListType tsl = TslReader.getTsl(TSL_PATH).orElseThrow();
    assertThat(documentsAreEqual(TslConverter.tslToDoc(tsl).orElseThrow(), TSL_PATH)).isTrue();
  }

  @Test
  void bytesToDoc() {
    final byte[] tslBytes = GemlibPkiUtils.readContent(TSL_PATH);
    assertThat(documentsAreEqual(TslConverter.bytesToDoc(tslBytes).orElseThrow(), TSL_PATH))
        .isTrue();
  }

  @Test
  void docToBytes() {
    final Document tslDoc = TslReader.getTslAsDoc(TSL_PATH).orElseThrow();
    assertThat(documentsAreEqual(TslConverter.docToBytes(tslDoc).orElseThrow(), TSL_PATH)).isTrue();
  }

  @Test
  void bytesToTsl() {
    final byte[] tslBytes = GemlibPkiUtils.readContent(TSL_PATH);
    assertThat(
            documentsAreEqual(
                TslConverter.bytesToTsl(tslBytes).orElseThrow(),
                TslReader.getTsl(TSL_PATH).orElseThrow()))
        .isTrue();
  }

  @Test
  void nonNullTests() {
    assertThatThrownBy(() -> TslConverter.tslToDoc(null))
        .isInstanceOf(NullPointerException.class)
        .hasMessage("tsl is marked non-null but is null");
    assertThatThrownBy(() -> TslConverter.docToBytes(null))
        .isInstanceOf(NullPointerException.class)
        .hasMessage("tslDoc is marked non-null but is null");
  }
}