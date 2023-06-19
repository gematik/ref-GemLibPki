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

package de.gematik.pki.gemlibpki.utils;

import static de.gematik.pki.gemlibpki.utils.TestUtils.assertNonNullParameter;
import static org.assertj.core.api.AssertionsForClassTypes.*;

import de.gematik.pki.gemlibpki.exception.GemPkiRuntimeException;
import org.junit.jupiter.api.Test;

class ResourceReaderTest {

  @Test
  void testGetFilePathFromResources() {

    assertNonNullParameter(
        () -> ResourceReader.getFilePathFromResources(null, getClass()), "filename");
    assertNonNullParameter(
        () -> ResourceReader.getFilePathFromResources("dummy.txt", null), "clazz");

    assertThatThrownBy(() -> ResourceReader.getFilePathFromResources("dummy.txt", getClass()))
        .isInstanceOf(GemPkiRuntimeException.class)
        .hasMessage("Error retrieving URL for resource: dummy.txt");
  }

  @Test
  void testGetUrlFromResources() {
    assertNonNullParameter(() -> ResourceReader.getUrlFromResources(null, getClass()), "filename");
    assertNonNullParameter(() -> ResourceReader.getUrlFromResources("dummy.txt", null), "clazz");
  }

  @Test
  void testFileFromResourceAsBytes() {

    assertNonNullParameter(
        () -> ResourceReader.getFileFromResourceAsBytes(null, getClass()), "filename");
    assertNonNullParameter(
        () -> ResourceReader.getFileFromResourceAsBytes("dummy.txt", null), "clazz");

    assertThatThrownBy(() -> ResourceReader.getFileFromResourceAsBytes("dummy.txt", getClass()))
        .isInstanceOf(GemPkiRuntimeException.class)
        .hasMessage("Error reading resource: dummy.txt");
  }

  @Test
  void testFileFromResourceAsString() {

    assertThat(ResourceReader.getFileFromResourceAsString("test.txt", getClass()))
        .isEqualTo("test");

    assertNonNullParameter(
        () -> ResourceReader.getFileFromResourceAsString(null, getClass()), "filename");
    assertNonNullParameter(
        () -> ResourceReader.getFileFromResourceAsString("dummy.txt", null), "clazz");

    assertThatThrownBy(() -> ResourceReader.getFileFromResourceAsString("dummy.txt", getClass()))
        .isInstanceOf(GemPkiRuntimeException.class)
        .hasMessage("Error reading resource: dummy.txt");
  }
}
