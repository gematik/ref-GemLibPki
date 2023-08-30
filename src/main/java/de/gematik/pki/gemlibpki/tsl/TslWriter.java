/*
 * Copyright 2023 gematik GmbH
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
 */

package de.gematik.pki.gemlibpki.tsl;

import de.gematik.pki.gemlibpki.exception.GemPkiRuntimeException;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.NonNull;
import org.w3c.dom.Document;

/** Class to write a TSL from different types to file */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class TslWriter {

  public static final String STATUS_LIST_TO_FILE_FAILED =
      "Schreiben der TSL in eine Datei fehlgeschlagen.";

  /**
   * Saves byte representation of the TSL under the provided path.
   *
   * @param tslUnsigned the TSL to save. Attention: The TSL signature is not valid with this
   *     operation.
   * @param tslFilePath target file name
   */
  public static void writeUnsigned(
      @NonNull final TrustStatusListType tslUnsigned, @NonNull final Path tslFilePath) {
    try {
      final byte[] tslBytes = TslConverter.tslUnsignedToBytes(tslUnsigned);
      Files.write(tslFilePath, tslBytes);
    } catch (final IOException e) {
      throw new GemPkiRuntimeException(STATUS_LIST_TO_FILE_FAILED, e);
    }
  }

  public static void write(@NonNull final Document tslDoc, @NonNull final Path tslFilePath) {
    try {
      final byte[] tslBytes = TslConverter.docToBytes(tslDoc);
      Files.write(tslFilePath, tslBytes);
    } catch (final IOException e) {
      throw new GemPkiRuntimeException(STATUS_LIST_TO_FILE_FAILED, e);
    }
  }
}
