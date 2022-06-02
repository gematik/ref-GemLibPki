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

package de.gematik.pki.utils;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import de.gematik.pki.exception.GemPkiRuntimeException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;

class CertReaderTest {

    @Test
    void readExistingX509DerCert() throws IOException {
        final byte[] file = Files.readAllBytes(Path.of("src/test/resources/certificates/GEM.SMCB-CA10/valid/DrMedGunther.der"));
        assertNotNull(CertReader.readX509(file));
    }

    @Test
    void readExistingX509PemCert() throws IOException {
        final byte[] file = Files.readAllBytes(Path.of("src/test/resources/certificates/GEM.SMCB-CA10/valid/DrMedGunther.pem"));
        assertNotNull(CertReader.readX509(file));
    }

    @Test
    void readInvalidCert() throws IOException {
        final byte[] file = Files.readAllBytes(Path.of("src/test/resources/log4j2.xml"));
        assertThatThrownBy(() -> CertReader.readX509(file))
            .isInstanceOf(GemPkiRuntimeException.class)
            .hasMessage("Konnte Zertifikat nicht lesen.");
    }
}
