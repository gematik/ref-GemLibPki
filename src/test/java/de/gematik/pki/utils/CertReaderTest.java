/*
 * Copyright (c) 2021 gematik GmbH
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *    http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.gematik.pki.utils;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.File;
import java.io.IOException;
import org.apache.commons.io.FileUtils;
import org.junit.jupiter.api.Test;

class CertReaderTest {

    @Test
    void readExistingX509DerCert() throws IOException {
        final byte[] file = FileUtils
            .readFileToByteArray(new File("src/test/resources/certificates/GEM.SMCB-CA10/valid/DrMedGunther.der"));
        assertNotNull(CertReader.readX509(file));
    }

    @Test
    void readExistingX509PemCert() throws IOException {
        final byte[] file = FileUtils
            .readFileToByteArray(new File("src/test/resources/certificates/GEM.SMCB-CA10/valid/DrMedGunther.pem"));
        assertNotNull(CertReader.readX509(file));
    }
}
