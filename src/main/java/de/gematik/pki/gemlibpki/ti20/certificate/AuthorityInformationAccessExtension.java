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

package de.gematik.pki.gemlibpki.ti20.certificate;

import de.gematik.pki.gemlibpki.commons.utils.GemLibPkiUtils;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import lombok.NonNull;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;

/**
 * Class to abstract the Authority Information Access extension of a certificate. This class works
 * with a parameterized variable for the certificate in its constructor.
 */
public class AuthorityInformationAccessExtension {

  private final AccessDescription[] accessDescriptions;

  /**
   * Uses Authority Information Access from extensions of the provided certificate
   *
   * @param x509EeCert end-entity certificate
   * @throws IOException thrown if cert cannot be read
   */
  public AuthorityInformationAccessExtension(@NonNull final X509Certificate x509EeCert)
      throws IOException {
    final AuthorityInformationAccess aia =
        AuthorityInformationAccess.fromExtensions(
            new X509CertificateHolder(GemLibPkiUtils.certToBytes(x509EeCert)).getExtensions());
    accessDescriptions = (aia != null) ? aia.getAccessDescriptions() : new AccessDescription[0];
  }

  /**
   * Reading OCSP responder URI (Service Supply Point)
   *
   * @return OCSP responder URI from the Authority Information Access extension, or null if not
   *     present
   */
  public String getSsp() {
    return Arrays.stream(accessDescriptions)
        .filter(
            accessDescription ->
                accessDescription.getAccessMethod().equals(X509ObjectIdentifiers.id_ad_ocsp))
        .filter(
            accessDescription ->
                accessDescription.getAccessLocation().getTagNo()
                    == GeneralName.uniformResourceIdentifier)
        .map(accessDescription -> accessDescription.getAccessLocation().getName().toString())
        .findFirst()
        .orElse(null);
  }
}
