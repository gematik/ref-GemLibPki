/*
 * Copyright 2025, gematik GmbH
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
 * ******
 *
 * For additional notes and disclaimer from gematik and in case of changes by gematik find details in the "Readme" file.
 */

package de.gematik.pki.gemlibpki.certificate;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.bouncycastle.asn1.x509.KeyPurposeId;

/** Enum that host {@link ExtendedKeyUsage} information. */
@RequiredArgsConstructor
@Getter
public enum ExtendedKeyUsage {
  EXT_KEYUSAGE_ANY_EXT_KEYUSAGE("anyExtendedKeyUsage", KeyPurposeId.anyExtendedKeyUsage.getId()),
  EXT_KEYUSAGE_ID_KP_SERVERAUTH("id-kp-serverAuth", KeyPurposeId.id_kp_serverAuth.getId()),
  EXT_KEYUSAGE_ID_KP_CLIENTAUTH("id-kp-clientAuth", KeyPurposeId.id_kp_clientAuth.getId()),
  EXT_KEYUSAGE_ID_KP_EMAILPROTECTION(
      "id-kp-emailProtection", KeyPurposeId.id_kp_emailProtection.getId()),
  EXT_KEYUSAGE_ID_KP_OCSPSIGNING("id-kp-OCSPSigning", KeyPurposeId.id_kp_OCSPSigning.getId()),
  EXT_KEYUSAGE_ID_TSL_KP_TSLSIGNING(
      "id-tsl-kp-tslSigning", "0.4.0.2231.3.0"); // http://oid-info.com/get/0.4.0.2231.3.0

  private final String value;
  private final String oid;
}
