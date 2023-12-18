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

package de.gematik.pki.gemlibpki.certificate;

import static de.gematik.pki.gemlibpki.certificate.CertificateType.CERT_TYPE_ANY;
import static de.gematik.pki.gemlibpki.certificate.CertificateType.CERT_TYPE_EGK_AUT;
import static de.gematik.pki.gemlibpki.certificate.CertificateType.CERT_TYPE_FD_OSIG;
import static de.gematik.pki.gemlibpki.certificate.CertificateType.CERT_TYPE_FD_SIG;
import static de.gematik.pki.gemlibpki.certificate.CertificateType.CERT_TYPE_FD_TLS_C;
import static de.gematik.pki.gemlibpki.certificate.CertificateType.CERT_TYPE_FD_TLS_S;
import static de.gematik.pki.gemlibpki.certificate.CertificateType.CERT_TYPE_GSMCK_AK_AUT;
import static de.gematik.pki.gemlibpki.certificate.CertificateType.CERT_TYPE_HBA_AUT;
import static de.gematik.pki.gemlibpki.certificate.CertificateType.CERT_TYPE_HSK_ENC;
import static de.gematik.pki.gemlibpki.certificate.CertificateType.CERT_TYPE_HSK_SIG;
import static de.gematik.pki.gemlibpki.certificate.CertificateType.CERT_TYPE_SMC_B_AUT;
import static de.gematik.pki.gemlibpki.certificate.CertificateType.CERT_TYPE_SMC_B_ENC;
import static de.gematik.pki.gemlibpki.certificate.CertificateType.CERT_TYPE_SMC_B_OSIG;
import static de.gematik.pki.gemlibpki.certificate.ExtendedKeyUsage.EXT_KEYUSAGE_ID_KP_CLIENTAUTH;
import static de.gematik.pki.gemlibpki.certificate.ExtendedKeyUsage.EXT_KEYUSAGE_ID_KP_EMAILPROTECTION;
import static de.gematik.pki.gemlibpki.certificate.ExtendedKeyUsage.EXT_KEYUSAGE_ID_KP_SERVERAUTH;
import static de.gematik.pki.gemlibpki.certificate.ExtendedKeyUsage.EXT_KEYUSAGE_ID_TSL_KP_TSLSIGNING;
import static de.gematik.pki.gemlibpki.certificate.KeyUsage.KEYUSAGE_DATA_ENCIPHERMENT;
import static de.gematik.pki.gemlibpki.certificate.KeyUsage.KEYUSAGE_DIGITAL_SIGNATURE;
import static de.gematik.pki.gemlibpki.certificate.KeyUsage.KEYUSAGE_KEY_AGREEMENT;
import static de.gematik.pki.gemlibpki.certificate.KeyUsage.KEYUSAGE_KEY_ENCIPHERMENT;
import static de.gematik.pki.gemlibpki.certificate.KeyUsage.KEYUSAGE_NON_REPUDIATION;

import java.util.List;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

/** Enum that host {@link CertificateProfile} information. */
@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
@Getter
public enum CertificateProfile {
  CERT_PROFILE_C_AK_AUT_RSA(
      CERT_TYPE_GSMCK_AK_AUT,
      List.of(KEYUSAGE_DIGITAL_SIGNATURE, KEYUSAGE_KEY_ENCIPHERMENT),
      List.of(EXT_KEYUSAGE_ID_KP_CLIENTAUTH, EXT_KEYUSAGE_ID_KP_SERVERAUTH),
      true),
  CERT_PROFILE_C_AK_AUT_ECC(
      CERT_TYPE_GSMCK_AK_AUT,
      List.of(KEYUSAGE_DIGITAL_SIGNATURE),
      List.of(EXT_KEYUSAGE_ID_KP_CLIENTAUTH, EXT_KEYUSAGE_ID_KP_SERVERAUTH),
      true),

  CERT_PROFILE_C_CH_AUT_RSA(
      CERT_TYPE_EGK_AUT,
      List.of(KEYUSAGE_DIGITAL_SIGNATURE, KEYUSAGE_KEY_ENCIPHERMENT),
      List.of(EXT_KEYUSAGE_ID_KP_CLIENTAUTH),
      false),
  CERT_PROFILE_C_CH_AUT_ECC(
      CERT_TYPE_EGK_AUT,
      List.of(KEYUSAGE_DIGITAL_SIGNATURE),
      List.of(EXT_KEYUSAGE_ID_KP_CLIENTAUTH),
      false),

  CERT_PROFILE_C_HP_AUT_RSA(
      CERT_TYPE_HBA_AUT,
      List.of(KEYUSAGE_DIGITAL_SIGNATURE, KEYUSAGE_KEY_ENCIPHERMENT),
      List.of(EXT_KEYUSAGE_ID_KP_CLIENTAUTH, EXT_KEYUSAGE_ID_KP_EMAILPROTECTION),
      true),
  CERT_PROFILE_C_HP_AUT_ECC(
      CERT_TYPE_HBA_AUT,
      List.of(KEYUSAGE_DIGITAL_SIGNATURE, KEYUSAGE_KEY_AGREEMENT),
      List.of(EXT_KEYUSAGE_ID_KP_CLIENTAUTH, EXT_KEYUSAGE_ID_KP_EMAILPROTECTION),
      true),

  CERT_PROFILE_C_HCI_AUT_RSA(
      CERT_TYPE_SMC_B_AUT,
      List.of(KEYUSAGE_DIGITAL_SIGNATURE, KEYUSAGE_KEY_ENCIPHERMENT),
      List.of(EXT_KEYUSAGE_ID_KP_CLIENTAUTH),
      true),
  CERT_PROFILE_C_HCI_AUT_ECC(
      CERT_TYPE_SMC_B_AUT,
      List.of(KEYUSAGE_DIGITAL_SIGNATURE),
      List.of(EXT_KEYUSAGE_ID_KP_CLIENTAUTH),
      true),

  CERT_PROFILE_C_HCI_ENC_RSA(
      CERT_TYPE_SMC_B_ENC,
      List.of(KEYUSAGE_KEY_ENCIPHERMENT, KEYUSAGE_DATA_ENCIPHERMENT),
      List.of(),
      false),
  CERT_PROFILE_C_HCI_ENC_ECC(
      CERT_TYPE_SMC_B_ENC, List.of(KEYUSAGE_KEY_AGREEMENT), List.of(), false),

  CERT_PROFILE_C_HCI_OSIG(
      CERT_TYPE_SMC_B_OSIG, List.of(KEYUSAGE_NON_REPUDIATION), List.of(), false),

  CERT_PROFILE_C_FD_SIG(CERT_TYPE_FD_SIG, List.of(KEYUSAGE_DIGITAL_SIGNATURE), List.of(), false),
  CERT_PROFILE_C_FD_OSIG(CERT_TYPE_FD_OSIG, List.of(KEYUSAGE_NON_REPUDIATION), List.of(), false),

  CERT_PROFILE_C_FD_TLS_S_ECC(
      CERT_TYPE_FD_TLS_S,
      List.of(KEYUSAGE_DIGITAL_SIGNATURE),
      List.of(EXT_KEYUSAGE_ID_KP_SERVERAUTH),
      true),
  CERT_PROFILE_C_FD_TLS_S_RSA(
      CERT_TYPE_FD_TLS_S,
      List.of(KEYUSAGE_DIGITAL_SIGNATURE, KEYUSAGE_KEY_ENCIPHERMENT),
      List.of(EXT_KEYUSAGE_ID_KP_SERVERAUTH),
      true),
  CERT_PROFILE_C_FD_TLS_C_ECC(
      CERT_TYPE_FD_TLS_C,
      List.of(KEYUSAGE_DIGITAL_SIGNATURE),
      List.of(EXT_KEYUSAGE_ID_KP_CLIENTAUTH),
      true),
  CERT_PROFILE_C_FD_TLS_C_RSA(
      CERT_TYPE_FD_TLS_C,
      List.of(KEYUSAGE_DIGITAL_SIGNATURE, KEYUSAGE_KEY_ENCIPHERMENT),
      List.of(EXT_KEYUSAGE_ID_KP_CLIENTAUTH),
      true),
  CERT_PROFILE_C_TSL_SIG(
      CERT_TYPE_ANY,
      List.of(KEYUSAGE_NON_REPUDIATION),
      List.of(EXT_KEYUSAGE_ID_TSL_KP_TSLSIGNING),
      true),

  CERT_PROFILE_C_HSK_ENC_ECC(
      CERT_TYPE_HSK_ENC,
      List.of(KEYUSAGE_KEY_AGREEMENT),
      List.of(EXT_KEYUSAGE_ID_KP_SERVERAUTH, EXT_KEYUSAGE_ID_KP_CLIENTAUTH),
      true),

  CERT_PROFILE_C_HSK_SIG_ECC(
      CERT_TYPE_HSK_SIG,
      List.of(KEYUSAGE_NON_REPUDIATION),
      List.of(EXT_KEYUSAGE_ID_KP_SERVERAUTH, EXT_KEYUSAGE_ID_KP_CLIENTAUTH),
      true),

  CERT_PROFILE_ANY(CERT_TYPE_ANY, List.of(), List.of(), false);

  private final CertificateType certificateType;
  private final List<KeyUsage> keyUsages;
  private final List<ExtendedKeyUsage> extKeyUsages;
  private final boolean failOnMissingEku;
}
