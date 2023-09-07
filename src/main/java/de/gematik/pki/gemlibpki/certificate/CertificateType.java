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

import lombok.Getter;
import lombok.RequiredArgsConstructor;

/** Enum that host {@link CertificateType} information. */
@RequiredArgsConstructor
@Getter
public enum CertificateType {
  CERT_TYPE_AK_AUT("C.AK.AUT", "oid_ak_aut", "1.2.276.0.76.4.79"),
  CERT_TYPE_CM_TLS_C("C.CM.TLS-CS", "oid_cm_tls_c", "1.2.276.0.76.4.175"),
  CERT_TYPE_EGK_AUT("C.CH.AUT", "oid_egk_aut", "1.2.276.0.76.4.70"),
  CERT_TYPE_EGK_AUTN("C.CH.AUTN", "oid_egk_autn", "1.2.276.0.76.4.71"),
  CERT_TYPE_EGK_ENC("C.CH.ENC", "oid_egk_enc", "1.2.276.0.76.4.68"),
  CERT_TYPE_EGK_ENCV("C.CH.ENCV", "oid_egk_encv", "1.2.276.0.76.4.69"),
  CERT_TYPE_FD_AUT("C.FD.AUT", "oid_fd_aut", "1.2.276.0.76.4.155"),
  CERT_TYPE_FD_ENC("C.FD.ENC", "oid_fd_enc", "1.2.276.0.76.4.202"),
  CERT_TYPE_FD_OSIG("C.FD.OSIG", "oid_fd_osig", "1.2.276.0.76.4.283"),
  CERT_TYPE_FD_SIG("C.FD.SIG", "oid_fd_sig", "1.2.276.0.76.4.203"),
  CERT_TYPE_FD_TLS_C("C.FD.TLS-C", "oid_fd_tls_c", "1.2.276.0.76.4.168"),
  CERT_TYPE_FD_TLS_S("C.FD.TLS-S", "oid_fd_tls_s", "1.2.276.0.76.4.169"),
  CERT_TYPE_GSMCK_AK_AUT("C.AK.AUT", "oid_ak_aut", "1.2.276.0.76.4.79"),
  CERT_TYPE_GSMCK_NK_VPN("C.NK.VPN", "oid_nk_vpn", "1.2.276.0.76.4.80"),
  CERT_TYPE_GSMCK_SAK_AUT("C.SAK.AUT", "oid_sak_aut", "1.2.276.0.76.4.113"),
  CERT_TYPE_HBA_AUT("C.HP.AUT", "oid_hba_aut", "1.2.276.0.76.4.75"),
  CERT_TYPE_HBA_QES("C.HP.QES", "oid_hba_qes", "1.2.276.0.76.4.72"),
  CERT_TYPE_NK_VPN("C.NK.VPN", "oid_nk_vpn", "1.2.276.0.76.4.80"),
  CERT_TYPE_SAK_AUT("C.SAK.AUT", "oid_sak_aut", "1.2.276.0.76.4.113"),
  CERT_TYPE_SGD_HSM_AUT("C.SGD-HSM.AUT", "oid_sgd_hsm_aut", "1.2.276.0.76.4.214"),
  CERT_TYPE_SMC_B_AUT("C.HCI.AUT", "oid_smc_b_aut", "1.2.276.0.76.4.77"),
  CERT_TYPE_SMC_B_ENC("C.HCI.ENC", "oid_smc_b_enc", "1.2.276.0.76.4.76"),
  CERT_TYPE_SMC_B_OSIG("C.HCI.OSIG", "oid_smc_b_osig", "1.2.276.0.76.4.78"),
  CERT_TYPE_SMKT_AUT("C.SMKT.AUT", "oid_smkt_aut", "1.2.276.0.76.4.82"),
  CERT_TYPE_ZD_SIG("C.ZD.SIG", "oid_zd_sig", "1.2.276.0.76.4.287"),
  CERT_TYPE_ZD_TLS_S("C.ZD.TLS-S", "oid_zd_tls_s", "1.2.276.0.76.4.157"),

  CERT_TYPE_ANY(null, null, null),

  TSL_FIELD_TSL_CCA_CERT(
      "Change of TSL Signer-CA Certificate", "oid_tsl_cca_cert", "1.2.276.0.76.4.164"),
  TSL_FIELD_TSL_PLACEHOLDER(
      "Platzhalter für eine leere TSL extension", "oid_tsl_placeholder", "1.2.276.0.76.4.124");

  private final String name;
  private final String oidReference;
  private final String oid;
}
