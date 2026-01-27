#ifndef NM_TOFU_H
#define NM_TOFU_H

/* -- TOFU session types -- */
typedef enum {
    NM_TOFU_SESSION_TYPE_NONE = 0,
    NM_TOFU_SESSION_TYPE_TOFU,                 // No CA cert, TOFU path
    NM_TOFU_SESSION_TYPE_CONFIGURED_CA,        // CA cert configured by the user or by TOFU
    NM_TOFU_SESSION_TYPE_USER_TRUSTED_NO_CA,   // No CA cert, but marked trusted
} NMTOFUSessionType;

/* -- Certificate handling structures -- */
typedef struct {
    guint depth;
    char *subject;
    char *hash;
    GBytes *cert_data;
} NMTOFUCertInfo;

typedef struct {
    GPtrArray *certs;     // array of NMTOFUCertInfo*
    gboolean finalized;
} NMTOFUCertSession;

/* -- Trusted server cert management -- */
#define TOFU_TRUSTED_SERVER_CERT_STORE "/var/lib/NetworkManager/tofu/trusted-server-certs.json"


/* -- session management -- */
void nm_tofu_reset_session(void);
NMTOFUSessionType nm_tofu_get_session_type(void);
void nm_tofu_set_session(NMTOFUSessionType type, const char *ssid, const char *uuid);

/* -- regular independent functions -- */
void tofu_list_everything(void);
void tofu_deauthenticate_connection_by_ssid(const char *ssid_target);
void tofu_set_autoconnect_for_ssid(const char *ssid_target, gboolean enable_autoconnect);
void tofu_authenticate_connection_by_ssid(const char *ssid_target);
void tofu_remove_connection(const char *ssid);

/* -- Certificate handling -- */
// this function is called when the certs are received from the server during TLS handshake used for all three cases
void nm_tofu_stage2_cert_signal(GVariant *parameters);

/* -- NM_TOFU_SESSION_TYPE_TOFU -- */
void tofu_stage3_send_signal(void);
int nm_tofu_verify_leaf_cert_with_system_ca(NMTOFUCertSession *session);
void nm_tofu_parse_cert_send_CertificateVerificationRequest(const char *str_disclaimer);
GPtrArray * extract_dnsname_from_gbytes(GBytes *cert_data);
void tofu_handle_cert_verification_response(gboolean user_response, const char *ssid);
char *tofu_save_cert_der_as_pem(NMTOFUCertInfo *cert_info, GError **error);
void tofu_update_ca_cert(const char *ssid_target);
void tofu_add_timestamp_to_connection(const char *ssid);

/* -- NM_TOFU_SESSION_TYPE_CONFIGURED_CA -- */
void nm_save_config_ca_cert_data(GBytes *cert_data);
void nm_tofu_verify_leaf_cert_with_config_ca(const char *ssid, NMTOFUCertSession *config_cert_data, NMTOFUCertSession *wpa_cert_data);
void nm_dbus_emit_cert_verification_failure_signal(const char *ssid);

/* -- NM_TOFU_SESSION_TYPE_USER_TRUSTED_NO_CA -- */
gboolean nm_tofu_is_uuid_trusted(const char *uuid);
gboolean nm_tofu_is_cert_hash_trusted(const char *uuid, const char *observed_hash);
gboolean nm_tofu_mark_server_cert_as_trusted(const char *uuid, const char *cert_hash);
void nm_tofu_remove_server_cert_from_trusted(const char *uuid);

#endif // NM_TOFU_H