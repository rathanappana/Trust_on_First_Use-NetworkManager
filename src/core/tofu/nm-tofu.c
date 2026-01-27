
#include "src/core/nm-default-daemon.h"
#include "nm-tofu.h"
#include "nm-certificate-agent.h"

#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/rtnetlink.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <syslog.h>
#include <unistd.h>
#include <glib.h>
#include <glib/gi18n.h>
#include <string.h>


#include "devices/nm-device.h"
#include "settings/nm-settings.h"
#include "settings/nm-settings-connection.h"
#include "nm-manager.h"
#include "nm-utils.h"
#include "nm-core-utils.h"
#include "libnm-log-core/nm-logging.h"
#include "libnm-core-aux-intern/nm-auth-subject.h"
#include "nm-setting-wireless.h"
#include "nm-active-connection.h"
#include "nm-connection.h"
#include "nm-setting-wireless.h"
#include "libnm-core-intern/nm-core-internal.h"
#include "nm-act-request.h"
#include <gnutls/x509.h>
#include <gio/gio.h>
#include "nm-dbus-manager.h"
#include "supplicant/nm-supplicant-config.h"
#include "supplicant/nm-supplicant-manager.h"
#include "settings/nm-agent-manager.h"
#include "settings/nm-secret-agent.h"

/*
Stage 1 : handling the EAP insecure networks which is in nm-device-wifi.c
Check if the network uses EAP authentication

Check if there is no ca_cert configured

Only then proceed to observe and validate the server certificate (via TOFU)

Stage 2 : listening and handling the certs

*/

static NMTOFUSessionType current_session_type = NM_TOFU_SESSION_TYPE_NONE;
const char *tofu_ssid = NULL; // SSID of the network for which the session is active
const char *tofu_uuid = NULL; // UUID of the network for which the session is active

NMTOFUSessionType nm_tofu_get_session_type(void) {
    return current_session_type;
}

void
nm_tofu_set_session(NMTOFUSessionType type, const char *ssid, const char *uuid) {
    //clear the previous session if any
    nm_tofu_reset_session();
    current_session_type = type;
    tofu_ssid = ssid ? g_strdup(ssid) : g_strdup("unknown");
    tofu_uuid = uuid ? g_strdup(uuid) : g_strdup("unknown");
    nm_log_info(LOGD_TOFU, "[TOFU] Received cert signal for SSID: %s", ssid);
}

// Certs sent by the server during TLS handshake via wpa_supplicant
static NMTOFUCertSession *observed_certs = NULL;
// CA cert or previously pinned cert configured by user in the connection profile
static NMTOFUCertSession *configured_cert = NULL;

void nm_tofu_stage2_cert_signal(GVariant *parameters)
{
    // Handle the cert signal

    const char *key, *subject = NULL, *hash = NULL;
    guint depth = ~0;
    GVariantIter *iter;
    GVariant *dict, *value;
    GBytes *cert_data = NULL;
    NMTOFUCertInfo *info;

    g_variant_get(parameters, "(@a{sv})", &dict);
    g_variant_get(dict, "a{sv}", &iter);
    g_variant_unref(dict);

    while (g_variant_iter_next(iter, "{sv}", &key, &value)) {
        if (g_strcmp0(key, "depth") == 0)
            depth = g_variant_get_uint32(value);
        else if (g_strcmp0(key, "subject") == 0)
            subject = g_variant_get_string(value, NULL);
        else if (g_strcmp0(key, "cert_hash") == 0)
            hash = g_variant_get_string(value, NULL);
        else if (g_strcmp0(key, "cert") == 0)
            cert_data = g_bytes_ref(g_variant_get_data_as_bytes(value));
        g_variant_unref(value);
    }
    g_variant_iter_free(iter);

    if (depth == ~0 || !subject || !hash || !cert_data) {
        nm_log_warn(LOGD_TOFU, "[TOFU] Incomplete cert signal. Skipping.");
        return;
    }

    // Init session if first time
    if (!observed_certs) {
        observed_certs = g_new0(NMTOFUCertSession, 1);
        observed_certs->certs = g_ptr_array_new_with_free_func((GDestroyNotify) g_free);
    }

    // Dedup check
    for (guint i = 0; i < observed_certs->certs->len; i++) {
        NMTOFUCertInfo *existing = g_ptr_array_index(observed_certs->certs, i);
        if (existing->depth == depth && g_strcmp0(existing->hash, hash) == 0)
            return;
    }

    // Save new cert
    info = g_new0(NMTOFUCertInfo, 1);
    info->depth = depth;
    info->subject = g_strdup(subject);
    info->hash = g_strdup(hash);
    info->cert_data = cert_data;

    g_ptr_array_add(observed_certs->certs, info);

    nm_log_info(LOGD_TOFU,
                "Cert saved: depth=%u subject=%s hash=%s",
                depth, subject, hash);

    // Leaf cert = depth 0
    if (depth == 0 && !observed_certs->finalized) {
        observed_certs->finalized = TRUE;
        nm_log_info(LOGD_TOFU, "[TOFU] Leaf cert received. Finalizing.");
        // here the logic splits based on the session type
        switch (nm_tofu_get_session_type())
        {
        case NM_TOFU_SESSION_TYPE_TOFU:
            // Handle TOFU session, goes to stage 3
            tofu_stage3_send_signal();
            break;
        case NM_TOFU_SESSION_TYPE_CONFIGURED_CA:
            // verify the leaf cert against the configured CA cert
            nm_tofu_verify_leaf_cert_with_config_ca(tofu_ssid, configured_cert, observed_certs);
            break;
        case NM_TOFU_SESSION_TYPE_USER_TRUSTED_NO_CA:
            // Handle user trusted session, no CA cert configured
            // check the leaf cert aganist the trusted server cert 
            // if verified continue with the connection else debug that verification failed and follow the same path as TOFU
            // actually we are at the leaf cert already loaded, so we can simply use the info->hash to verify the server cert
            if (nm_tofu_is_cert_hash_trusted(tofu_uuid, info->hash)) {
                nm_log_info(LOGD_TOFU, "Server cert is trusted by user (matched) for SSID=%s", tofu_ssid);
                // simply continue the connection, nothing to do here
            } else {
                nm_log_warn(LOGD_TOFU, "[TOFU] Server cert is NOT trusted by user (not matched) for SSID=%s", tofu_ssid);
                // might be because server changed its cert, as normal pop up will be shown to the user
                tofu_stage3_send_signal(); 
            }
            break;
        default:
            // usually it won't reach here, but just in case
            nm_log_warn(LOGD_TOFU, "[TOFU] Unexpected session type.");
            break;
        }
    }
}

/*
 * Stage 3: Send signal to nm-applet, nmtui or nmcli to verify the server cert
 * This function is called after the leaf cert is received and verified
 * It will deauthenticate the connection and send the signal to nm-applet, nmtui or nmcli
 */
void
tofu_stage3_send_signal(void)
{
    int result;
    const char *str_disclaimer;
    // stage 3: 1st step is deauthenticating the connection and autoconnect is disabled
    tofu_deauthenticate_connection_by_ssid(tofu_ssid);
    tofu_set_autoconnect_for_ssid(tofu_ssid, FALSE);

    //analyze the certs verify aganist the system's CA bundle
    result = nm_tofu_verify_leaf_cert_with_system_ca(observed_certs);
    switch (result) {
        case 1:
            nm_log_info(LOGD_TOFU, "Server cert is trusted by system CAs.");
            str_disclaimer = _("The server certificate is trusted by the system's CA bundle.");
            break;
        case 0:
            nm_log_warn(LOGD_TOFU, "Server cert is NOT trusted (unknown CA or self-signed).");
            str_disclaimer = _("The server certificate is not trusted by the system's CA bundle. Please verify the certificate.");
            break;
        default:
            nm_log_err(LOGD_TOFU, "Error verifying server cert: code %d", result);
            str_disclaimer = _("An error occurred while verifying the server certificate using the system's CA bundle.");
            break;
    }
    // analyze and parse the server cert and send dbus signal to nm-applet, nmtui or nmcli
    nm_tofu_parse_cert_send_CertificateVerificationRequest(str_disclaimer);

}

// stage 4 getting response from nm-applet, nmtui or nmcli
void
tofu_handle_cert_verification_response(gboolean user_response, const char *ssid)
{
    NMTOFUCertInfo *cert_info = NULL;

    nm_log_info(LOGD_TOFU, "User responded to certificate verification: %s for ssid %s", user_response ? "ACCEPT" : "REJECT", ssid ? ssid : "NULL");

    if (!ssid || !*ssid) {
        nm_log_warn(LOGD_TOFU, "SSID is NULL or empty, cannot proceed");
        return;
    }
    if (g_strcmp0(ssid, tofu_ssid) != 0) {
        nm_log_warn(LOGD_TOFU, "SSID mismatch, may be a expired session/test signal");
        return;
    }

    if (user_response) {
        // Accept: Save the ca-cert/ mark the server cert as trusted and update the connection profile
        cert_info = observed_certs->certs->pdata[0]; // top level cert from the chain provided by the server
        if (cert_info->depth == 0) {
            // observed_certs does not have the CA cert, we need to mark the server cert as trusted w.r.t the uuid
            nm_log_info(LOGD_TOFU, "Server cert is only sent by the server for uuid=%s", tofu_uuid);
            // here the server cert need to mark as trusted, it handles for new connection and if the server cert is changed connection uuid is already present it updates the cert hash
            nm_tofu_mark_server_cert_as_trusted(tofu_uuid, cert_info->hash);
            //restart the connection right away
            nm_tofu_reset_session();
            tofu_set_autoconnect_for_ssid(ssid, TRUE);
            //tofu_add_timestamp_to_connection(ssid);
            tofu_authenticate_connection_by_ssid(ssid);
        } else {
            //observed_certs has the CA cert, we need to update the CA cert in the connection profile
            nm_log_info(LOGD_TOFU, "Top level cert is also sent by the server for SSID=%s", tofu_ssid);
            tofu_update_ca_cert(ssid);
            nm_tofu_reset_session();
            tofu_set_autoconnect_for_ssid(ssid, TRUE);
            // everything is populated properly, everyhting is in the place
            // but sometimes we saw pop asks for password, this is due to delay in the EAP authentication, which NM thinks that was because of the wrong password credentials,
            // we can avoid that by adding a timestamp that is was connected before, but it is not a good idea because it will not be able to connect to the network if the password is changed (password popup will not be shown)
            tofu_add_timestamp_to_connection(ssid);
            tofu_authenticate_connection_by_ssid(ssid);
        }
    } else {
        // after rejecting the cert, some case that uuid is can be present in the trusted server cert store, so we need to remove it
        // new function need to be written
        nm_tofu_remove_server_cert_from_trusted(tofu_uuid);
        // Reject: Cleanup and prevent future auto-connect
        nm_tofu_reset_session();
        tofu_remove_connection(ssid);
        nm_log_info(LOGD_TOFU, "User rejected certificate. Autoconnect disabled for SSID=%s", ssid);
    }
}

gboolean
nm_tofu_mark_server_cert_as_trusted(const char *uuid, const char *cert_hash)
{
    GKeyFile *keyfile;
    gchar *data;
    gsize length;
    GError *error = NULL;

    g_return_val_if_fail(uuid && *uuid, FALSE);
    g_return_val_if_fail(cert_hash && *cert_hash, FALSE);

    keyfile = g_key_file_new();

    // Load existing file if it exists
    if (g_file_test(TOFU_TRUSTED_SERVER_CERT_STORE, G_FILE_TEST_EXISTS)) {
        if (!g_key_file_load_from_file(keyfile, TOFU_TRUSTED_SERVER_CERT_STORE, G_KEY_FILE_KEEP_COMMENTS, &error)) {
            g_warning("Failed to load trusted certs file: %s", error->message);
            g_clear_error(&error);
            g_key_file_free(keyfile);
            return FALSE;
        }
    }

    // Set the UUID → cert_hash mapping
    g_key_file_set_string(keyfile, uuid, "cert_hash", cert_hash);

    // Dump to string
    data = g_key_file_to_data(keyfile, &length, NULL);

    // Ensure directory exists
    g_mkdir_with_parents("/var/lib/NetworkManager/tofu", 0700);

    // Write to file
    if (!g_file_set_contents(TOFU_TRUSTED_SERVER_CERT_STORE, data, (gssize)length, &error)) {
        g_warning("Failed to write trusted certs file: %s", error->message);
        g_free(data);
        g_key_file_free(keyfile);
        g_clear_error(&error);
        return FALSE;
    }

    nm_log_info(LOGD_TOFU, "Trusted server certificate hash for UUID=%s stored successfully.", uuid);

    g_free(data);
    g_key_file_free(keyfile);
    return TRUE;
}

void
nm_tofu_remove_server_cert_from_trusted(const char *uuid)
{
    GKeyFile *keyfile;
    gchar *data;
    GError *error = NULL;

    if (!uuid || !*uuid) {
        nm_log_warn(LOGD_TOFU, "Cannot remove cert: UUID is NULL or empty");
        return;
    }

    keyfile = g_key_file_new();
    if (!g_key_file_load_from_file(keyfile, TOFU_TRUSTED_SERVER_CERT_STORE, G_KEY_FILE_NONE, &error)) {
        nm_log_warn(LOGD_TOFU, "Could not load trusted cert store: %s", error->message);
        g_error_free(error);
        g_key_file_free(keyfile);
        return;
    }

    if (!g_key_file_has_group(keyfile, uuid)) {
        nm_log_info(LOGD_TOFU, "UUID %s not found in trusted cert store. Skipping removal.", uuid);
        g_key_file_free(keyfile);
        return;
    }

    g_key_file_remove_group(keyfile, uuid, NULL);

    // Write back to file
    data = g_key_file_to_data(keyfile, NULL, NULL);
    if (!g_file_set_contents(TOFU_TRUSTED_SERVER_CERT_STORE, data, -1, &error)) {
        nm_log_warn(LOGD_TOFU, "Failed to update cert store file: %s", error->message);
        g_error_free(error);
    } else {
        nm_log_info(LOGD_TOFU, "Removed trusted server cert for UUID=%s", uuid);
    }

    g_free(data);
    g_key_file_free(keyfile);
}

gboolean
nm_tofu_is_uuid_trusted(const char *uuid)
{
    GKeyFile *keyfile;
    GError *error = NULL;
    gboolean result = FALSE;

    g_return_val_if_fail(uuid && *uuid, FALSE);

    if (!g_file_test(TOFU_TRUSTED_SERVER_CERT_STORE, G_FILE_TEST_EXISTS))
        return FALSE;

    keyfile = g_key_file_new();

    if (!g_key_file_load_from_file(keyfile, TOFU_TRUSTED_SERVER_CERT_STORE, G_KEY_FILE_KEEP_COMMENTS, &error)) {
        g_warning("Failed to load trusted certs file: %s", error->message);
        g_clear_error(&error);
        g_key_file_free(keyfile);
        return FALSE;
    }

    if (g_key_file_has_group(keyfile, uuid))
        result = TRUE;

    g_key_file_free(keyfile);
    return result;
}

gboolean
nm_tofu_is_cert_hash_trusted(const char *uuid, const char *observed_hash)
{
    GKeyFile *keyfile;
    GError *error = NULL;
    gchar *stored_hash;
    gboolean result = FALSE;

    g_return_val_if_fail(uuid && *uuid, FALSE);
    g_return_val_if_fail(observed_hash && *observed_hash, FALSE);

    if (!g_file_test(TOFU_TRUSTED_SERVER_CERT_STORE, G_FILE_TEST_EXISTS))
        return FALSE;

    keyfile = g_key_file_new();

    if (!g_key_file_load_from_file(keyfile, TOFU_TRUSTED_SERVER_CERT_STORE, G_KEY_FILE_KEEP_COMMENTS, &error)) {
        g_warning("Failed to load trusted certs file: %s", error->message);
        g_clear_error(&error);
        g_key_file_free(keyfile);
        return FALSE;
    }

    if (!g_key_file_has_group(keyfile, uuid)) {
        g_key_file_free(keyfile);
        return FALSE;
    }

    stored_hash = g_key_file_get_string(keyfile, uuid, "cert_hash", &error);
    if (error || !stored_hash) {
        g_clear_error(&error);
        g_key_file_free(keyfile);
        return FALSE;
    }

    if (g_strcmp0(stored_hash, observed_hash) == 0) {
        result = TRUE;
    }

    g_free(stored_hash);
    g_key_file_free(keyfile);
    return result;
}

void
tofu_update_ca_cert(const char *ssid_target)
{
    NMTOFUCertInfo *cert_info = NULL;
    char *pem_path = NULL;
    GError *error = NULL;
    gboolean success = FALSE;
    NMSettings *settings = nm_settings_get();
    NMSettingsConnection *const *connections;
    NMSettingsConnection *sconn;
    NMConnection *conn;
    guint n_conn, i;
    const char *id = NULL;
    NMSetting8021x *s_8021x = NULL;

    if (!observed_certs || !observed_certs->certs || observed_certs->certs->len == 0) {
        nm_log_warn(LOGD_TOFU, "No certificate session/certs available to update CA cert");
        return;
    }

    // Get the current CA cert info
    cert_info = observed_certs->certs->pdata[0]; // ca or root cert
    if (!cert_info) {
        nm_log_warn(LOGD_TOFU, "No valid CA cert info available");
        return;
    }

    pem_path = tofu_save_cert_der_as_pem(cert_info, &error);
    if (!pem_path) {
        nm_log_warn(LOGD_TOFU, "Failed to save CA cert to PEM: %s", error->message);
        g_clear_error(&error);
        return;
    }

    nm_log_info(LOGD_TOFU, "Updated CA cert: %s", pem_path);

    //update the ca-cert in the config file

    connections = nm_settings_get_connections(settings, &n_conn);
    for (i = 0; i < n_conn; i++) {
        sconn = connections[i];
        if (!sconn) {
            nm_log_warn(LOGD_TOFU, "No 'connection' setting in connection %s", id);
            return;
        }

        id = nm_settings_connection_get_id(sconn);
        if (g_strcmp0(id, ssid_target) == 0) {

            conn = nm_simple_connection_new_clone(nm_settings_connection_get_connection(sconn));
           if (!conn) {
               nm_log_warn(LOGD_TOFU, "No 'connection' setting in connection %s", id);
               return;
           }

           s_8021x = nm_connection_get_setting_802_1x(conn);

            if (!s_8021x) {
            nm_log_warn(LOGD_TOFU, "No '802-1x' setting in connection %s", id);
            return;
            }

            success = nm_setting_802_1x_set_ca_cert(
                        s_8021x,
                        pem_path,
                        NM_SETTING_802_1X_CK_SCHEME_PATH,
                        NULL,
                        &error);

            if (!success) {
                nm_log_err(LOGD_TOFU, "Failed to set CA cert for SSID=%s: %s", ssid_target, error ? error->message : "Unknown error");
                g_error_free(error);
                g_free(pem_path);
                return;
            }
            nm_log_info(LOGD_TOFU, "Successfully set CA cert for SSID=%s", ssid_target);

            if (!nm_settings_connection_update(sconn,
                                            "keyfile",                 // plugin_name
                                            conn,                   // new_connection
                                            NM_SETTINGS_CONNECTION_PERSIST_MODE_KEEP, // persist_mode
                                            0,                            // sett_flags
                                            0,                            // sett_mask
                                            NM_SETTINGS_CONNECTION_UPDATE_REASON_NONE, // update_reason
                                            "tofu-update",                // log_context_name
                                            &error)) {
                nm_log_err(LOGD_CORE, "[TOFU] Failed to update settings: %s", error->message);
                g_clear_error(&error);
            } else {
                nm_log_info(LOGD_CORE, "[TOFU] Successfully updated connection with new CA cert");
            }
        }
    }
    g_free(pem_path);
}

char *
tofu_save_cert_der_as_pem(NMTOFUCertInfo *cert_info, GError **error)
{
    gnutls_x509_crt_t crt;
    gnutls_datum_t datum;
    gchar *pem_data = NULL;
    size_t pem_size = 0;
    gconstpointer data;
    size_t data_size;
    GBytes *cert_data = cert_info->cert_data;
    const char *hash = cert_info->hash;
    char *output_path = NULL;
    char cn[256] = {0};
    size_t cn_len = sizeof(cn);
    char *safe_name = NULL;
    //const char *base_dir = "/usr/share/ca-certificates/tofu";
    const char *base_dir = "/var/lib/NetworkManager/tofu";

    g_return_val_if_fail(cert_data != NULL, FALSE);

    data = g_bytes_get_data(cert_data, &data_size);
    datum.data = (unsigned char *)data;
    datum.size = data_size;

    if (gnutls_x509_crt_init(&crt) != GNUTLS_E_SUCCESS) {
        g_set_error(error, G_FILE_ERROR, G_FILE_ERROR_FAILED, "Failed to init certificate");
        return FALSE;
    }

    if (gnutls_x509_crt_import(crt, &datum, GNUTLS_X509_FMT_DER) != GNUTLS_E_SUCCESS) {
        g_set_error(error, G_FILE_ERROR, G_FILE_ERROR_FAILED, "Failed to import DER cert");
        goto cleanup;
    }

    // Sanitize filename from CN or fallback to hash
    if (gnutls_x509_crt_get_dn_by_oid(crt, GNUTLS_OID_X520_COMMON_NAME, 0, 0, cn, &cn_len) == GNUTLS_E_SUCCESS) {
        for (char *p = cn; *p; p++) {
            if (!g_ascii_isalnum(*p)) *p = '_';
        }
        safe_name = g_strdup_printf("%s_CA.crt", cn);
    } else if (hash && *hash) {
        safe_name = g_strdup_printf("%.*s_CA.crt", 8, hash);
    } else {
        safe_name = g_strdup("tofu_CA.crt");
    }

    output_path = g_build_filename(base_dir, safe_name, NULL);
    g_free(safe_name);
    /* Prepare output directory */
    if (g_mkdir_with_parents(base_dir, 0755) < 0) {
        g_set_error(error, G_FILE_ERROR, g_file_error_from_errno(errno),
                    "Failed to create directory: %s", base_dir);
        g_clear_pointer(&output_path, g_free);
        goto cleanup;
    }

    // Estimate PEM buffer size (larger than DER)
    pem_size = datum.size * 2;
    pem_data = g_malloc0(pem_size);

    if (gnutls_x509_crt_export(crt, GNUTLS_X509_FMT_PEM, pem_data, &pem_size) != GNUTLS_E_SUCCESS) {
        g_set_error(error, G_FILE_ERROR, G_FILE_ERROR_FAILED, "Failed to convert to PEM");
        g_clear_pointer(&output_path, g_free);
        goto cleanup;
    }

    // Resize to actual size
    pem_data = g_realloc(pem_data, pem_size);

    if (!g_file_set_contents(output_path, pem_data, pem_size, error)) {
        g_clear_pointer(&output_path, g_free);
        goto cleanup;
    }

    nm_log_info(LOGD_TOFU, "Saved CA cert to PEM: %s", output_path);

cleanup:
    gnutls_x509_crt_deinit(crt);
    g_free(pem_data);
    return output_path;
}

void
nm_tofu_parse_cert_send_CertificateVerificationRequest(const char *str_disclaimer)
{
    NMTOFUCertInfo *cert_info = NULL;
    NMTOFUCertInfo *server_info = NULL;
    const guchar *data;
    gnutls_x509_crt_t crt;
    gnutls_datum_t datum ={
        .data = NULL,
        .size = 0,
    };
    char certificate_name[256] = {0}, issuer_name[256] = {0}, organization[256] = {0}, sha256_hex[65] = {0}, best_url[256] = "N/A";
    size_t certificate_name_len = sizeof(certificate_name);
    size_t issuer_name_len = sizeof(issuer_name);
    size_t organization_len = sizeof(organization);
    size_t best_url_len = sizeof(best_url);
    time_t expiration = 0;
    struct tm *tm_info;
    char expiration_str[128] = {0};
    unsigned char sha256[32];
    size_t sha256_len, i;
    NMDBusManager *dbus_manager;
    GPtrArray *urls = g_ptr_array_new_with_free_func(g_free);
    char *url;

    // This function will parse the server cert and verify it against the local trusted certs
    // We can use gnutls library to parse the cert and verify it
    nm_log_info(LOGD_TOFU, "Parsing server cert...");
    // Implementation of parsing logic go

    if (!observed_certs || !observed_certs->certs || observed_certs->certs->len == 0) {
        nm_log_warn(LOGD_TOFU, "No certificate session/certs available to analyze for SSID=%s", tofu_ssid);
        return;
    }

    nm_log_info(LOGD_TOFU, "Analyzing %u certificates for SSID=%s", observed_certs->certs->len, tofu_ssid);

    // if we get the chain of certs from server (series of ca certs and server cert), top level cert is to be shown to the user, if only one cert is received then it is the server cert
    cert_info = observed_certs->certs->pdata[0]; // top level cert from the chain provided by the server
    // this is the server cert which is sent by the server, it is the last cert in the chain // used only for showing DNS name in the SAN field
    for ( i = 0; i < observed_certs->certs->len; i++) {
        server_info = g_ptr_array_index(observed_certs->certs, i);
        if (server_info && server_info->depth == 0) {
            break;
        }
    }

   if (cert_info->depth == 0) {
        nm_log_info(LOGD_TOFU, "Server cert is only sent by the server for SSID=%s", tofu_ssid);
    }else {
        nm_log_info(LOGD_TOFU, "Top level cert is also sent by the server for SSID=%s", tofu_ssid);
    }

    data = g_bytes_get_data(cert_info->cert_data, NULL);

    if (!cert_info || !cert_info->cert_data) {
        nm_log_err(LOGD_TOFU, "Invalid cert info for analysis");
        return;
    }

    datum.data = (unsigned char *) data;
    datum.size = g_bytes_get_size(cert_info->cert_data);

    if (gnutls_x509_crt_init(&crt) < 0 || gnutls_x509_crt_import(crt, &datum, GNUTLS_X509_FMT_DER) < 0) {
        nm_log_err(LOGD_TOFU, "Failed to parse server certificate for SSID=%s", tofu_ssid);
        return;
    }

    gnutls_x509_crt_get_dn_by_oid(crt, GNUTLS_OID_X520_COMMON_NAME, 0, 0, certificate_name, &certificate_name_len);
    gnutls_x509_crt_get_issuer_dn_by_oid(crt, GNUTLS_OID_X520_COMMON_NAME, 0, 0, issuer_name, &issuer_name_len);
    gnutls_x509_crt_get_dn_by_oid(crt, GNUTLS_OID_X520_ORGANIZATION_NAME, 0, 0, organization, &organization_len);
    // the real domain names url is in the SAN (Subject Alternative Name) field
    // --- Extract Best URL (DNSName → URI → CN -> N/A) ---
    urls = extract_dnsname_from_gbytes(server_info->cert_data);
    if (urls->len > 0) {
        for (guint j = 0; j < urls->len; j++) {
            url = g_ptr_array_index(urls, j);
            nm_log_info(LOGD_TOFU, "Best URL[%u]: %s", j, url);
        }
        strncpy(best_url, g_ptr_array_index(urls, 0), best_url_len - 1);
        best_url[best_url_len - 1] = '\0';
    } else {
        nm_log_info(LOGD_TOFU, "Failed to extract Best URL from server cert");
    }
    g_ptr_array_free(urls, TRUE);  

    expiration = gnutls_x509_crt_get_expiration_time(crt);
    tm_info = localtime(&expiration);
    if (tm_info)
    strftime(expiration_str, sizeof(expiration_str), "%c", tm_info);
    // SHA-256 fingerprint

    sha256_len = sizeof(sha256);
    gnutls_x509_crt_get_fingerprint(crt, GNUTLS_DIG_SHA256, sha256, &sha256_len);

    for (i = 0; i < sha256_len; i++)
        sprintf(&sha256_hex[i * 2], "%02X", sha256[i]);

    gnutls_x509_crt_deinit(crt);

    nm_log_info(LOGD_TOFU, "Server Name: %s, Issuer Name: %s, Organization: %s, SHA-256: %s, Expiration: %s, Best URL: %s", certificate_name, issuer_name, organization, sha256_hex, ctime(&expiration), best_url);

    dbus_manager = nm_dbus_manager_get();
    // send the method call to specific agent
    nm_certificate_agent_call_request(nm_dbus_manager_get_dbus_connection(dbus_manager), tofu_ssid, certificate_name, issuer_name, organization, sha256_hex, expiration_str, str_disclaimer, best_url);
}

GPtrArray * extract_dnsname_from_gbytes(GBytes *cert_data) {
    gnutls_x509_crt_t crt;
    gconstpointer der = g_bytes_get_data(cert_data, NULL);
    gsize der_len = g_bytes_get_size(cert_data);
    GPtrArray *urls = g_ptr_array_new_with_free_func(g_free);
    gnutls_datum_t datum;
    unsigned int idx = 0, san_type;
    void *san_data = NULL;
    size_t san_len;
    char *url = NULL;
    // Fallback: dump raw SAN extension
    unsigned char buf[2048], tag;
    size_t buf_size = sizeof(buf);
    unsigned int critical;
    size_t i = 0, len;
    // fall back to the Common Name (CN) if no SAN found
    char cn_buf[256] = {0};
    size_t cn_len = sizeof(cn_buf);

    if (!der || der_len == 0) {
        nm_log_warn(LOGD_TOFU, "No cert data provided");
        return urls;
    }

    if (gnutls_x509_crt_init(&crt) < 0) {
        nm_log_err(LOGD_TOFU, "gnutls_x509_crt_init() failed");
        return urls;
    }

    datum.data = (unsigned char *)der;
    datum.size = der_len;
    if (gnutls_x509_crt_import(crt, &datum, GNUTLS_X509_FMT_DER) < 0) {
        nm_log_err(LOGD_TOFU, "gnutls_x509_crt_import() failed");
        gnutls_x509_crt_deinit(crt);
        return urls;
    }

    while (gnutls_x509_crt_get_subject_alt_name(crt, idx++, &san_data, &san_len, &san_type) == GNUTLS_E_SUCCESS) {
        //nm_log_info(LOGD_TOFU, "  SAN[%u]: type=%u len=%zu value='%.*s'\n", idx - 1, san_type, san_len, (int)san_len, (char *)san_data);
        if (san_type == GNUTLS_SAN_DNSNAME) {
            url = g_strndup(san_data, san_len); // allocates null-terminated string
            g_ptr_array_add(urls, url);
            nm_log_info(LOGD_TOFU, "Found DNSName: %s\n", url);
            gnutls_free(san_data);
        }else if (san_type == GNUTLS_SAN_URI) {
            url = g_strndup(san_data, san_len);
            g_ptr_array_add(urls, url);
            nm_log_info(LOGD_TOFU, "Found URI: %s\n", url);
        }
        gnutls_free(san_data);
    }

    if (urls->len == 0) {
        nm_log_warn(LOGD_TOFU, "No DNSName found in SAN, trying fallback to raw SAN parse...\n");

        if (gnutls_x509_crt_get_extension_by_oid(crt, "2.5.29.17", 0, buf, &buf_size, &critical) >= 0) {
            nm_log_info(LOGD_TOFU, "Raw SAN extension (%zu bytes):\n", buf_size);
            if (buf[i++] == 0x30) { // SEQUENCE
                i++; // skip length byte
                while (i < buf_size) {
                    tag = buf[i++];
                    len = buf[i++];
                    if ((tag & 0x1F) == 2) { // [2] = DNSName
                        url = g_strndup((char *)&buf[i], len);
                        g_ptr_array_add(urls, url);
                        nm_log_info(LOGD_TOFU, "Found DNSName in raw SAN: %s", url);
                    }

                    i += len; // skip this entry
                }
            }
        } else {
            nm_log_err(LOGD_TOFU, " No SAN extension found");
            if (gnutls_x509_crt_get_dn_by_oid(crt, GNUTLS_OID_X520_COMMON_NAME, 0, 0, cn_buf, &cn_len) >= 0) {
                cn_buf[cn_len] = '\0';
                url = g_strdup(cn_buf);
                g_ptr_array_add(urls, url);
                nm_log_info(LOGD_TOFU, " Fallback CN: %s", url);
            } else {
                url = g_strdup("N/A");
                g_ptr_array_add(urls, url);
                nm_log_err(LOGD_TOFU, "No CN found, setting Best URL to N/A");
            }
        }

        
    }

    gnutls_x509_crt_deinit(crt);
    return urls; // Caller must g_free() it
}

/**
 * nm_tofu_reset_session:
 *
 * This function resets the Tofu session state, freeing any allocated resources.
 * It is called when the session is no longer needed or when a new connection
 * is initiated.
 */
void
nm_tofu_reset_session(void)
{
    if (!observed_certs)
        return;

    if (observed_certs->certs) {
        g_ptr_array_free(observed_certs->certs, TRUE);
        observed_certs->certs = NULL;
    }
    if (configured_cert) {
        if (configured_cert->certs) {
            g_ptr_array_free(configured_cert->certs, TRUE);
            configured_cert->certs = NULL;
        }
        g_free(configured_cert);
        configured_cert = NULL;
    }

    g_free(observed_certs);
    observed_certs = NULL;
    current_session_type = NM_TOFU_SESSION_TYPE_NONE;
    tofu_ssid = NULL;
    tofu_uuid = NULL;

    nm_log_info(LOGD_TOFU, "Cert session cleaned up for next connection");
}

/**
 * nm_tofu_verify_leaf_cert_with_system_ca:
 * @session: The NMTOFUCertSession containing the certificates.
 *
 * This function checks if the leaf certificate (depth 0) is trusted by the system's CA bundle.
 * It returns:
 *   - 1 if the certificate is trusted,
 *   - 0 if it is not trusted,
 *   - negative error codes for various failure conditions.
 */
int
nm_tofu_verify_leaf_cert_with_system_ca(NMTOFUCertSession *session)
{
    NMTOFUCertInfo *leaf_cert_info = NULL;
    gnutls_x509_crt_t cert;
    gnutls_x509_trust_list_t trust_list;
    gnutls_datum_t datum;
    const guint8 *cert_data;
    gsize cert_size = 0;
    unsigned int verify;
    int ret;

    if (!session || !session->certs)
        return -10;

    /* Step 1: Find the leaf certificate */
    for (guint i = 0; i < session->certs->len; i++) {
        NMTOFUCertInfo *info = g_ptr_array_index(session->certs, i);
        if (info && info->depth == 0) {
            leaf_cert_info = info;
            break;
        }
    }

    if (!leaf_cert_info)
        return -9;

    cert_data = g_bytes_get_data(leaf_cert_info->cert_data, &cert_size);
    if (!cert_data || cert_size == 0)
        return -8;

    datum.data = (unsigned char *) cert_data;
    datum.size = cert_size;

    ret = gnutls_x509_crt_init(&cert); // parase the certificate
    if (ret < 0)
        return -7;

    ret = gnutls_x509_crt_import(cert, &datum, GNUTLS_X509_FMT_DER);
    if (ret < 0) {
        gnutls_x509_crt_deinit(cert);
        return -6;
    }

    /* Step 2: Initialize the trust list and load system CAs */
    ret = gnutls_x509_trust_list_init(&trust_list, 0);
    if (ret < 0) {
        gnutls_x509_crt_deinit(cert);
        return -5;
    }

    ret = gnutls_x509_trust_list_add_system_trust(trust_list, 0, 0);
    if (ret < 0) {
        gnutls_x509_trust_list_deinit(trust_list, 1);
        gnutls_x509_crt_deinit(cert);
        return -4;
    }

    /* Step 3: Verify certificate */
    ret = gnutls_x509_trust_list_verify_crt(trust_list, &cert, 1, 0, &verify, NULL);
    gnutls_x509_trust_list_deinit(trust_list, 1);
    gnutls_x509_crt_deinit(cert);

    if (ret < 0)
        return -3;

    if (verify == 0)
        return 1;  /* Trusted */
    else
        return 0;  /* Not trusted */
}

/**
 * tofu_deauthenticate_connection_by_ssid:
 * @ssid_target: The SSID of the connection to deauthenticate.
 *
 * This function deauthenticates the active connection with the specified SSID.
 * It iterates through all active connections, checks their SSIDs, and deactivates
 * the one that matches the given SSID.
 */
void
tofu_deauthenticate_connection_by_ssid(const char *ssid_target)
{
    NMManager *manager = nm_manager_get();
    const CList *iter, *active_connections_lst;
    NMActiveConnection *ac;
    NMSettingsConnection *sconn;
    NMConnection *conn;
    const char *id;
    GError *error = NULL;
    NMDevice *device = NULL;

    if (!manager || !ssid_target) {
        nm_log_err(LOGD_TOFU, "Manager or SSID is NULL");
        return;
    }

    active_connections_lst = nm_manager_get_active_connections(manager);
    if (!active_connections_lst || c_list_is_empty(active_connections_lst)) {
        nm_log_info(LOGD_TOFU, "No active connections to consider for SSID=%s", ssid_target);
        return;
    }

    c_list_for_each(iter, active_connections_lst) {
        ac = c_list_entry(iter, NMActiveConnection, active_connections_lst);
        sconn = nm_active_connection_get_settings_connection(ac);
        device = nm_active_connection_get_device(ac);
        if (!sconn)
            continue;

        conn = nm_settings_connection_get_connection(sconn);
        if (!conn)
            continue;

        id = nm_settings_connection_get_id(sconn);
        if (g_strcmp0(id, ssid_target) == 0) {
            nm_log_info(LOGD_TOFU, "Deauthenticating connection with SSID=%s", ssid_target);
            nm_manager_deactivate_connection(manager, ac, NM_DEVICE_STATE_REASON_USER_REQUESTED, &error);
            nm_device_state_changed(device, NM_DEVICE_STATE_DISCONNECTED, NM_DEVICE_STATE_REASON_USER_REQUESTED);
            return;
        }
    }

    nm_log_info(LOGD_TOFU, "No active connection found with SSID=%s", ssid_target);
}


/**
 * @brief Sets the autoconnect property for a given SSID.
 *
 * This function modifies the autoconnect setting for a connection profile
 * identified by its SSID. It updates the setting in persistent storage.
 *
 * @param ssid_target The SSID of the Wi-Fi connection to modify.
 * @param enable_autoconnect TRUE to enable autoconnect, FALSE to disable.
 */
void
tofu_set_autoconnect_for_ssid(const char *ssid_target, gboolean enable_autoconnect)
{
    NMManager *manager = nm_manager_get();
    NMSettings *settings = nm_settings_get();
    NMSettingsConnection *const *connections;
    NMSettingsConnection *sconn;
    NMSettingConnection *s_con;
    NMConnection *conn, *new_conn;
    guint n_conn, i;
    const char *id = NULL;
    GError *error = NULL;

    if (!manager || !settings || !ssid_target) {
        nm_log_err(LOGD_TOFU, "Missing manager/settings/SSID input");
        return;
    }

    connections = nm_settings_get_connections(settings, &n_conn);
    for (i = 0; i < n_conn; i++) {
        sconn = connections[i];
        if (!sconn) {
            nm_log_warn(LOGD_TOFU, "No 'connection' setting in connection %s", id);
            return;
        }

        id = nm_settings_connection_get_id(sconn);
        if (g_strcmp0(id, ssid_target) == 0) {

            conn = nm_settings_connection_get_connection(sconn);
            new_conn = nm_simple_connection_new_clone(conn);
            s_con = nm_connection_get_setting_connection(new_conn);
            if (!s_con) {
                nm_log_warn(LOGD_TOFU, "No 'connection' setting in connection %s", id);
                return;
            }

            // Check if the setting is already what we want it to be
            if (nm_setting_connection_get_autoconnect (s_con) == enable_autoconnect) {
                nm_log_warn(LOGD_TOFU, "Autoconnect for SSID %s is already set to %d.", ssid_target, enable_autoconnect);
                return;
            }

            g_object_set(s_con, NM_SETTING_CONNECTION_AUTOCONNECT, enable_autoconnect, NULL);

            if (!nm_settings_connection_update(
                                sconn,
                                "keyfile",
                                new_conn,
                                NM_SETTINGS_CONNECTION_PERSIST_MODE_KEEP,
                                NM_SETTINGS_CONNECTION_INT_FLAGS_NONE,
                                NM_SETTINGS_CONNECTION_INT_FLAGS_NONE,
                                NM_SETTINGS_CONNECTION_UPDATE_REASON_NONE,
                                "tofu",
                                &error)) {
                            nm_log_err(LOGD_TOFU, "Failed to update autoconnect for SSID=%s, reason = %s", ssid_target, error ? error->message : "Unknown error");
                            g_error_free(error);
                            return;
            }

            nm_log_info(LOGD_TOFU, "Successfully set autoconnect=%s for SSID=%s",
                        enable_autoconnect ? "TRUE" : "FALSE", ssid_target);
            return;
        }
    }

    nm_log_info(LOGD_TOFU, "No matching connection found with SSID=%s", ssid_target);
}

/**
 * @brief Authenticates a connection by its SSID.
 *
 * This function attempts to activate a connection profile identified by its SSID.
 * It retrieves the connection settings and activates it on the best available device.
 *
 * @param ssid_target The SSID of the Wi-Fi connection to authenticate.
 * Be careful with this function, it will activate the connection, when the the state is idle or unused.
 */
void
tofu_authenticate_connection_by_ssid(const char *ssid_target)
{
    NMManager *manager = NULL;
    NMSettings *settings = NULL;
    NMSettingsConnection *const *connections;
    NMSettingsConnection *sconn;
    NMConnection *conn;
    NMSettingConnection *s_con;
    NMDevice *device;
    guint n_conn, i;
    const char *id, *ifname;
    GError *error = NULL;
    NMAuthSubject *subject;

    manager = nm_manager_get();
    settings = nm_settings_get();

    if (!manager || !settings || !ssid_target) {
        nm_log_err(LOGD_TOFU, "Missing manager/settings/SSID input");
        return;
    }

    connections = nm_settings_get_connections(settings, &n_conn);
    for (i = 0; i < n_conn; i++) {
        sconn = connections[i];
        id = nm_settings_connection_get_id(sconn);

        if (g_strcmp0(id, ssid_target) == 0) {

            conn = nm_simple_connection_new_clone(nm_settings_connection_get_connection(sconn));
            if (!conn) {
                nm_log_warn(LOGD_TOFU, "Connection object is NULL for SSID=%s", ssid_target);
                return;
            }

            //device = nm_manager_get_best_device_for_connection(manager, conn, NULL);
            //ifname = nm_setting_wireless_get_ifname(nm_connection_get_setting_wireless(conn));
            s_con = nm_connection_get_setting_connection(conn);
            ifname = nm_setting_connection_get_interface_name(s_con);
            if (!ifname) {
                nm_log_warn(LOGD_TOFU, "No interface name found for SSID=%s", ssid_target);
                return;
            }
            device = nm_manager_get_device(manager, ifname, NM_DEVICE_TYPE_WIFI);

            if (!device) {
                nm_log_warn(LOGD_TOFU, "No suitable device found for SSID=%s", ssid_target);
                return;
            }

            nm_log_info(LOGD_TOFU, "Attempting to activate connection for SSID=%s on device=%s",
                        ssid_target, nm_device_get_iface(device));

            subject = nm_auth_subject_new_internal();
            //nm_log_info(LOGD_TOFU, "Device=%s type=%d managed=%d available=%d", nm_device_get_iface(device), nm_device_get_device_type(device), nm_device_get_managed(device), nm_device_get_available(device));
            //nm_log_info(LOGD_TOFU, "Subject type = %d", nm_auth_subject_get_subject_type(subject));
            if (!nm_manager_activate_connection(
                    manager,
                    sconn,
                    conn,
                    NULL,  // specific_object
                    device,
                    subject,
                    NM_ACTIVATION_TYPE_MANAGED, // Use INTERNAL for Tofu
                    NM_ACTIVATION_REASON_USER_REQUEST,
                    NM_ACTIVATION_STATE_FLAG_NONE,
                    &error)) {
                nm_log_err(LOGD_TOFU, "Failed to activate connection for SSID=%s: %s",
                        ssid_target, error ? error->message : "unknown error");
                g_clear_error(&error);
            } else {
                nm_log_info(LOGD_TOFU, "Successfully initiated authentication for SSID=%s", ssid_target);
            }
            return;


        }
    }

    nm_log_info(LOGD_TOFU, "No matching connection found with SSID=%s", ssid_target);
}

void
tofu_remove_connection(const char *ssid)
{
    NMSettings *settings;
    NMSettingsConnection *const *connections;
    guint n_conn;
    const char *id = NULL;

    if (!ssid) {
        nm_log_err(LOGD_TOFU, "Missing SSID input");
        return;
    }


    settings = nm_settings_get();
    connections = nm_settings_get_connections(settings, &n_conn);

    for (guint i = 0; i < n_conn; i++) {
        id = nm_settings_connection_get_id(connections[i]);

        if (g_strcmp0(id, ssid) == 0) {
            nm_log_info(LOGD_TOFU, "[TOFU] Removing saved profile for SSID: %s", ssid);

            // Remove the connection; TRUE = save to disk (i.e., remove from persistent storage)
            nm_settings_connection_delete(connections[i], FALSE);

            return;
        }
    }

    nm_log_warn(LOGD_TOFU, "[TOFU] No matching connection found to remove for SSID: %s", ssid);
}
/**
 * @brief Adds a timestamp to the connection profile for the given SSID.
 *
 * This function updates the connection profile with a timestamp indicating
 * when the connection was last modified or created. It is useful for tracking
 * when the connection was established.
 * 
 * This function is called for the tofu senario to add a timestamp because to avoid request secrets prompt due to delay in the EAP authentication
 * @param ssid The SSID of the Wi-Fi connection to update.
 */
void
tofu_add_timestamp_to_connection(const char *ssid)
{
    NMSettings *settings;
    NMSettingsConnection *const *connections;
    NMSettingsConnection *sconn;
    guint n_conn;
    const char *id = NULL;
    guint64 now;

    if (!ssid) {
        nm_log_err(LOGD_TOFU, "Missing SSID input");
        return;
    }

    settings = nm_settings_get();
    connections = nm_settings_get_connections(settings, &n_conn);

    for (guint i = 0; i < n_conn; i++) {
        sconn = connections[i];
        id = nm_settings_connection_get_id(sconn);

        if (g_strcmp0(id, ssid) == 0) {
            nm_log_info(LOGD_TOFU, "Adding timestamp to connection for SSID: %s", ssid);
            now = (guint64) time(NULL);

            // Add timestamp logic here
            nm_settings_connection_update_timestamp(sconn, now);

            return;
        }
    }

    nm_log_warn(LOGD_TOFU, "[TOFU] No matching connection found to add timestamp for SSID: %s", ssid);
}
/*
this function is to verify server certificate against the CA cert saved in the configuration file
*/
void
nm_tofu_verify_leaf_cert_with_config_ca(const char *ssid, NMTOFUCertSession *config_cert_data, NMTOFUCertSession *wpa_cert_data)
{
    // Extract certs
    NMTOFUCertInfo *config_ca = NULL, *server_ca = NULL, *leaf_cert = NULL, *info = NULL;
    guint i;
    // verification variables
    gnutls_x509_crt_t crt_leaf, crt_config_ca, crt_server_ca;
    gnutls_datum_t leaf_data, ca_config_data, ca_server_data;
    gnutls_x509_crt_t ca_list[1];
    unsigned int verify_result = 0;
    int ret;

    nm_log_info(LOGD_TOFU, "Verifying leaf certificate for SSID=%s", ssid);
    if (!config_cert_data || !config_cert_data->certs->len) {
        nm_log_warn(LOGD_TOFU, "[NON-TOFU] No CA cert saved from config.");
        return;
    }

    if (!wpa_cert_data || !wpa_cert_data->certs->len) {
        nm_log_warn(LOGD_TOFU, "[NON-TOFU] No certs received from server.");
        return;
    }
    // Get the CA cert from config
    config_ca = g_ptr_array_index(config_cert_data->certs, 0);

    server_ca = g_ptr_array_index(wpa_cert_data->certs, 0); // extract the first cert as server CA, if it doesn't present any CA cert, then it will be same server certificate evntually it will fail comparison

    for (i = 0; i < wpa_cert_data->certs->len; i++) {
        info = g_ptr_array_index(wpa_cert_data->certs, i);
        if (info && info->depth == 0)
            leaf_cert = info;
    }

    if (!leaf_cert || !server_ca) {
        nm_log_warn(LOGD_TOFU, "[NON-TOFU] Missing leaf or CA cert in WPA cert data.");
        return;
    }

    // Verify leaf cert using config CA cert via GnuTLS
    leaf_data.data = (unsigned char *) g_bytes_get_data(leaf_cert->cert_data, NULL);
    leaf_data.size = g_bytes_get_size(leaf_cert->cert_data);

    ca_server_data.data = (unsigned char *) g_bytes_get_data(server_ca->cert_data, NULL);
    ca_server_data.size = g_bytes_get_size(server_ca->cert_data);

    ca_config_data.data = (unsigned char *) g_bytes_get_data(config_ca->cert_data, NULL);
    ca_config_data.size = g_bytes_get_size(config_ca->cert_data);


    gnutls_x509_crt_init(&crt_leaf);
    gnutls_x509_crt_init(&crt_config_ca);
    gnutls_x509_crt_init(&crt_server_ca);

    if (gnutls_x509_crt_import(crt_leaf, &leaf_data, GNUTLS_X509_FMT_DER) != GNUTLS_E_SUCCESS ||
        gnutls_x509_crt_import(crt_config_ca, &ca_config_data, GNUTLS_X509_FMT_PEM) != GNUTLS_E_SUCCESS ||
        gnutls_x509_crt_import(crt_server_ca, &ca_server_data, GNUTLS_X509_FMT_DER) != GNUTLS_E_SUCCESS) {
        nm_log_warn(LOGD_TOFU, "[NON-TOFU] Failed to parse certs.");
        gnutls_x509_crt_deinit(crt_leaf);
        gnutls_x509_crt_deinit(crt_config_ca);
        gnutls_x509_crt_deinit(crt_server_ca);
        return;
    }

    ca_list[0] = crt_config_ca;
    ret = gnutls_x509_crt_verify(crt_leaf, ca_list, 1, 0, &verify_result);


    // Do the comparion between the CA cert in the configuration and the received ca cert from wpa_supplicant 
    // strict comparison
    if (gnutls_x509_crt_equals(crt_config_ca, crt_server_ca)) {
        nm_log_info(LOGD_TOFU, "[NON-TOFU] Config CA cert exactly matches server CA cert.");
    } else {
        nm_log_warn(LOGD_TOFU, "[NON-TOFU] CA cert mismatch! Cert content is different.");
    }

    gnutls_x509_crt_deinit(crt_leaf);
    gnutls_x509_crt_deinit(crt_config_ca);
    gnutls_x509_crt_deinit(crt_server_ca);
    // Check the verification result
    if (ret < 0 || verify_result != 0) {
        nm_log_warn(LOGD_TOFU, "[NON-TOFU] Leaf cert verification against config CA failed! (0x%x)", verify_result);
        // The user GUI allows to modify the connection when it is not connected, we do not need to remove the connection profile completely
        tofu_set_autoconnect_for_ssid(ssid, FALSE);
        tofu_deauthenticate_connection_by_ssid(ssid);
        //tofu_remove_connection(ssid);

        //send the warning signal to the user
        nm_dbus_emit_cert_verification_failure_signal(ssid);
    } else {
        nm_log_info(LOGD_TOFU, "[NON-TOFU] Leaf cert successfully verified with config CA.");
    }

}

/**
 * @brief Emits a D-Bus signal indicating a certificate verification failure.
 *
 * This function emits a D-Bus signal to notify that the certificate verification
 * for a specific SSID has failed.
 *
 * @param ssid The SSID of the connection for which the verification failed.
 */
void
nm_dbus_emit_cert_verification_failure_signal(const char *ssid)
{
    NMDBusManager *dbus_manager;
    dbus_manager = nm_dbus_manager_get();
    nm_log_info(LOGD_TOFU, "[NM->CertAgent] Method call for certificate verification failure signal for SSID: %s", ssid);
    // send cert failure method call to the specific registered agent
    nm_certificate_agent_notify_certificate_failure(nm_dbus_manager_get_dbus_connection(dbus_manager), ssid, "hello");
}

/**
 * @brief Saves non-TOFU CA certificate data.
 *
 * This function saves the CA certificate data that is mentioned in the configuration.
 * It initializes a new NMTOFUCertSession and stores the certificate data in it.
 *
 * @param cert_data The GBytes containing the CA certificate data to save.
 */
void
nm_save_config_ca_cert_data(GBytes *cert_data)
{
    NMTOFUCertInfo *info = NULL;
    nm_log_info(LOGD_TOFU, "saving the cert data which mentioned in the config");
    if (configured_cert) {
        // clean up if needed
        g_ptr_array_unref(configured_cert->certs);
        g_free(configured_cert);
    }

    configured_cert = g_new0(NMTOFUCertSession, 1);
    configured_cert->certs = g_ptr_array_new_with_free_func((GDestroyNotify) g_free);

    info = g_new0(NMTOFUCertInfo, 1);
    info->cert_data = g_bytes_ref(cert_data); // retain our own copy

    g_ptr_array_add(configured_cert->certs, info);
    configured_cert->finalized = TRUE;

    nm_log_info(LOGD_TOFU, "configured_cert updated with cert_data (%zu bytes)", g_bytes_get_size(cert_data));
}

/**
 * tofu_list_everything:
 *
 * This function lists all connections, devices, and active connections
 * in the NetworkManager. It retrieves the NMManager, NMSettings, and
 * iterates through the connections and devices, logging their details.
 */
// very important function to list all connections, devices, and active connections, can be used for debugging and monitoring purposes and writing new functions for modifying connections or devices
void
tofu_list_everything(void)
{

    NMManager *manager = nm_manager_get();
    //GError *error = NULL;
    NMSettings *settings = NULL;
    NMSettingsConnection *const *connections = NULL;
    NMSettingsConnection *sconn = NULL;
    NMConnection *conn = NULL;
    guint n_conn = 0, i = 0;
    const char *uuid = NULL, *id = NULL;

    const CList *devices_lst, *active_connections_lst;
    const CList *iter;
    NMDevice *device = NULL;
    const char *iface = NULL;
    //const char *path = NULL;
    NMActiveConnection *ac = NULL;


    if (!manager) {
        nm_log_err(LOGD_TOFU, "Failed to get default NMManager");
        return;
    }
    nm_log_info(LOGD_TOFU, "Default NMManager obtained successfully");

    settings = nm_settings_get();
    if (!settings) {
        nm_log_err(LOGD_TOFU, "Failed to get NMSettings from NMManager");
        return;
    }
    nm_log_info(LOGD_TOFU, "NMSettings obtained successfully");

    connections = nm_settings_get_connections(settings, &n_conn);
    if (n_conn == 0) {
        nm_log_info(LOGD_TOFU, "No connections found in NMSettings");
        return;
    }
    nm_log_info(LOGD_TOFU, "Found %d connections in NMSettings", n_conn);

    for (i = 0; i < n_conn; i++) {
        sconn = connections[i];
        if (!sconn) {
            nm_log_warn(LOGD_TOFU, "Connection at index %d is NULL", i);
            continue;
        }
        conn = nm_settings_connection_get_connection(sconn);
        if (!conn) {
            nm_log_warn(LOGD_TOFU, "Connection object at index %d is NULL", i);
            continue;
        }
        uuid = nm_settings_connection_get_uuid(sconn);
        id = nm_settings_connection_get_id(sconn);
        nm_log_info(LOGD_TOFU, "Connection %d: UUID=%s ID=%s", i, uuid, id);
    }
    //g_ptr_array_free(connections, TRUE);
    nm_log_info(LOGD_TOFU, "Listing all connections completed");

    // Optionally, you can also list devices or other relevant information here
    devices_lst = nm_manager_get_devices(manager);
    if (!devices_lst) {
        nm_log_info(LOGD_TOFU, "No devices found in NMManager");
        return;
    }
    nm_log_info(LOGD_TOFU, "Found %zu devices in NMManager", c_list_length(devices_lst));

    c_list_for_each(iter, devices_lst) {
        device = c_list_entry(iter, NMDevice, devices_lst);
        // Do something with device
        iface = nm_device_get_iface(device);
        //path = nm_object_get_path(NM_OBJECT(device));
        if (!iface) {
            nm_log_warn(LOGD_TOFU, "Device at has NULL iface");
            continue;
        }
        nm_log_info(LOGD_TOFU, "Device: Interface=%s", iface);
        //nm_log_info(LOGD_TOFU, "Device: Path=%s", path);
    }


    // Optionally, you can also list active connections or other relevant information here
    active_connections_lst = nm_manager_get_active_connections(manager);
    if (!active_connections_lst) {
        nm_log_info(LOGD_TOFU, "No active connections found in NMManager");
        return;
    }
    nm_log_info(LOGD_TOFU, "Found %zu active connections in NMManager", c_list_length(active_connections_lst));

    c_list_for_each(iter, active_connections_lst) {
        ac = c_list_entry(iter, NMActiveConnection, active_connections_lst);
        sconn = nm_active_connection_get_settings_connection(ac);
        if (!ac) {
            nm_log_warn(LOGD_TOFU, "Active connection is NULL");
            continue;
        }
        uuid = nm_settings_connection_get_uuid(sconn);
        id = nm_settings_connection_get_id(sconn);
        if (!uuid || !id) {
            nm_log_warn(LOGD_TOFU, "Active connection UUID or ID is NULL");
            continue;
        }
        nm_log_info(LOGD_TOFU, "Active Connection: UUID=%s ID=%s", uuid, id);

    }
    nm_log_info(LOGD_TOFU, "Listing all active connections completed");
}