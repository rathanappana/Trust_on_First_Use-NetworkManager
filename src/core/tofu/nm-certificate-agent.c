#include "src/core/nm-default-daemon.h"
#include "nm-certificate-agent.h"
#include "nm-tofu.h"

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

/* ---------------------------------------------------- */

// To store the agent details at the time of the registration
typedef struct {
    char   *unique;     /* :1.x  unique bus identifier */
    char   *obj_path;   /* /org/freedesktop/NetworkManager/CertificateAgent */
    guint   watch_id;   /* NameOwnerChanged subscription */
    guint32 uid;        /* for selection policy */
    guint64 registered_msec;
} CertificateAgent;

// List of all registered certificate agents
static GPtrArray *s_agents;

/* ---------- tiny helpers ---------- */

static void agents_ensure(void) {
    if (!s_agents)
        s_agents = g_ptr_array_new();  // <-- NOT new_with_free_func
}

/* ---------- Cleaning agents ---------- */
/* We wrapped CertificateAgent free to also unsubscribe. */
static void
certificate_agent_destroy_full(CertificateAgent *agent, GDBusConnection *conn)
{
    if (!agent)
        return;

    if (agent->watch_id) {
        g_dbus_connection_signal_unsubscribe(conn, agent->watch_id);
        agent->watch_id = 0;
    }
    nm_log_info(LOGD_TOFU, "CertificateAgent %s destroyed", agent->unique);

    g_free(agent->unique);
    g_free(agent->obj_path);
    g_free(agent);
}

/* Remove by index (fast) */
static void certificate_agents_remove_idx(guint idx, GDBusConnection *conn) {
    CertificateAgent *agent = g_ptr_array_index(s_agents, idx);
    nm_log_info(LOGD_TOFU, "Removing CertificateAgent %s at index %u", agent->unique, idx);
    /* free first, then remove the pointer from the array */
    certificate_agent_destroy_full(agent, conn);
    g_ptr_array_remove_index_fast(s_agents, idx);
}

static gboolean
certificate_agents_remove_by_unique(const char *unique, GDBusConnection *conn)
{
    guint i;
    CertificateAgent *agent;

    if (!s_agents)
        return FALSE;

    for (i = 0; i < s_agents->len; i++) {
        agent = g_ptr_array_index(s_agents, i);
        if (g_strcmp0(agent->unique, unique) == 0) {
            nm_log_info(LOGD_TOFU, "Removing unique CertificateAgent %s at index %u", unique, i);
            certificate_agents_remove_idx(i, conn);
            return TRUE;
        }
    }
    return FALSE;
}

/* ---------------------------------------------------- */

// uid lookup for selection; best effort, the best thing to select the agents with user uid as it was desktop
static guint32
uid_for_unique (GDBusConnection *conn, const char *unique)
{
    GError   *e   = NULL;
    GVariant *v   = NULL;
    guint32   uid = G_MAXUINT32;  /* sentinel */

    v = g_dbus_connection_call_sync(conn,
                                    "org.freedesktop.DBus",
                                    "/org/freedesktop/DBus",
                                    "org.freedesktop.DBus",
                                    "GetConnectionUnixUser",
                                    g_variant_new("(s)", unique),
                                    G_VARIANT_TYPE("(u)"),     /* <- expect a tuple with one uint32 */
                                    G_DBUS_CALL_FLAGS_NONE,
                                    2000,
                                    NULL,
                                    &e);
    if (!v) {
        if (e)
            g_error_free(e);
        return G_MAXUINT32;
    }

    /* Unpack the one-element tuple */
    g_variant_get(v, "(u)", &uid);
    g_variant_unref(v);
    return uid;
}

/* ---------- DBus watch ---------- */

// look for changes in the owner of the DBus name means the agent is being activated or deactivated, so we clean the agent on the deactivation
static void on_name_owner_changed(GDBusConnection *conn,
                                  const gchar *sender_name,
                                  const gchar *object_path,
                                  const gchar *iface,
                                  const gchar *signal,
                                  GVariant *params,
                                  gpointer user_data)
{
    const char *name, *old_owner, *new_owner;
    guint i;
    CertificateAgent *agent;
    g_variant_get(params, "(&s&s&s)", &name, &old_owner, &new_owner);

    if (!s_agents)
        return;

    if (new_owner && *new_owner == '\0' && old_owner && *old_owner != '\0') {
        /* unique name disconnected -> drop agent */
        for (i = 0; i < s_agents->len; i++) {
            agent = g_ptr_array_index(s_agents, i);
            if (g_strcmp0(agent->unique, name) == 0) {
                nm_log_info(LOGD_TOFU, "CertificateAgent %s vanished; unregistering", name);
                certificate_agents_remove_by_unique(name, conn);
                break;
            }
        }
    }
}

/* ---------- API ---------- */

// Agent registration from GUI agents
gboolean nm_certificate_agent_register(GDBusConnection *conn,
                        const char *sender_unique,
                        const char *object_path,
                        GDBusMethodInvocation *inv)
{
    guint i;
    CertificateAgent *agent;
    g_return_val_if_fail(conn && sender_unique && object_path, FALSE);
    if (!g_str_equal(object_path, "/org/freedesktop/NetworkManager/CertificateAgent")) {
        g_dbus_method_invocation_return_error(inv, G_DBUS_ERROR, G_DBUS_ERROR_INVALID_ARGS,
                                              "Bad object path: %s", object_path);
        return FALSE;
    }

    agents_ensure();

    /* Replace if the same sender re-registers. */
    for (i=0; i<s_agents->len; i++) {
        agent = g_ptr_array_index(s_agents, i);
        if (g_strcmp0(agent->unique, sender_unique)==0) {
            certificate_agents_remove_by_unique(sender_unique, conn);
            break;
        }
    }

    agent = g_new0(CertificateAgent, 1);
    agent->unique          = g_strdup(sender_unique);
    agent->obj_path        = g_strdup(object_path);
    agent->registered_msec = nm_utils_get_monotonic_timestamp_msec();
    agent->uid             = uid_for_unique(conn, sender_unique);

    agent->watch_id = g_dbus_connection_signal_subscribe(
        conn,
        "org.freedesktop.DBus",
        "org.freedesktop.DBus",
        "NameOwnerChanged",
        "/org/freedesktop/DBus",
        agent->unique,                                /* arg0 filter */
        G_DBUS_SIGNAL_FLAGS_NONE,
        on_name_owner_changed, NULL, NULL);

    g_ptr_array_add(s_agents, agent);

    nm_log_info(LOGD_TOFU, "Registered CertificateAgent: unique=%s path=%s uid=%u",
                 agent->unique, agent->obj_path, agent->uid);
    g_dbus_method_invocation_return_value(inv, NULL);
    return TRUE;
}

// To handle the unregistration of the agents, (method call doesn't exist yet)
gboolean nm_certificate_agent_unregister(GDBusConnection *conn,
                          const char *sender_unique,
                          GDBusMethodInvocation *inv)
{
    guint i;
    CertificateAgent *agent;

    if (!s_agents) {
        g_dbus_method_invocation_return_error(inv, G_DBUS_ERROR,
                                              G_DBUS_ERROR_ACCESS_DENIED,
                                              "No agents registered");
        return FALSE;
    }
    for (i=0; i<s_agents->len; i++) {
        agent = g_ptr_array_index(s_agents, i);
        if (g_strcmp0(agent->unique, sender_unique)==0) {
            certificate_agents_remove_by_unique(sender_unique, conn);
            nm_log_info(LOGD_TOFU, "CertificateAgent %s unregistered", sender_unique);
            g_dbus_method_invocation_return_value(inv, NULL);
            return TRUE;
        }
    }
    g_dbus_method_invocation_return_error(inv, G_DBUS_ERROR,
                                          G_DBUS_ERROR_ACCESS_DENIED,
                                          "No registered agent for this sender");
    return FALSE;
}

/* ---------- Selection of the agent ---------- */
// Choose newest non-root; if none, newest overall
gboolean nm_certificate_agent_pick(char **out_unique, char **out_obj_path)
{
    CertificateAgent *best = NULL, *agent;
    if (!s_agents || s_agents->len == 0) return FALSE;

    for (gint i=(gint)s_agents->len-1; i>=0; i--) {
        agent = g_ptr_array_index(s_agents, i);
        if (agent->uid != 0) { best = agent; break; }
        if (!best) best = agent;
    }
    if (!best) return FALSE;
    *out_unique = best->unique;
    *out_obj_path = best->obj_path;
    return TRUE;
}

/* ---------------------------------------------------- */

static void certificate_agent_handle_user_response(gboolean user_response, const char *ssid)
{
    // send response properly to the nm-tofu core logic or directly we can use the below function to send the response to the
    tofu_handle_cert_verification_response(user_response, ssid);
}

/* -------------------- Save the request context -------------------------------- */
// to save the request context so the response can be properly handled later
// it doesn't require at the agent level but requires at the tofu core level, to avoid fake test signals
typedef struct {
    char *dest_unique;   /* for logging / optional cleanup */
    char *ssid;          /* optional: for logs */
} CertCallCtx;

/* ---- async reply handler from the agent ---- */

static void
cert_req_cb(GObject *src, GAsyncResult *res, gpointer user_data)
{
    CertCallCtx *ctx;
    GError      *err;
    GVariant    *r;
    gboolean     response;
    gchar       *remote;

    ctx  = (CertCallCtx *) user_data;
    err  = NULL;
    r    = g_dbus_connection_call_finish(G_DBUS_CONNECTION(src), res, &err);

    if (!r) {
        /* classify common failure modes for easier debugging */
        if (g_error_matches(err, G_IO_ERROR, G_IO_ERROR_TIMED_OUT) || g_error_matches(err, G_DBUS_ERROR, G_DBUS_ERROR_NO_REPLY)) {
            nm_log_err(LOGD_TOFU,
                       "[CertAgent %s] timeout waiting for reply (SSID=%s, %u ms)",
                       ctx && ctx->dest_unique ? ctx->dest_unique : NULL,
                       ctx && ctx->ssid ? ctx->ssid : NULL,
                       (unsigned) NM_CERT_AGENT_TIMEOUT_MS);

            /* === future: retry with another agent ===
            // if (certificate_agents_remove_by_unique && ctx->dest_unique)
            //     certificate_agents_remove_by_unique(ctx->dest_unique, G_DBUS_CONNECTION(src));
            // nm_certificate_agent_call_request(G_DBUS_CONNECTION(src), ctx->ssid, ...);
            */

            /* For now, treat as declined */
            certificate_agent_handle_user_response(FALSE, ctx->ssid);

        } else if (g_error_matches(err, G_DBUS_ERROR, G_DBUS_ERROR_SERVICE_UNKNOWN) || g_error_matches(err, G_DBUS_ERROR, G_DBUS_ERROR_NAME_HAS_NO_OWNER)) {
            nm_log_err(LOGD_TOFU,
                       "[CertAgent %s] agent disappeared during request (SSID=%s): %s",
                       ctx && ctx->dest_unique ? ctx->dest_unique : NULL,
                       ctx && ctx->ssid ? ctx->ssid : NULL,
                       err->message);

            /* === future: drop dead agent & try next ===
            // if (certificate_agents_remove_by_unique && ctx->dest_unique)
            //     certificate_agents_remove_by_unique(ctx->dest_unique, G_DBUS_CONNECTION(src));
            // nm_certificate_agent_call_request(G_DBUS_CONNECTION(src), ctx->ssid, ...);
            */

            certificate_agent_handle_user_response(FALSE, ctx->ssid);

        } else {
            remote = g_dbus_error_get_remote_error(err);
            nm_log_err(LOGD_TOFU,
                       "[CertAgent %s] call failed (SSID=%s): %s%s%s",
                       ctx && ctx->dest_unique ? ctx->dest_unique : NULL,
                       ctx && ctx->ssid ? ctx->ssid : NULL,
                       err->message,
                       remote ? " [remote=" : "",
                       remote ? remote : "");
            /* if (remote) g_dbus_error_strip_remote_error(err); */ /* optional */

            /* === future: maybe notify the agent UI about failure ===
            // nm_certificate_agent_notify_failure(G_DBUS_CONNECTION(src),
            //     ctx->dest_unique, ctx->path, ctx->ssid, "Verification failed.");
            */

            certificate_agent_handle_user_response(FALSE, ctx->ssid);
        }

        g_clear_error(&err);
        goto out;
        return;
    }

    /* Success path: extract OUT bool "(b)" */
    g_variant_get(r, "(b)", &response);
    g_variant_unref(r);

    nm_log_info(LOGD_TOFU, "[CertAgent %s] user %s certificate (SSID=%s)", ctx && ctx->dest_unique ? ctx->dest_unique : NULL, response ? "ACCEPTED" : "REJECTED", ctx && ctx->ssid ? ctx->ssid : NULL);

    certificate_agent_handle_user_response(response, ctx->ssid);

out:
    g_free(ctx->dest_unique);
    g_free(ctx->ssid);
    g_free(ctx);
}

/* ---------------------- Method call implementation here ------------------------------ */

void
nm_certificate_agent_call_request(GDBusConnection *conn,
                        const char *ssid, const char *cn, const char *issuer, const char *org,
                        const char *sha256, const char *exp, const char *disc, const char *url)
{
    char *dest=NULL, *path=NULL;
    CertCallCtx *ctx = g_new0(CertCallCtx, 1);
    if (!nm_certificate_agent_pick(&dest, &path)) {
        nm_log_warn(LOGD_TOFU, "No CertificateAgent available");
        g_free(ctx);
        return;
    }
    nm_log_info(LOGD_TOFU, "[NM->CertAgent] Calling method call on CertificateAgent %s at %s for SSID=%s", dest, path, ssid);
    ctx->dest_unique = g_strdup(dest);
    ctx->ssid        = g_strdup(ssid);
    g_dbus_connection_call(conn,
        dest, path,
        "org.freedesktop.NetworkManager.CertificateAgent",
        "CertificateVerificationRequest",
        g_variant_new("(ssssssss)", ssid, cn, issuer, org, sha256, exp, disc, url),
        G_VARIANT_TYPE("(b)"),
        G_DBUS_CALL_FLAGS_NONE,
        NM_CERT_AGENT_TIMEOUT_MS, //keep the generous amount of time so that user can respond in time, which is 3 minutes
        NULL, cert_req_cb, ctx);
}

void
nm_certificate_agent_notify_certificate_failure(GDBusConnection *conn,
                                                const char *ssid, const char *msg)
{
    char *dest=NULL, *path=NULL;
    if (!nm_certificate_agent_pick(&dest, &path)) {
        nm_log_warn(LOGD_TOFU, "No CertificateAgent available");
        return;
    }

    g_dbus_connection_call(conn,
        dest, path,
        "org.freedesktop.NetworkManager.CertificateAgent",
        "CertificateVerificationFailure",
        g_variant_new("(ss)", ssid, msg),
        NULL,
        G_DBUS_CALL_FLAGS_NONE,
        0, NULL, NULL, NULL);
}