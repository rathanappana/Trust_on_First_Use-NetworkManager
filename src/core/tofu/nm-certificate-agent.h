#ifndef NM_CERTIFICATE_AGENT_H
#define NM_CERTIFICATE_AGENT_H

#include "nm-dbus-manager.h"           /* for nm_dbus_manager_get_dbus_connection() */

#define NM_CERT_AGENT_TIMEOUT_MS 180000 /* 3 min; pick 120000–300000 or use G_MAXINT to make no timeout */

gboolean nm_certificate_agent_register   (GDBusConnection *conn,
                           const char      *sender_unique,
                           const char      *object_path,
                           GDBusMethodInvocation *invocation);

gboolean nm_certificate_agent_unregister (GDBusConnection *conn,
                           const char      *sender_unique,
                           GDBusMethodInvocation *invocation);

/* Choose one agent for a request. Returns FALSE if none. */
gboolean nm_certificate_agent_pick       (char **out_unique, char **out_object_path);

/* Fire the method call CertificateVerification request. */
void     nm_certificate_agent_call_request(GDBusConnection *conn,
                            const char *ssid, const char *cn, const char *issuer, const char *org,
                            const char *sha256, const char *exp, const char *disc, const char *url);

void nm_certificate_agent_notify_certificate_failure(GDBusConnection *conn,
                    const char *ssid, const char *msg);
#endif /* NM_CERTIFICATE_AGENT_H */