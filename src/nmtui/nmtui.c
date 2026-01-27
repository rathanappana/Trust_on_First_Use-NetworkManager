/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2013 Red Hat, Inc.
 */

/**
 * SECTION:nmtui
 * @short_description: nmtui toplevel
 *
 * The top level of nmtui. Exists mostly just to call nmtui_connect(),
 * nmtui_edit(), and nmtui_hostname().
 */

#include "libnm-client-aux-extern/nm-default-client.h"

#include "nmtui.h"

#include <locale.h>
#include <stdlib.h>

#include "libnm-client-aux-extern/nm-libnm-aux.h"

#include "libnmt-newt/nmt-newt.h"
#include "nm-editor-bindings.h"

#include "nmtui-edit.h"
#include "nmtui-connect.h"
#include "nmtui-hostname.h"
#include "nmtui-radio.h"

NMClient         *nm_client;
static GMainLoop *loop;

typedef NmtNewtForm *(*NmtuiSubprogram)(gboolean is_top, int argc, char **argv);

static const struct {
    const char     *name, *shortcut, *arg;
    const char     *display_name;
    NmtuiSubprogram func;
} subprograms[] = {
    {"edit", "nmtui-edit", N_("connection"), N_("Edit a connection"), nmtui_edit},
    {"connect", "nmtui-connect", N_("connection"), N_("Activate a connection"), nmtui_connect},
    {"hostname", "nmtui-hostname", N_("new hostname"), N_("Set system hostname"), nmtui_hostname},
    {"radio", "nmtui-radio", N_("radio"), N_("Radio"), nmtui_radio}};
static const int    num_subprograms = G_N_ELEMENTS(subprograms);
static NmtNewtForm *toplevel_form;

static void
cert_verification_signal_handler(GDBusConnection *connection,
                                  const gchar *sender_name,
                                  const gchar *object_path,
                                  const gchar *interface_name,
                                  const gchar *signal_name,
                                  GVariant *parameters,
                                  gpointer user_data);
static NmtNewtForm *
quit_func(int argc, char **argv)
{
    if (toplevel_form)
        nmt_newt_form_quit(toplevel_form);

    nmtui_quit();

    return NULL;
}

static void
main_list_activated(NmtNewtWidget *widget, NmtNewtListbox *listbox)
{
    NmtNewtForm    *form;
    NmtuiSubprogram sub;

    sub = nmt_newt_listbox_get_active_key(listbox);
    if (sub) {
        form = sub(FALSE, 0, NULL);
        if (form) {
            nmt_newt_form_show(form);
            g_object_unref(form);
        }
    }
}

static NmtNewtForm *
nmtui_main(gboolean is_top, int argc, char **argv)
{
    NmtNewtForm      *form;
    NmtNewtWidget    *widget, *ok;
    NmtNewtGrid      *grid;
    NmtNewtListbox   *listbox;
    NmtNewtButtonBox *bbox;
    int               i;

    form = g_object_new(NMT_TYPE_NEWT_FORM, "title", _("NetworkManager TUI"), NULL);

    widget = nmt_newt_grid_new();
    nmt_newt_form_set_content(form, widget);
    grid = NMT_NEWT_GRID(widget);

    widget = nmt_newt_label_new(_("Please select an option"));
    nmt_newt_grid_add(grid, widget, 0, 0);

    widget = g_object_new(NMT_TYPE_NEWT_LISTBOX,
                          "height",
                          num_subprograms + 2,
                          "skip-null-keys",
                          TRUE,
                          NULL);
    nmt_newt_grid_add(grid, widget, 0, 1);
    nmt_newt_widget_set_padding(widget, 0, 1, 0, 1);
    listbox = NMT_NEWT_LISTBOX(widget);
    g_signal_connect(widget, "activated", G_CALLBACK(main_list_activated), listbox);

    for (i = 0; i < num_subprograms; i++) {
        nmt_newt_listbox_append(listbox, _(subprograms[i].display_name), subprograms[i].func);
    }
    nmt_newt_listbox_append(listbox, "", NULL);
    nmt_newt_listbox_append(listbox, _("Quit"), quit_func);

    widget = nmt_newt_button_box_new(NMT_NEWT_BUTTON_BOX_HORIZONTAL);
    nmt_newt_grid_add(grid, widget, 0, 2);
    bbox = NMT_NEWT_BUTTON_BOX(widget);

    ok = nmt_newt_button_box_add_end(bbox, _("OK"));
    g_signal_connect(ok, "activated", G_CALLBACK(main_list_activated), listbox);

    toplevel_form = form;

    return form;
}

/**
 * nmtui_quit:
 *
 * Causes nmtui to exit.
 */
void
nmtui_quit(void)
{
    g_main_loop_quit(loop);
}

static void
usage(void)
{
    const char *argv0     = g_get_prgname();
    const char *usage_str = _("Usage");
    int         i;

    for (i = 0; i < num_subprograms; i++) {
        if (!strcmp(argv0, subprograms[i].shortcut)) {
            g_printerr("%s: %s [%s]\n", usage_str, argv0, _(subprograms[i].arg));
            exit(1);
        }
    }

    g_printerr("%s: nmtui\n", usage_str);
    for (i = 0; i < num_subprograms; i++) {
        g_printerr("%*s  nmtui %s [%s]\n",
                   nmt_newt_text_width(usage_str),
                   " ",
                   subprograms[i].name,
                   _(subprograms[i].arg));
    }
    exit(1);
}

typedef struct {
    NmtuiSubprogram subprogram;
    int             argc;
    char          **argv;
} NmtuiStartupData;

static void
toplevel_form_quit(NmtNewtForm *form, gpointer user_data)
{
    nmtui_quit();
}

static gboolean
idle_run_subprogram(gpointer user_data)
{
    NmtuiStartupData *data = user_data;
    NmtNewtForm      *form;

    form = data->subprogram(TRUE, data->argc, data->argv);
    if (form) {
        g_signal_connect(form, "quit", G_CALLBACK(toplevel_form_quit), NULL);
        nmt_newt_form_show(form);
        g_object_unref(form);
    } else
        nmtui_quit();

    return FALSE;
}

gboolean sleep_on_startup = FALSE;
gboolean noinit           = FALSE;

GOptionEntry entries[] = {{"sleep",
                           's',
                           G_OPTION_FLAG_HIDDEN,
                           G_OPTION_ARG_NONE,
                           &sleep_on_startup,
                           "Sleep on startup",
                           NULL},
                          {"noinit",
                           'n',
                           G_OPTION_FLAG_HIDDEN,
                           G_OPTION_ARG_NONE,
                           &noinit,
                           "Don't initialize newt",
                           NULL},
                          {NULL}};

int
main(int argc, char **argv)
{
    GOptionContext  *opts;
    GError          *error = NULL;
    NmtuiStartupData startup_data;
    const char      *prgname;
    int              i;
    GDBusConnection *connection;

    setlocale(LC_ALL, "");
    bindtextdomain(GETTEXT_PACKAGE, NMLOCALEDIR);
    bind_textdomain_codeset(GETTEXT_PACKAGE, "UTF-8");
    textdomain(GETTEXT_PACKAGE);

    opts = g_option_context_new(NULL);
    g_option_context_add_main_entries(opts, entries, NULL);

    if (!g_option_context_parse(opts, &argc, &argv, &error)) {
        g_printerr("%s: %s: %s\n", argv[0], _("Could not parse arguments"), error->message);
        exit(1);
    }
    g_option_context_free(opts);

    nm_editor_bindings_init();

    if (!nmc_client_new_waitsync(NULL,
                                 &nm_client,
                                 &error,
                                 NM_CLIENT_INSTANCE_FLAGS,
                                 (guint) NM_CLIENT_INSTANCE_FLAGS_NO_AUTO_FETCH_PERMISSIONS,
                                 NULL)) {
        g_printerr(_("Could not contact NetworkManager: %s.\n"), error->message);
        g_error_free(error);
        exit(1);
    }
    if (!nm_client_get_nm_running(nm_client)) {
        g_printerr("%s\n", _("NetworkManager is not running."));
        exit(1);
    }

    // subscribe to the internal dbus signal before it is going to the gloop
    connection = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, NULL);

    g_dbus_connection_signal_subscribe(connection,
        NULL, // sender (any sender)
        "org.freedesktop.NetworkManager.CertificateVerification", // your custom interface
        "CertificateVerificationRequest", // the signal name
        "/org/freedesktop/NetworkManager/CertificateVerification", // object path
        NULL, // arg0
        G_DBUS_SIGNAL_FLAGS_NONE,
        cert_verification_signal_handler, // your C function to handle it
        NULL,
        NULL);

    if (sleep_on_startup)
        sleep(5);

    startup_data.subprogram = NULL;
    prgname                 = g_get_prgname();
    if (g_str_has_prefix(prgname, "lt-"))
        prgname += 3;
    if (!strcmp(prgname, "nmtui")) {
        if (argc > 1) {
            for (i = 0; i < num_subprograms; i++) {
                if (!strcmp(argv[1], subprograms[i].name)) {
                    argc--;
                    argv[0] = (char *) subprograms[i].shortcut;
                    memmove(&argv[1], &argv[2], argc * sizeof(char *));
                    startup_data.subprogram = subprograms[i].func;
                    break;
                }
            }
        } else
            startup_data.subprogram = nmtui_main;
    } else {
        for (i = 0; i < num_subprograms; i++) {
            if (!strcmp(prgname, subprograms[i].shortcut)) {
                startup_data.subprogram = subprograms[i].func;
                break;
            }
        }
    }
    if (!startup_data.subprogram)
        usage();

    if (!noinit)
        nmt_newt_init();

    startup_data.argc = argc;
    startup_data.argv = argv;
    nm_g_idle_add(idle_run_subprogram, &startup_data);
    loop = g_main_loop_new(NULL, FALSE);
    g_main_loop_run(loop);
    g_main_loop_unref(loop);

    if (!noinit)
        nmt_newt_finished();

    g_object_unref(nm_client);

    return 0;
}

static void
cert_verification_signal_handler(GDBusConnection *connection,
                                  const gchar *sender_name,
                                  const gchar *object_path,
                                  const gchar *interface_name,
                                  const gchar *signal_name,
                                  GVariant *parameters,
                                  gpointer user_data)
{
    const gchar *ssid = NULL;
    const gchar *subject = NULL;
    const gchar *issuer = NULL;
    const gchar *organization = NULL;
    const gchar *hash = NULL;
	const gchar *expiration = NULL;
    const gchar *str_disclaimer = NULL;
    gchar *message;
    int choice;
    gboolean user_response;

    g_debug("[nmtui] Received CertificateVerificationRequest signal!");
    g_printerr("[nmtui] Received CertificateVerificationRequest signal!");

    if (!parameters)
        return;

    // Unpack parameters (we expect (@a{sv}))
    g_variant_get(parameters, "(sssssss)", &ssid, &subject, &issuer, &organization, &hash, &expiration, &str_disclaimer);

    // Create the prompt message
    message = g_strdup_printf(
        //"Server Certificate Verification\n\n"
        "Is this Network '%s' Trusted ?\n\n"
        "Only allow this network if the information below is correct.\n\n"
        "Server Name: %s\n\n"
        "Issuer Name: %s\n\n"
        "Organization Name: %s\n\n"
        "Certificate Expiration: %s\n\n"
        "Disclaimer: %s\n\n"
        "SHA-256 Fingerprint: %s \n\n",
        ssid ? ssid : "(unknown)",
        subject ? subject : "(unknown)",
        issuer ? issuer : "(unknown)",
        organization ? organization : "(unknown)",
        expiration ? expiration : "(unknown)",
        str_disclaimer ? str_disclaimer : "(no disclaimer provided)",
        hash ? hash : "(unknown)"
    );

    // Show a choice dialog with Accept / Reject buttons
    choice = newtWinChoice(
        (char *) "Verify Certificate",
        (char *) "Continue",
        (char *) "Cancel",
        message
    );

    g_free(message);

    g_printerr("\n[nmtui] User chose: %d", choice);

    // Interpret the user's choice
    user_response = (choice == 1); // 0 = first button clicked (Accept)

    g_printerr("\n[nmtui] User chose: %s", user_response ? "Accept" : "Reject");

    // Send response back to NetworkManager via D-Bus method call
    g_dbus_connection_call(
        connection,
        "org.freedesktop.NetworkManager",
        "/org/freedesktop/NetworkManager",
        "org.freedesktop.NetworkManager",
        "CertificateVerificationResponse",
        g_variant_new("(bs)", user_response, ssid ? ssid : ""),
        NULL,                         // No reply expected
        G_DBUS_CALL_FLAGS_NONE,
        -1,                           // Default timeout
        NULL,                         // No GCancellable
        NULL,                         // No callback
        NULL                          // No user_data
    );
}
