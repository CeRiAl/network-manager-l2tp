/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/***************************************************************************
 *
 * Copyright (C) 2011 Geo Carncross, <geocar@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 **************************************************************************/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>
#include <sys/types.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include <glib.h>
#include <glib/gi18n-lib.h>

#ifdef NM_L2TP_OLD
#define NM_VPN_LIBNM_COMPAT
#include <nm-connection.h>
#include <nm-setting-vpn.h>

#else /* !NM_L2TP_OLD */

#include <NetworkManager.h>
#endif

#include "ipsec-dialog.h"
#include "nm-l2tp.h"
#include "../src/nm-l2tp-service-defines.h"

static const char *ipsec_keys[] = {
	NM_L2TP_KEY_IPSEC_ENABLE,
	NM_L2TP_KEY_IPSEC_GROUP_NAME,
	NM_L2TP_KEY_IPSEC_GATEWAY_ID,
	NM_L2TP_KEY_IPSEC_AUTH_TYPE,
	NM_L2TP_KEY_IPSEC_PSK,
	NM_L2TP_KEY_IPSEC_RSA_CERT,
	NM_L2TP_KEY_IPSEC_RSA_KEY,
	NM_L2TP_KEY_IPSEC_RSA_PASSPHRASE,
	NM_L2TP_KEY_IPSEC_PFS,
	NULL
};

static void
copy_values (const char *key, const char *value, gpointer user_data)
{
	GHashTable *hash = (GHashTable *) user_data;
	const char **i;

	for (i = &ipsec_keys[0]; *i; i++) {
		if (strcmp (key, *i))
			continue;
		g_hash_table_insert (hash, g_strdup (key), g_strdup (value));
	}
}

GHashTable *
ipsec_dialog_new_hash_from_connection (NMConnection *connection,
                                          GError **error)
{
	GHashTable *hash;
	NMSettingVpn *s_vpn;

	hash = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);

	s_vpn = nm_connection_get_setting_vpn (connection);
	nm_setting_vpn_foreach_data_item (s_vpn, copy_values, hash);
	return hash;
}

#define IPSEC_AUTH_PSK  0
#define IPSEC_AUTH_RSA  1

static void
handle_auth_changed (GtkWidget *combo, gboolean is_init, GtkBuilder *builder)
{
	GtkWidget *widget;

	switch (gtk_combo_box_get_active (GTK_COMBO_BOX (combo))) {
	default:
	case IPSEC_AUTH_PSK:
		widget = GTK_WIDGET (gtk_builder_get_object (builder, "ipsec_psk_settings"));
		gtk_widget_set_sensitive (widget, TRUE);

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "ipsec_rsa_settings"));
		gtk_widget_set_sensitive (widget, FALSE);
		break;
	case IPSEC_AUTH_RSA:
		widget = GTK_WIDGET (gtk_builder_get_object (builder, "ipsec_rsa_settings"));
		gtk_widget_set_sensitive (widget, TRUE);

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "ipsec_psk_settings"));
		gtk_widget_set_sensitive (widget, FALSE);
		break;
	}
}

static void
handle_enable_changed (GtkWidget *check, gboolean is_init, GtkBuilder *builder)
{
	GtkWidget *widget;
	gboolean enabledp;

	enabledp = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (check));

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "label_auth_type_combo"));
	gtk_widget_set_sensitive (widget, enabledp);

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "ipsec_auth_type_combo"));
	gtk_widget_set_sensitive (widget, enabledp);

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "label_psk"));
	gtk_widget_set_sensitive (widget, enabledp);

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "ipsec_psk"));
	gtk_widget_set_sensitive (widget, enabledp);

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "label_rsa_cert"));
	gtk_widget_set_sensitive (widget, enabledp);

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "ipsec_rsa_cert"));
	gtk_widget_set_sensitive (widget, enabledp);

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "label_rsa_key"));
	gtk_widget_set_sensitive (widget, enabledp);

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "ipsec_rsa_key"));
	gtk_widget_set_sensitive (widget, enabledp);

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "label_rsa_passphrase"));
	gtk_widget_set_sensitive (widget, enabledp);

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "ipsec_rsa_passphrase"));
	gtk_widget_set_sensitive (widget, enabledp);

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "label_gateway_id"));
	gtk_widget_set_sensitive (widget, enabledp);

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "ipsec_gateway_id"));
	gtk_widget_set_sensitive (widget, enabledp);

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "label_group_name"));
	gtk_widget_set_sensitive (widget, enabledp);

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "ipsec_group_name"));
	gtk_widget_set_sensitive (widget, enabledp);

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "pfs_enable"));
	gtk_widget_set_sensitive (widget, enabledp);
}

static void
setup_auth_type_combo (GtkBuilder *builder, GHashTable *hash)
{
	GtkWidget *widget;
	GtkListStore *store;
	GtkTreeIter iter;
	int active = -1;
	const char *value;

	g_return_if_fail (builder != NULL);
	g_return_if_fail (hash != NULL);

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "ipsec_auth_type_combo"));

	store = gtk_list_store_new (1, G_TYPE_STRING);

	/* PSK */
	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("Pre-shared key"), -1);
	if (active < 0) {
		value = g_hash_table_lookup (hash, NM_L2TP_KEY_IPSEC_AUTH_TYPE);
		if (value && !strcmp (value, "psk"))
			active = IPSEC_AUTH_PSK;
	}

	/* RSA */
	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("RSA authentication"), -1);
	if (active < 0) {
		value = g_hash_table_lookup (hash, NM_L2TP_KEY_IPSEC_AUTH_TYPE);
		if (value && !strcmp (value, "rsa"))
			active = IPSEC_AUTH_RSA;
	}

	gtk_combo_box_set_model (GTK_COMBO_BOX (widget), GTK_TREE_MODEL (store));
	g_object_unref (store);
	gtk_combo_box_set_active (GTK_COMBO_BOX (widget), active < 0 ? IPSEC_AUTH_PSK : active);

	switch (active) {
	default:
	case IPSEC_AUTH_PSK:
		widget = GTK_WIDGET (gtk_builder_get_object (builder, "ipsec_psk_settings"));
		gtk_widget_set_sensitive (widget, TRUE);

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "ipsec_rsa_settings"));
		gtk_widget_set_sensitive (widget, FALSE);
		break;
	case IPSEC_AUTH_RSA:
		widget = GTK_WIDGET (gtk_builder_get_object (builder, "ipsec_rsa_settings"));
		gtk_widget_set_sensitive (widget, TRUE);

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "ipsec_psk_settings"));
		gtk_widget_set_sensitive (widget, FALSE);
		break;
	}
}

static void
auth_toggled_cb (GtkWidget *combo, gpointer user_data)
{
	handle_auth_changed (combo, FALSE, (GtkBuilder *) user_data);
}

static void
enable_toggled_cb (GtkWidget *check, gpointer user_data)
{
	handle_enable_changed (check, FALSE, (GtkBuilder *) user_data);
}

GtkWidget *
ipsec_dialog_new (GHashTable *hash)
{
	GtkBuilder *builder;
	GtkWidget *dialog = NULL;
	char *ui_file = NULL;
	GtkWidget *widget;
	const char *value;
	GError *error = NULL;

	g_return_val_if_fail (hash != NULL, NULL);

	ui_file = g_strdup_printf ("%s/%s", UIDIR, "nm-l2tp-dialog.ui");
	builder = gtk_builder_new ();

	if (!gtk_builder_add_from_file(builder, ui_file, &error)) {
		g_warning("Couldn't load builder file: %s", error ? error->message
				: "(unknown)");
		g_clear_error(&error);
		g_object_unref(G_OBJECT(builder));
		goto out;
	}
	gtk_builder_set_translation_domain(builder, GETTEXT_PACKAGE);


	dialog = GTK_WIDGET (gtk_builder_get_object (builder, "l2tp-ipsec-dialog"));
	if (!dialog) {
		g_object_unref (G_OBJECT (builder));
		goto out;
	}
	gtk_window_set_modal (GTK_WINDOW (dialog), TRUE);

	g_object_set_data_full (G_OBJECT (dialog), "gtkbuilder-xml",
			builder, (GDestroyNotify) g_object_unref);

	setup_auth_type_combo (builder, hash);

	value = g_hash_table_lookup (hash, NM_L2TP_KEY_IPSEC_ENABLE);
	if (value && !strcmp (value, "yes")) {
		widget = GTK_WIDGET (gtk_builder_get_object (builder, "ipsec_enable"));
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (widget), TRUE);
	}

	value = g_hash_table_lookup (hash, NM_L2TP_KEY_IPSEC_PFS);
	if (value && !strcmp (value, "no")) {
		widget = GTK_WIDGET (gtk_builder_get_object (builder, "pfs_enable"));
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (widget), FALSE);
	}

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "ipsec_group_name"));
	if((value = g_hash_table_lookup (hash, NM_L2TP_KEY_IPSEC_GROUP_NAME)))
		gtk_entry_set_text(GTK_ENTRY(widget), value);

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "ipsec_gateway_id"));
	if((value = g_hash_table_lookup (hash, NM_L2TP_KEY_IPSEC_GATEWAY_ID)))
		gtk_entry_set_text(GTK_ENTRY(widget), value);

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "ipsec_psk"));
	if((value = g_hash_table_lookup (hash, NM_L2TP_KEY_IPSEC_PSK)))
		gtk_entry_set_text(GTK_ENTRY(widget), value);

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "ipsec_rsa_cert"));
	if((value = g_hash_table_lookup (hash, NM_L2TP_KEY_IPSEC_RSA_CERT)))
		gtk_entry_set_text(GTK_ENTRY(widget), value);

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "ipsec_rsa_key"));
	if((value = g_hash_table_lookup (hash, NM_L2TP_KEY_IPSEC_RSA_KEY)))
		gtk_entry_set_text(GTK_ENTRY(widget), value);

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "ipsec_rsa_passphrase"));
	if((value = g_hash_table_lookup (hash, NM_L2TP_KEY_IPSEC_RSA_PASSPHRASE)))
		gtk_entry_set_text(GTK_ENTRY(widget), value);

	widget = GTK_WIDGET (gtk_builder_get_object (builder,"ipsec_auth_type_combo"));
	handle_auth_changed (widget, TRUE, builder);
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (auth_toggled_cb), builder);

	widget = GTK_WIDGET (gtk_builder_get_object (builder,"ipsec_enable"));
	handle_enable_changed (widget, TRUE, builder);
	g_signal_connect (G_OBJECT (widget), "toggled", G_CALLBACK (enable_toggled_cb), builder);

out:
	g_free (ui_file);
	return dialog;
}

GHashTable *
ipsec_dialog_new_hash_from_dialog (GtkWidget *dialog, GError **error)
{
	GHashTable *hash;
	GtkWidget *widget;
	GtkBuilder *builder;

	g_return_val_if_fail (dialog != NULL, NULL);
	if (error)
		g_return_val_if_fail (*error == NULL, NULL);

	builder = g_object_get_data (G_OBJECT (dialog), "gtkbuilder-xml");
	g_return_val_if_fail (builder != NULL, NULL);


	hash = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "ipsec_enable"));
	if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (widget)))
		g_hash_table_insert(hash, g_strdup(NM_L2TP_KEY_IPSEC_ENABLE), g_strdup("yes"));

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "pfs_enable"));
	if (!gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (widget)))
		g_hash_table_insert(hash, g_strdup(NM_L2TP_KEY_IPSEC_PFS), g_strdup("no"));

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "ipsec_gateway_id"));
	g_hash_table_insert(hash, g_strdup(NM_L2TP_KEY_IPSEC_GATEWAY_ID),
			g_strdup(gtk_entry_get_text(GTK_ENTRY(widget))));

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "ipsec_group_name"));
	g_hash_table_insert(hash, g_strdup(NM_L2TP_KEY_IPSEC_GROUP_NAME),
			g_strdup(gtk_entry_get_text(GTK_ENTRY(widget))));

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "ipsec_auth_type_combo"));
	switch (gtk_combo_box_get_active (GTK_COMBO_BOX (widget))) {
	default:
	case IPSEC_AUTH_PSK:
		g_hash_table_insert (hash, g_strdup (NM_L2TP_KEY_IPSEC_AUTH_TYPE), g_strdup ("psk"));
		break;
	case IPSEC_AUTH_RSA:
		g_hash_table_insert (hash, g_strdup (NM_L2TP_KEY_IPSEC_AUTH_TYPE), g_strdup ("rsa"));
		break;
	}

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "ipsec_psk"));
	g_hash_table_insert(hash, g_strdup(NM_L2TP_KEY_IPSEC_PSK),
			g_strdup(gtk_entry_get_text(GTK_ENTRY(widget))));

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "ipsec_rsa_cert"));
	g_hash_table_insert(hash, g_strdup(NM_L2TP_KEY_IPSEC_RSA_CERT),
			g_strdup(gtk_entry_get_text(GTK_ENTRY(widget))));

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "ipsec_rsa_key"));
	g_hash_table_insert(hash, g_strdup(NM_L2TP_KEY_IPSEC_RSA_KEY),
			g_strdup(gtk_entry_get_text(GTK_ENTRY(widget))));

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "ipsec_rsa_passphrase"));
	g_hash_table_insert(hash, g_strdup(NM_L2TP_KEY_IPSEC_RSA_PASSPHRASE),
			g_strdup(gtk_entry_get_text(GTK_ENTRY(widget))));

	return hash;
}

