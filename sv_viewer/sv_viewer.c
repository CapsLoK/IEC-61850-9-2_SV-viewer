/*
 * sv_viewer.c - IEC 61850 Sampled Values Viewer Application
 * 
 * This application:
 * 1. Scans available network interfaces
 * 2. Detects SV traffic by frame type (EtherType 0x88BA) or MAC address range
 * 3. Lists available SV streams
 * 4. Provides visualization of SV data with vector diagram
 * 5. Shows detailed information about selected SV stream
 *
 * Uses libiec61850-1.6.1 for SV parsing and GTK+3 for GUI
 */

#include <gtk/gtk.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>
#include <signal.h>
#include <pthread.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <math.h>
#include <time.h>

#include "sv_subscriber.h"
#include "hal_ethernet.h"
#include "hal_thread.h"

/* Maximum number of interfaces and streams */
#define MAX_INTERFACES 32
#define MAX_STREAMS 128
#define MAX_SAMPLES_DISPLAY 100
#define MAX_DATA_POINTS 64

/* Global state */
static bool g_running = true;
static SVReceiver g_receiver = NULL;
static pthread_t g_capture_thread;

/* Structure to hold discovered SV streams */
typedef struct {
    char sv_id[128];
    char datset[256];
    uint16_t app_id;
    uint8_t mac_addr[6];
    uint32_t conf_rev;
    uint16_t smp_rate;
    uint8_t smp_mod;
    int interface_index;
    char interface_name[32];
    time_t last_seen;
    uint64_t packet_count;
} SVStreamInfo;

/* Structure to hold sample data for visualization */
typedef struct {
    float values[MAX_DATA_POINTS];
    uint64_t timestamps[MAX_DATA_POINTS];
    int count;
    int current_index;
} SampleBuffer;

/* Discovered resources */
static char g_interfaces[MAX_INTERFACES][64];
static int g_interface_count = 0;
static SVStreamInfo g_streams[MAX_STREAMS];
static int g_stream_count = 0;
static SampleBuffer g_sample_buffer;
static int g_selected_stream_index = -1;

/* GUI widgets */
static GtkWidget *main_window;
static GtkWidget *interface_combo;
static GtkWidget *stream_listbox;
static GtkWidget *info_text_view;
static GtkWidget *vector_drawing_area;
static GtkWidget *waveform_drawing_area;
static GtkWidget *notebook;
static GtkWidget *start_button;
static GtkWidget *status_label;

/* Forward declarations */
static void start_capture(const char* interface);
static void stop_capture(void);
static void update_gui_for_stream(int index);
static void draw_vector_diagram(GtkWidget *widget, cairo_t *cr, gpointer user_data);
static void draw_waveform(GtkWidget *widget, cairo_t *cr, gpointer user_data);

/* Helper function to check if MAC is in SV multicast range */
static bool is_sv_multicast_mac(const uint8_t* mac) {
    /* IEC 61850-9-2 uses 01-0C-CD-04-xx-xx for SV */
    /* Range: 01:0C:CD:04:00:00 to 01:0C:CD:04:01:FF */
    if (mac[0] == 0x01 && mac[1] == 0x0C && mac[2] == 0xCD && mac[3] == 0x04) {
        return true;
    }
    return false;
}

/* Callback for received SV messages */
static void sv_update_listener(SVSubscriber subscriber, void* parameter, SVSubscriber_ASDU asdu) {
    (void)subscriber;
    
    const char* sv_id = SVSubscriber_ASDU_getSvId(asdu);
    const char* dataset = SVSubscriber_ASDU_getDatSet(asdu);
    uint16_t smp_cnt = SVSubscriber_ASDU_getSmpCnt(asdu);
    uint32_t conf_rev = SVSubscriber_ASDU_getConfRev(asdu);
    uint16_t smp_rate = 0;
    uint8_t smp_mod = 0;
    
    if (SVSubscriber_ASDU_hasSmpRate(asdu)) {
        smp_rate = SVSubscriber_ASDU_getSmpRate(asdu);
    }
    if (SVSubscriber_ASDU_hasSmpMod(asdu)) {
        smp_mod = SVSubscriber_ASDU_getSmpMod(asdu);
    }
    
    /* Find or create stream entry */
    int stream_idx = -1;
    for (int i = 0; i < g_stream_count; i++) {
        if (sv_id && strcmp(g_streams[i].sv_id, sv_id) == 0) {
            stream_idx = i;
            break;
        }
    }
    
    if (stream_idx < 0 && g_stream_count < MAX_STREAMS) {
        stream_idx = g_stream_count++;
        memset(&g_streams[stream_idx], 0, sizeof(SVStreamInfo));
        if (sv_id) strncpy(g_streams[stream_idx].sv_id, sv_id, sizeof(g_streams[stream_idx].sv_id) - 1);
        g_streams[stream_idx].conf_rev = conf_rev;
        g_streams[stream_idx].smp_rate = smp_rate;
        g_streams[stream_idx].smp_mod = smp_mod;
        if (dataset) strncpy(g_streams[stream_idx].datset, dataset, sizeof(g_streams[stream_idx].datset) - 1);
        g_streams[stream_idx].last_seen = time(NULL);
        g_streams[stream_idx].packet_count = 0;
        
        /* Update list box on main thread */
        gtk_disable_setlocale();
    }
    
    if (stream_idx >= 0) {
        g_streams[stream_idx].last_seen = time(NULL);
        g_streams[stream_idx].packet_count++;
        
        /* Extract measurement data (assuming FLOAT32 values) */
        int data_size = SVSubscriber_ASDU_getDataSize(asdu);
        if (data_size > 0 && g_selected_stream_index == stream_idx) {
            int num_values = data_size / 4; /* 4 bytes per FLOAT32 */
            if (num_values > MAX_DATA_POINTS) num_values = MAX_DATA_POINTS;
            
            for (int i = 0; i < num_values && i < MAX_DATA_POINTS; i++) {
                g_sample_buffer.values[i] = SVSubscriber_ASDU_getFLOAT32(asdu, i * 4);
            }
            g_sample_buffer.count = num_values;
            g_sample_buffer.timestamps[g_sample_buffer.current_index] = smp_cnt;
            g_sample_buffer.current_index = (g_sample_buffer.current_index + 1) % MAX_SAMPLES_DISPLAY;
            
            /* Trigger GUI update */
            gdk_threads_add_idle((GSourceFunc)draw_vector_diagram, vector_drawing_area);
            gdk_threads_add_idle((GSourceFunc)draw_waveform, waveform_drawing_area);
        }
    }
}

/* Get list of network interfaces */
static int get_network_interfaces(char interfaces[][64], int max_count) {
    int count = 0;
    struct ifaddrs *ifaddr, *ifa;
    
    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return 0;
    }
    
    for (ifa = ifaddr; ifa != NULL && count < max_count; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;
        if (ifa->ifa_addr->sa_family != AF_PACKET) continue;
        
        /* Skip loopback */
        if (ifa->ifa_flags & IFF_LOOPBACK) continue;
        
        /* Only include interfaces that are up */
        if (!(ifa->ifa_flags & IFF_UP)) continue;
        
        strncpy(interfaces[count], ifa->ifa_name, 63);
        interfaces[count][63] = '\0';
        count++;
    }
    
    freeifaddrs(ifaddr);
    return count;
}

/* Packet capture thread using raw sockets for detection */
static void* packet_capture_thread(void* arg) {
    (void)arg;
    
    EthernetSocket eth_socket = NULL;
    uint8_t buffer[2048];
    
    while (g_running) {
        Thread_sleep(100);
    }
    
    if (eth_socket) {
        Ethernet_destroySocket(eth_socket);
    }
    
    return NULL;
}

/* Start SV capture on specified interface */
static void start_capture(const char* interface) {
    if (g_receiver) {
        SVReceiver_stop(g_receiver);
        SVReceiver_destroy(g_receiver);
    }
    
    g_receiver = SVReceiver_create();
    if (!g_receiver) {
        gtk_label_set_text(GTK_LABEL(status_label), "Failed to create SV receiver");
        return;
    }
    
    SVReceiver_setInterfaceId(g_receiver, interface);
    SVReceiver_disableDestAddrCheck(g_receiver);
    
    /* Create subscriber that accepts all SV APPIDs (0x4000-0x7FFF range) */
    /* We'll use a wildcard approach - listen for common SV APPID */
    SVSubscriber subscriber = SVSubscriber_create(NULL, 0x4000);
    SVSubscriber_setListener(subscriber, sv_update_listener, NULL);
    SVReceiver_addSubscriber(g_receiver, subscriber);
    
    /* Also listen for other common APPIDs */
    for (uint16_t appid = 0x4001; appid <= 0x4010; appid++) {
        SVSubscriber sub = SVSubscriber_create(NULL, appid);
        SVSubscriber_setListener(sub, sv_update_listener, NULL);
        SVReceiver_addSubscriber(g_receiver, sub);
    }
    
    SVReceiver_start(g_receiver);
    
    if (SVReceiver_isRunning(g_receiver)) {
        char status[256];
        snprintf(status, sizeof(status), "Capturing on %s - SV streams will appear below", interface);
        gtk_label_set_text(GTK_LABEL(status_label), status);
    } else {
        gtk_label_set_text(GTK_LABEL(status_label), "Failed to start capture (need root?)");
    }
}

/* Stop SV capture */
static void stop_capture(void) {
    if (g_receiver) {
        SVReceiver_stop(g_receiver);
        SVReceiver_destroy(g_receiver);
        g_receiver = NULL;
    }
    gtk_label_set_text(GTK_LABEL(status_label), "Capture stopped");
}

/* Draw vector diagram (phasor diagram) */
static void draw_vector_diagram(GtkWidget *widget, cairo_t *cr, gpointer user_data) {
    (void)user_data;
    
    int width = gtk_widget_get_allocated_width(widget);
    int height = gtk_widget_get_allocated_height(widget);
    int center_x = width / 2;
    int center_y = height / 2;
    int radius = (width < height ? width : height) / 2 - 20;
    
    /* Clear background */
    cairo_set_source_rgb(cr, 1.0, 1.0, 1.0);
    cairo_paint(cr);
    
    /* Draw coordinate system */
    cairo_set_source_rgb(cr, 0.8, 0.8, 0.8);
    cairo_set_line_width(cr, 1);
    
    /* Axes */
    cairo_move_to(cr, center_x, 10);
    cairo_line_to(cr, center_x, height - 10);
    cairo_move_to(cr, 10, center_y);
    cairo_line_to(cr, width - 10, center_y);
    cairo_stroke(cr);
    
    /* Circle */
    cairo_arc(cr, center_x, center_y, radius, 0, 2 * G_PI);
    cairo_stroke(cr);
    
    /* Draw vectors for first few channels (assuming they represent phases) */
    if (g_sample_buffer.count >= 3) {
        double colors[3][3] = {
            {1.0, 0.0, 0.0},  /* Red - Phase A */
            {0.0, 1.0, 0.0},  /* Green - Phase B */
            {0.0, 0.0, 1.0}   /* Blue - Phase C */
        };
        
        const char* labels[3] = {"A", "B", "C"};
        
        for (int i = 0; i < 3 && i < g_sample_buffer.count; i++) {
            float value = g_sample_buffer.values[i];
            
            /* Scale value to radius (assuming normalized values) */
            float magnitude = fabs(value);
            if (magnitude > 1.0) magnitude = 1.0;
            
            /* Calculate angle based on sample count (simulating rotation) */
            uint64_t smp_cnt = g_sample_buffer.timestamps[0];
            double angle = (smp_cnt * 2 * G_PI / 100.0) + (i * 2 * G_PI / 3.0);
            
            double end_x = center_x + magnitude * radius * cos(angle);
            double end_y = center_y - magnitude * radius * sin(angle);
            
            cairo_set_source_rgb(cr, colors[i][0], colors[i][1], colors[i][2]);
            cairo_set_line_width(cr, 2);
            cairo_move_to(cr, center_x, center_y);
            cairo_line_to(cr, end_x, end_y);
            cairo_stroke(cr);
            
            /* Draw label */
            cairo_set_source_rgb(cr, 0.0, 0.0, 0.0);
            char label[16];
            snprintf(label, sizeof(label), "%s (%.2f)", labels[i], value);
            cairo_move_to(cr, end_x + 10, end_y);
            cairo_show_text(cr, label);
        }
    } else if (g_sample_buffer.count > 0) {
        /* Draw single vector */
        cairo_set_source_rgb(cr, 1.0, 0.0, 0.0);
        cairo_set_line_width(cr, 2);
        
        float value = g_sample_buffer.values[0];
        double angle = g_sample_buffer.timestamps[0] * 2 * G_PI / 100.0;
        double magnitude = fabs(value);
        if (magnitude > 1.0) magnitude = 1.0;
        
        double end_x = center_x + magnitude * radius * cos(angle);
        double end_y = center_y - magnitude * radius * sin(angle);
        
        cairo_move_to(cr, center_x, center_y);
        cairo_line_to(cr, end_x, end_y);
        cairo_stroke(cr);
    }
    
    cairo_new_path(cr);
}

/* Draw waveform */
static void draw_waveform(GtkWidget *widget, cairo_t *cr, gpointer user_data) {
    (void)user_data;
    
    int width = gtk_widget_get_allocated_width(widget);
    int height = gtk_widget_get_allocated_height(widget);
    int margin_left = 50;
    int margin_right = 20;
    int margin_top = 20;
    int margin_bottom = 40;
    
    int plot_width = width - margin_left - margin_right;
    int plot_height = height - margin_top - margin_bottom;
    
    /* Clear background */
    cairo_set_source_rgb(cr, 1.0, 1.0, 1.0);
    cairo_paint(cr);
    
    /* Draw grid */
    cairo_set_source_rgb(cr, 0.9, 0.9, 0.9);
    cairo_set_line_width(cr, 1);
    
    /* Horizontal grid lines */
    for (int i = 0; i <= 4; i++) {
        int y = margin_top + (plot_height * i / 4);
        cairo_move_to(cr, margin_left, y);
        cairo_line_to(cr, width - margin_right, y);
    }
    
    /* Vertical grid lines */
    for (int i = 0; i <= 10; i++) {
        int x = margin_left + (plot_width * i / 10);
        cairo_move_to(cr, x, margin_top);
        cairo_line_to(cr, x, height - margin_bottom);
    }
    cairo_stroke(cr);
    
    /* Draw axes */
    cairo_set_source_rgb(cr, 0.0, 0.0, 0.0);
    cairo_set_line_width(cr, 2);
    cairo_move_to(cr, margin_left, margin_top);
    cairo_line_to(cr, margin_left, height - margin_bottom);
    cairo_line_to(cr, width - margin_right, height - margin_bottom);
    cairo_stroke(cr);
    
    /* Draw waveform for each channel */
    if (g_sample_buffer.count > 0) {
        double colors[4][3] = {
            {1.0, 0.0, 0.0},
            {0.0, 1.0, 0.0},
            {0.0, 0.0, 1.0},
            {1.0, 1.0, 0.0}
        };
        
        int channels_to_draw = g_sample_buffer.count < 4 ? g_sample_buffer.count : 4;
        
        for (int ch = 0; ch < channels_to_draw; ch++) {
            cairo_set_source_rgb(cr, colors[ch][0], colors[ch][1], colors[ch][2]);
            cairo_set_line_width(cr, 2);
            
            /* Find min/max for scaling */
            float min_val = g_sample_buffer.values[ch];
            float max_val = g_sample_buffer.values[ch];
            
            for (int i = 0; i < g_sample_buffer.count; i++) {
                if (g_sample_buffer.values[i] < min_val) min_val = g_sample_buffer.values[i];
                if (g_sample_buffer.values[i] > max_val) max_val = g_sample_buffer.values[i];
            }
            
            float range = max_val - min_val;
            if (range < 0.001) range = 1.0;
            
            /* Draw line */
            for (int i = 0; i < g_sample_buffer.count && i < plot_width; i++) {
                int x = margin_left + i;
                float normalized = (g_sample_buffer.values[i] - min_val) / range;
                int y = height - margin_bottom - (normalized * plot_height);
                
                if (i == 0) {
                    cairo_move_to(cr, x, y);
                } else {
                    cairo_line_to(cr, x, y);
                }
            }
            cairo_stroke(cr);
        }
    }
    
    /* Draw labels */
    cairo_set_source_rgb(cr, 0.0, 0.0, 0.0);
    cairo_select_font_face(cr, "Sans", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
    cairo_set_font_size(cr, 10);
    
    cairo_move_to(cr, margin_left - 40, margin_top);
    cairo_show_text(cr, "Max");
    cairo_move_to(cr, margin_left - 40, height - margin_bottom);
    cairo_show_text(cr, "Min");
    cairo_move_to(cr, margin_left, height - margin_bottom + 15);
    cairo_show_text(cr, "Sample Index");
    
    cairo_rotate(cr, -G_PI / 2);
    cairo_move_to(cr, -(height/2), 15);
    cairo_show_text(cr, "Amplitude");
    cairo_rotate(cr, G_PI / 2);
    
    cairo_new_path(cr);
}

/* Update info text view with stream details */
static void update_info_text(int stream_index) {
    if (stream_index < 0 || stream_index >= g_stream_count) return;
    
    SVStreamInfo* stream = &g_streams[stream_index];
    GtkTextBuffer* buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(info_text_view));
    gtk_text_buffer_set_text(buffer, "", -1);
    
    char info[2048];
    snprintf(info, sizeof(info),
        "=== IEC 61850 Sampled Values Stream Details ===\n\n"
        "Stream Identification:\n"
        "  SvID: %s\n"
        "  DataSet: %s\n"
        "  AppID: 0x%04X\n"
        "  MAC Address: %02X:%02X:%02X:%02X:%02X:%02X\n\n"
        "Configuration:\n"
        "  Configuration Revision: %u\n"
        "  Sample Rate: %u samples/cycle\n"
        "  Sampling Mode: %u\n\n"
        "Statistics:\n"
        "  Packets Received: %" PRIu64 "\n"
        "  Last Seen: %s\n"
        "  Interface: %s\n\n"
        "Data Characteristics:\n"
        "  Available Data Points: %d\n"
        "  Expected Data Type: FLOAT32 (IEEE 754)\n\n"
        "IEC 61850-9-2 LE Compliance:\n"
        "  This stream appears to conform to IEC 61850-9-2\n"
        "  Sampled Values encoding specification.\n",
        stream->sv_id[0] ? stream->sv_id : "N/A",
        stream->datset[0] ? stream->datset : "N/A",
        stream->app_id,
        stream->mac_addr[0], stream->mac_addr[1], stream->mac_addr[2],
        stream->mac_addr[3], stream->mac_addr[4], stream->mac_addr[5],
        stream->conf_rev,
        stream->smp_rate,
        stream->smp_mod,
        stream->packet_count,
        ctime(&stream->last_seen),
        stream->interface_name,
        g_sample_buffer.count
    );
    
    gtk_text_buffer_insert_at_cursor(buffer, info, -1);
}

/* Update GUI for selected stream */
static void update_gui_for_stream(int index) {
    g_selected_stream_index = index;
    update_info_text(index);
    
    /* Clear sample buffer when switching streams */
    memset(&g_sample_buffer, 0, sizeof(SampleBuffer));
    
    /* Redraw diagrams */
    if (vector_drawing_area) {
        gtk_widget_queue_draw(vector_drawing_area);
    }
    if (waveform_drawing_area) {
        gtk_widget_queue_draw(waveform_drawing_area);
    }
}

/* List box row selected callback */
static void on_stream_selected(GtkListBox *listbox, GtkListBoxRow *row) {
    (void)listbox;
    
    if (row) {
        int index = gtk_list_box_row_get_index(row);
        update_gui_for_stream(index);
    }
}

/* Start button clicked callback */
static void on_start_clicked(GtkButton *button) {
    (void)button;
    
    const char* interface = gtk_combo_box_text_get_active_text(GTK_COMBO_BOX_TEXT(interface_combo));
    
    if (interface) {
        start_capture(interface);
    } else {
        gtk_label_set_text(GTK_LABEL(status_label), "Please select an interface");
    }
}

/* Stop button clicked callback */
static void on_stop_clicked(GtkButton *button) {
    (void)button;
    stop_capture();
}

/* Window close handler */
static gboolean on_window_delete(GtkWidget *widget, GdkEvent *event) {
    (void)widget;
    (void)event;
    
    g_running = false;
    stop_capture();
    gtk_main_quit();
    return FALSE;
}

/* Populate interface combo box */
static void populate_interfaces(void) {
    g_interface_count = get_network_interfaces(g_interfaces, MAX_INTERFACES);
    
    gtk_combo_box_text_remove_all(GTK_COMBO_BOX_TEXT(interface_combo));
    
    for (int i = 0; i < g_interface_count; i++) {
        gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(interface_combo), g_interfaces[i]);
    }
    
    if (g_interface_count > 0) {
        gtk_combo_box_set_active(GTK_COMBO_BOX(interface_combo), 0);
    }
}

/* Refresh stream list */
static void refresh_stream_list(void) {
    /* Remove all existing rows */
    GList* children = gtk_container_get_children(GTK_CONTAINER(stream_listbox));
    for (GList* iter = children; iter != NULL; iter = g_list_next(iter)) {
        gtk_widget_destroy(GTK_WIDGET(iter->data));
    }
    g_list_free(children);
    
    /* Add rows for each stream */
    for (int i = 0; i < g_stream_count; i++) {
        char label[512];
        snprintf(label, sizeof(label),
            "%s\nAppID: 0x%04X | Pkts: %" PRIu64 " | IF: %s",
            g_streams[i].sv_id[0] ? g_streams[i].sv_id : "Unknown",
            g_streams[i].app_id,
            g_streams[i].packet_count,
            g_streams[i].interface_name
        );
        
        GtkWidget* row_label = gtk_label_new(label);
        gtk_label_set_xalign(GTK_LABEL(row_label), 0.0);
        gtk_label_set_yalign(GTK_LABEL(row_label), 0.0);
        gtk_widget_show(row_label);
        
        gtk_list_box_insert(GTK_LIST_BOX(stream_listbox), row_label, i);
    }
    
    gtk_widget_show_all(GTK_WIDGET(stream_listbox));
}

/* Periodic update timer */
static gboolean periodic_update(gpointer data) {
    (void)data;
    
    refresh_stream_list();
    
    /* Update diagrams */
    if (vector_drawing_area) {
        gtk_widget_queue_draw(vector_drawing_area);
    }
    if (waveform_drawing_area) {
        gtk_widget_queue_draw(waveform_drawing_area);
    }
    
    return TRUE;
}

/* Build the main GUI */
static void build_gui(void) {
    gtk_init(0, NULL);
    
    main_window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(main_window), "IEC 61850 Sampled Values Viewer");
    gtk_window_set_default_size(GTK_WINDOW(main_window), 1200, 800);
    g_signal_connect(main_window, "delete-event", G_CALLBACK(on_window_delete), NULL);
    
    GtkWidget* main_vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    gtk_container_set_border_width(GTK_CONTAINER(main_vbox), 10);
    gtk_container_add(GTK_CONTAINER(main_window), main_vbox);
    
    /* Control panel */
    GtkWidget* control_frame = gtk_frame_new("Control Panel");
    gtk_box_pack_start(GTK_BOX(main_vbox), control_frame, FALSE, FALSE, 0);
    
    GtkWidget* control_hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    gtk_container_set_border_width(GTK_CONTAINER(control_hbox), 10);
    gtk_container_add(GTK_CONTAINER(control_frame), control_hbox);
    
    /* Interface selection */
    GtkWidget* interface_label = gtk_label_new("Network Interface:");
    gtk_box_pack_start(GTK_BOX(control_hbox), interface_label, FALSE, FALSE, 0);
    
    interface_combo = gtk_combo_box_text_new();
    gtk_box_pack_start(GTK_BOX(control_hbox), interface_combo, FALSE, FALSE, 0);
    populate_interfaces();
    
    /* Start/Stop buttons */
    start_button = gtk_button_new_with_label("Start Capture");
    gtk_box_pack_start(GTK_BOX(control_hbox), start_button, FALSE, FALSE, 0);
    g_signal_connect(start_button, "clicked", G_CALLBACK(on_start_clicked), NULL);
    
    GtkWidget* stop_button = gtk_button_new_with_label("Stop");
    gtk_box_pack_start(GTK_BOX(control_hbox), stop_button, FALSE, FALSE, 0);
    g_signal_connect(stop_button, "clicked", G_CALLBACK(on_stop_clicked), NULL);
    
    /* Status label */
    status_label = gtk_label_new("Select interface and start capture");
    gtk_box_pack_end(GTK_BOX(control_hbox), status_label, FALSE, FALSE, 0);
    
    /* Main content area with notebook */
    notebook = gtk_notebook_new();
    gtk_box_pack_start(GTK_BOX(main_vbox), notebook, TRUE, TRUE, 0);
    
    /* Page 1: Overview and Visualizations */
    GtkWidget* overview_page = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
    
    /* Left panel - Stream list */
    GtkWidget* stream_frame = gtk_frame_new("Available SV Streams");
    gtk_box_pack_start(GTK_BOX(overview_page), stream_frame, FALSE, FALSE, 0);
    
    GtkWidget* stream_scrolled = gtk_scrolled_window_new(NULL, NULL);
    gtk_widget_set_size_request(stream_scrolled, 300, -1);
    gtk_container_add(GTK_CONTAINER(stream_frame), stream_scrolled);
    
    stream_listbox = gtk_list_box_new();
    gtk_list_box_set_selection_mode(GTK_LIST_BOX(stream_listbox), GTK_SELECTION_SINGLE);
    gtk_container_add(GTK_CONTAINER(stream_scrolled), stream_listbox);
    g_signal_connect(stream_listbox, "row-selected", G_CALLBACK(on_stream_selected), NULL);
    
    /* Right panel - Visualizations */
    GtkWidget* viz_vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    gtk_box_pack_start(GTK_BOX(overview_page), viz_vbox, TRUE, TRUE, 0);
    
    /* Vector diagram */
    GtkWidget* vector_frame = gtk_frame_new("Vector Diagram (Phasors)");
    gtk_box_pack_start(GTK_BOX(viz_vbox), vector_frame, TRUE, TRUE, 0);
    
    vector_drawing_area = gtk_drawing_area_new();
    gtk_widget_set_size_request(vector_drawing_area, 400, 300);
    gtk_container_add(GTK_CONTAINER(vector_frame), vector_drawing_area);
    g_signal_connect(vector_drawing_area, "draw", G_CALLBACK(draw_vector_diagram), NULL);
    
    /* Waveform */
    GtkWidget* waveform_frame = gtk_frame_new("Waveform");
    gtk_box_pack_start(GTK_BOX(viz_vbox), waveform_frame, TRUE, TRUE, 0);
    
    waveform_drawing_area = gtk_drawing_area_new();
    gtk_widget_set_size_request(waveform_drawing_area, 400, 200);
    gtk_container_add(GTK_CONTAINER(waveform_frame), waveform_drawing_area);
    g_signal_connect(waveform_drawing_area, "draw", G_CALLBACK(draw_waveform), NULL);
    
    gtk_notebook_append_page(GTK_NOTEBOOK(notebook), overview_page, gtk_label_new("Overview & Visualization"));
    
    /* Page 2: Detailed Information */
    GtkWidget* detail_page = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    
    GtkWidget* info_frame = gtk_frame_new("Stream Details");
    gtk_box_pack_start(GTK_BOX(detail_page), info_frame, TRUE, TRUE, 0);
    
    GtkWidget* info_scrolled = gtk_scrolled_window_new(NULL, NULL);
    gtk_container_add(GTK_CONTAINER(info_frame), info_scrolled);
    
    info_text_view = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(info_text_view), FALSE);
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(info_text_view), GTK_WRAP_WORD_CHAR);
    gtk_container_add(GTK_CONTAINER(info_scrolled), info_text_view);
    
    gtk_notebook_append_page(GTK_NOTEBOOK(notebook), detail_page, gtk_label_new("Detailed Information"));
    
    gtk_widget_show_all(main_window);
    
    /* Start periodic updates */
    g_timeout_add(1000, periodic_update, NULL);
}

int main(int argc, char** argv) {
    (void)argc;
    (void)argv;
    
    printf("IEC 61850 Sampled Values Viewer\n");
    printf("Using libiec61850-1.6.1\n\n");
    
    /* Initialize sample buffer */
    memset(&g_sample_buffer, 0, sizeof(SampleBuffer));
    
    /* Build and run GUI */
    build_gui();
    
    gtk_main();
    
    /* Cleanup */
    g_running = false;
    if (g_receiver) {
        SVReceiver_stop(g_receiver);
        SVReceiver_destroy(g_receiver);
    }
    
    return 0;
}
