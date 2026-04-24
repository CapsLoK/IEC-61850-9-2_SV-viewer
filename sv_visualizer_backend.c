/*
 * sv_visualizer.c
 * 
 * IEC 61850 Sampled Values Visualizer
 * Captures SV streams and provides data for visualization
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>
#include <unistd.h>
#include <math.h>

#include "sv_subscriber.h"
#include "hal_thread.h"

#define MAX_STREAMS 100
#define MAX_SAMPLES_PER_STREAM 1000
#define MAX_DATA_VALUES 32

/* Structure to hold SV stream information */
typedef struct {
    char svId[256];
    char datSet[256];
    uint16_t appID;
    uint16_t smpCnt;
    uint32_t confRev;
    uint8_t smpMod;
    uint16_t smpRate;
    uint64_t refrTm;
    float dataValues[MAX_DATA_VALUES];
    int dataCount;
    int packetCount;
    uint8_t dstMac[6];
    bool active;
} SVStreamInfo;

/* Global storage for discovered streams */
static SVStreamInfo g_streams[MAX_STREAMS];
static int g_streamCount = 0;
static pthread_mutex_t g_streamsMutex = PTHREAD_MUTEX_INITIALIZER;

/* Callback for latest sample per stream */
static SVSubscriber_ASDU g_latestASDU[MAX_STREAMS] = {0};
static bool g_running = true;

/* Find or create stream entry */
static int findOrCreateStream(const char* svId, uint16_t appID, const uint8_t* dstMac) {
    pthread_mutex_lock(&g_streamsMutex);
    
    // Search existing
    for (int i = 0; i < g_streamCount; i++) {
        if (strcmp(g_streams[i].svId, svId) == 0 && g_streams[i].appID == appID) {
            pthread_mutex_unlock(&g_streamsMutex);
            return i;
        }
    }
    
    // Create new
    if (g_streamCount < MAX_STREAMS) {
        int idx = g_streamCount++;
        memset(&g_streams[idx], 0, sizeof(SVStreamInfo));
        strncpy(g_streams[idx].svId, svId ? svId : "unknown", sizeof(g_streams[idx].svId) - 1);
        g_streams[idx].appID = appID;
        if (dstMac) {
            memcpy(g_streams[idx].dstMac, dstMac, 6);
        }
        g_streams[idx].active = true;
        pthread_mutex_unlock(&g_streamsMutex);
        return idx;
    }
    
    pthread_mutex_unlock(&g_streamsMutex);
    return -1;
}

/* SV Update Listener Callback */
static void svUpdateListener(SVSubscriber subscriber, void* parameter, SVSubscriber_ASDU asdu) {
    const char* svID = SVSubscriber_ASDU_getSvId(asdu);
    if (!svID) return;
    
    int idx = findOrCreateStream(svID, SVSubscriber_getAppID(subscriber), NULL);
    if (idx < 0) return;
    
    pthread_mutex_lock(&g_streamsMutex);
    SVStreamInfo* stream = &g_streams[idx];
    
    // Update metadata
    stream->smpCnt = SVSubscriber_ASDU_getSmpCnt(asdu);
    stream->confRev = SVSubscriber_ASDU_getConfRev(asdu);
    stream->packetCount++;
    
    if (SVSubscriber_ASDU_hasDatSet(asdu)) {
        const char* datSet = SVSubscriber_ASDU_getDatSet(asdu);
        if (datSet) strncpy(stream->datSet, datSet, sizeof(stream->datSet) - 1);
    }
    
    if (SVSubscriber_ASDU_hasSmpMod(asdu)) {
        stream->smpMod = SVSubscriber_ASDU_getSmpMod(asdu);
    }
    
    if (SVSubscriber_ASDU_hasSmpRate(asdu)) {
        stream->smpRate = SVSubscriber_ASDU_getSmpRate(asdu);
    }
    
    if (SVSubscriber_ASDU_hasRefrTm(asdu)) {
        stream->refrTm = SVSubscriber_ASDU_getRefrTmAsMs(asdu);
    }
    
    // Extract data values (assume FLOAT32 for now)
    int dataSize = SVSubscriber_ASDU_getDataSize(asdu);
    stream->dataCount = 0;
    for (int i = 0; i < MAX_DATA_VALUES && i * 4 < dataSize; i++) {
        stream->dataValues[i] = SVSubscriber_ASDU_getFLOAT32(asdu, i * 4);
        stream->dataCount++;
    }
    
    pthread_mutex_unlock(&g_streamsMutex);
}

/* Get stream info as JSON-like string for Python */
void sv_get_streams_json(char* buffer, size_t bufferSize) {
    pthread_mutex_lock(&g_streamsMutex);
    
    char* ptr = buffer;
    char* end = buffer + bufferSize;
    
    ptr += snprintf(ptr, end - ptr, "[");
    
    for (int i = 0; i < g_streamCount; i++) {
        if (i > 0) ptr += snprintf(ptr, end - ptr, ",");
        
        SVStreamInfo* s = &g_streams[i];
        ptr += snprintf(ptr, end - ptr, 
            "{\"id\":%d,\"svId\":\"%s\",\"appID\":%u,\"smpCnt\":%u,"
            "\"confRev\":%u,\"smpMod\":%u,\"smpRate\":%u,\"dataCount\":%d,\"packets\":%u,",
            i, s->svId, s->appID, s->smpCnt, s->confRev, s->smpMod, s->smpRate, 
            s->dataCount, s->packetCount);
        
        ptr += snprintf(ptr, end - ptr, "\"data\":[");
        for (int j = 0; j < s->dataCount; j++) {
            if (j > 0) ptr += snprintf(ptr, end - ptr, ",");
            ptr += snprintf(ptr, end - ptr, "%.6f", s->dataValues[j]);
        }
        ptr += snprintf(ptr, end - ptr, "]}");
    }
    
    ptr += snprintf(ptr, end - ptr, "]");
    
    pthread_mutex_unlock(&g_streamsMutex);
}

/* Get specific stream data */
void sv_get_stream_data(int streamIdx, char* buffer, size_t bufferSize) {
    pthread_mutex_lock(&g_streamsMutex);
    
    if (streamIdx < 0 || streamIdx >= g_streamCount) {
        snprintf(buffer, bufferSize, "{}");
        pthread_mutex_unlock(&g_streamsMutex);
        return;
    }
    
    SVStreamInfo* s = &g_streams[streamIdx];
    
    snprintf(buffer, bufferSize,
        "{"
        "\"svId\":\"%s\","
        "\"datSet\":\"%s\","
        "\"appID\":%u,"
        "\"smpCnt\":%u,"
        "\"confRev\":%u,"
        "\"smpMod\":%u,"
        "\"smpRate\":%u,"
        "\"refrTm\":%lu,"
        "\"dataCount\":%d,"
        "\"packets\":%u,"
        "\"data\":[",
        s->svId, s->datSet, s->appID, s->smpCnt, s->confRev,
        s->smpMod, s->smpRate, s->refrTm, s->dataCount, s->packetCount);
    
    char* ptr = buffer + strlen(buffer);
    char* end = buffer + bufferSize;
    
    for (int j = 0; j < s->dataCount; j++) {
        if (j > 0) ptr += snprintf(ptr, end - ptr, ",");
        ptr += snprintf(ptr, end - ptr, "%.6f", s->dataValues[j]);
    }
    
    snprintf(ptr, end - ptr, "]}");
    
    pthread_mutex_unlock(&g_streamsMutex);
}

/* Get count of discovered streams */
int sv_get_stream_count(void) {
    pthread_mutex_lock(&g_streamsMutex);
    int count = g_streamCount;
    pthread_mutex_unlock(&g_streamsMutex);
    return count;
}

/* Reset all streams */
void sv_reset_streams(void) {
    pthread_mutex_lock(&g_streamsMutex);
    g_streamCount = 0;
    pthread_mutex_unlock(&g_streamsMutex);
}

/* SV Receiver thread context */
typedef struct {
    char interfaceId[64];
    SVReceiver receiver;
    bool running;
} SVReceiverContext;

static SVReceiverContext g_receiverCtx = {0};

/* Thread function for SV reception */
static void* sv_receiver_thread(void* arg) {
    SVReceiverContext* ctx = (SVReceiverContext*)arg;
    
    ctx->receiver = SVReceiver_create();
    if (!ctx->receiver) {
        fprintf(stderr, "Failed to create SV receiver\n");
        return NULL;
    }
    
    if (strlen(ctx->interfaceId) > 0) {
        SVReceiver_setInterfaceId(ctx->receiver, ctx->interfaceId);
        printf("Using interface: %s\n", ctx->interfaceId);
    } else {
        printf("Using default interface\n");
    }
    
    // Create subscriber that listens to all APPIDs (0 means wildcard in some implementations)
    // For discovery, we'll use a broad filter
    SVSubscriber subscriber = SVSubscriber_create(NULL, 0);
    SVSubscriber_setListener(subscriber, svUpdateListener, NULL);
    SVReceiver_addSubscriber(ctx->receiver, subscriber);
    
    SVReceiver_start(ctx->receiver);
    
    if (SVReceiver_isRunning(ctx->receiver)) {
        ctx->running = true;
        printf("SV receiver started successfully\n");
        
        while (g_running && ctx->running) {
            Thread_sleep(100);
        }
        
        SVReceiver_stop(ctx->receiver);
    } else {
        fprintf(stderr, "Failed to start SV receiver\n");
    }
    
    SVReceiver_destroy(ctx->receiver);
    ctx->receiver = NULL;
    return NULL;
}

/* Start SV reception on specified interface */
int sv_start_receiver(const char* interfaceId) {
    if (g_receiverCtx.running) {
        printf("Receiver already running\n");
        return 0;
    }
    
    sv_reset_streams();
    
    if (interfaceId) {
        strncpy(g_receiverCtx.interfaceId, interfaceId, sizeof(g_receiverCtx.interfaceId) - 1);
    } else {
        g_receiverCtx.interfaceId[0] = '\0';
    }
    
    pthread_t thread;
    if (pthread_create(&thread, NULL, sv_receiver_thread, &g_receiverCtx) != 0) {
        fprintf(stderr, "Failed to create receiver thread\n");
        return -1;
    }
    
    pthread_detach(thread);
    return 0;
}

/* Stop SV reception */
void sv_stop_receiver(void) {
    g_running = false;
    g_receiverCtx.running = false;
    
    if (g_receiverCtx.receiver) {
        SVReceiver_stop(g_receiverCtx.receiver);
    }
    
    sleep(1);
}

/* Signal handler */
static void sigint_handler(int signalId) {
    g_running = false;
    g_receiverCtx.running = false;
}

/* Main entry point for testing */
#ifdef STANDALONE_TEST
int main(int argc, char** argv) {
    const char* interfaceId = (argc > 1) ? argv[1] : "eth0";
    
    printf("IEC 61850 SV Visualizer Backend\n");
    printf("Listening on interface: %s\n", interfaceId);
    printf("Press Ctrl+C to stop\n\n");
    
    signal(SIGINT, sigint_handler);
    
    if (sv_start_receiver(interfaceId) != 0) {
        fprintf(stderr, "Failed to start SV receiver\n");
        return 1;
    }
    
    // Print discovered streams periodically
    while (g_running) {
        sleep(2);
        
        char buffer[65536];
        sv_get_streams_json(buffer, sizeof(buffer));
        
        printf("Streams: %s\n", buffer);
        printf("Total streams: %d\n\n", sv_get_stream_count());
    }
    
    sv_stop_receiver();
    printf("Stopped.\n");
    
    return 0;
}
#endif
