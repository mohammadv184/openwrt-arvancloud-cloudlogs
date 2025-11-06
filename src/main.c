/*
 * Copyright (c) Mohammad Abbasi <mohammad.v184@gmail.com> - All Rights Reserved
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <syslog.h>

#include <libubox/uloop.h>
#include <libubox/blobmsg_json.h>
#include <libubus.h>
#include <curl/curl.h>

// Default values (can be overridden via command-line arguments)
#define DEFAULT_MAX_BUFFER_SIZE 500
#define DEFAULT_MAX_BUFFER_BYTES (512 * 1024)  // 512KB
#define DEFAULT_FLUSH_INTERVAL_SEC 10
#define DEFAULT_MIN_BATCH_SIZE 10
#define LOG_TAG "arvancloud-cloudlogs"   // Tag for our own logs

#define CURL_MAX_IDLE_TIME 30

#define CLOUDLOGS_BASE_URL "https://napi.arvancloud.ir"
#define CLOUDLOGS_ENDPOINT_WRITE_LOGS "/logging/v1/entries/write"


struct log_entry {
    long long time;
    int priority;
    int source;
    char *tag;
    char *message;
    struct log_entry *next;
};

// Struct to hold the response data from curl
struct curl_response_buffer {
    char *buffer;
    size_t size;
};

static struct ubus_context *ctx;
static struct ubus_subscriber subscriber;
static const char *api_key = NULL;
static const char *device_name = NULL; // device hostname

// Configurable buffer parameters
static int max_buffer_size = DEFAULT_MAX_BUFFER_SIZE;
static size_t max_buffer_bytes = DEFAULT_MAX_BUFFER_BYTES;
static int flush_interval_sec = DEFAULT_FLUSH_INTERVAL_SEC;
static int min_batch_size = DEFAULT_MIN_BATCH_SIZE;
static int allow_partial_process = 0; // default: false

static struct log_entry *buffer_head = NULL;
static struct log_entry *buffer_tail = NULL;
static int buffer_count = 0;
static size_t buffer_bytes = 0;
static struct uloop_timeout flush_timer;
static int shutdown_requested = 0;
static CURL *curl_handle = NULL;         // Reused CURL handle
static time_t curl_last_used = 0;        // Last time CURL handle was used

// Logging helpers that write to syslog
#define log_debug(...) do { \
    fprintf(stderr, __VA_ARGS__); \
    fprintf(stderr, "\n"); \
} while(0)
#define log_info(...) do { \
    fprintf(stderr, __VA_ARGS__); \
    fprintf(stderr, "\n"); \
} while(0)
#define log_warn(...) do { \
    fprintf(stderr, __VA_ARGS__); \
    fprintf(stderr, "\n"); \
} while(0)
#define log_err(...) do { \
    fprintf(stderr, __VA_ARGS__); \
    fprintf(stderr, "\n"); \
} while(0)

static void flush_buffer_forced(void);
static void flush_buffer(int force);


static void handle_signal(const int sig)
{
    (void)sig;
    shutdown_requested = 1;
    flush_buffer_forced();
    uloop_end();
}

// json_escape escapes a string for safe inclusion in JSON
static char *json_escape(const char *s)
{
    if (!s) return strdup("");
    size_t len = 0;
    const char *p;
    for (p = s; *p; ++p) {
        switch (*p) {
            case '\\':
            case '"':
            case '\n':
            case '\r':
            case '\t':
                len += 2; break;
            default:
                if ((unsigned char)*p < 0x20) len += 6; else len += 1;
        }
    }
    char *out = malloc(len + 1);
    if (!out) return NULL;
    char *q = out;
    for (p = s; *p; ++p) {
        unsigned char c = (unsigned char)*p;
        switch (c) {
            case '\\': *q++ = '\\'; *q++ = '\\'; break;
            case '"': *q++ = '\\'; *q++ = '"'; break;
            case '\n': *q++ = '\\'; *q++ = 'n'; break;
            case '\r': *q++ = '\\'; *q++ = 'r'; break;
            case '\t': *q++ = '\\'; *q++ = 't'; break;
            default:
                if (c < 0x20) {
                    sprintf(q, "\\u%04x", c);
                    q += 6;
                } else {
                    *q++ = *p;
                }
        }
    }
    *q = '\0';
    return out;
}

static void curl_cleanup_handle(void)
{
    if (curl_handle) {
        curl_easy_cleanup(curl_handle);
        curl_handle = NULL;
    }
}

static CURL *curl_get_handle(void)
{
    const time_t now = time(NULL);
    
    // Reuse handle if it exists and is still fresh
    if (curl_handle && (now - curl_last_used) < CURL_MAX_IDLE_TIME) {
        curl_last_used = now;
        return curl_handle;
    }
    
    // Cleanup old handle if it exists
    curl_cleanup_handle();
    
    // Create a new handle
    curl_handle = curl_easy_init();
    if (curl_handle) {
        curl_easy_setopt(curl_handle, CURLOPT_TCP_KEEPALIVE, 1L);
        curl_easy_setopt(curl_handle, CURLOPT_TCP_KEEPIDLE, 30L);
        curl_easy_setopt(curl_handle, CURLOPT_TCP_KEEPINTVL, 10L);
        curl_easy_setopt(curl_handle, CURLOPT_TCP_NODELAY, 1L);
        curl_easy_setopt(curl_handle, CURLOPT_NOSIGNAL, 1L);
        curl_easy_setopt(curl_handle, CURLOPT_TIMEOUT, 15L);  // Increased timeout for batches
        curl_easy_setopt(curl_handle, CURLOPT_CONNECTTIMEOUT, 5L);
        curl_last_used = now;
    }
    
    return curl_handle;
}

static const char *priority_to_severity(int priority)
{
    // Map OpenWrt syslog priorities to ArvanCloud severity levels
    // OpenWrt: 0=EMERG, 1=ALERT, 2=CRIT, 3=ERR, 4=WARNING, 5=NOTICE, 6=INFO, 7=DEBUG
    // ArvanCloud: DEBUG, INFO, NOTICE, WARNING, ERROR, CRITICAL
    switch (priority) {
        case 0:  // EMERG
        case 1:  // ALERT
        case 2:  // CRIT
            return "CRITICAL";
        case 3:  // ERR
            return "ERROR";
        case 4:  // WARNING
            return "WARNING";
        case 5:  // NOTICE
            return "NOTICE";
        case 6:  // INFO
            return "INFO";
        case 7:  // DEBUG
        default:
            return "DEBUG";
    }
}

static const char *facility_to_string(int facility)
{
    // Map syslog facility codes to strings
    const char *facilityNames[] = {
        "kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news",
        "uucp", "cron", "authpriv", "ftp", "ntp", "security", "console",
        "solaris-cron", "local0", "local1", "local2", "local3",
        "local4", "local5", "local6", "local7"
    };

    return (facility >= 0 && facility < 24) ? facilityNames[facility] : "unknown";
}

static void format_iso8601_timestamp(char *buf, size_t bufsize, long long unix_time_ms)
{
    // unix_time_ms is milliseconds since epoch (UTC)
    time_t t = (time_t)(unix_time_ms / 1000LL);
    struct tm *tm_info = gmtime(&t);
    if (tm_info) {
        snprintf(buf, bufsize, "%04d-%02d-%02dT%02d:%02d:%02dZ",
                 tm_info->tm_year + 1900, tm_info->tm_mon + 1, tm_info->tm_mday,
                 tm_info->tm_hour, tm_info->tm_min, tm_info->tm_sec);
    } else {
        // Fallback to current time if conversion fails
        time_t now = time(NULL);
        struct tm *now_tm = gmtime(&now);
        if (now_tm) {
            snprintf(buf, bufsize, "%04d-%02d-%02dT%02d:%02d:%02dZ",
                     now_tm->tm_year + 1900, now_tm->tm_mon + 1, now_tm->tm_mday,
                     now_tm->tm_hour, now_tm->tm_min, now_tm->tm_sec);
        } else {
            strncpy(buf, "1970-01-01T00:00:00Z", bufsize);
        }
    }
}

// Callback function for curl to write received data
static size_t curl_write_callback_func(void *contents, size_t size, size_t nmemb, void *userp)
{
    size_t realsize = size * nmemb;
    struct curl_response_buffer *mem = (struct curl_response_buffer *)userp;

    char *ptr = realloc(mem->buffer, mem->size + realsize + 1);
    if (!ptr) {
        log_err("%s: not enough memory (realloc returned NULL)", LOG_TAG);
        return 0; // out of memory
    }

    mem->buffer = ptr;
    memcpy(&(mem->buffer[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->buffer[mem->size] = 0; // Null-terminate

    return realsize;
}


static int http_post_json(const char *url, const char *api_key, const char *json, int batch_size)
{
    int ret = -1;
    CURL *curl = curl_get_handle();
    if (!curl) return -1;

    // Initialize our response buffer
    struct curl_response_buffer response;
    response.buffer = malloc(1); // Will be realloc'd
    if (!response.buffer) {
        log_err("%s: Failed to allocate memory for curl response buffer", LOG_TAG);
        return -1;
    }
    response.size = 0;
    response.buffer[0] = '\0';

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, "User-Agent: openwrt-arvancloud-cloudlogs/0.1.0");
    char keyhdr[256];
    if (api_key) {
        snprintf(keyhdr, sizeof(keyhdr), "Authorization: apikey %s", api_key);
        headers = curl_slist_append(headers, keyhdr);
    }

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(json));

    // Set the write callback to capture the response
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_callback_func);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&response);

    CURLcode res = curl_easy_perform(curl);
    if (res == CURLE_OK) {
        long code = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
        // ArvanCloud API returns 202 for accepted logs, 422 for validation errors
        ret = (code == 202) ? 0 : -1;
    } else {
        // On error, cleanup handle to force recreation on next request
        log_warn("%s: HTTP request failed: %s", LOG_TAG, curl_easy_strerror(res));
        curl_cleanup_handle();
    }

    if (ret == 0) {
        log_debug("%s: Successfully sent batch of %d logs", LOG_TAG, batch_size);
    } else {
        long code = 0;
        if (curl) {
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
        }

        // Log the error and the response payload
        if (response.size > 0) {
            log_err("%s: HTTP request failed with status code %ld. Server response: %s", LOG_TAG, code, response.buffer);
        } else {
            log_err("%s: HTTP request failed with status code %ld. No server response.", LOG_TAG, code);
        }
    }

    curl_slist_free_all(headers);
    free(response.buffer);
    return ret;
}

static void free_log_entry(struct log_entry *entry)
{
    if (!entry) return;
    free(entry->tag);
    free(entry->message);
    free(entry);
}

static void flush_buffer_forced(void)
{
    flush_buffer(1);
}

static void flush_buffer(const int force)
{
    // Don't flush if buffer is too small (unless forced)
    if (!force && buffer_count < min_batch_size) {
        return;
    }
    
    if (!buffer_head || !api_key) { // return if nothing to send or no API key
        if (!api_key) {
            log_warn("%s: Cannot flush: missing api_key", LOG_TAG);
        }
        return;
    }
    
    log_debug("%s: Flushing buffer with %d entries (forced=%d)", LOG_TAG, buffer_count, force);

    // Estimate JSON size: each log entry is roughly 200-500 bytes
    // Add 30% overhead for JSON formatting and escaping
    // Use a minimum of 8KB to avoid too many small allocations
    size_t estimated_size = (buffer_bytes * 13 / 10) + 2048;
    if (estimated_size < 8192) estimated_size = 8192;
    if (estimated_size > 512 * 1024) estimated_size = 512 * 1024; // Cap at 512KB
    
    char *json = malloc(estimated_size);
    if (!json) {
        log_err("%s: Failed to allocate memory for JSON buffer (%zu bytes)", LOG_TAG, estimated_size);
        // If allocation fails, drop the buffer
        while (buffer_head) {
            struct log_entry *next = buffer_head->next;
            free_log_entry(buffer_head);
            buffer_head = next;
        }
        buffer_tail = NULL;
        buffer_count = 0;
        buffer_bytes = 0;
        return;
    }

    char *p = json;
    size_t remaining = estimated_size;
    
    // Start request object with allowPartialProcess from configuration
    int n = snprintf(p, remaining, "{\"allowPartialProcess\":%s,\"logs\":[",
                     allow_partial_process ? "true" : "false");
    if (n > 0 && (size_t)n < remaining) {
        p += n;
        remaining -= n;
    }

    struct log_entry *entry = buffer_head;
    struct log_entry *last_sent = NULL;
    int first = 1;
    int sent_count = 0;
    char timestamp_buf[32];


    while (entry && remaining > 512) {
        if (!first) {
            n = snprintf(p, remaining, ",");
            if (n > 0 && (size_t)n < remaining) {
                p += n;
                remaining -= n;
            }
        }
        first = 0;

        // Format log timestamp
        format_iso8601_timestamp(timestamp_buf, sizeof(timestamp_buf), entry->time);

        char *msg_esc = json_escape(entry->message ? entry->message : "");
        char *tag_esc = json_escape(entry->tag ? entry->tag : "");
        char *device_name_esc = json_escape(device_name ? device_name : "");
        const char *severity = priority_to_severity(LOG_PRI(entry->priority));
        const char *facility = facility_to_string(LOG_FAC(entry->priority));

        // Build ArvanCloud logEntry format
        // logType, timestamp, severity, resource, payload
        n = snprintf(p, remaining,
            "{\"logType\":\"generic\",\"timestamp\":\"%s\",\"severity\":\"%s\","
            "\"resource\":{\"type\":\"general\",\"attributes\":{\"device\":\"%s\"}},"
            "\"payload\":{\"message\":\"%s\",\"tag\":\"%s\",\"source\":%d,\"severity\":\"%s\",\"facility\":\"%s\",\"device_name\":\"%s\"}}",
            timestamp_buf, severity,
            device_name_esc ? device_name_esc : "",
            msg_esc ? msg_esc : "", tag_esc ? tag_esc : "", entry->source, severity, facility,
            device_name_esc ? device_name_esc : "");

        free(msg_esc);
        free(tag_esc);
        free(device_name_esc);

        if (n > 0 && (size_t)n < remaining) {
            p += n;
            remaining -= n;
            last_sent = entry;
            sent_count++;
            entry = entry->next;
        } else {
            // Buffer too small, stop here
            break;
        }
    }

    // Close logs array and request object
    n = snprintf(p, remaining, "]}");
    if (n > 0 && (size_t)n < remaining) {
        p += n;
    }

    // Build ArvanCloud endpoint URL with spaceId
    char url[512];
    snprintf(url, sizeof(url),
                CLOUDLOGS_BASE_URL CLOUDLOGS_ENDPOINT_WRITE_LOGS);

    // Send the batch only if we have entries
    if (sent_count > 0) {
        http_post_json(url, api_key, json, sent_count);
    }
    free(json);

    // Only free entries that were sent
    if (last_sent) {
        struct log_entry *to_free = buffer_head;
        while (to_free != last_sent->next) {
            struct log_entry *next = to_free->next;
            // Recalculate actual size for accurate tracking
            size_t entry_size = sizeof(struct log_entry) + 
                                (to_free->tag ? strlen(to_free->tag) : 0) + 
                                (to_free->message ? strlen(to_free->message) : 0) + 100;
            free_log_entry(to_free);
            buffer_count--;
            if (buffer_bytes >= entry_size) {
                buffer_bytes -= entry_size;
            } else {
                buffer_bytes = 0; // Prevent underflow
            }
            to_free = next;
        }
        buffer_head = last_sent->next;
        if (!buffer_head) {
            buffer_tail = NULL;
        }
    } else {
        // No entries were sent, clear everything
        entry = buffer_head;
        while (entry) {
            struct log_entry *next = entry->next;
            free_log_entry(entry);
            entry = next;
        }
        buffer_head = NULL;
        buffer_tail = NULL;
        buffer_count = 0;
        buffer_bytes = 0;
    }
}

static void flush_timer_cb(struct uloop_timeout *t)
{
    (void)t;
    // Force flush on timer to ensure logs don't sit too long
    flush_buffer(1);
    if (!shutdown_requested) {
        uloop_timeout_set(&flush_timer, flush_interval_sec * 1000);
    }
}



static void process_log_message(struct blob_attr *msg)
{
    enum {
        F_PRIORITY,
        F_SOURCE,
        F_TIME,
        F_TAG,
        F_MSG,
        __F_MAX
    };

    static const struct blobmsg_policy policy[__F_MAX] = {
        [F_PRIORITY] = { .name = "priority", .type = BLOBMSG_TYPE_INT32 },
        [F_SOURCE]   = { .name = "source",   .type = BLOBMSG_TYPE_INT32 },
        [F_TIME]     = { .name = "time",     .type = BLOBMSG_TYPE_INT64 },
        [F_TAG]      = { .name = "tag",      .type = BLOBMSG_TYPE_STRING },
        [F_MSG]      = { .name = "msg",      .type = BLOBMSG_TYPE_STRING },
    };

    struct blob_attr *tb[__F_MAX];
    memset(tb, 0, sizeof(tb));
    blobmsg_parse(policy, __F_MAX, tb, blob_data(msg), blob_len(msg));

    int priority = tb[F_PRIORITY] ? blobmsg_get_u32(tb[F_PRIORITY]) : -1;
    int source = tb[F_SOURCE] ? blobmsg_get_u32(tb[F_SOURCE]) : -1;
    long long t = tb[F_TIME] ? (long long)blobmsg_get_u64(tb[F_TIME]) : (long long)time(NULL);
    const char *tag = tb[F_TAG] ? blobmsg_get_string(tb[F_TAG]) : "";
    const char *message = tb[F_MSG] ? blobmsg_get_string(tb[F_MSG]) : "";

    // Filter out our own log messages to prevent a recursive loop
    if (message && strcmp(message, LOG_TAG) == 0) {
        return; // It's our own log, drop it.
    }

    if (!api_key) return; // not configured, drop

    struct log_entry *entry = malloc(sizeof(struct log_entry));
    if (!entry) {
        log_warn("%s: Out of memory, dropping log entry", LOG_TAG);
        return;
    }

    entry->time = t; // stored as milliseconds since epoch
    entry->priority = priority;
    entry->source = source;
    entry->tag = strdup(tag ? tag : "");
    entry->message = strdup(message ? message : "");
    entry->next = NULL;

    if (!entry->tag || !entry->message) {
        log_warn("%s: Failed to allocate memory for log entry tag/message", LOG_TAG);
        free_log_entry(entry);
        return;
    }

    size_t entry_size = sizeof(struct log_entry) + strlen(entry->tag) + strlen(entry->message) + 100;

    if (buffer_count >= max_buffer_size || buffer_bytes + entry_size > max_buffer_bytes) {
        flush_buffer(1);
    }

    if (buffer_tail) {
        buffer_tail->next = entry;
        buffer_tail = entry;
    } else {
        buffer_head = entry;
        buffer_tail = entry;
    }
    buffer_count++;
    buffer_bytes += entry_size;
}

// Subscriber notification callback
static int log_notify_cb(struct ubus_context *ctx, struct ubus_object *obj,
                        struct ubus_request_data *req, const char *method,
                        struct blob_attr *msg)
{
    (void)ctx; (void)obj; (void)req;
    if (!method || strcmp(method, "message") != 0) {
        return 0;
    }
    if (!msg) {
        return 0;
    }
    process_log_message(msg);
    return 0;
}

static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s -k <api_key> [options]\n", prog);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -k <api_key>           ArvanCloud API key (required)\n");
    fprintf(stderr, "  -d <device_name>       Device identity/hostname (optional)\n");
    fprintf(stderr, "  -b <max_buffer_size>   Max log entries in buffer (default: %d)\n", DEFAULT_MAX_BUFFER_SIZE);
    fprintf(stderr, "  -m <max_buffer_bytes>  Max buffer size in bytes (default: %d)\n", DEFAULT_MAX_BUFFER_BYTES);
    fprintf(stderr, "  -f <flush_interval>    Flush interval in seconds (default: %d)\n", DEFAULT_FLUSH_INTERVAL_SEC);
    fprintf(stderr, "  -t <min_batch_size>    Min logs before sending (default: %d)\n", DEFAULT_MIN_BATCH_SIZE);
    fprintf(stderr, "  -p <allow_partial>     Allow server partial processing (0/1) (default: 0)\n");
}

int main(const int argc, char **argv)
{
    int opt;
    while ((opt = getopt(argc, argv, "k:d:b:m:f:t:p:")) != -1) {
        switch (opt) {
            case 'k': api_key = optarg; break;
            case 'd': device_name = optarg; break;
            case 'b': max_buffer_size = atoi(optarg); break;
            case 'm': max_buffer_bytes = (size_t)atol(optarg); break;
            case 'f': flush_interval_sec = atoi(optarg); break;
            case 't': min_batch_size = atoi(optarg); break;
            case 'p': allow_partial_process = atoi(optarg); break;
            default: usage(argv[0]); return 1;
        }
    }
    
    // Validate configuration values
    if (max_buffer_size < 1) {
        fprintf(stderr, "Error: max_buffer_size must be at least 1\n");
        return 1;
    }
    if (max_buffer_bytes < 1024) {
        fprintf(stderr, "Error: max_buffer_bytes must be at least 1024\n");
        return 1;
    }
    if (flush_interval_sec < 1) {
        fprintf(stderr, "Error: flush_interval_sec must be at least 1\n");
        return 1;
    }
    if (min_batch_size < 1) {
        fprintf(stderr, "Error: min_batch_size must be at least 1\n");
        return 1;
    }

    if (!api_key) api_key = getenv("CLOUDLOGS_API_KEY");
    if (!device_name || !*device_name) {
        char hostname[128];
        if (gethostname(hostname, sizeof(hostname)) == 0) {
            device_name = strdup(hostname);
        }
    }

    if (!api_key) {
        usage(argv[0]);
        fprintf(stderr, "Missing api_key.\n");
        return 2;
    }

    log_info("%s: Starting arvancloud-cloudlogs forwarder", LOG_TAG);
    log_info("%s: Configuration - buffer_size=%d, buffer_bytes=%zu, flush_interval=%ds, min_batch=%d, curl_idle=%ds, allow_partial=%d",
             LOG_TAG, max_buffer_size, max_buffer_bytes, flush_interval_sec, min_batch_size, CURL_MAX_IDLE_TIME, allow_partial_process);

    curl_global_init(CURL_GLOBAL_DEFAULT);

    uloop_init();

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    ctx = ubus_connect(NULL);
    if (!ctx) {
        log_err("%s: Failed to connect to ubus", LOG_TAG);
        closelog();
        return 3;
    }
    log_info("%s: Connected to ubus", LOG_TAG);

    ubus_add_uloop(ctx);

    // Register subscriber and subscribe to notifications from "log" object
    memset(&subscriber, 0, sizeof(subscriber));
    subscriber.cb = log_notify_cb;
    int ret = ubus_register_subscriber(ctx, &subscriber);
    if (ret) {
        log_err("%s: Failed to register subscriber: %d", LOG_TAG, ret);
        log_err("%s: Make sure logd service is running (opkg install logd)", LOG_TAG);
        ubus_free(ctx);
        closelog();
        return 4;
    }

    uint32_t log_obj_id = 0;
    ret = ubus_lookup_id(ctx, "log", &log_obj_id);
    if (ret) {
        log_err("%s: Failed to lookup 'log' object: %d", LOG_TAG, ret);
        ubus_free(ctx);
        closelog();
        return 4;
    }

    ret = ubus_subscribe(ctx, &subscriber, log_obj_id);
    if (ret) {
        log_err("%s: Failed to subscribe to 'log' notifications: %d", LOG_TAG, ret);
        ubus_free(ctx);
        closelog();
        return 4;
    }

    log_info("%s: Subscribed to 'log' notifications from logd...", LOG_TAG);

    // Initialize flush timer
    flush_timer.cb = flush_timer_cb;
    uloop_timeout_set(&flush_timer, flush_interval_sec * 1000);

    uloop_run();

    // Flush any remaining logs before exit
    log_info("%s: Shutting down, flushing remaining logs...", LOG_TAG);
    flush_buffer(1);

    uloop_timeout_cancel(&flush_timer);
    curl_cleanup_handle(); // Cleanup CURL handle
    ubus_free(ctx);
    uloop_done();
    curl_global_cleanup();
    
    log_info("%s: Shutdown complete", LOG_TAG);
    return 0;
}
