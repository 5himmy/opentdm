/*
 Copyright (C) 1997-2001 Id Software, Inc.

 This program is free software; you can redistribute it and/or
 modify it under the terms of the GNU General Public License
 as published by the Free Software Foundation; either version 2
 of the License, or (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

 See the GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program; if not, write to the Free Software
 Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.

 */

//Curl interface functions. OpenTDM can use libcurl to fetch and POST to the
//website, used for downloading configs and uploading stats (todo).
#include "g_local.h"
#include "g_tdm.h"

#ifdef HAVE_CURL

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#endif

#include <curl/curl.h>

typedef struct dlhandle_s {
    CURL *curl;
    size_t fileSize;
    size_t position;
    double speed;
    char filePath[1024];
    char URL[2048];
    char *tempBuffer;
    qboolean inuse;
    tdm_download_t *tdm_handle;
} dlhandle_t;

//we need this high in case a sudden server switch causes a bunch of people
//to connect, we want to be able to download their configs
#define MAX_DOWNLOADS	16

//size limits for configs, must be power of two
#define MAX_DLSIZE	0x100000	// 1 MiB
#define MIN_DLSIZE	0x8000		// 32 KiB

dlhandle_t downloads[MAX_DOWNLOADS];

// POST request handle for async API calls
typedef struct posthandle_s {
    CURL *curl;
    struct curl_slist *headers;
    char payload[32768];    // 32KB for full match stats
    char url[512];
    qboolean inuse;
} posthandle_t;

#define MAX_POST_HANDLES 4
static posthandle_t post_handles[MAX_POST_HANDLES];

static CURLM *multi = NULL;
static unsigned handleCount = 0;

static char otdm_api_ip[16];
static char hostHeader[64];
static struct curl_slist *http_header_slist;

static time_t last_dns_lookup;

// Pre-resolved API URL for async POST (avoids DNS blocking during match)
static char api_resolved_host[256];      // e.g., "example.com:443:1.2.3.4"
static struct curl_slist *api_resolve_list = NULL;
static time_t api_last_resolve;

/**
 * Properly escapes a path with HTTP %encoding. libcurl's function
 * seems to treat '/' and such as illegal chars and encodes almost
 * the entire URL...
 */
static void HTTP_EscapePath(const char *filePath, char *escaped) {
    int i;
    size_t len;
    char *p;

    p = escaped;

    len = strlen(filePath);
    for (i = 0; i < len; i++) {
        if (!isalnum(filePath[i]) && filePath[i] != ';' && filePath[i] != '/'
                && filePath[i] != '?' && filePath[i] != ':'
                && filePath[i] != '@' && filePath[i] != '&'
                && filePath[i] != '=' && filePath[i] != '+'
                && filePath[i] != '$' && filePath[i] != ','
                && filePath[i] != '[' && filePath[i] != ']'
                && filePath[i] != '-' && filePath[i] != '_'
                && filePath[i] != '.' && filePath[i] != '!'
                && filePath[i] != '~' && filePath[i] != '*'
                && filePath[i] != '\'' && filePath[i] != '('
                && filePath[i] != ')') {
            sprintf(p, "%%%02x", filePath[i]);
            p += 3;
        } else {
            *p = filePath[i];
            p++;
        }
    }
    p[0] = 0;

    //using ./ in a url is legal, but all browsers condense the path and some IDS / request
    //filtering systems act a bit funky if http requests come in with uncondensed paths.
    len = strlen(escaped);
    p = escaped;
    while ((p = strstr(p, "./"))) {
        memmove(p, p + 2, len - (p - escaped) - 1);
        len -= 2;
    }
}

/**
 * libcurl callback.
 */
static size_t EXPORT HTTP_Recv(void *ptr, size_t size, size_t nmemb,
        void *stream) {
    dlhandle_t *dl;
    size_t new_size, bytes;

    dl = (dlhandle_t*) stream;

    if (!nmemb) {
        return 0;
    }

    if (size > SIZE_MAX / nmemb) {
        goto oversize;
    }

    if (dl->position > MAX_DLSIZE) {
        goto oversize;
    }

    bytes = size * nmemb;
    if (bytes >= MAX_DLSIZE - dl->position) {
        goto oversize;
    }

    //grow buffer in MIN_DLSIZE chunks. +1 for NUL.
    new_size = (dl->position + bytes + MIN_DLSIZE) & ~(MIN_DLSIZE - 1);
    if (new_size > dl->fileSize) {
        char *tmp;

        tmp = dl->tempBuffer;
        dl->tempBuffer = gi.TagMalloc((int) new_size, TAG_GAME);
        if (tmp) {
            memcpy(dl->tempBuffer, tmp, dl->fileSize);
            gi.TagFree(tmp);
        }
        dl->fileSize = new_size;
    }

    memcpy(dl->tempBuffer + dl->position, ptr, bytes);
    dl->position += bytes;
    dl->tempBuffer[dl->position] = 0;

    return bytes;

    oversize: gi.dprintf(
            "Suspiciously large file while trying to download %s!\n", dl->URL);
    return 0;
}

/**
 *
 */
int EXPORT CURL_Debug(CURL *c, curl_infotype type, char *data, size_t size,
        void *ptr) {
    if (type == CURLINFO_TEXT) {
        char buff[4096];
        if (size > sizeof(buff) - 1) {
            size = sizeof(buff) - 1;
        }
        Q_strncpy(buff, data, size);
        gi.dprintf("  OpenTDM HTTP DEBUG: %s", buff);
        if (!strchr(buff, '\n')) {
            gi.dprintf("\n");
        }
    }
    return 0;
}

/**
 * Resolve the g_http_domain and cache it, so we don't do DNS
 * lookups at critical times (eg mid match).
 */
void HTTP_ResolveOTDMServer(void) {
    if (!g_http_enabled->value) {
        return;
    }

    //re-resolve if its been more than one day since we last did it
    if (time(NULL) - last_dns_lookup > 86400) {
        gi.cprintf(NULL, PRINT_HIGH, "Resolving API server %s -> ",
                g_http_domain->string);
        struct hostent *h;
        h = gethostbyname(g_http_domain->string);

        if (!h) {
            otdm_api_ip[0] = '\0';
            gi.dprintf(
                    "WARNING: Could not resolve OpenTDM web API server '%s'. HTTP functions unavailable.\n",
                    g_http_domain->string);
            return;
        }

        time(&last_dns_lookup);

        Q_strncpy(otdm_api_ip, inet_ntoa(*(struct in_addr* )h->h_addr_list[0]),
                sizeof(otdm_api_ip) - 1);
        gi.cprintf(NULL, PRINT_HIGH, "%s\n", otdm_api_ip);
    }
}

/**
 * Pre-resolve the g_api_url hostname so we don't block during matches.
 * Call this on server startup and periodically.
 */
void HTTP_ResolveAPIServer(void) {
    char url_copy[512];
    char *host_start, *host_end;
    char hostname[256];
    int port = 443;  // default HTTPS
    struct hostent *h;
    char resolved_ip[16];

    if (!g_http_enabled->value) {
        return;
    }

    if (!g_api_url || !g_api_url->string[0]) {
        return;
    }

    // Only resolve once (at startup) - never during gameplay
    if (api_resolve_list) {
        return;
    }

    Q_strncpy(url_copy, g_api_url->string, sizeof(url_copy) - 1);

    // Parse hostname from URL (http://host:port/path or https://host/path)
    host_start = strstr(url_copy, "://");
    if (!host_start) {
        return;
    }
    host_start += 3;

    // Check for port
    if (strncmp(g_api_url->string, "http://", 7) == 0) {
        port = 80;
    }

    host_end = strchr(host_start, '/');
    if (host_end) {
        *host_end = '\0';
    }

    // Check for explicit port
    char *port_str = strchr(host_start, ':');
    if (port_str) {
        *port_str = '\0';
        port = atoi(port_str + 1);
    }

    Q_strncpy(hostname, host_start, sizeof(hostname) - 1);

    gi.cprintf(NULL, PRINT_HIGH, "Resolving API server %s -> ", hostname);

    h = gethostbyname(hostname);
    if (!h) {
        gi.dprintf("FAILED\n");
        gi.dprintf("WARNING: Could not resolve API server '%s'. Match stats will not be sent.\n", hostname);
        return;
    }

    Q_strncpy(resolved_ip, inet_ntoa(*(struct in_addr*)h->h_addr_list[0]), sizeof(resolved_ip) - 1);
    gi.cprintf(NULL, PRINT_HIGH, "%s\n", resolved_ip);

    // Build CURLOPT_RESOLVE format: "hostname:port:ip"
    Com_sprintf(api_resolved_host, sizeof(api_resolved_host), "%s:%d:%s", hostname, port, resolved_ip);

    // Free old list and create new one
    if (api_resolve_list) {
        curl_slist_free_all(api_resolve_list);
    }
    api_resolve_list = curl_slist_append(NULL, api_resolved_host);

    time(&api_last_resolve);

    if (g_http_debug->value) {
        gi.dprintf("API DNS pre-resolved: %s\n", api_resolved_host);
    }
}

/**
 * Actually starts a download by adding it to the curl multihandle.
 */
void HTTP_StartDownload(dlhandle_t *dl) {
    cvar_t *hostname;
    char escapedFilePath[1024 * 3];

    hostname = gi.cvar("hostname", NULL, 0);
    if (!hostname) {
        TDM_Error("HTTP_StartDownload: Couldn't get hostname cvar");
    }

    dl->tempBuffer = NULL;
    dl->speed = 0;
    dl->fileSize = 0;
    dl->position = 0;

    if (!dl->curl) {
        dl->curl = curl_easy_init();
    }

    HTTP_EscapePath(dl->filePath, escapedFilePath);

    Com_sprintf(dl->URL, sizeof(dl->URL), "http://%s%s%s", otdm_api_ip,
            g_http_path->string, escapedFilePath);

    curl_easy_setopt(dl->curl, CURLOPT_HTTPHEADER, http_header_slist);
    curl_easy_setopt(dl->curl, CURLOPT_ENCODING, "");

    if (g_http_debug->value) {
        curl_easy_setopt(dl->curl, CURLOPT_DEBUGFUNCTION, CURL_Debug);
        curl_easy_setopt(dl->curl, CURLOPT_VERBOSE, 1);
    } else {
        curl_easy_setopt(dl->curl, CURLOPT_DEBUGFUNCTION, NULL);
        curl_easy_setopt(dl->curl, CURLOPT_VERBOSE, 0);
    }

    curl_easy_setopt(dl->curl, CURLOPT_NOPROGRESS, 1);
    curl_easy_setopt(dl->curl, CURLOPT_WRITEDATA, dl);
    if (g_http_bind->string[0]) {
        curl_easy_setopt(dl->curl, CURLOPT_INTERFACE, g_http_bind->string);
    } else {
        curl_easy_setopt(dl->curl, CURLOPT_INTERFACE, NULL);
    }

    curl_easy_setopt(dl->curl, CURLOPT_WRITEFUNCTION, HTTP_Recv);

    if (g_http_proxy->string[0]) {
        curl_easy_setopt(dl->curl, CURLOPT_PROXY, g_http_proxy->string);
    } else {
        curl_easy_setopt(dl->curl, CURLOPT_PROXY, NULL);
    }
    curl_easy_setopt(dl->curl, CURLOPT_FOLLOWLOCATION, 1);
    curl_easy_setopt(dl->curl, CURLOPT_MAXREDIRS, 5);
    curl_easy_setopt(dl->curl, CURLOPT_USERAGENT,
            "OpenTDM (" OPENTDM_VERSION ")");
    curl_easy_setopt(dl->curl, CURLOPT_REFERER, hostname->string);
    curl_easy_setopt(dl->curl, CURLOPT_URL, dl->URL);

    if (curl_multi_add_handle(multi, dl->curl) != CURLM_OK) {
        gi.dprintf("HTTP_StartDownload: curl_multi_add_handle: error\n");
        return;
    }

    handleCount++;
}

/**
 * Init libcurl
 */
void HTTP_Init(void) {
    curl_global_init(CURL_GLOBAL_NOTHING);
    multi = curl_multi_init();

    Com_sprintf(hostHeader, sizeof(hostHeader), "Host: %s",
            g_http_domain->string);
    http_header_slist = curl_slist_append(http_header_slist, hostHeader);

    // Pre-resolve API server to avoid DNS blocking during matches
    HTTP_ResolveAPIServer();

    gi.dprintf("%s initialized.\n", curl_version());
}

/**
 *
 */
void HTTP_Shutdown(void) {
    if (multi) {
        curl_multi_cleanup(multi);
        multi = NULL;
    }
    curl_slist_free_all(http_header_slist);
    if (api_resolve_list) {
        curl_slist_free_all(api_resolve_list);
        api_resolve_list = NULL;
    }
    curl_global_cleanup();
}

/**
 * Handle completion of a POST request
 */
static void HTTP_FinishPost(posthandle_t *ph, CURLcode result) {
    long responseCode = 0;

    if (result == CURLE_OK) {
        curl_easy_getinfo(ph->curl, CURLINFO_RESPONSE_CODE, &responseCode);
        if (g_http_debug->value) {
            gi.dprintf("HTTP POST: %s - Response: %ld\n", ph->url, responseCode);
        }
    } else {
        gi.dprintf("HTTP POST Error: %s - %s\n", ph->url, curl_easy_strerror(result));
    }

    curl_multi_remove_handle(multi, ph->curl);
    curl_easy_cleanup(ph->curl);
    ph->curl = NULL;

    if (ph->headers) {
        curl_slist_free_all(ph->headers);
        ph->headers = NULL;
    }

    ph->inuse = false;
}

/**
 * A download finished, find out what it was, whether there were any errors and
 * if so, how severe. If none, rename file and other such stuff.
 */
static void HTTP_FinishDownload(void) {
    int msgs_in_queue;
    CURLMsg *msg;
    CURLcode result;
    dlhandle_t *dl;
    CURL *curl;
    long responseCode;
    double timeTaken;
    double fileSize;
    unsigned i;
    qboolean found_post;

    do {
        msg = curl_multi_info_read(multi, &msgs_in_queue);

        if (!msg) {
            gi.dprintf("HTTP_FinishDownload: Odd, no message for us...\n");
            return;
        }

        if (msg->msg != CURLMSG_DONE) {
            gi.dprintf("HTTP_FinishDownload: Got some weird message...\n");
            continue;
        }

        curl = msg->easy_handle;

        // Check if this is a POST request
        found_post = false;
        for (i = 0; i < MAX_POST_HANDLES; i++) {
            if (post_handles[i].inuse && post_handles[i].curl == curl) {
                HTTP_FinishPost(&post_handles[i], msg->data.result);
                found_post = true;
                break;
            }
        }
        if (found_post) {
            continue;
        }

        // Check downloads
        for (i = 0; i < MAX_DOWNLOADS; i++) {
            if (downloads[i].curl == curl)
                break;
        }

        if (i == MAX_DOWNLOADS) {
            gi.dprintf("HTTP_FinishDownload: Handle not found, ignoring.\n");
            curl_multi_remove_handle(multi, curl);
            continue;
        }

        dl = &downloads[i];

        result = msg->data.result;

        switch (result) {
        //for some reason curl returns CURLE_OK for a 404...
        case CURLE_HTTP_RETURNED_ERROR:
        case CURLE_OK:

            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &responseCode);
            if (responseCode == 404) {
                TDM_HandleDownload(dl->tdm_handle, NULL, 0, responseCode);
                gi.dprintf("HTTP: %s: 404 File Not Found\n", dl->URL);
                curl_multi_remove_handle(multi, dl->curl);
                dl->inuse = false;
                continue;
            } else if (responseCode == 200) {
                TDM_HandleDownload(dl->tdm_handle, dl->tempBuffer, dl->position,
                        responseCode);
                gi.TagFree(dl->tempBuffer);
            } else {
                TDM_HandleDownload(dl->tdm_handle, NULL, 0, responseCode);
                if (dl->tempBuffer) {
                    gi.TagFree(dl->tempBuffer);
                }
            }
            break;

            //fatal error
        default:
            TDM_HandleDownload(dl->tdm_handle, NULL, 0, 0);
            gi.dprintf("HTTP Error: %s: %s\n", dl->URL,
                    curl_easy_strerror(result));
            curl_multi_remove_handle(multi, dl->curl);
            dl->inuse = false;
            continue;
        }

        //show some stats
        curl_easy_getinfo(curl, CURLINFO_TOTAL_TIME, &timeTaken);
        curl_easy_getinfo(curl, CURLINFO_SIZE_DOWNLOAD_T, &fileSize);

        //FIXME:
        //technically i shouldn't need to do this as curl will auto reuse the
        //existing handle when you change the URL. however, the handleCount goes
        //all weird when reusing a download slot in this way. if you can figure
        //out why, please let me know.
        curl_multi_remove_handle(multi, dl->curl);

        dl->inuse = false;

        gi.dprintf("HTTP: Finished %s: %.f bytes, %.2fkB/sec\n", dl->URL,
                fileSize, (fileSize / 1024.0) / timeTaken);
    } while (msgs_in_queue > 0);
}

/**
 *
 */
qboolean HTTP_QueueDownload(tdm_download_t *d) {
    unsigned i;

    if (handleCount == MAX_DOWNLOADS) {
        if (d->type == DL_CONFIG) {
            gi.cprintf(d->initiator, PRINT_HIGH,
                    "Another download is already pending, please try again later.\n");
        }
        return false;
    }

    if (!g_http_enabled->value) {
        if (d->type == DL_CONFIG) {
            gi.cprintf(d->initiator, PRINT_HIGH,
                    "HTTP functions are disabled on this server.\n");
        }
        return false;
    }

    if (!otdm_api_ip[0]) {
        if (d->type == DL_CONFIG) {
            gi.cprintf(d->initiator, PRINT_HIGH,
                    "This server failed to resolve the OpenTDM web API server.\n");
        }
        return false;
    }

    for (i = 0; i < MAX_DOWNLOADS; i++) {
        if (!downloads[i].inuse) {
            break;
        }
    }

    if (i == MAX_DOWNLOADS) {
        if (d->type == DL_CONFIG) {
            gi.cprintf(d->initiator, PRINT_HIGH,
                    "The server is too busy to download configs right now.\n");
        }
        return false;
    }

    downloads[i].tdm_handle = d;
    downloads[i].inuse = true;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstringop-truncation"
    Q_strncpy(downloads[i].filePath, d->path,
            sizeof(downloads[i].filePath) - 1);
#pragma GCC diagnostic pop
    HTTP_StartDownload(&downloads[i]);

    return true;
}

/**
 *
 */
void HTTP_RunDownloads(void) {
    int newHandleCount;
    CURLMcode ret;

    if (!handleCount) {
        return;
    }

    do {
        ret = curl_multi_perform(multi, &newHandleCount);
        if (newHandleCount < handleCount) {
            HTTP_FinishDownload();
            handleCount = newHandleCount;
        }
    } while (ret == CURLM_CALL_MULTI_PERFORM);

    if (ret != CURLM_OK) {
        gi.dprintf("HTTP_RunDownloads: curl_multi_perform error.\n");
    }
}

/**
 * Discard callback - we don't care about response body for POST requests
 */
static size_t HTTP_DiscardResponse(void *ptr, size_t size, size_t nmemb, void *data) {
    (void)ptr;
    (void)data;
    return size * nmemb;
}

/**
 * Send match event to web API (non-blocking, async)
 * Uses curl_multi for async operation - won't freeze the game server
 */
void HTTP_PostMatchEvent(const char *event_type, const char *match_id,
                         const char *team_a, const char *team_b,
                         int score_a, int score_b, qboolean forfeit)
{
    posthandle_t *ph = NULL;
    unsigned i;
    cvar_t *hostname;
    char *map_name;

    // Check if API URL is configured
    if (!g_api_url->string[0]) {
        if (g_http_debug->value) {
            gi.dprintf("HTTP_PostMatchEvent: g_api_url not set, skipping.\n");
        }
        return;
    }

    if (!g_http_enabled->value) {
        return;
    }

    // Find a free POST handle
    for (i = 0; i < MAX_POST_HANDLES; i++) {
        if (!post_handles[i].inuse) {
            ph = &post_handles[i];
            break;
        }
    }

    if (!ph) {
        gi.dprintf("HTTP_PostMatchEvent: No free POST handles available.\n");
        return;
    }

    hostname = gi.cvar("hostname", "unknown", 0);
    map_name = level.mapname;

    // Build JSON payload (stored in handle to persist during async operation)
    Com_sprintf(ph->payload, sizeof(ph->payload),
        "{"
        "\"event\":\"%s\","
        "\"match_id\":\"%s\","
        "\"server\":\"%s\","
        "\"map\":\"%s\","
        "\"team_a\":\"%s\","
        "\"team_b\":\"%s\","
        "\"score_a\":%d,"
        "\"score_b\":%d,"
        "\"forfeit\":%s"
        "}",
        event_type,
        match_id,
        hostname->string,
        map_name,
        team_a,
        team_b,
        score_a,
        score_b,
        forfeit ? "true" : "false"
    );

    Q_strncpy(ph->url, g_api_url->string, sizeof(ph->url) - 1);

    if (g_http_debug->value) {
        gi.dprintf("HTTP_PostMatchEvent: URL=%s Payload=%s\n", ph->url, ph->payload);
    }

    ph->curl = curl_easy_init();
    if (!ph->curl) {
        gi.dprintf("HTTP_PostMatchEvent: curl_easy_init failed.\n");
        return;
    }

    // Setup headers
    ph->headers = NULL;
    ph->headers = curl_slist_append(ph->headers, "Content-Type: application/json");

    // Configure curl options
    curl_easy_setopt(ph->curl, CURLOPT_URL, ph->url);
    curl_easy_setopt(ph->curl, CURLOPT_POST, 1L);
    curl_easy_setopt(ph->curl, CURLOPT_POSTFIELDS, ph->payload);
    curl_easy_setopt(ph->curl, CURLOPT_HTTPHEADER, ph->headers);
    curl_easy_setopt(ph->curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(ph->curl, CURLOPT_CONNECTTIMEOUT, 5L);
    curl_easy_setopt(ph->curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(ph->curl, CURLOPT_USERAGENT, "OpenTDM (" OPENTDM_VERSION ")");

    // Discard response body
    curl_easy_setopt(ph->curl, CURLOPT_WRITEFUNCTION, HTTP_DiscardResponse);

    // Proxy settings
    if (g_http_proxy->string[0]) {
        curl_easy_setopt(ph->curl, CURLOPT_PROXY, g_http_proxy->string);
    } else {
        curl_easy_setopt(ph->curl, CURLOPT_PROXY, "");
        curl_easy_setopt(ph->curl, CURLOPT_NOPROXY, "*");
    }

    // Bind to specific interface if configured
    if (g_http_bind->string[0]) {
        curl_easy_setopt(ph->curl, CURLOPT_INTERFACE, g_http_bind->string);
    }

    // SSL settings - verify by default (secure)
    curl_easy_setopt(ph->curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(ph->curl, CURLOPT_SSL_VERIFYHOST, 2L);

    // Use pre-resolved DNS to avoid blocking during match
    if (api_resolve_list) {
        curl_easy_setopt(ph->curl, CURLOPT_RESOLVE, api_resolve_list);
    }

    // Set CA bundle path for static libcurl (try common locations)
#ifdef _WIN32
    // Windows uses schannel by default which uses system certs
#else
    // Try common CA bundle locations on Linux
    if (access("/etc/ssl/certs/ca-certificates.crt", R_OK) == 0) {
        curl_easy_setopt(ph->curl, CURLOPT_CAINFO, "/etc/ssl/certs/ca-certificates.crt");
    } else if (access("/etc/pki/tls/certs/ca-bundle.crt", R_OK) == 0) {
        curl_easy_setopt(ph->curl, CURLOPT_CAINFO, "/etc/pki/tls/certs/ca-bundle.crt");
    } else if (access("/etc/ssl/ca-bundle.pem", R_OK) == 0) {
        curl_easy_setopt(ph->curl, CURLOPT_CAINFO, "/etc/ssl/ca-bundle.pem");
    }
#endif

    // HTTP/1.1, no redirects
    curl_easy_setopt(ph->curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
    curl_easy_setopt(ph->curl, CURLOPT_FOLLOWLOCATION, 0L);

    // Debug output if enabled
    if (g_http_debug->value) {
        curl_easy_setopt(ph->curl, CURLOPT_DEBUGFUNCTION, CURL_Debug);
        curl_easy_setopt(ph->curl, CURLOPT_VERBOSE, 1L);
    }

    // Add to multi handle for async processing
    if (curl_multi_add_handle(multi, ph->curl) != CURLM_OK) {
        gi.dprintf("HTTP_PostMatchEvent: curl_multi_add_handle failed.\n");
        curl_easy_cleanup(ph->curl);
        ph->curl = NULL;
        curl_slist_free_all(ph->headers);
        ph->headers = NULL;
        return;
    }

    ph->inuse = true;
    handleCount++;

    if (g_http_debug->value) {
        gi.dprintf("HTTP_PostMatchEvent: Request queued for %s\n", event_type);
    }
}

// Weapon names for JSON output
static const char *weapon_names[] = {
    "invalid", "world", "bl", "sg", "ssg", "mg", "cg",
    "hg", "gl", "rl", "hb", "rg", "bfg"
};

/**
 * Escape a string for JSON (handles quotes and backslashes)
 */
static void JSON_EscapeString(char *dest, const char *src, size_t dest_size) {
    size_t i = 0;
    size_t j = 0;

    while (src[i] && j < dest_size - 2) {
        if (src[i] == '"' || src[i] == '\\') {
            dest[j++] = '\\';
        }
        dest[j++] = src[i++];
    }
    dest[j] = '\0';
}

/**
 * Send full match stats to web API at end of match
 */
void HTTP_PostMatchEndWithStats(matchinfo_t *match, qboolean forfeit)
{
    posthandle_t *ph = NULL;
    unsigned i, w;
    cvar_t *hostname;
    char *p;
    size_t remaining;
    int written;
    teamplayer_t *player;
    char escaped_name[64];
    int total_damage_dealt, total_damage_received;

    // Check if API URL is configured
    if (!g_api_url->string[0]) {
        if (g_http_debug->value) {
            gi.dprintf("HTTP_PostMatchEndWithStats: g_api_url not set, skipping.\n");
        }
        return;
    }

    if (!g_http_enabled->value) {
        return;
    }

    if (!match || !match->teamplayers) {
        gi.dprintf("HTTP_PostMatchEndWithStats: No match data available.\n");
        return;
    }

    // Find a free POST handle
    for (i = 0; i < MAX_POST_HANDLES; i++) {
        if (!post_handles[i].inuse) {
            ph = &post_handles[i];
            break;
        }
    }

    if (!ph) {
        gi.dprintf("HTTP_PostMatchEndWithStats: No free POST handles available.\n");
        return;
    }

    hostname = gi.cvar("hostname", "unknown", 0);

    p = ph->payload;
    remaining = sizeof(ph->payload);

    // Start JSON - match metadata
    written = snprintf(p, remaining,
        "{"
        "\"event\":\"MATCH_ENDED\","
        "\"match_id\":\"%s\","
        "\"server\":\"%s\","
        "\"map\":\"%s\","
        "\"mode\":%d,"
        "\"timelimit\":%d,"
        "\"forfeit\":%s,"
        "\"demo\":\"%s\","
        "\"teams\":{"
            "\"a\":{\"name\":\"%s\",\"score\":%d},"
            "\"b\":{\"name\":\"%s\",\"score\":%d}"
        "},"
        "\"winner\":\"%s\","
        "\"players\":[",
        match->match_id,
        hostname->string,
        match->mapname,
        match->game_mode,
        match->timelimit,
        forfeit ? "true" : "false",
        game.mvd.filename,
        match_rosters.team_a.names,
        match->scores[TEAM_A],
        match_rosters.team_b.names,
        match->scores[TEAM_B],
        match->winning_team == TEAM_A ? "a" :
            (match->winning_team == TEAM_B ? "b" : "tie")
    );

    if (written < 0 || (size_t)written >= remaining) {
        gi.dprintf("HTTP_PostMatchEndWithStats: Buffer overflow in header.\n");
        return;
    }
    p += written;
    remaining -= written;

    // Add each player's stats
    for (i = 0; i < match->num_teamplayers; i++) {
        player = &match->teamplayers[i];

        // Calculate total damage
        total_damage_dealt = 0;
        total_damage_received = 0;
        for (w = 0; w < TDMG_MAX; w++) {
            total_damage_dealt += player->damage_dealt[w];
            total_damage_received += player->damage_received[w];
        }

        JSON_EscapeString(escaped_name, player->name, sizeof(escaped_name));

        // Player base stats
        written = snprintf(p, remaining,
            "%s{"
            "\"name\":\"%s\","
            "\"team\":\"%s\","
            "\"ping\":%u,"
            "\"kills\":{\"enemy\":%u,\"team\":%u,\"self\":%u},"
            "\"deaths\":%u,"
            "\"telefrags\":%u,"
            "\"damage\":{\"dealt\":%d,\"received\":%d,\"team_dealt\":%u,\"team_received\":%u},"
            "\"powerups\":{"
                "\"quad\":{\"kills\":%u,\"deaths\":%u,\"dealt\":%u,\"received\":%u},"
                "\"pent\":{\"kills\":%u,\"deaths\":%u,\"dealt\":%u,\"received\":%u}"
            "},"
            "\"weapons\":{",
            i > 0 ? "," : "",
            escaped_name,
            player->team == TEAM_A ? "a" : "b",
            player->ping,
            player->enemy_kills,
            player->team_kills,
            player->suicides,
            player->deaths,
            player->telefrags,
            total_damage_dealt,
            total_damage_received,
            player->team_dealt,
            player->team_recvd,
            player->quad_kills,
            player->quad_deaths,
            player->quad_dealt,
            player->quad_recvd,
            player->pent_kills,
            player->pent_deaths,
            player->pent_dealt,
            player->pent_recvd
        );

        if (written < 0 || (size_t)written >= remaining) {
            gi.dprintf("HTTP_PostMatchEndWithStats: Buffer overflow in player %d.\n", i);
            return;
        }
        p += written;
        remaining -= written;

        // Add weapon stats (skip INVALID and WORLD)
        for (w = TDMG_BLASTER; w < TDMG_MAX; w++) {
            // Skip weapons with no activity
            if (player->shots_fired[w] == 0 && player->killweapons[w] == 0 &&
                player->deathweapons[w] == 0 && player->damage_dealt[w] == 0) {
                continue;
            }

            written = snprintf(p, remaining,
                "%s\"%s\":{\"shots\":%u,\"hits\":%u,\"kills\":%u,\"deaths\":%u,\"dmg_dealt\":%u,\"dmg_recv\":%u}",
                (p[-1] == '{') ? "" : ",",
                weapon_names[w],
                player->shots_fired[w],
                player->shots_hit[w],
                player->killweapons[w],
                player->deathweapons[w],
                player->damage_dealt[w],
                player->damage_received[w]
            );

            if (written < 0 || (size_t)written >= remaining) {
                gi.dprintf("HTTP_PostMatchEndWithStats: Buffer overflow in weapons.\n");
                return;
            }
            p += written;
            remaining -= written;
        }

        // Close weapons object, add items object
        // Note: ITEM_ITEM_HEALTH only tracks mega health (regular health not tracked)
        // Armor shards also not tracked per TDM_IsTrackableItem
        written = snprintf(p, remaining,
            "},\"items\":{"
            "\"ra\":%u,\"ya\":%u,\"ga\":%u,"
            "\"mh\":%u,"
            "\"quad\":%u,\"pent\":%u"
            "}}",
            player->items_collected[ITEM_ITEM_ARMOR_BODY],
            player->items_collected[ITEM_ITEM_ARMOR_COMBAT],
            player->items_collected[ITEM_ITEM_ARMOR_JACKET],
            player->items_collected[ITEM_ITEM_HEALTH],
            player->items_collected[ITEM_ITEM_QUAD],
            player->items_collected[ITEM_ITEM_INVULNERABILITY]
        );
        if (written < 0 || (size_t)written >= remaining) {
            return;
        }
        p += written;
        remaining -= written;
    }

    // Close players array and root object
    written = snprintf(p, remaining, "]}");
    if (written < 0 || (size_t)written >= remaining) {
        gi.dprintf("HTTP_PostMatchEndWithStats: Buffer overflow in footer.\n");
        return;
    }
    p += written;

    Q_strncpy(ph->url, g_api_url->string, sizeof(ph->url) - 1);

    if (g_http_debug->value) {
        gi.dprintf("HTTP_PostMatchEndWithStats: Payload size=%d bytes\n",
                   (int)(p - ph->payload));
    }

    ph->curl = curl_easy_init();
    if (!ph->curl) {
        gi.dprintf("HTTP_PostMatchEndWithStats: curl_easy_init failed.\n");
        return;
    }

    // Setup headers
    ph->headers = NULL;
    ph->headers = curl_slist_append(ph->headers, "Content-Type: application/json");

    // Configure curl options
    curl_easy_setopt(ph->curl, CURLOPT_URL, ph->url);
    curl_easy_setopt(ph->curl, CURLOPT_POST, 1L);
    curl_easy_setopt(ph->curl, CURLOPT_POSTFIELDS, ph->payload);
    curl_easy_setopt(ph->curl, CURLOPT_HTTPHEADER, ph->headers);
    curl_easy_setopt(ph->curl, CURLOPT_TIMEOUT, 15L);
    curl_easy_setopt(ph->curl, CURLOPT_CONNECTTIMEOUT, 5L);
    curl_easy_setopt(ph->curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(ph->curl, CURLOPT_USERAGENT, "OpenTDM (" OPENTDM_VERSION ")");

    // Discard response body
    curl_easy_setopt(ph->curl, CURLOPT_WRITEFUNCTION, HTTP_DiscardResponse);

    // Proxy settings
    if (g_http_proxy->string[0]) {
        curl_easy_setopt(ph->curl, CURLOPT_PROXY, g_http_proxy->string);
    } else {
        curl_easy_setopt(ph->curl, CURLOPT_PROXY, "");
        curl_easy_setopt(ph->curl, CURLOPT_NOPROXY, "*");
    }

    // Bind to specific interface if configured
    if (g_http_bind->string[0]) {
        curl_easy_setopt(ph->curl, CURLOPT_INTERFACE, g_http_bind->string);
    }

    // SSL settings
    curl_easy_setopt(ph->curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(ph->curl, CURLOPT_SSL_VERIFYHOST, 2L);

    // Use pre-resolved DNS to avoid blocking during match
    if (api_resolve_list) {
        curl_easy_setopt(ph->curl, CURLOPT_RESOLVE, api_resolve_list);
    }

#ifndef _WIN32
    if (access("/etc/ssl/certs/ca-certificates.crt", R_OK) == 0) {
        curl_easy_setopt(ph->curl, CURLOPT_CAINFO, "/etc/ssl/certs/ca-certificates.crt");
    } else if (access("/etc/pki/tls/certs/ca-bundle.crt", R_OK) == 0) {
        curl_easy_setopt(ph->curl, CURLOPT_CAINFO, "/etc/pki/tls/certs/ca-bundle.crt");
    } else if (access("/etc/ssl/ca-bundle.pem", R_OK) == 0) {
        curl_easy_setopt(ph->curl, CURLOPT_CAINFO, "/etc/ssl/ca-bundle.pem");
    }
#endif

    curl_easy_setopt(ph->curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
    curl_easy_setopt(ph->curl, CURLOPT_FOLLOWLOCATION, 0L);

    if (g_http_debug->value) {
        curl_easy_setopt(ph->curl, CURLOPT_DEBUGFUNCTION, CURL_Debug);
        curl_easy_setopt(ph->curl, CURLOPT_VERBOSE, 1L);
    }

    // Add to multi handle
    if (curl_multi_add_handle(multi, ph->curl) != CURLM_OK) {
        gi.dprintf("HTTP_PostMatchEndWithStats: curl_multi_add_handle failed.\n");
        curl_easy_cleanup(ph->curl);
        ph->curl = NULL;
        curl_slist_free_all(ph->headers);
        ph->headers = NULL;
        return;
    }

    ph->inuse = true;
    handleCount++;

    if (g_http_debug->value) {
        gi.dprintf("HTTP_PostMatchEndWithStats: Request queued with %d players.\n",
                   match->num_teamplayers);
    }
}
#else

/**
 *
 */
void HTTP_RunDownloads(void) {
}

/**
 *
 */
void HTTP_Init(void) {
    gi.dprintf(
            "WARNING: OpenTDM was built without libcurl. Some features will be unavailable.\n");
}

/**
 *
 */
qboolean HTTP_QueueDownload(tdm_download_t *d) {
    if (d->type == DL_CONFIG)
        gi.cprintf(d->initiator, PRINT_HIGH,
                "HTTP functions are not compiled on this server.\n");
    return false;
}

/**
 *
 */
void HTTP_ResolveOTDMServer(void) {
}

/**
 *
 */
void HTTP_ResolveAPIServer(void) {
}

/**
 *
 */
void HTTP_PostMatchEvent(const char *event_type, const char *match_id,
                         const char *team_a, const char *team_b,
                         int score_a, int score_b, qboolean forfeit) {
    (void)event_type;
    (void)match_id;
    (void)team_a;
    (void)team_b;
    (void)score_a;
    (void)score_b;
    (void)forfeit;
}

/**
 *
 */
void HTTP_PostMatchEndWithStats(matchinfo_t *match, qboolean forfeit) {
    (void)match;
    (void)forfeit;
}
#endif
