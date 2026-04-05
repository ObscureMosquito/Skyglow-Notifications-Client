/*
 * SFHTTPServer.m
 * Compile with -fno-objc-arc (MRC).
 */

#import "SFHTTPServer.h"

#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <fcntl.h>

/* ── Constants ────────────────────────────────────────────────────────────── */
#define SFHTTP_HDR_MAX      8192
#define SFHTTP_BODY_MAX     (8 * 1024 * 1024)
#define SFHTTP_RECV_TIMEOUT 15
#define SFHTTP_MAX_CONNS    4
#define SFHTTP_FNAME_MAX    256

/* ── HTML upload form ─────────────────────────────────────────────────────── */
static const char *SFHTTP_HTML =
    "<!DOCTYPE html>"
    "<html><head><meta charset='utf-8'>"
    "<meta name='viewport' content='width=device-width,initial-scale=1'>"
    "<title>Skyglow File Upload</title>"
    "<style>"
    "body{font-family:-apple-system,sans-serif;background:#1a1a2e;color:#e0e0e0;"
    "display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0}"
    ".card{background:#16213e;border-radius:12px;padding:32px;width:90%%;max-width:400px;"
    "box-shadow:0 8px 32px rgba(0,0,0,0.4)}"
    "h1{margin:0 0 8px;font-size:22px;color:#e94560}"
    ".dir{font-size:12px;color:#888;margin-bottom:24px;word-break:break-all}"
    "label{display:block;margin-bottom:8px;font-size:14px;color:#a0a0c0}"
    "input[type=file]{width:100%%;padding:10px;background:#0f3460;border:1px solid #e94560;"
    "border-radius:6px;color:#e0e0e0;box-sizing:border-box;margin-bottom:20px}"
    "button{width:100%%;padding:12px;background:#e94560;color:#fff;border:none;"
    "border-radius:6px;font-size:16px;cursor:pointer}"
    "button:hover{background:#c73652}"
    "</style></head><body>"
    "<div class='card'>"
    "<h1>Upload File</h1>"
    "<div class='dir'>%s</div>"
    "<form method='POST' action='/upload' enctype='multipart/form-data'>"
    "<label>Choose a file to upload:</label>"
    "<input type='file' name='file'>"
    "<button type='submit'>Upload</button>"
    "</form>"
    "</div></body></html>";

/* ── Connection context ───────────────────────────────────────────────────── */
typedef struct {
    int fd;
    id  server;   /* SFHTTPServer*, retained */
} sfhttp_conn_t;

/* Forward declarations for helpers used before definition */
static void sfhttp_progress(id server, float progress);
static int sfhttp_write_all(int fd, const char *buf, size_t len);

/* ── C helpers ────────────────────────────────────────────────────────────── */

static const void *sfhttp_memmem(const void *hay, size_t hLen,
                                 const void *ndl, size_t nLen) {
    if (nLen == 0) return hay;
    if (hLen < nLen) return NULL;

    const unsigned char *h = (const unsigned char *)hay;
    const unsigned char *n = (const unsigned char *)ndl;
    size_t limit = hLen - nLen;

    for (size_t i = 0; i <= limit; i++) {
        if (h[i] == n[0] && memcmp(h + i, n, nLen) == 0)
            return h + i;
    }
    return NULL;
}

static ssize_t sfhttp_read_headers(int fd, char *buf, size_t bufmax,
                                   size_t *hdrEnd) {
    size_t total = 0;
    static const char sep[] = "\r\n\r\n";

    while (total < bufmax) {
        ssize_t n = recv(fd, buf + total, bufmax - total, 0);
        if (n <= 0) return -1;

        total += (size_t)n;

        {
            const char *found = (const char *)sfhttp_memmem(buf, total, sep, 4);
            if (found) {
                *hdrEnd = (size_t)(found - buf) + 4;
                return (ssize_t)total;
            }
        }
    }

    return -1;
}

static int sfhttp_read_exact_progress(int fd,
                                      char *buf,
                                      size_t len,
                                      size_t alreadyHave,
                                      size_t totalExpected,
                                      id server) {
    size_t got = 0;

    while (got < len) {
        ssize_t n = recv(fd, buf + got, len - got, 0);
        if (n <= 0) return 0;

        got += (size_t)n;

        if (totalExpected > 0) {
            size_t totalSoFar = alreadyHave + got;
            float progress = (float)totalSoFar / (float)totalExpected;
            sfhttp_progress(server, progress);
        }
    }

    return 1;
}

static int sfhttp_write_all(int fd, const char *buf, size_t len) {
    size_t total = 0;

    while (total < len) {
        ssize_t n = write(fd, buf + total, len - total);
        if (n <= 0) return 0;
        total += (size_t)n;
    }

    return 1;
}

static int sfhttp_get_header(const char *block, const char *name,
                             char *out, size_t outLen) {
    size_t nLen = strlen(name);
    const char *p = block;

    while (*p) {
        const char *eol = strstr(p, "\r\n");
        if (!eol) eol = p + strlen(p);

        if ((size_t)(eol - p) > nLen + 1) {
            if (strncasecmp(p, name, nLen) == 0 && p[nLen] == ':') {
                const char *v = p + nLen + 1;
                while (*v == ' ') v++;

                size_t vLen = (size_t)(eol - v);
                if (vLen >= outLen) vLen = outLen - 1;

                memcpy(out, v, vLen);
                out[vLen] = '\0';
                return 1;
            }
        }

        if (*eol == '\0') break;
        p = eol + 2;
    }

    return 0;
}

static int sfhttp_get_param(const char *val, const char *param,
                            char *out, size_t outLen) {
    size_t pLen = strlen(param);
    const char *p = val;

    while (*p) {
        while (*p == ' ' || *p == ';') p++;

        if (strncasecmp(p, param, pLen) == 0 && p[pLen] == '=') {
            const char *v = p + pLen + 1;

            if (*v == '"') {
                v++;
                {
                    const char *end = strchr(v, '"');
                    if (!end) return 0;

                    size_t len = (size_t)(end - v);
                    if (len >= outLen) len = outLen - 1;
                    memcpy(out, v, len);
                    out[len] = '\0';
                }
            } else {
                size_t len = 0;
                while (v[len] && v[len] != ';' && v[len] != ' ') len++;

                if (len >= outLen) len = outLen - 1;
                memcpy(out, v, len);
                out[len] = '\0';
            }

            return 1;
        }

        while (*p && *p != ';') p++;
    }

    return 0;
}

static void sfhttp_url_decode(const char *in, char *out, size_t outLen) {
    size_t j = 0;

    for (size_t i = 0; in[i] && j + 1 < outLen; i++) {
        if (in[i] == '%' && in[i + 1] && in[i + 2]) {
            char hex[3] = { in[i + 1], in[i + 2], '\0' };
            char *endp = NULL;
            long v = strtol(hex, &endp, 16);

            if (endp == hex + 2) {
                out[j++] = (char)v;
                i += 2;
                continue;
            }
        }

        out[j++] = in[i];
    }

    out[j] = '\0';
}

static int sfhttp_sanitize_fname(const char *raw, char *out, size_t outLen) {
    char decoded[SFHTTP_FNAME_MAX];
    sfhttp_url_decode(raw, decoded, sizeof(decoded));

    {
        const char *last = strrchr(decoded, '/');
        const char *base = last ? last + 1 : decoded;

        if (base[0] == '\0' || strcmp(base, ".") == 0 || strcmp(base, "..") == 0)
            return 0;

        for (const char *c = base; *c; c++) {
            unsigned char u = (unsigned char)*c;
            if (u < 0x20 || u == 0x7F) return 0;
        }

        {
            size_t len = strlen(base);
            if (len == 0 || len >= outLen) return 0;
            memcpy(out, base, len + 1);
            return 1;
        }
    }
}

static void sfhttp_send_header(int fd, int code, const char *status,
                               const char *ctype, size_t bodyLen) {
    char buf[256];
    int n = snprintf(buf, sizeof(buf),
                     "HTTP/1.0 %d %s\r\n"
                     "Content-Type: %s\r\n"
                     "Content-Length: %zu\r\n"
                     "Connection: close\r\n"
                     "\r\n",
                     code, status, ctype, bodyLen);
    if (n > 0) send(fd, buf, (size_t)n, 0);
}

static void sfhttp_error(int fd, int code, const char *status, const char *msg) {
    size_t len = strlen(msg);
    sfhttp_send_header(fd, code, status, "text/plain", len);
    send(fd, msg, len, 0);
}

static void sfhttp_success(int fd, const char *msg) {
    size_t len = strlen(msg);
    sfhttp_send_header(fd, 200, "OK", "text/html; charset=utf-8", len);
    send(fd, msg, len, 0);
}

@interface SFHTTPServer () {
@public
    int _serverFd;
    uint16_t _boundPort;
    volatile BOOL _running;
    pthread_t _acceptThread;
    pthread_mutex_t _mutex;
    int _activeConns;
    id<SFHTTPServerDelegate> _delegate; /* weak */
    NSString *_directory;
}
@end

@interface SFHTTPServer (Private)
- (void)_deliverLog:(NSString *)msg;
- (void)_connectionFinished;
- (void)_deliverProgress:(NSNumber *)progress;
@end

static NSString *sfhttp_string_from_cstr(const char *cstr) {
    if (!cstr) return @"";

    {
        NSString *s = [NSString stringWithCString:cstr encoding:NSUTF8StringEncoding];
        if (s) return s;
    }
    {
        NSString *s = [NSString stringWithCString:cstr encoding:NSISOLatin1StringEncoding];
        if (s) return s;
    }
    {
        NSString *s = [NSString stringWithCString:cstr encoding:NSWindowsCP1252StringEncoding];
        if (s) return s;
    }

    return @"";
}

static void sfhttp_log(id server, const char *fmt, ...) {
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    {
        time_t t = time(NULL);
        struct tm *tm = localtime(&t);
        char ts[32];
        strftime(ts, sizeof(ts), "%H:%M:%S", tm);

        NSString *msg = sfhttp_string_from_cstr(buf);
        NSString *line = [NSString stringWithFormat:@"[%s] %@", ts, msg];

        [(SFHTTPServer *)server performSelectorOnMainThread:@selector(_deliverLog:)
                                                withObject:line
                                             waitUntilDone:NO];
    }
}

static void sfhttp_progress(id server, float progress) {
    if (progress < 0.0f) progress = 0.0f;
    if (progress > 1.0f) progress = 1.0f;

    {
        NSNumber *num = [NSNumber numberWithFloat:progress];
        [(SFHTTPServer *)server performSelectorOnMainThread:@selector(_deliverProgress:)
                                                 withObject:num
                                              waitUntilDone:NO];
    }
}

static void sfhttp_handle_upload(int fd,
                                 const char *hdrs,
                                 const char *bodyPrefixBuf,
                                 size_t bodyPrefixLen,
                                 const char *destDir,
                                 id server) {
    char clStr[32] = {0};

    if (!sfhttp_get_header(hdrs, "Content-Length", clStr, sizeof(clStr))) {
        sfhttp_error(fd, 400, "Bad Request", "Missing Content-Length");
        sfhttp_log(server, "Upload rejected: missing Content-Length");
        sfhttp_progress(server, 0.0f);
        return;
    }

    errno = 0;
    {
        long long bodyLen64 = strtoll(clStr, NULL, 10);
        if (errno != 0 || bodyLen64 <= 0 || bodyLen64 > SFHTTP_BODY_MAX) {
            sfhttp_error(fd, 413, "Request Entity Too Large", "Body too large (max 8 MB)");
            sfhttp_log(server, "Upload rejected: body too large (%lld)", bodyLen64);
            sfhttp_progress(server, 0.0f);
            return;
        }

        {
            size_t bodyLen = (size_t)bodyLen64;
            char ctVal[256] = {0};

            if (!sfhttp_get_header(hdrs, "Content-Type", ctVal, sizeof(ctVal))) {
                sfhttp_error(fd, 400, "Bad Request", "Missing Content-Type");
                sfhttp_progress(server, 0.0f);
                return;
            }

            if (strncasecmp(ctVal, "multipart/form-data", 19) != 0) {
                sfhttp_error(fd, 400, "Bad Request", "Expected multipart/form-data");
                sfhttp_progress(server, 0.0f);
                return;
            }

            {
                char boundary[128] = {0};
                if (!sfhttp_get_param(ctVal, "boundary", boundary, sizeof(boundary))) {
                    sfhttp_error(fd, 400, "Bad Request", "Missing boundary");
                    sfhttp_progress(server, 0.0f);
                    return;
                }

                {
                    char *body = (char *)malloc(bodyLen + 1);
                    if (!body) {
                        sfhttp_error(fd, 500, "Internal Server Error", "Out of memory");
                        sfhttp_progress(server, 0.0f);
                        return;
                    }

                    {
                        size_t prefixCopy = (bodyPrefixLen < bodyLen) ? bodyPrefixLen : bodyLen;
                        if (prefixCopy > 0)
                            memcpy(body, bodyPrefixBuf, prefixCopy);

                        sfhttp_progress(server, (bodyLen > 0) ? ((float)prefixCopy / (float)bodyLen) : 0.0f);

                        if (prefixCopy < bodyLen &&
                            !sfhttp_read_exact_progress(fd,
                                                        body + prefixCopy,
                                                        bodyLen - prefixCopy,
                                                        prefixCopy,
                                                        bodyLen,
                                                        server)) {
                            sfhttp_error(fd, 400, "Bad Request", "Incomplete body");
                            free(body);
                            sfhttp_log(server, "Upload rejected: incomplete body");
                            sfhttp_progress(server, 0.0f);
                            return;
                        }

                        body[bodyLen] = '\0';

                        {
                            char delim[132];
                            snprintf(delim, sizeof(delim), "--%s\r\n", boundary);

                            {
                                const char *partStart = (const char *)sfhttp_memmem(body, bodyLen,
                                                                                    delim, strlen(delim));
                                if (!partStart) {
                                    sfhttp_error(fd, 400, "Bad Request", "Boundary not found");
                                    free(body);
                                    sfhttp_progress(server, 0.0f);
                                    return;
                                }

                                partStart += strlen(delim);

                                {
                                    const char *partHdrEnd = (const char *)sfhttp_memmem(
                                        partStart,
                                        bodyLen - (size_t)(partStart - body),
                                        "\r\n\r\n",
                                        4);

                                    if (!partHdrEnd) {
                                        sfhttp_error(fd, 400, "Bad Request", "Part headers not found");
                                        free(body);
                                        sfhttp_progress(server, 0.0f);
                                        return;
                                    }

                                    {
                                        size_t partHdrLen = (size_t)(partHdrEnd - partStart);
                                        char *partHdrs = (char *)malloc(partHdrLen + 1);
                                        if (!partHdrs) {
                                            sfhttp_error(fd, 500, "Internal Server Error", "Out of memory");
                                            free(body);
                                            sfhttp_progress(server, 0.0f);
                                            return;
                                        }

                                        memcpy(partHdrs, partStart, partHdrLen);
                                        partHdrs[partHdrLen] = '\0';

                                        {
                                            char cdVal[256] = {0};
                                            if (!sfhttp_get_header(partHdrs, "Content-Disposition", cdVal, sizeof(cdVal))) {
                                                sfhttp_error(fd, 400, "Bad Request", "Missing part Content-Disposition");
                                                free(partHdrs);
                                                free(body);
                                                sfhttp_progress(server, 0.0f);
                                                return;
                                            }

                                            {
                                                char rawName[SFHTTP_FNAME_MAX] = {0};
                                                if (!sfhttp_get_param(cdVal, "filename", rawName, sizeof(rawName))) {
                                                    sfhttp_error(fd, 400, "Bad Request", "No filename in disposition");
                                                    free(partHdrs);
                                                    free(body);
                                                    sfhttp_progress(server, 0.0f);
                                                    return;
                                                }

                                                free(partHdrs);

                                                {
                                                    char safeName[SFHTTP_FNAME_MAX];
                                                    if (!sfhttp_sanitize_fname(rawName, safeName, sizeof(safeName))) {
                                                        sfhttp_error(fd, 400, "Bad Request", "Invalid filename");
                                                        sfhttp_log(server, "Upload rejected: invalid filename '%s'", rawName);
                                                        free(body);
                                                        sfhttp_progress(server, 0.0f);
                                                        return;
                                                    }

                                                    {
                                                        const char *fileData = partHdrEnd + 4;
                                                        size_t remaining = bodyLen - (size_t)(fileData - body);

                                                        char closingDelim[132];
                                                        snprintf(closingDelim, sizeof(closingDelim), "\r\n--%s", boundary);

                                                        {
                                                            const char *fileEnd = (const char *)sfhttp_memmem(fileData,
                                                                                                              remaining,
                                                                                                              closingDelim,
                                                                                                              strlen(closingDelim));
                                                            size_t fileLen = fileEnd ? (size_t)(fileEnd - fileData) : remaining;

                                                            char destPath[PATH_MAX];
                                                            snprintf(destPath, sizeof(destPath), "%s/%s", destDir, safeName);

                                                            {
                                                                char resolved[PATH_MAX];
                                                                char resolvedDir[PATH_MAX];

                                                                if (realpath(destDir, resolvedDir) == NULL) {
                                                                    sfhttp_error(fd, 500, "Internal Server Error", "Cannot resolve destination");
                                                                    free(body);
                                                                    sfhttp_progress(server, 0.0f);
                                                                    return;
                                                                }

                                                                snprintf(resolved, sizeof(resolved), "%s/%s", resolvedDir, safeName);

                                                                {
                                                                    size_t dirLen = strlen(resolvedDir);
                                                                    if (strncmp(resolved, resolvedDir, dirLen) != 0 ||
                                                                        resolved[dirLen] != '/') {
                                                                        sfhttp_error(fd, 400, "Bad Request", "Path traversal detected");
                                                                        sfhttp_log(server, "Upload rejected: path traversal '%s'", safeName);
                                                                        free(body);
                                                                        sfhttp_progress(server, 0.0f);
                                                                        return;
                                                                    }
                                                                }

                                                                strlcpy(destPath, resolved, sizeof(destPath));
                                                            }

                                                            {
                                                                int outFd = open(destPath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
                                                                if (outFd < 0) {
                                                                    sfhttp_error(fd, 500, "Internal Server Error", "Cannot create file");
                                                                    sfhttp_log(server, "Upload failed: cannot create '%s': %s",
                                                                               safeName, strerror(errno));
                                                                    free(body);
                                                                    sfhttp_progress(server, 0.0f);
                                                                    return;
                                                                }

                                                                {
                                                                    int okWrite = sfhttp_write_all(outFd, fileData, fileLen);
                                                                    close(outFd);
                                                                    free(body);

                                                                    if (!okWrite) {
                                                                        sfhttp_error(fd, 500, "Internal Server Error", "Write failed");
                                                                        sfhttp_log(server, "Upload failed: write error for '%s'", safeName);
                                                                        sfhttp_progress(server, 0.0f);
                                                                        return;
                                                                    }
                                                                }
                                                            }

                                                            sfhttp_progress(server, 1.0f);
                                                            sfhttp_log(server, "Uploaded '%s' (%zu bytes)", safeName, fileLen);

                                                            {
                                                                static const char *successHtml =
                                                                    "<!DOCTYPE html><html><head><meta charset='utf-8'>"
                                                                    "<meta http-equiv='refresh' content='2;url=/'>"
                                                                    "<style>body{font-family:-apple-system,sans-serif;background:#1a1a2e;"
                                                                    "color:#e0e0e0;display:flex;justify-content:center;align-items:center;"
                                                                    "min-height:100vh;margin:0}"
                                                                    ".card{background:#16213e;border-radius:12px;padding:32px;text-align:center}"
                                                                    "h2{color:#4caf50}</style></head><body>"
                                                                    "<div class='card'><h2>&#10003; Upload successful!</h2>"
                                                                    "<p>Redirecting back...</p></div></body></html>";
                                                                sfhttp_success(fd, successHtml);
                                                            }

                                                            return;
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

/* ── Per-connection thread ────────────────────────────────────────────────── */
static void *sfhttp_connection_thread(void *arg) {
    sfhttp_conn_t *ctx = (sfhttp_conn_t *)arg;
    int fd = ctx->fd;
    SFHTTPServer *server = (SFHTTPServer *)ctx->server;
    free(ctx);

    {
        char hdrBuf[SFHTTP_HDR_MAX];
        size_t bodyStart = 0;
        ssize_t total = sfhttp_read_headers(fd, hdrBuf, sizeof(hdrBuf) - 1, &bodyStart);

        if (total < 0) {
            close(fd);
            [server performSelectorOnMainThread:@selector(_connectionFinished)
                                     withObject:nil
                                  waitUntilDone:NO];
            [server release];
            return NULL;
        }

        hdrBuf[total] = '\0';

        {
            char method[8] = {0};
            char path[256] = {0};
            sscanf(hdrBuf, "%7s %255s", method, path);

            {
                const char *bodyPrefixBuf = hdrBuf + bodyStart;
                size_t bodyPrefixLen = (total > (ssize_t)bodyStart)
                                     ? (size_t)((ssize_t)total - (ssize_t)bodyStart)
                                     : 0;

                char *headerBlock = (char *)malloc((size_t)bodyStart + 1);
                if (headerBlock) {
                    memcpy(headerBlock, hdrBuf, bodyStart);
                    headerBlock[bodyStart] = '\0';
                }

                if (strcmp(method, "GET") == 0 && strcmp(path, "/") == 0) {
                    char html[4096];
                    snprintf(html, sizeof(html), SFHTTP_HTML,
                             server->_directory ? [server->_directory UTF8String] : "/");
                    sfhttp_send_header(fd, 200, "OK", "text/html; charset=utf-8", strlen(html));
                    send(fd, html, strlen(html), 0);
                    sfhttp_progress(server, 0.0f);
                    sfhttp_log(server, "GET / — served upload form");

                } else if (strcmp(method, "POST") == 0 && strcmp(path, "/upload") == 0) {
                    if (headerBlock) {
                        sfhttp_handle_upload(fd,
                                             headerBlock,
                                             bodyPrefixBuf,
                                             bodyPrefixLen,
                                             [server->_directory UTF8String],
                                             server);
                    } else {
                        sfhttp_error(fd, 500, "Internal Server Error", "Out of memory");
                        sfhttp_progress(server, 0.0f);
                    }

                } else {
                    sfhttp_error(fd, 404, "Not Found", "Not found");
                    sfhttp_progress(server, 0.0f);
                    sfhttp_log(server, "%s %s — 404", method, path);
                }

                if (headerBlock) free(headerBlock);
            }
        }
    }

    close(fd);

    [server performSelectorOnMainThread:@selector(_connectionFinished)
                             withObject:nil
                          waitUntilDone:NO];
    [server release];
    return NULL;
}

/* ── Accept loop ──────────────────────────────────────────────────────────── */
static void *sfhttp_accept_loop(void *arg) {
    SFHTTPServer *server = (SFHTTPServer *)arg;

    while (server->_running) {
        struct sockaddr_in clientAddr;
        socklen_t clientLen = sizeof(clientAddr);

        int clientFd = accept(server->_serverFd,
                              (struct sockaddr *)&clientAddr,
                              &clientLen);
        if (clientFd < 0) {
            if (!server->_running) break;
            continue;
        }

        pthread_mutex_lock(&server->_mutex);
        {
            int active = server->_activeConns;
            pthread_mutex_unlock(&server->_mutex);

            if (active >= SFHTTP_MAX_CONNS) {
                sfhttp_error(clientFd, 503, "Service Unavailable", "Too many connections");
                close(clientFd);
                sfhttp_log(server, "Connection rejected (limit %d reached)", SFHTTP_MAX_CONNS);
                continue;
            }
        }

        {
            struct timeval tv;
            tv.tv_sec  = SFHTTP_RECV_TIMEOUT;
            tv.tv_usec = 0;
            setsockopt(clientFd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            setsockopt(clientFd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        }

        pthread_mutex_lock(&server->_mutex);
        server->_activeConns++;
        pthread_mutex_unlock(&server->_mutex);

        {
            sfhttp_conn_t *ctx = (sfhttp_conn_t *)malloc(sizeof(sfhttp_conn_t));
            if (!ctx) {
                pthread_mutex_lock(&server->_mutex);
                server->_activeConns--;
                pthread_mutex_unlock(&server->_mutex);
                close(clientFd);
                continue;
            }

            ctx->fd = clientFd;
            ctx->server = [server retain];

            {
                pthread_t thr;
                if (pthread_create(&thr, NULL, sfhttp_connection_thread, ctx) != 0) {
                    free(ctx);
                    [server release];
                    pthread_mutex_lock(&server->_mutex);
                    server->_activeConns--;
                    pthread_mutex_unlock(&server->_mutex);
                    close(clientFd);
                    continue;
                }
                pthread_detach(thr);
            }
        }
    }

    [server release];
    return NULL;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * SFHTTPServer
 * ═══════════════════════════════════════════════════════════════════════════ */

@implementation SFHTTPServer

- (instancetype)init {
    self = [super init];
    if (self) {
        _serverFd    = -1;
        _boundPort   = 0;
        _running     = NO;
        _activeConns = 0;
        _delegate    = nil;
        _directory   = nil;
        pthread_mutex_init(&_mutex, NULL);
    }
    return self;
}

- (void)dealloc {
    [self stop];
    [_directory release];
    pthread_mutex_destroy(&_mutex);
    [super dealloc];
}

- (uint16_t)boundPort {
    return _boundPort;
}

- (BOOL)startInDirectory:(NSString *)dir
               startPort:(uint16_t)port
                delegate:(id<SFHTTPServerDelegate>)del {
    if (_running) return NO;

    _delegate = del;
    [_directory release];
    _directory = [dir copy];

    {
        int fd = -1;
        uint16_t boundPort = 0;

        for (int i = 0; i < 10; i++) {
            fd = socket(AF_INET, SOCK_STREAM, 0);
            if (fd < 0) continue;

            {
                int yes = 1;
                setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
            }

            {
                struct sockaddr_in addr;
                memset(&addr, 0, sizeof(addr));
                addr.sin_family      = AF_INET;
                addr.sin_addr.s_addr = INADDR_ANY;
                addr.sin_port        = htons(port + (uint16_t)i);

                if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
                    boundPort = port + (uint16_t)i;
                    break;
                }
            }

            close(fd);
            fd = -1;
        }

        if (fd < 0) return NO;
        if (listen(fd, 5) != 0) {
            close(fd);
            return NO;
        }

        _serverFd  = fd;
        _boundPort = boundPort;
        _running   = YES;
    }

    [self retain];

    {
        pthread_t thr;
        if (pthread_create(&thr, NULL, sfhttp_accept_loop, self) != 0) {
            [self release];
            _running = NO;
            close(_serverFd);
            _serverFd = -1;
            _boundPort = 0;
            return NO;
        }
        _acceptThread = thr;
        pthread_detach(thr);
    }

    return YES;
}

- (void)stop {
    if (!_running) return;

    _running = NO;

    if (_serverFd >= 0) {
        close(_serverFd);
        _serverFd = -1;
    }

    _boundPort = 0;
}

- (void)_deliverLog:(NSString *)msg {
    if ([_delegate respondsToSelector:@selector(httpServer:didLog:)]) {
        [_delegate httpServer:self didLog:msg];
    }
}

- (void)_deliverProgress:(NSNumber *)progress {
    if ([_delegate respondsToSelector:@selector(httpServer:didUpdateUploadProgress:)]) {
        [_delegate httpServer:self didUpdateUploadProgress:[progress floatValue]];
    }
}

- (void)_connectionFinished {
    pthread_mutex_lock(&_mutex);
    if (_activeConns > 0) _activeConns--;
    pthread_mutex_unlock(&_mutex);
}

+ (NSString *)localIPAddress {
    struct ifaddrs *ifas = NULL;
    if (getifaddrs(&ifas) != 0) return nil;

    NSString *result = nil;

    for (struct ifaddrs *ifa = ifas; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr) continue;
        if (ifa->ifa_addr->sa_family != AF_INET) continue;
        if (strcmp(ifa->ifa_name, "lo0") == 0) continue;

        {
            struct sockaddr_in *sin = (struct sockaddr_in *)ifa->ifa_addr;
            char ipStr[INET_ADDRSTRLEN];

            if (inet_ntop(AF_INET, &sin->sin_addr, ipStr, sizeof(ipStr))) {
                result = [NSString stringWithUTF8String:ipStr];
                break;
            }
        }
    }

    freeifaddrs(ifas);
    return result;
}

@end