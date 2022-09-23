#include <arpa/inet.h>
#include <event2/http.h>
#include <event2/event.h>
#include <event2/listener.h>
#include <event2/buffer.h>
#include <event2/keyvalq_struct.h>
#include <signal.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <iostream>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/types.h>
#include <dirent.h>
#include <json.hpp>
#include "http.h"
#include "database.h"

using json = nlohmann::json;

char uri_root[512];
std::unordered_map<std::string, std::string> Http::m_accounts;

struct table_entry {
    const char *extension;
    const char *content_type;
};

static const table_entry content_type_table[] = {
    { "txt", "text/plain" },
    { "c", "text/plain" },
    { "h", "text/plain" },
    { "html", "text/html" },
    { "htm", "text/htm" },
    { "css", "text/css" },
    { "gif", "image/gif" },
    { "jpg", "image/jpeg" },
    { "jpeg", "image/jpeg" },
    { "png", "image/png" },
    { "pdf", "application/pdf" },
    { "ps", "application/postscript" },
    { NULL, NULL },
};

struct options {
    int port;
    int iocp;
    int verbose;

    int unlink;
    const char *unixsock;
    const char *docroot;
};

/* Try to guess a good content-type for 'path' */
static const char *
guess_content_type(const char *path)
{
    const char *last_period, *extension;
    const struct table_entry *ent;
    last_period = strrchr(path, '.');  // 在参数 str 所指向的字符串中搜索最后一次出现字符 c（一个无符号字符）的位置
    if (!last_period || strchr(last_period, '/'))
        goto not_found; /* no exension */
    extension = last_period + 1;  //aquire extension name
    for (ent = &content_type_table[0]; ent->extension; ++ent) {
        printf("ent->extension: %s, extension: %s\n", ent->extension, extension);
        if (!evutil_ascii_strcasecmp(ent->extension, extension))
            return ent->content_type;
    }

not_found:
    return "application/misc";
}

/* Callback used for the /dump URI, and for every non-GET request:
 * dumps all information to stdout and gives back a trivial 200 ok */
static void
dump_request_cb(struct evhttp_request *req, void *arg)
{
    const char *cmdtype;
    struct evkeyvalq *headers;
    struct evkeyval *header;
    struct evbuffer *buf;

    switch (evhttp_request_get_command(req)) {
    case EVHTTP_REQ_GET: cmdtype = "GET"; break;
    case EVHTTP_REQ_POST: cmdtype = "POST"; break;
    case EVHTTP_REQ_HEAD: cmdtype = "HEAD"; break;
    case EVHTTP_REQ_PUT: cmdtype = "PUT"; break;
    case EVHTTP_REQ_DELETE: cmdtype = "DELETE"; break;
    case EVHTTP_REQ_OPTIONS: cmdtype = "OPTIONS"; break;
    case EVHTTP_REQ_TRACE: cmdtype = "TRACE"; break;
    case EVHTTP_REQ_CONNECT: cmdtype = "CONNECT"; break;
    case EVHTTP_REQ_PATCH: cmdtype = "PATCH"; break;
    default: cmdtype = "unknown"; break;
    }

    printf("Received a %s request for %s\nHeaders:\n",
           cmdtype, evhttp_request_get_uri(req));

    headers = evhttp_request_get_input_headers(req);
    for (header = headers->tqh_first; header;
         header = header->next.tqe_next) {
        printf("  %s: %s\n", header->key, header->value);
    }

    buf = evhttp_request_get_input_buffer(req);
    puts("Input data: <<<");
    while (evbuffer_get_length(buf)) {
        int n;
        char cbuf[128];
        n = evbuffer_remove(buf, cbuf, sizeof(cbuf));
        if (n > 0)
            (void) fwrite(cbuf, 1, n, stdout);
    }
    puts(">>>");

    evhttp_send_reply(req, 200, "OK", NULL);
}

/* Callback used for the /dump URI, and for every non-GET request:
 * dumps all information to stdout and gives back a trivial 200 ok */
static void
dump_register_cb(struct evhttp_request *req, void *arg)
{
    const char *cmdtype;
    struct evkeyvalq *headers;
    struct evkeyval *header;
    struct evbuffer *buf;

    switch (evhttp_request_get_command(req)) {
    case EVHTTP_REQ_GET: cmdtype = "GET"; break;
    case EVHTTP_REQ_POST: cmdtype = "POST"; break;
    case EVHTTP_REQ_HEAD: cmdtype = "HEAD"; break;
    case EVHTTP_REQ_PUT: cmdtype = "PUT"; break;
    case EVHTTP_REQ_DELETE: cmdtype = "DELETE"; break;
    case EVHTTP_REQ_OPTIONS: cmdtype = "OPTIONS"; break;
    case EVHTTP_REQ_TRACE: cmdtype = "TRACE"; break;
    case EVHTTP_REQ_CONNECT: cmdtype = "CONNECT"; break;
    case EVHTTP_REQ_PATCH: cmdtype = "PATCH"; break;
    default: cmdtype = "unknown"; break;
    }

    printf("Received a %s request for %s\nHeaders:\n",
           cmdtype, evhttp_request_get_uri(req));

    headers = evhttp_request_get_input_headers(req);
    for (header = headers->tqh_first; header;
         header = header->next.tqe_next) {
        printf("  %s: %s\n", header->key, header->value);
    }

    buf = evhttp_request_get_input_buffer(req);
    puts("Input data: <<<");
    while (evbuffer_get_length(buf)) {
        int n;
        char cbuf[128];
        n = evbuffer_remove(buf, cbuf, sizeof(cbuf));
        if (n > 0)
            (void) fwrite(cbuf, 1, n, stdout);
    }
    puts(">>>");

    evhttp_send_reply(req, 200, "OK", NULL);
}

/* This callback gets invoked when we get any http request that doesn't match
 * any other callback.  Like any evhttp server callback, it has a simple job:
 * it must eventually call evhttp_send_error() or evhttp_send_reply().
 */
static void
send_document_cb(struct evhttp_request *req, void *arg)
{
    struct evbuffer *evb = NULL;
    struct options *o = (options *)arg;
    const char *uri = evhttp_request_get_uri(req);
    struct evhttp_uri *decoded = NULL;
    const char *path;
    char *decoded_path;
    char *whole_path = NULL;
    size_t len;
    int fd = -1;
    struct stat st;

    if (evhttp_request_get_command(req) != EVHTTP_REQ_GET) {
        dump_request_cb(req, arg);
        return;
    }

    printf("Got a GET request for <%s>\n",  uri);

    /* Decode the URI */
    decoded = evhttp_uri_parse(uri);
    if (!decoded) {
        printf("It's not a good URI. Sending BADREQUEST\n");
        evhttp_send_error(req, HTTP_BADREQUEST, 0);
        return;
    }

    struct evkeyvalq *headers;
    struct evkeyval *header;
    headers = evhttp_request_get_input_headers(req);
    for (header = headers->tqh_first; header;
         header = header->next.tqe_next) {
        printf("  %s: %s\n", header->key, header->value);
    }

    /* Let's see what path the user asked for. */
    path = evhttp_uri_get_path(decoded);
    printf("path: %s\n", path);
    if (!path) path = "/";

    /* We need to decode it, to see what path the user really wanted. */
    decoded_path = evhttp_uridecode(path, 0, NULL);
    printf("decoded path: %s\n", decoded_path);
    if (decoded_path == NULL)
        goto err;
    /* Don't allow any ".."s in the path, to avoid exposing stuff outside
     * of the docroot.  This test is both overzealous and underzealous:
     * it forbids aceptable paths like "/this/one..here", but it doesn't
     * do anything to prevent symlink following." */
    if (strstr(decoded_path, ".."))
        goto err;

    len = strlen(decoded_path)+strlen(o->docroot)+2;
    if (!(whole_path = (char *)malloc(len))) {
        perror("malloc");
        goto err;
    }
    evutil_snprintf(whole_path, len, "%s/%s", o->docroot, decoded_path);
    printf("whole path: %s\n", whole_path);
    if (stat(whole_path, &st)<0) {
        goto err;
    }

    /* This holds the content we're sending. */
    evb = evbuffer_new();

    if (S_ISDIR(st.st_mode)) {
        /* If it's a directory, read the comments and make a little
         * index page */
#ifdef _WIN32
        HANDLE d;
        WIN32_FIND_DATAA ent;
        char *pattern;
        size_t dirlen;
#else
        DIR *d;
        struct dirent *ent;
#endif
        const char *trailing_slash = "";

        if (!strlen(path) || path[strlen(path)-1] != '/')
            trailing_slash = "/";

#ifdef _WIN32
        dirlen = strlen(whole_path);
        pattern = malloc(dirlen+3);
        memcpy(pattern, whole_path, dirlen);
        pattern[dirlen] = '\\';
        pattern[dirlen+1] = '*';
        pattern[dirlen+2] = '\0';
        d = FindFirstFileA(pattern, &ent);
        free(pattern);
        if (d == INVALID_HANDLE_VALUE)
            goto err;
#else
        if (!(d = opendir(whole_path)))
            goto err;
#endif

        evbuffer_add_printf(evb,
                            "<!DOCTYPE html>\n"
                            "<html>\n <head>\n"
                            "  <meta charset='utf-8'>\n"
                            "  <title>%s</title>\n"
                            "  <base href='%s%s'>\n"
                            " </head>\n"
                            " <body>\n"
                            "  <h1>%s</h1>\n"
                            "  <ul>\n",
                            decoded_path, /* XXX html-escape this. */
                            path, /* XXX html-escape this? */
                            trailing_slash,
                            decoded_path /* XXX html-escape this */);
#ifdef _WIN32
        do {
            const char *name = ent.cFileName;
#else
        while ((ent = readdir(d))) {
            const char *name = ent->d_name;
#endif
            evbuffer_add_printf(evb,
                                "    <li><a href=\"%s\">%s</a>\n",
                                name, name);/* XXX escape this */
#ifdef _WIN32
        } while (FindNextFileA(d, &ent));
#else
        }
#endif
        evbuffer_add_printf(evb, "</ul></body></html>\n");
#ifdef _WIN32
        FindClose(d);
#else
        closedir(d);
#endif
        evhttp_add_header(evhttp_request_get_output_headers(req),
                          "Content-Type", "text/html");
    } else {
        /* Otherwise it's a file; add it to the buffer to get
         * sent via sendfile */
        const char *type = guess_content_type(decoded_path);
        if ((fd = open(whole_path, O_RDONLY)) < 0) {
            perror("open");
            goto err;
        }

        if (fstat(fd, &st)<0) {  //acquire file property
            /* Make sure the length still matches, now that we
             * opened the file :/ */
            perror("fstat");
            goto err;
        }
        evhttp_add_header(evhttp_request_get_output_headers(req), "Content-Type", type);
        evbuffer_add_file(evb, fd, 0, st.st_size);
    }

    evhttp_send_reply(req, 200, "OK", evb);
    goto done;
err:
    evhttp_send_error(req, 404, "Document was not found");
    if (fd>=0)
        close(fd);
done:
    if (decoded)
        evhttp_uri_free(decoded);
    if (decoded_path)
        free(decoded_path);
    if (whole_path)
        free(whole_path);
    if (evb)
        evbuffer_free(evb);
}

static void
print_usage(FILE *out, const char *prog, int exit_code)
{
    fprintf(out,
            "Syntax: %s [ OPTS ] <docroot>\n"
            " -p      - port\n"
            " -U      - bind to unix socket\n"
            " -u      - unlink unix socket before bind\n"
            " -I      - IOCP\n"
            " -v      - verbosity, enables libevent debug logging too\n", prog);
    exit(exit_code);
}
static struct options
        parse_opts(int argc, char **argv)
{
    struct options o;
    int opt;

    memset(&o, 0, sizeof(o));

    while ((opt = getopt(argc, argv, "hp:U:uIv")) != -1) {
        switch (opt) {
        case 'p': o.port = atoi(optarg); break;
        case 'U': o.unixsock = optarg; break;
        case 'u': o.unlink = 1; break;
        case 'I': o.iocp = 1; break;
        case 'v': ++o.verbose; break;
        case 'h': print_usage(stdout, argv[0], 0); break;
        default : fprintf(stderr, "Unknown option %c\n", opt); break;
        }
    }

    if (optind >= argc || (argc - optind) > 1) {
        print_usage(stdout, argv[0], 1);
    }
    o.docroot = argv[optind];

    return o;
}

static void
do_term(int sig, short events, void *arg)
{
    struct event_base *base = (event_base *)arg;
    event_base_loopbreak(base);
    fprintf(stderr, "Got %i, Terminating\n", sig);
}

static int
display_listen_sock(struct evhttp_bound_socket *handle)
{
    struct sockaddr_storage ss;
    evutil_socket_t fd;
    ev_socklen_t socklen = sizeof(ss);
    char addrbuf[128];
    void *inaddr;
    const char *addr;
    int got_port = -1;

    fd = evhttp_bound_socket_get_fd(handle);
    memset(&ss, 0, sizeof(ss));
    if (getsockname(fd, (struct sockaddr *)&ss, &socklen)) {
        perror("getsockname() failed");
        return 1;
    }

    if (ss.ss_family == AF_INET) {
        got_port = ntohs(((struct sockaddr_in*)&ss)->sin_port);
        inaddr = &((struct sockaddr_in*)&ss)->sin_addr;
    } else if (ss.ss_family == AF_INET6) {
        got_port = ntohs(((struct sockaddr_in6*)&ss)->sin6_port);
        inaddr = &((struct sockaddr_in6*)&ss)->sin6_addr;
    }
#ifdef EVENT__HAVE_STRUCT_SOCKADDR_UN
    else if (ss.ss_family == AF_UNIX) {
        //printf("Listening on <%s>\n", ((struct sockaddr_un*)&ss)->sun_path);
        return 0;
    }
#endif
    else {
        fprintf(stderr, "Weird address family %d\n",
                ss.ss_family);
        return 1;
    }

    addr = evutil_inet_ntop(ss.ss_family, inaddr, addrbuf,
                            sizeof(addrbuf));
    if (addr) {
        printf("Listening on %s:%d\n", addr, got_port);
        evutil_snprintf(uri_root, sizeof(uri_root),
                        "http://%s:%d",addr,got_port);
    } else {
        fprintf(stderr, "evutil_inet_ntop failed\n");
        return 1;
    }

    return 0;
}
Http::Http()
{

}



int Http::Init(int port, std::string ip)
{

    port = 8888;
    struct event_config *cfg = NULL;
    struct event_base *base = nullptr;
    struct evhttp *http = nullptr;
    struct evconnlistener *lev = nullptr;
    struct sockaddr_in addr;
    struct evhttp_bound_socket *handle = nullptr;
    struct event *term = nullptr;
    int ret = 0;
    struct options o = {0};
    o.port = port;
    o.docroot = "/home/wang/test5/resources";

    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
        ret = 1;
        goto err;
    }

    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    base = event_base_new();
    http = evhttp_new(base);

    evhttp_set_cb(http, "/login", dump_login_cb, this);
    evhttp_set_cb(http, "/register", dump_register_cb, NULL);
    evhttp_set_gencb(http, send_document_cb, &o);

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    lev = evconnlistener_new_bind(base, NULL, NULL, LEV_OPT_CLOSE_ON_FREE, -1, (struct sockaddr *)&addr, sizeof(addr));
    handle = evhttp_bind_listener(http, lev);
    //handle = evhttp_bind_socket_with_handle(http, "0.0.0.0", port);
    if (!handle) {
        fprintf(stderr, "couldn't bind to port %d. Exiting.\n", o.port);
        ret = 1;
        goto err;
    }

    if (display_listen_sock(handle)) {
        ret = 1;
        goto err;
    }

    term = evsignal_new(base, SIGINT, do_term, base);
    if (!term)
        goto err;
    if (event_add(term, NULL))
        goto err;

    event_base_dispatch(base);

err:
    std::cout<<"error"<<std::endl;
    if (cfg)
        event_config_free(cfg);
    if (http)
        evhttp_free(http);
    if (term)
        event_free(term);
    if (base)
        event_base_free(base);

    return ret;
}

void Http::test()
{

}

/* Callback used for the /login URI, and for POST request:
 * dumps all information to content and gives back a trivial 200 ok */
void Http::dump_login_cb(evhttp_request *req, void *arg)
{
    Http *http = (Http *)arg;
    const char *cmdtype;
    struct evbuffer *buf;

    struct evkeyvalq *headers;
    struct evkeyval *header;
    headers = evhttp_request_get_input_headers(req);
    for (header = headers->tqh_first; header;
         header = header->next.tqe_next) {
        printf("  %s: %s\n", header->key, header->value);
    }

    evhttp_cmd_type requesttype = evhttp_request_get_command(req);
    printf("Received a login request for %s\nHeaders:\n",
           evhttp_request_get_uri(req));
    if(requesttype == EVHTTP_REQ_POST)
    {
        //printf("Received a %s request for %s\nHeaders:\n",
               //cmdtype, evhttp_request_get_uri(req));

        buf = evhttp_request_get_input_buffer(req);
        int contentlen = evbuffer_get_length(buf);
        char *content = new char[contentlen + 1];
        memset(content, 0, contentlen + 1);
        int readindex = 0;
        int readlen = 0;
        while(readindex != contentlen)
        {
            readlen = evbuffer_remove(buf, content, contentlen);
            readindex += readlen;
        }

        json j3=json::parse(content);

        Database *database = Database::GetInstance();

        evbuffer *evb = nullptr;
        evb = evbuffer_new();
        if(!evb)
        {
            std::cerr<<"new evbuffer fail"<<std::endl;
        }

        if(database->Longin(j3["account"], j3["password"]))
        {
            std::cout<<"Login success"<<std::endl;
            std::string password = j3["password"];
            m_accounts[password] = j3["account"];
            json state;
            state["status"] = "success";
            std::string s = state.dump();

            char *recontent = new char[s.size() + 1];
            memset(recontent,0,s.size() + 1);
            memcpy(recontent, s.data(), s.size());
            printf("reply: %s\n", recontent);
            evbuffer_add(evb, recontent, s.size());
        }
        else
        {
            std::cout<<"Login fail"<<std::endl;
            json state;
            state["status"] = "fail";
            std::string s = state.dump();

            char *recontent = new char[s.size() + 1];
            memset(recontent,0,s.size() + 1);
            memcpy(recontent, s.data(), s.size());
            printf("reply: %s\n", recontent);
            evbuffer_add(evb, recontent, strlen(recontent));
        }

        evhttp_add_header(evhttp_request_get_output_headers(req),"Content-Type", "application/json");
        evhttp_add_header(evhttp_request_get_output_headers(req), "Connection", "keep-alive");

        evhttp_send_reply(req, 200, "OK", evb);

        evbuffer_free(evb);
    }
}

void Http::Init()
{
    database = Database::GetInstance();
}
