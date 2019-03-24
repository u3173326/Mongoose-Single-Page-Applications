// INCLUDES
#include "mongoose.h"
#include "stdlib.h"
#include "time.h"

// PAGES
#include "pages/page1.h"
#include "pages/page2.h"
#include "pages/page3.h"

// SETTINGS
#define PORT "8000"
#define MAX_CONNECTIONS 16
#define TIMEOUT 60
#define CLIENT_MESSAGE_SIZE 32
#define PAGE_DIR "./pages/"
#define PASSWORD1 "PASSWORD1"
#define PASSWORD2 "PASSWORD2"

// GLOBAL VARIABLES
static sig_atomic_t s_signal_received = 0;
static struct mg_serve_http_opts s_http_server_opts;
static int num_connections = 0;



static int is_websocket(const struct mg_connection *c)
{
  return c->flags & MG_F_IS_WEBSOCKET;
}

static void signal_handler(int sig_num)
{
  signal(sig_num, signal_handler);  // Reinstantiate signal handler
  s_signal_received = sig_num;
}

static void ev_handler(struct mg_connection *c, int ev, void *ev_data)
{
    char addr[22];
    mg_sock_addr_to_str(&c->sa, addr, sizeof(addr), MG_SOCK_STRINGIFY_IP | MG_SOCK_STRINGIFY_PORT);

	switch(ev)
	{
        case MG_EV_WEBSOCKET_HANDSHAKE_REQUEST:
        {
            if (num_connections >= MAX_CONNECTIONS)
            {
                printf("%-32s%s\n", addr, "DROPPED");
                c->flags |= MG_F_CLOSE_IMMEDIATELY;
            }
            break;
        }
        case MG_EV_WEBSOCKET_HANDSHAKE_DONE:
        {
            if (is_websocket(c)) // make sure its one of the websocket connections and not some other connection used for god knows what
            {
                num_connections++;
                printf("%-32s%s\n", addr, "JOINED");
            }
            break;
        }
        case MG_EV_WEBSOCKET_FRAME:
        {
            // MAKE STRING FROM FRAME
            struct websocket_message *wm = (struct websocket_message *) ev_data;
            struct mg_str ms = {(char *) wm->data, wm->size};
            char *msg;
            msg = malloc(strlen(PAGE_DIR)+ms.len);
            strcpy(msg, PAGE_DIR);
            strncat(msg, ms.p, ms.len);

            // GET PAGE AND AUTHENTICATE
            char *page_content;
            FILE *f = fopen(msg, "r");
            if (f != NULL && strstr(msg, "..") == NULL) // file must exist and DEFINITELY don't go up a directory
            {
                fseek(f, 0, SEEK_END);
                int *length = ftell(f);
                page_content = malloc(length);
                fseek(f, 0, SEEK_SET);
                fread(page_content, length, 1, f);
                c->user_data = malloc(msg); // turns out user_data doesn't need to be freed, mongoose
                c->user_data = msg;         // takes care of it somehow, dunno. anyway dont worry about this
                mg_send_websocket_frame(c, WEBSOCKET_OP_TEXT, page_content, length);
                printf("%-32s%s%s%s\n", addr, "LEGAL REQUEST \"", msg, "\"");
                fclose(f);
            }
            else
            {
                mg_send_websocket_frame(c, WEBSOCKET_OP_TEXT, "Illegal Request", 16);
                printf("%-32s%s%s%s\n", addr, "ILLEGAL REQUEST \"", msg, "\"");
            }
            free(msg);
            free(page_content);
            break;
        }
        case MG_EV_HTTP_REQUEST:
        {
            mg_serve_http(c, (struct http_message *) ev_data, s_http_server_opts);
            break;
        }
        case MG_EV_CLOSE:
        {
            if (is_websocket(c))
            {
                num_connections--;
                printf("%-32s%s\n", addr, "DISCONNECTED");
            }
            break;
        }
	}
	return;
}


int main(void)
{
	struct mg_mgr mgr;
	struct mg_connection *c;

    mg_mgr_init(&mgr, NULL);
	c = mg_bind(&mgr, PORT, ev_handler);
	mg_set_protocol_http_websocket(c);
	s_http_server_opts.document_root = ".";
	s_http_server_opts.enable_directory_listing = "no";

	printf("PORT: %s | MAX CONNECTIONS: %d | MESSAGE MAX SIZE: %d | TIMEOUT: %d\n", PORT, MAX_CONNECTIONS, CLIENT_MESSAGE_SIZE, TIMEOUT);
	printf("___________________________________________________________________________________________________\n\n");

  	while (s_signal_received == 0)
    		mg_mgr_poll(&mgr, TIMEOUT);


  	mg_mgr_free(&mgr);
	printf("SHUTTING DOWN...");
    return 0;
}
