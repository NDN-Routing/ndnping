/*
 * ndnpingserver responds to ping Interests with empty Data.
 * Copyright (C) 2011 University of Arizona
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Author: Cheng Yi <yic@email.arizona.edu>
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <ndn/ndn.h>
#include <ndn/uri.h>
#include <ndn/keystore.h>
#include <ndn/signing.h>

#define PING_COMPONENT "ping"
#define PING_ACK "ping ack"

struct ndn_ping_server {
    struct ndn_charbuf *prefix;
    int count;
    int expire;
};

static void daemonize(void)
{
    pid_t pid;
    pid = fork();

    // In case of fork is error.
    if (pid < 0) {
        fprintf(stderr, "fork failed: %d", errno);
        exit(-1);
    }

    // In case of this is parent process.
    if (pid != 0)
        exit(0);

    // Become session leader and get pid.
    pid = setsid();

    if (pid == -1) {
        fprintf(stderr, "setsid failed: %d", errno);
        exit(-1);
    }

    // Change directory to root.
    if (chdir("/") < 0)
        exit(-1);

    // File descriptor close.
    if (!freopen("/dev/null", "r", stdin) ||
        !freopen("/dev/null", "w", stdout) ||
        !freopen("/dev/null", "w", stderr))
        exit(-1);

    umask(0027);
}

static void usage(const char *progname)
{
    fprintf(stderr,
            "Usage: %s ndnx:/name/prefix [options]\n"
            "Starts a NDN ping server that responds to Interests with name"
            " ndnx:/name/prefix/ping/number.\n"
            "  [-x freshness] - set FreshnessSeconds\n"
            "  [-d] - run server in daemon mode\n"
            "  [-h] - print this message and exit\n",
            progname);
    exit(1);
}

// Checks whether Interest name is valid.
// - prefix is ndnx:/name/prefix/ping.
// - Interest name should be ndnx:/name/prefix/ping/number or
//   ndnx:/name/prefix/ping/identifier/number.
// - returns 1 if Interest name is valid, 0 otherwise.
int ping_interest_valid(struct ndn_charbuf *prefix,
        const unsigned char *interest_msg, const struct ndn_parsed_interest *pi)
{
    struct ndn_indexbuf *prefix_components;
    int prefix_ncomps;
    long number;
    char *end;

    prefix_components = ndn_indexbuf_create();
    prefix_ncomps = ndn_name_split(prefix, prefix_components);
    ndn_indexbuf_destroy(&prefix_components);

    if (pi->prefix_comps == prefix_ncomps + 1 || pi->prefix_comps == prefix_ncomps + 2) {
        number = strtol((char *)interest_msg + pi->offset[NDN_PI_B_LastPrefixComponent] + 2,
                &end, 10);
        if (*end == '\0' && number >= 0)
            return 1;
    }

    return 0;
}

int construct_ping_response(struct ndn *h, struct ndn_charbuf *data, 
        const unsigned char *interest_msg, const struct ndn_parsed_interest *pi, int expire)
{
    struct ndn_charbuf *name = ndn_charbuf_create();
    struct ndn_signing_params sp = NDN_SIGNING_PARAMS_INIT;
    int res;

    ndn_charbuf_append(name, interest_msg + pi->offset[NDN_PI_B_Name],
            pi->offset[NDN_PI_E_Name] - pi->offset[NDN_PI_B_Name]);

    // Set freshness seconds.
    if (expire >= 0) {
        sp.template_ndnb = ndn_charbuf_create();
        ndn_charbuf_append_tt(sp.template_ndnb, NDN_DTAG_SignedInfo, NDN_DTAG);
        ndnb_tagged_putf(sp.template_ndnb, NDN_DTAG_FreshnessSeconds, "%ld", expire);
        sp.sp_flags |= NDN_SP_TEMPL_FRESHNESS;
        ndn_charbuf_append_closer(sp.template_ndnb);
    }

    res = ndn_sign_content(h, data, name, &sp, PING_ACK, strlen(PING_ACK));

    ndn_charbuf_destroy(&sp.template_ndnb);
    ndn_charbuf_destroy(&name);
    return res;
}

enum ndn_upcall_res incoming_interest(struct ndn_closure *selfp,
        enum ndn_upcall_kind kind, struct ndn_upcall_info *info)
{
    struct ndn_ping_server *server = selfp->data;
    int res;

    switch (kind) {
        case NDN_UPCALL_FINAL:
            break;
        case NDN_UPCALL_INTEREST:
            if (ping_interest_valid(server->prefix, info->interest_ndnb, info->pi)) {
                // Construct Data content with given Interest name.
                struct ndn_charbuf *data = ndn_charbuf_create();
                construct_ping_response(info->h, data, info->interest_ndnb,
                        info->pi, server->expire);

                res = ndn_put(info->h, data->buf, data->length);
                ndn_charbuf_destroy(&data);

                server->count ++;

                if (res >= 0)
                    return NDN_UPCALL_RESULT_INTEREST_CONSUMED;
            }
            break;
        default:
            break;
    }

    return NDN_UPCALL_RESULT_OK;
}

int main(int argc, char **argv)
{
    const char *progname = argv[0];
    struct ndn *ndn = NULL;
    struct ndn_ping_server server = {.count = 0, .expire = 1};
    struct ndn_closure in_interest = {.p = &incoming_interest};
    int res;
    int daemon_mode = 0;

    while ((res = getopt(argc, argv, "hdx:")) != -1) {
        switch (res) {
            case 'x':
                server.expire = atol(optarg);
                if (server.expire <= 0)
                    usage(progname);
                break;
            case 'd':
                daemon_mode = 1;
                break;
            case 'h':
            default:
                usage(progname);
                break;
        }
    }

    argc -= optind;
    argv += optind;

    if (argv[0] == NULL)
        usage(progname);

    server.prefix = ndn_charbuf_create();
    res = ndn_name_from_uri(server.prefix, argv[0]);
    if (res < 0) {
        fprintf(stderr, "%s: bad ndn URI: %s\n", progname, argv[0]);
        exit(1);
    }
    if (argv[1] != NULL)
        fprintf(stderr, "%s warning: extra arguments ignored\n", progname);

    // Append "/ping" to the given name prefix.
    res = ndn_name_append_str(server.prefix, PING_COMPONENT);
    if (res < 0) {
        fprintf(stderr, "%s: error constructing ndn URI: %s/%s\n",
                progname, argv[0], PING_COMPONENT);
        exit(1);
    }

    // Connect to ndnd.
    ndn = ndn_create();
    if (ndn_connect(ndn, NULL) == -1) {
        perror("Could not connect to ndnd");
        exit(1);
    }

    in_interest.data = &server;
    res = ndn_set_interest_filter(ndn, server.prefix, &in_interest);
    if (res < 0) {
        fprintf(stderr, "Failed to register interest (res == %d)\n", res);
        exit(1);
    }

    if (daemon_mode)
        daemonize();

    res = ndn_run(ndn, -1);

    ndn_destroy(&ndn);
    ndn_charbuf_destroy(&server.prefix);

    exit(0);
}
