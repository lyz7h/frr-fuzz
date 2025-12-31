// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BFD daemon code
 * Copyright (C) 2018 Network Device Education Foundation, Inc. ("NetDEF")
 */

 #include <zebra.h>

 #include <arpa/inet.h>
 #include <netinet/in.h>
 #include <sys/socket.h>
 #include <sys/un.h>
 
 #include <err.h>
 
 #include "filter.h"
 #include "if.h"
 #include "vrf.h"
 
 #include "bfd.h"
 #include "bfdd_nb.h"
 #include "bfddp_packet.h"
 #include "lib/version.h"
 #include "lib/command.h"
 
 #ifdef FUZZING
 #include "lib/fuzz.h"
 #include "lib/network.h"
 #include <stdlib.h>
 #include <string.h>
 #include <arpa/inet.h>
 #endif
 
 
 /*
  * FRR related code.
  */
 DEFINE_MGROUP(BFDD, "Bidirectional Forwarding Detection Daemon");
 DEFINE_MTYPE(BFDD, BFDD_CONTROL, "control socket memory");
 DEFINE_MTYPE(BFDD, BFDD_NOTIFICATION, "control notification data");
 
 /* Master of threads. */
 struct event_loop *master;
 
 /* BFDd privileges */
 static zebra_capabilities_t _caps_p[] = {ZCAP_BIND, ZCAP_SYS_ADMIN, ZCAP_NET_RAW};
 
 /* BFD daemon information. */
 static struct frr_daemon_info bfdd_di;
 
 void socket_close(int *s)
 {
	 if (*s <= 0)
		 return;
 
	 if (close(*s) != 0)
		 zlog_err("%s: close(%d): (%d) %s", __func__, *s, errno,
			  strerror(errno));
 
	 *s = -1;
 }
 
 static void sigusr1_handler(void)
 {
	 zlog_rotate();
 }
 
 static void sigterm_handler(void)
 {
	 bglobal.bg_shutdown = true;
 
	 /* Signalize shutdown. */
	 frr_early_fini();
 
	 /* Stop receiving message from zebra. */
	 bfdd_zclient_stop();
 
	 /* Shutdown controller to avoid receiving anymore commands. */
	 control_shutdown();
 
	 /* Shutdown and free all protocol related memory. */
	 bfd_shutdown();
 
	 bfd_vrf_terminate();
 
	 /* Terminate and free() FRR related memory. */
	 frr_fini();
 
	 exit(0);
 }
 
 static void sighup_handler(void)
 {
	 zlog_info("SIGHUP received");
 
	 /* Reload config file. */
	 vty_read_config(NULL, bfdd_di.config_file, config_default);
 }
 
 static struct frr_signal_t bfd_signals[] = {
	 {
		 .signal = SIGUSR1,
		 .handler = &sigusr1_handler,
	 },
	 {
		 .signal = SIGTERM,
		 .handler = &sigterm_handler,
	 },
	 {
		 .signal = SIGINT,
		 .handler = &sigterm_handler,
	 },
	 {
		 .signal = SIGHUP,
		 .handler = &sighup_handler,
	 },
 };
 
 static const struct frr_yang_module_info *const bfdd_yang_modules[] = {
	 &frr_filter_info,
	 &frr_interface_info,
	 &frr_bfdd_info,
	 &frr_vrf_info,
 };
 
 FRR_DAEMON_INFO(bfdd, BFD, .vty_port = 2617,
		 .proghelp = "Implementation of the BFD protocol.",
		 .signals = bfd_signals, .n_signals = array_size(bfd_signals),
		 .privs = &bglobal.bfdd_privs,
		 .yang_modules = bfdd_yang_modules,
		 .n_yang_modules = array_size(bfdd_yang_modules),
 );
 
 #define OPTION_CTLSOCK 1001
 #define OPTION_DPLANEADDR 2000
 static const struct option longopts[] = {
	 {"bfdctl", required_argument, NULL, OPTION_CTLSOCK},
	 {"dplaneaddr", required_argument, NULL, OPTION_DPLANEADDR},
	 {0}
 };
 
 
 /*
  * BFD daemon related code.
  */
 struct bfd_global bglobal;
 
 #ifdef FUZZING
 static struct bfd_session *FuzzingSession;
 static struct bfd_vrf_global *FuzzingBvrf;
 static bool FuzzingInitialized;
 
 static bool FuzzingInit(void)
 {
	 const char *name[] = { "bfdd" };
	 /* bg_init() is called in main, but we need to initialize bglobal */
	 TAILQ_INIT(&bglobal.bg_bcslist);
	 TAILQ_INIT(&bglobal.bg_obslist);
	 frr_preinit(&bfdd_di, 1, (char **) &name);
	 master = frr_init_fast();
	 bfd_initialize();
	 bfd_vrf_init();
	 access_list_init();
	 return true;
 }
 
 static struct bfd_session *FuzzingCreateBfd(void)
 {
	 struct vrf *vrf = vrf_get(VRF_DEFAULT, VRF_DEFAULT_NAME);
	 struct interface *ifp = if_get_by_name("fuzziface", 0, "default");
	 ifp->mtu = 1500;
 
	 /* Get VRF global structure from vrf->info */
	 struct bfd_vrf_global *bvrf = (struct bfd_vrf_global *)vrf->info;
	 if (!bvrf) {
		 /* Create VRF global if it doesn't exist */
		 bvrf = calloc(1, sizeof(struct bfd_vrf_global));
		 if (!bvrf)
			 return NULL;
		 bvrf->vrf = vrf;
		 bvrf->bg_shop = -1;
		 bvrf->bg_mhop = -1;
		 bvrf->bg_shop6 = -1;
		 bvrf->bg_mhop6 = -1;
		 bvrf->bg_echo = -1;
		 bvrf->bg_echov6 = -1;
		 vrf->info = bvrf;
	 }
	 FuzzingBvrf = bvrf;
 
	 /* Create BFD peer configuration */
	 struct bfd_peer_cfg bpc = {};
	 bpc.bpc_ipv4 = true;
	 bpc.bpc_mhop = false;
	 bpc.bpc_has_localif = true;
	 strlcpy(bpc.bpc_localif, "fuzziface", sizeof(bpc.bpc_localif));
	 bpc.bpc_has_vrfname = false;
 
	 /* Set peer and local addresses */
	 bpc.bpc_peer.sa_sin.sin_family = AF_INET;
	 bpc.bpc_peer.sa_sin.sin_addr.s_addr = inet_addr("192.168.1.2");
	 bpc.bpc_local.sa_sin.sin_family = AF_INET;
	 bpc.bpc_local.sa_sin.sin_addr.s_addr = inet_addr("192.168.1.1");
 
	 /* Create BFD session */
	 struct bfd_session *bs = ptm_bfd_sess_new(&bpc);
	 if (!bs)
		 return NULL;
 
	 /* Ensure session is enabled */
	 bs->vrf = vrf;
	 bs->ifp = ifp;
	 bs->local_address.sa_sin.sin_family = AF_INET;
	 bs->local_address.sa_sin.sin_addr.s_addr = inet_addr("192.168.1.1");
 
	 return bs;
 }
 
 /* Fuzzing helper function to process BFD packets */
 void bfd_fuzz_process_packet(struct bfd_vrf_global *bvrf,
				  struct bfd_pkt *cp, int len,
				  struct sockaddr_any *peer,
				  struct sockaddr_any *local,
				  struct interface *ifp, vrf_id_t vrfid,
				  bool is_mhop, uint8_t ttl)
 {
	 struct bfd_session *bfd;
 
	 /* Basic validation */
	 if (len < BFD_PKT_LEN)
		 return;
 
	 if (BFD_GETVER(cp->diag) != BFD_VERSION)
		 return;
 
	 if (cp->detect_mult == 0)
		 return;
 
	 if ((cp->len < BFD_PKT_LEN) || (cp->len > len))
		 return;
 
	 if (cp->discrs.my_discr == 0)
		 return;
 
	 /* Find the session */
	 bfd = ptm_bfd_sess_find(cp, peer, local, ifp, vrfid, is_mhop);
	 if (bfd == NULL)
		 return;
 
	 /* Validate TTL for multi-hop */
	 if (is_mhop && ttl < bfd->mh_ttl)
		 return;
 
	 /* Set local address if needed */
	 if (!is_mhop && bfd->local_address.sa_sin.sin_family == AF_UNSPEC)
		 bfd->local_address = *local;
 
	 bfd->stats.rx_ctrl_pkt++;
 
	 /* Update remote discriminator */
	 bfd->discrs.remote_discr = ntohl(cp->discrs.my_discr);
 
	 /* Check authentication (skip for fuzzing) */
	 /* bfd_check_auth(bfd, cp); */
 
	 /* Save remote diagnostics */
	 bfd->remote_diag = cp->diag & BFD_DIAGMASK;
 
	 /* Update remote timers */
	 bfd->remote_timers.desired_min_tx = ntohl(cp->timers.desired_min_tx);
	 bfd->remote_timers.required_min_rx = ntohl(cp->timers.required_min_rx);
	 bfd->remote_timers.required_min_echo =
		 ntohl(cp->timers.required_min_echo);
	 bfd->remote_detect_mult = cp->detect_mult;
 
	 if (BFD_GETCBIT(cp->flags))
		 bfd->remote_cbit = 1;
	 else
		 bfd->remote_cbit = 0;
 
	 /* State switch */
	 bs_state_handler(bfd, BFD_GETSTATE(cp->flags));
 
	 /* Handle POLL/FINAL */
	 if (bfd->polling && BFD_GETFBIT(cp->flags)) {
		 bfd->polling = 0;
		 bs_final_handler(bfd);
	 }
 
	 /* Update detection timeout */
	 if (bfd->cur_timers.required_min_rx > bfd->remote_timers.desired_min_tx)
		 bfd->detect_TO = bfd->remote_detect_mult
				  * bfd->cur_timers.required_min_rx;
	 else
		 bfd->detect_TO = bfd->remote_detect_mult
				  * bfd->remote_timers.desired_min_tx;
 
	 /* Apply new receive timer */
	 bfd_recvtimer_update(bfd);
 
	 /* Handle echo timers */
	 bs_echo_timer_handler(bfd);
 
	 /* Handle POLL bit */
	 if (BFD_GETPBIT(cp->flags)) {
		 bs_final_handler(bfd);
		 /* Note: ptm_bfd_snd would send packet, skip for fuzzing */
	 }
 }
 
 int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
 {
	 if (!FuzzingInitialized) {
		 FuzzingInit();
		 FuzzingInitialized = true;
		 FuzzingSession = FuzzingCreateBfd();
		 if (!FuzzingSession)
			 return 0;
	 }
 
	 if (size < BFD_PKT_LEN || size > 1516)
		 return 0;
 
	 /* Create packet buffer */
	 struct bfd_pkt *cp = (struct bfd_pkt *)data;
	 struct sockaddr_any peer, local;
	 struct interface *ifp = FuzzingSession->ifp;
	 vrf_id_t vrfid = VRF_DEFAULT;
	 bool is_mhop = false;
	 uint8_t ttl = BFD_TTL_VAL;
 
	 memset(&peer, 0, sizeof(peer));
	 memset(&local, 0, sizeof(local));
	 peer.sa_sin.sin_family = AF_INET;
	 peer.sa_sin.sin_addr.s_addr = inet_addr("192.168.1.2");
	 local.sa_sin.sin_family = AF_INET;
	 local.sa_sin.sin_addr.s_addr = inet_addr("192.168.1.1");
 
	 /* Process packet */
	 bfd_fuzz_process_packet(FuzzingBvrf, cp, size, &peer, &local, ifp,
				   vrfid, is_mhop, ttl);
 
	 return 0;
 }
 #endif /* FUZZING */
 
 const struct bfd_diag_str_list diag_list[] = {
	 {.str = "control-expired", .type = BD_CONTROL_EXPIRED},
	 {.str = "echo-failed", .type = BD_ECHO_FAILED},
	 {.str = "neighbor-down", .type = BD_NEIGHBOR_DOWN},
	 {.str = "forwarding-reset", .type = BD_FORWARDING_RESET},
	 {.str = "path-down", .type = BD_PATH_DOWN},
	 {.str = "concatenated-path-down", .type = BD_CONCATPATH_DOWN},
	 {.str = "administratively-down", .type = BD_ADMIN_DOWN},
	 {.str = "reverse-concat-path-down", .type = BD_REVCONCATPATH_DOWN},
	 {.str = NULL},
 };
 
 const struct bfd_state_str_list state_list[] = {
	 {.str = "admin-down", .type = PTM_BFD_ADM_DOWN},
	 {.str = "down", .type = PTM_BFD_DOWN},
	 {.str = "init", .type = PTM_BFD_INIT},
	 {.str = "up", .type = PTM_BFD_UP},
	 {.str = NULL},
 };
 
 static uint16_t
 parse_port(const char *str)
 {
	 char *nulbyte;
	 long rv;
 
	 errno = 0;
	 rv = strtol(str, &nulbyte, 10);
	 /* No conversion performed. */
	 if (rv == 0 && errno == EINVAL) {
		 fprintf(stderr, "invalid BFD data plane address port: %s\n",
			 str);
		 exit(0);
	 }
	 /* Invalid number range. */
	 if ((rv <= 0 || rv >= 65535) || errno == ERANGE) {
		 fprintf(stderr, "invalid BFD data plane port range: %s\n",
			 str);
		 exit(0);
	 }
	 /* There was garbage at the end of the string. */
	 if (*nulbyte != 0) {
		 fprintf(stderr, "invalid BFD data plane port: %s\n",
			 str);
		 exit(0);
	 }
 
	 return (uint16_t)rv;
 }
 
 static void
 distributed_bfd_init(const char *arg)
 {
	 char *sptr, *saux;
	 bool is_client = false;
	 size_t slen;
	 socklen_t salen;
	 char addr[64];
	 char type[64];
	 union {
		 struct sockaddr_in sin;
		 struct sockaddr_in6 sin6;
		 struct sockaddr_un sun;
	 } sa;
 
	 /* Basic parsing: find ':' to figure out type part and address part. */
	 sptr = strchr(arg, ':');
	 if (sptr == NULL) {
		 fprintf(stderr, "invalid BFD data plane socket: %s\n", arg);
		 exit(1);
	 }
 
	 /* Calculate type string length. */
	 slen = (size_t)(sptr - arg);
 
	 /* Copy the address part. */
	 sptr++;
	 strlcpy(addr, sptr, sizeof(addr));
 
	 /* Copy type part. */
	 strlcpy(type, arg, slen + 1);
 
	 /* Reset address data. */
	 memset(&sa, 0, sizeof(sa));
 
	 /* Fill the address information. */
	 if (strcmp(type, "unix") == 0 || strcmp(type, "unixc") == 0) {
		 if (strcmp(type, "unixc") == 0)
			 is_client = true;
 
		 salen = sizeof(sa.sun);
		 sa.sun.sun_family = AF_UNIX;
		 strlcpy(sa.sun.sun_path, addr, sizeof(sa.sun.sun_path));
	 } else if (strcmp(type, "ipv4") == 0 || strcmp(type, "ipv4c") == 0) {
		 if (strcmp(type, "ipv4c") == 0)
			 is_client = true;
 
		 salen = sizeof(sa.sin);
		 sa.sin.sin_family = AF_INET;
 
		 /* Parse port if any. */
		 sptr = strchr(addr, ':');
		 if (sptr == NULL) {
			 sa.sin.sin_port = htons(BFD_DATA_PLANE_DEFAULT_PORT);
		 } else {
			 *sptr = 0;
			 sa.sin.sin_port = htons(parse_port(sptr + 1));
		 }
 
		 if (inet_pton(AF_INET, addr, &sa.sin.sin_addr) != 1)
			 errx(1, "%s: inet_pton: invalid address %s", __func__,
				  addr);
	 } else if (strcmp(type, "ipv6") == 0 || strcmp(type, "ipv6c") == 0) {
		 if (strcmp(type, "ipv6c") == 0)
			 is_client = true;
 
		 salen = sizeof(sa.sin6);
		 sa.sin6.sin6_family = AF_INET6;
 
		 /* Check for IPv6 enclosures '[]' */
		 sptr = &addr[0];
		 if (*sptr != '[')
			 errx(1, "%s: invalid IPv6 address format: %s", __func__,
				  addr);
 
		 saux = strrchr(addr, ']');
		 if (saux == NULL)
			 errx(1, "%s: invalid IPv6 address format: %s", __func__,
				  addr);
 
		 /* Consume the '[]:' part. */
		 slen = saux - sptr;
		 memmove(addr, addr + 1, slen);
		 addr[slen - 1] = 0;
 
		 /* Parse port if any. */
		 saux++;
		 sptr = strrchr(saux, ':');
		 if (sptr == NULL) {
			 sa.sin6.sin6_port = htons(BFD_DATA_PLANE_DEFAULT_PORT);
		 } else {
			 *sptr = 0;
			 sa.sin6.sin6_port = htons(parse_port(sptr + 1));
		 }
 
		 if (inet_pton(AF_INET6, addr, &sa.sin6.sin6_addr) != 1)
			 errx(1, "%s: inet_pton: invalid address %s", __func__,
				  addr);
	 } else {
		 fprintf(stderr, "invalid BFD data plane socket type: %s\n",
			 type);
		 exit(1);
	 }
 
	 /* Initialize BFD data plane listening socket. */
	 bfd_dplane_init((struct sockaddr *)&sa, salen, is_client);
 }
 
 static void bg_init(void)
 {
	 struct zebra_privs_t bfdd_privs = {
 #if defined(FRR_USER) && defined(FRR_GROUP)
		 .user = FRR_USER,
		 .group = FRR_GROUP,
 #endif
 #if defined(VTY_GROUP)
		 .vty_group = VTY_GROUP,
 #endif
		 .caps_p = _caps_p,
		 .cap_num_p = array_size(_caps_p),
		 .cap_num_i = 0,
	 };
 
	 TAILQ_INIT(&bglobal.bg_bcslist);
	 TAILQ_INIT(&bglobal.bg_obslist);
 
	 memcpy(&bglobal.bfdd_privs, &bfdd_privs,
			sizeof(bfdd_privs));
 }
 
 #if !defined(FUZZING_LIBFUZZER)
 int main(int argc, char *argv[])
 {
	 char ctl_path[512], dplane_addr[512];
	 bool ctlsockused = false;
	 int opt;
 
	 bglobal.bg_use_dplane = false;
 
	 /* Initialize system sockets. */
	 bg_init();
 
	 frr_preinit(&bfdd_di, argc, argv);
	 frr_opt_add("", longopts,
			 "      --bfdctl       Specify bfdd control socket\n"
			 "      --dplaneaddr   Specify BFD data plane address\n");
 
	 snprintf(ctl_path, sizeof(ctl_path), BFDD_CONTROL_SOCKET,
		  "", "");
	 while (true) {
		 opt = frr_getopt(argc, argv, NULL);
		 if (opt == EOF)
			 break;
 
		 switch (opt) {
		 case OPTION_CTLSOCK:
			 strlcpy(ctl_path, optarg, sizeof(ctl_path));
			 ctlsockused = true;
			 break;
		 case OPTION_DPLANEADDR:
			 strlcpy(dplane_addr, optarg, sizeof(dplane_addr));
			 bglobal.bg_use_dplane = true;
			 break;
 
		 default:
			 frr_help_exit(1);
		 }
	 }
 
	 if (bfdd_di.pathspace && !ctlsockused)
		 snprintf(ctl_path, sizeof(ctl_path), BFDD_CONTROL_SOCKET,
			  "/", bfdd_di.pathspace);
 
	 /* Initialize FRR infrastructure. */
	 master = frr_init();
 
	 /* Initialize control socket. */
	 control_init(ctl_path);
 
	 /* Initialize BFD data structures. */
	 bfd_initialize();
 
	 bfd_vrf_init();
 
	 access_list_init();
 
	 /* Initialize zebra connection. */
	 bfdd_zclient_init(&bglobal.bfdd_privs);
 
	 event_add_read(master, control_accept, NULL, bglobal.bg_csock,
				&bglobal.bg_csockev);
 
	 /* Install commands. */
	 bfdd_vty_init();
 
	 /* read configuration file and daemonize  */
	 frr_config_fork();
 
	 /* Initialize BFD data plane listening socket. */
	 if (bglobal.bg_use_dplane)
		 distributed_bfd_init(dplane_addr);
 
	 frr_run(master);
	 /* NOTREACHED */
 
	 return 0;
 }
 #endif /* !defined(FUZZING_LIBFUZZER) */