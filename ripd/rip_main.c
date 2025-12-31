// SPDX-License-Identifier: GPL-2.0-or-later
/* RIPd main routine.
 * Copyright (C) 1997, 98 Kunihiro Ishiguro <kunihiro@zebra.org>
 */

 #include <zebra.h>

 #include <lib/version.h>
 #include "getopt.h"
 #include "frrevent.h"
 #include "command.h"
 #include "memory.h"
 #include "prefix.h"
 #include "filter.h"
 #include "keychain.h"
 #include "log.h"
 #include "privs.h"
 #include "sigevent.h"
 #include "zclient.h"
 #include "vrf.h"
 #include "if_rmap.h"
 #include "libfrr.h"
 #include "routemap.h"
 #include "bfd.h"
 
 #include "ripd/ripd.h"
 #include "ripd/rip_bfd.h"
 #include "ripd/rip_nb.h"
 #include "ripd/rip_errors.h"
 
 #ifdef FUZZING
 #include "lib/fuzz.h"
 #include "lib/network.h"
 #include <stdlib.h>
 #include <string.h>
 #include <arpa/inet.h>
 #endif
 
 /* ripd options. */
 static struct option longopts[] = {{0}};
 
 /* ripd privileges */
 zebra_capabilities_t _caps_p[] = {ZCAP_NET_RAW, ZCAP_BIND, ZCAP_SYS_ADMIN};
 
 uint32_t zebra_ecmp_count = MULTIPATH_NUM;
 
 struct zebra_privs_t ripd_privs = {
 #if defined(FRR_USER)
	 .user = FRR_USER,
 #endif
 #if defined FRR_GROUP
	 .group = FRR_GROUP,
 #endif
 #ifdef VTY_GROUP
	 .vty_group = VTY_GROUP,
 #endif
	 .caps_p = _caps_p,
	 .cap_num_p = array_size(_caps_p),
	 .cap_num_i = 0};
 
 /* Master of threads. */
 struct event_loop *master;
 
 static struct frr_daemon_info ripd_di;
 
 /* SIGHUP handler. */
 static void sighup(void)
 {
	 zlog_info("SIGHUP received");
 
	 /* Reload config file. */
	 vty_read_config(NULL, ripd_di.config_file, config_default);
 }
 
 /* SIGINT handler. */
 static void sigint(void)
 {
	 zlog_notice("Terminating on signal");
 
	 bfd_protocol_integration_set_shutdown(true);
	 rip_vrf_terminate();
	 if_rmap_terminate();
	 rip_zclient_stop();
	 frr_fini();
 
	 exit(0);
 }
 
 /* SIGUSR1 handler. */
 static void sigusr1(void)
 {
	 zlog_rotate();
 }
 
 static struct frr_signal_t ripd_signals[] = {
	 {
		 .signal = SIGHUP,
		 .handler = &sighup,
	 },
	 {
		 .signal = SIGUSR1,
		 .handler = &sigusr1,
	 },
	 {
		 .signal = SIGINT,
		 .handler = &sigint,
	 },
	 {
		 .signal = SIGTERM,
		 .handler = &sigint,
	 },
 };
 
 static const struct frr_yang_module_info *const ripd_yang_modules[] = {
	 &frr_filter_info,
	 &frr_interface_info,
	 &frr_ripd_info,
	 &frr_route_map_info,
	 &frr_vrf_info,
 };
 
 FRR_DAEMON_INFO(ripd, RIP, .vty_port = RIP_VTY_PORT,
 
		 .proghelp = "Implementation of the RIP routing protocol.",
 
		 .signals = ripd_signals, .n_signals = array_size(ripd_signals),
 
		 .privs = &ripd_privs, .yang_modules = ripd_yang_modules,
		 .n_yang_modules = array_size(ripd_yang_modules),
 );
 
 #define DEPRECATED_OPTIONS ""
 
 #ifdef FUZZING
 static struct rip *FuzzingRip;
 static struct interface *FuzzingInterface;
 static struct connected *FuzzingConnected;
 static bool FuzzingInitialized;
 
 static bool FuzzingInit(void)
 {
	 const char *name[] = { "ripd" };
	 frr_preinit(&ripd_di, 1, (char **) &name);
	 master = frr_init_fast();
	 rip_error_init();
	 keychain_init();
	 rip_vrf_init();
	 rip_init();
	 rip_if_init();
	 rip_cli_init();
	 rip_zclient_init(master);
	 rip_bfd_init(master);
	 return true;
 }
 
 static struct connected *FuzzingCreateRip(void)
 {
	 struct vrf *vrf = vrf_get(VRF_DEFAULT, VRF_DEFAULT_NAME);
	 struct interface *ifp = if_get_by_name("fuzziface", 0, "default");
	 ifp->mtu = 1500;
 
	 /* Create RIP instance */
	 struct rip *rip = rip_lookup_by_vrf_name(VRF_DEFAULT_NAME);
	 if (!rip) {
		 rip = rip_create(VRF_DEFAULT_NAME, vrf, -1);
		 if (!rip)
			 return NULL;
		 /* Ensure VRF info is set for fuzzing */
		 if (vrf && !vrf->info)
			 vrf->info = rip;
	 }
	 FuzzingRip = rip;
 
	 /* Set up interface */
	 struct rip_interface *ri = ifp->info;
	 /* rip_interface_new_hook should have created it via if_get_by_name */
	 if (!ri) {
		 /* Fallback: create manually if hook didn't run */
		 ri = calloc(1, sizeof(struct rip_interface));
		 if (!ri)
			 return NULL;
		 ifp->info = ri;
		 /* Initialize with default values for fuzzing */
		 ri->auth_type = RIP_NO_AUTH;
		 ri->md5_auth_len = RIP_AUTH_MD5_COMPAT_SIZE;
		 ri->split_horizon = RIP_SPLIT_HORIZON;
		 ri->ri_send = RI_RIP_UNSPEC;
		 ri->ri_receive = RI_RIP_UNSPEC;
		 ri->v2_broadcast = false;
	 }
	 ri->rip = rip;
	 ri->ifp = ifp;
	 ri->running = 1;
 
	 /* Create connected address */
	 struct prefix_ipv4 p;
	 memset(&p, 0, sizeof(p));
	 p.family = AF_INET;
	 p.prefix.s_addr = inet_addr("192.168.1.1");
	 p.prefixlen = 24;
 
	 struct connected *ifc = connected_new();
	 ifc->ifp = ifp;
	 struct prefix_ipv4 *addr = prefix_ipv4_new();
	 *addr = p;
	 ifc->address = (struct prefix *)addr;
	 listnode_add(ifp->connected, ifc);
 
	 return ifc;
 }
 
 int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
 {
	 if (!FuzzingInitialized) {
		 FuzzingInit();
		 FuzzingInitialized = true;
		 FuzzingConnected = FuzzingCreateRip();
		 if (!FuzzingConnected)
			 return 0;
	 }
 
	 if (size < RIP_PACKET_MINSIZ || size > RIP_PACKET_MAXSIZ)
		 return 0;
 
	 /* Create packet buffer */
	 union rip_buf rip_buf;
	 memset(&rip_buf, 0, sizeof(rip_buf));
	 memcpy(rip_buf.buf, data, size);
 
	 struct rip_packet *packet = &rip_buf.rip_packet;
	 struct sockaddr_in from;
	 memset(&from, 0, sizeof(from));
	 from.sin_family = AF_INET;
	 from.sin_addr.s_addr = inet_addr("192.168.1.2");
	 from.sin_port = htons(RIP_PORT_DEFAULT);
 
	 /* Process packet */
	 rip_fuzz_process_packet(FuzzingRip, packet, size, &from,
					FuzzingConnected);
 
	 return 0;
 }
 #endif /* FUZZING */
 
 /* Main routine of ripd. */
 #if !defined(FUZZING_LIBFUZZER)
 int main(int argc, char **argv)
 {
	 frr_preinit(&ripd_di, argc, argv);
 
	 frr_opt_add("" DEPRECATED_OPTIONS, longopts, "");
 
	 /* Command line option parse. */
	 while (1) {
		 int opt;
 
		 opt = frr_getopt(argc, argv, NULL);
 
		 if (opt && opt < 128 && strchr(DEPRECATED_OPTIONS, opt)) {
			 fprintf(stderr,
				 "The -%c option no longer exists.\nPlease refer to the manual.\n",
				 opt);
			 continue;
		 }
 
		 if (opt == EOF)
			 break;
 
		 switch (opt) {
		 case 0:
			 break;
		 default:
			 frr_help_exit(1);
		 }
	 }
 
	 /* Prepare master thread. */
	 master = frr_init();
 
	 /* Library initialization. */
	 rip_error_init();
	 keychain_init();
	 rip_vrf_init();
 
	 /* RIP related initialization. */
	 rip_init();
	 rip_if_init();
	 rip_cli_init();
	 rip_zclient_init(master);
	 rip_bfd_init(master);
 
	 frr_config_fork();
	 frr_run(master);
 
	 /* Not reached. */
	 return 0;
 }
 #endif /* !defined(FUZZING_LIBFUZZER) */