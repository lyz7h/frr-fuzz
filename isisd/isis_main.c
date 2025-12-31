// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * IS-IS Rout(e)ing protocol - isis_main.c
 *
 * Copyright (C) 2001,2002   Sampo Saaristo
 *                           Tampere University of Technology
 *                           Institute of Communications Engineering
 */

#include <zebra.h>

#include "getopt.h"
#include "frrevent.h"
#include "log.h"
#include <lib/version.h>
#include "command.h"
#include "vty.h"
#include "memory.h"
#include "stream.h"
#include "if.h"
#include "privs.h"
#include "sigevent.h"
#include "filter.h"
#include "plist.h"
#include "zclient.h"
#include "vrf.h"
#include "qobj.h"
#include "libfrr.h"
#include "routemap.h"
#include "affinitymap.h"

#include "isisd/isis_affinitymap.h"
#include "isisd/isis_constants.h"
#include "isisd/isis_common.h"
#include "isisd/isis_flags.h"
#include "isisd/isis_circuit.h"
#include "isisd/isisd.h"
#include "isisd/isis_dynhn.h"
#include "isisd/isis_spf.h"
#include "isisd/isis_route.h"
#include "isisd/isis_routemap.h"
#include "isisd/isis_zebra.h"
#include "isisd/isis_te.h"
#include "isisd/isis_errors.h"
#include "isisd/isis_bfd.h"
#include "isisd/isis_lsp.h"
#include "isisd/isis_mt.h"
#include "isisd/fabricd.h"
#include "isisd/isis_nb.h"
#include "isisd/isis_ldp_sync.h"
#include "isisd/isis_pdu.h"
#include "isisd/isis_adjacency.h"
#include "isisd/isis_tx_queue.h"

#ifdef FUZZING
#include "lib/fuzz.h"
#endif

/* Default configuration file name */
#define ISISD_DEFAULT_CONFIG "isisd.conf"
/* Default vty port */
#define ISISD_VTY_PORT       2608
#define FABRICD_VTY_PORT     2618

/* isisd privileges */
zebra_capabilities_t _caps_p[] = {ZCAP_NET_RAW, ZCAP_BIND, ZCAP_SYS_ADMIN};

struct zebra_privs_t isisd_privs = {
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

/* isisd options */
static const struct option longopts[] = {
	{"int_num", required_argument, NULL, 'I'},
	{0}};

/* Master of threads. */
struct event_loop *master;

/*
 * Prototypes.
 */
void sighup(void);
void sigint(void);
void sigterm(void);
void sigusr1(void);


static __attribute__((__noreturn__)) void terminate(int i)
{
	isis_terminate();
	isis_sr_term();
	isis_zebra_stop();
	exit(i);
}

/*
 * Signal handlers
 */
#ifdef FABRICD
void sighup(void)
{
	zlog_notice("SIGHUP/reload is not implemented for fabricd");
	return;
}
#else
static struct frr_daemon_info isisd_di;
void sighup(void)
{
	zlog_info("SIGHUP received");

	/* Reload config file. */
	vty_read_config(NULL, isisd_di.config_file, config_default);
}

#endif

__attribute__((__noreturn__)) void sigint(void)
{
	zlog_notice("Terminating on signal SIGINT");
	terminate(0);
}

__attribute__((__noreturn__)) void sigterm(void)
{
	zlog_notice("Terminating on signal SIGTERM");
	terminate(0);
}

void sigusr1(void)
{
	zlog_debug("SIGUSR1 received");
	zlog_rotate();
}

struct frr_signal_t isisd_signals[] = {
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
		.handler = &sigterm,
	},
};


/* clang-format off */
static const struct frr_yang_module_info *const isisd_yang_modules[] = {
	&frr_filter_info,
	&frr_interface_info,
#ifndef FABRICD
	&frr_isisd_info,
#endif /* ifndef FABRICD */
	&frr_route_map_info,
	&frr_affinity_map_info,
	&frr_vrf_info,
};
/* clang-format on */


static void isis_config_finish(struct event *t)
{
	struct listnode *node, *inode;
	struct isis *isis;
	struct isis_area *area;

	for (ALL_LIST_ELEMENTS_RO(im->isis, inode, isis)) {
		for (ALL_LIST_ELEMENTS_RO(isis->area_list, node, area))
			config_end_lsp_generate(area);
	}
}

static void isis_config_start(void)
{
	/* Max wait time for config to load before generating lsp */
#define ISIS_PRE_CONFIG_MAX_WAIT_SECONDS 600
	EVENT_OFF(t_isis_cfg);
	event_add_timer(im->master, isis_config_finish, NULL,
			ISIS_PRE_CONFIG_MAX_WAIT_SECONDS, &t_isis_cfg);
}

static void isis_config_end(void)
{
	/* If ISIS config processing thread isn't running, then
	 * we can return and rely it's properly handled.
	 */
	if (!event_is_scheduled(t_isis_cfg))
		return;

	EVENT_OFF(t_isis_cfg);
	isis_config_finish(t_isis_cfg);
}

#ifdef FABRICD
FRR_DAEMON_INFO(fabricd, OPEN_FABRIC, .vty_port = FABRICD_VTY_PORT,

		.proghelp = "Implementation of the OpenFabric routing protocol.",
#else
FRR_DAEMON_INFO(isisd, ISIS, .vty_port = ISISD_VTY_PORT,

		.proghelp = "Implementation of the IS-IS routing protocol.",
#endif
		.copyright =
			"Copyright (c) 2001-2002 Sampo Saaristo, Ofer Wald and Hannes Gredler",

		.signals = isisd_signals,
		.n_signals = array_size(isisd_signals),

		.privs = &isisd_privs, .yang_modules = isisd_yang_modules,
		.n_yang_modules = array_size(isisd_yang_modules),
);

#ifdef FUZZING

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static bool FuzzingInit(void)
{
#ifdef FABRICD
	const char *name[] = {"fabricd"};
	frr_preinit(&fabricd_di, 1, (char **)name);
#else
	const char *name[] = {"isisd"};
	frr_preinit(&isisd_di, 1, (char **)name);
#endif

	/* Initialize ISIS master */
	isis_master_init(frr_init_fast());
	master = im->master;

	/* Set unit test flag to skip certain operations */
	SET_FLAG(im->options, F_ISIS_UNIT_TEST);

	/* Initializations */
	isis_error_init();
	access_list_init();
	isis_vrf_init();
	prefix_list_init();
	isis_init();
	isis_circuit_init();
	isis_spf_init();
	isis_redist_init();
	isis_route_map_init();
	isis_mpls_te_init();
	isis_sr_init();
	lsp_init();
	mt_init();
	fabricd_init();

	return true;
}

static struct isis_circuit *FuzzingCreateCircuit(void)
{
	struct interface *ifp;
	struct isis_area *area;
	struct isis_circuit *circuit;
	struct isis *isis;
	struct prefix p;
	static uint8_t sysid[ISIS_SYS_ID_LEN] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x01};

	/* Create a fake interface */
	ifp = if_get_by_name("fuzziface", VRF_DEFAULT, "default");
	if (!ifp)
		return NULL;

	ifp->mtu = 1500;
	ifp->ifindex = 1;
	SET_FLAG(ifp->status, ZEBRA_INTERFACE_ACTIVE);
	ifp->flags = IFF_UP | IFF_RUNNING | IFF_BROADCAST;

	/* Add an IP address to the interface */
	str2prefix("10.0.0.1/24", &p);
	connected_add_by_prefix(ifp, &p, NULL);

	/* Create ISIS instance */
	isis = isis_new(VRF_DEFAULT_NAME);
	if (!isis)
		return NULL;

	/* Set system ID */
	memcpy(isis->sysid, sysid, ISIS_SYS_ID_LEN);
	isis->sysid_set = 1;

	/* Create ISIS area */
	area = isis_area_create("fuzzing", VRF_DEFAULT_NAME);
	if (!area)
		return NULL;

	area->is_type = IS_LEVEL_1_AND_2;

	/* Initialize LSP databases */
	lsp_db_init(&area->lspdb[0]);
	lsp_db_init(&area->lspdb[1]);

	/* Create and configure ISIS circuit */
	circuit = isis_circuit_new(ifp, "fuzzing");
	if (!circuit)
		return NULL;

	circuit->state = C_STATE_UP;
	circuit->is_type = IS_LEVEL_1_AND_2;
	circuit->circ_type = CIRCUIT_T_P2P;
	circuit->interface = ifp;
	circuit->isis = isis;
	circuit->ip_router = 1;
	ifp->info = circuit;

	/* Configure circuit for area */
	isis_area_add_circuit(area, circuit);

	/* Initialize receive stream */
	isis_circuit_stream(circuit, &circuit->rcv_stream);

	return circuit;
}

static bool FuzzingInitialized;
static struct isis_circuit *FuzzingCircuit;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	uint8_t ssnpa[ETH_ALEN] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};

	if (!FuzzingInitialized) {
		FuzzingInit();
		FuzzingInitialized = true;
		FuzzingCircuit = FuzzingCreateCircuit();
	}

	if (!FuzzingCircuit || !FuzzingCircuit->area)
		return 0;

	/* Need at least ISIS fixed header size */
	if (size < ISIS_FIXED_HDR_LEN)
		return 0;

	/* Limit size to stream capacity */
	size_t max_size = STREAM_SIZE(FuzzingCircuit->rcv_stream);
	if (size > max_size)
		size = max_size;

	/* Reset and fill the receive stream with fuzzed data */
	stream_reset(FuzzingCircuit->rcv_stream);
	stream_put(FuzzingCircuit->rcv_stream, data, size);

	/* Process the PDU */
	isis_handle_pdu(FuzzingCircuit, ssnpa);

	/* Clean up state to prevent accumulation between iterations */
	if (FuzzingCircuit->area) {
		/* Clean up adjacencies first, as they may reference LSPs */
		if (FuzzingCircuit->circ_type == CIRCUIT_T_P2P) {
			if (FuzzingCircuit->u.p2p.neighbor) {
				isis_delete_adj(FuzzingCircuit->u.p2p.neighbor);
				FuzzingCircuit->u.p2p.neighbor = NULL;
			}
		} else if (FuzzingCircuit->circ_type == CIRCUIT_T_BROADCAST) {
			/* For broadcast circuits, manually remove from adjdb first */
			if (FuzzingCircuit->u.bc.adjdb[0]) {
				struct listnode *node, *nnode;
				struct isis_adjacency *adj;
				for (ALL_LIST_ELEMENTS(FuzzingCircuit->u.bc.adjdb[0],
						      node, nnode, adj)) {
					listnode_delete(FuzzingCircuit->u.bc.adjdb[0],
							adj);
					isis_delete_adj(adj);
				}
			}
			if (FuzzingCircuit->u.bc.adjdb[1]) {
				struct listnode *node, *nnode;
				struct isis_adjacency *adj;
				for (ALL_LIST_ELEMENTS(FuzzingCircuit->u.bc.adjdb[1],
						      node, nnode, adj)) {
					listnode_delete(FuzzingCircuit->u.bc.adjdb[1],
							adj);
					isis_delete_adj(adj);
				}
			}
		}

		/* Clean up area adjacency list before LSP databases */
		if (FuzzingCircuit->area->adjacency_list) {
			struct listnode *node, *nnode;
			struct isis_adjacency *adj;
			for (ALL_LIST_ELEMENTS(FuzzingCircuit->area->adjacency_list,
					      node, nnode, adj)) {
				listnode_delete(FuzzingCircuit->area->adjacency_list,
						adj);
				isis_delete_adj(adj);
			}
		}

		/* Clean up LSP databases before SPF trees and TX queues
		 * Note: lsp_destroy() calls isis_spf_schedule() which needs
		 * SPF trees to still exist, and also tries to remove LSPs from
		 * TX queues, so we must clean LSPs first.
		 */
		lsp_db_fini(&FuzzingCircuit->area->lspdb[0]);
		lsp_db_fini(&FuzzingCircuit->area->lspdb[1]);

		/* Clean up TX queues after LSP databases, as lsp_destroy()
		 * may have already removed entries from them
		 */
		struct listnode *cnode;
		struct isis_circuit *circuit;
		for (ALL_LIST_ELEMENTS_RO(FuzzingCircuit->area->circuit_list, cnode, circuit)) {
			if (circuit->tx_queue) {
				isis_tx_queue_clean(circuit->tx_queue);
			}
		}

		/* Clean up SPF trees after LSP databases */
		spftree_area_del(FuzzingCircuit->area);

		/* Re-initialize LSP databases */
		lsp_db_init(&FuzzingCircuit->area->lspdb[0]);
		lsp_db_init(&FuzzingCircuit->area->lspdb[1]);

		/* Re-initialize SPF trees */
		spftree_area_init(FuzzingCircuit->area);
	}

	return 0;
}
#endif /* FUZZING */

#ifndef FUZZING_LIBFUZZER
/*
 * Main routine of isisd. Parse arguments and handle IS-IS state machine.
 */
int main(int argc, char **argv, char **envp)
{
	int opt;
	int instance = 1;

#ifdef FABRICD
	frr_preinit(&fabricd_di, argc, argv);
#else
	frr_preinit(&isisd_di, argc, argv);
#endif

#ifdef FUZZING
	FuzzingInit();
	FuzzingCircuit = FuzzingCreateCircuit();
	FuzzingInitialized = true;

#ifdef __AFL_HAVE_MANUAL_CONTROL
	__AFL_INIT();
#endif /* __AFL_HAVE_MANUAL_CONTROL */

	uint8_t *input = NULL;
	int r = frrfuzz_read_input(&input);

	if (r < 0 || !input)
		return 0;

	LLVMFuzzerTestOneInput(input, r);

	free(input);
	return 0;
#endif /* FUZZING */

	frr_opt_add(
		"I:", longopts,
		"  -I, --int_num      Set instance number (label-manager)\n");

	/* Command line argument treatment. */
	while (1) {
		opt = frr_getopt(argc, argv, NULL);

		if (opt == EOF)
			break;

		switch (opt) {
		case 0:
			break;
		case 'I':
			instance = atoi(optarg);
			if (instance < 1 || instance > (unsigned short)-1)
				zlog_err("Instance %i out of range (1..%u)",
					 instance, (unsigned short)-1);
			break;
		default:
			frr_help_exit(1);
		}
	}

	/* thread master */
	isis_master_init(frr_init());
	master = im->master;
	/*
	 *  initializations
	 */
	cmd_init_config_callbacks(isis_config_start, isis_config_end);
	isis_error_init();
	access_list_init();
	access_list_add_hook(isis_filter_update);
	access_list_delete_hook(isis_filter_update);
	isis_vrf_init();
	prefix_list_init();
	prefix_list_add_hook(isis_prefix_list_update);
	prefix_list_delete_hook(isis_prefix_list_update);
	isis_init();
	isis_circuit_init();
#ifdef FABRICD
	isis_vty_daemon_init();
#endif /* FABRICD */
#ifndef FABRICD
	isis_cli_init();
#endif /* ifndef FABRICD */
	isis_spf_init();
	isis_redist_init();
	isis_route_map_init();
	isis_mpls_te_init();
	isis_sr_init();
	lsp_init();
	mt_init();

#ifndef FABRICD
	isis_affinity_map_init();
#endif /* ifndef FABRICD */

	isis_zebra_init(master, instance);
	isis_bfd_init(master);
	isis_ldp_sync_init();
	fabricd_init();

	frr_config_fork();
	frr_run(master);

	/* Not reached. */
	exit(0);
}
#endif /* FUZZING_LIBFUZZER */
