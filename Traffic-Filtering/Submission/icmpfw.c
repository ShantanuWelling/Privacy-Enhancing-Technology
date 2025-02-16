#include <sys/param.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <net/pfil.h>

static int dropped_icmp_count = 0;
static struct pfil_hook *icmp_pfil_hook;

static pfil_return_t icmp_filter(struct mbuf **mp, struct ifnet *ifp, int dir, void *arg, struct inpcb *inp) {
    struct mbuf *m = *mp;
    struct ip *ip_header;
    struct icmp *icmp_header;

    if (m == NULL) return PFIL_PASS;

    if (m->m_len < sizeof(struct ip)) {
        return PFIL_PASS;  // Ignore incomplete packets
    }

    ip_header = mtod(m, struct ip *);
    if (ip_header->ip_p == IPPROTO_ICMP) {
        if (m->m_len < (ip_header->ip_hl << 2) + sizeof(struct icmp)) {
            return PFIL_PASS;  // Ignore incomplete ICMP packets
        }

        icmp_header = (struct icmp *)((char *)ip_header + (ip_header->ip_hl << 2));
        if (icmp_header->icmp_type == ICMP_ECHO) {
            dropped_icmp_count++;
            printf("Dropped ICMP Echo Request: %d bytes\n", m->m_pkthdr.len);
            m_freem(m);
            return PFIL_DROPPED;  // Drop the packet
        }
    }
    return PFIL_PASS;
}

static int load_module(struct module *module, int event, void *arg) {
    struct pfil_hook_args pha;
    struct pfil_link_args pla;
    int err;

    switch (event) {
        case MOD_LOAD:
            pha.pa_version = PFIL_VERSION;
            pha.pa_flags = 0;
            pha.pa_type = PFIL_TYPE_IP4;
            pha.pa_mbuf_chk = icmp_filter;
            pha.pa_modname = "icmp_filter";
            pha.pa_rulname = "icmp_filter";
            icmp_pfil_hook = pfil_add_hook(&pha);
            if (!icmp_pfil_hook) {
                printf("Failed to register pfil hook\n");
                return ENOMEM;
            }

            pla.pa_version = PFIL_VERSION;
            pla.pa_flags = PFIL_IN | PFIL_HOOKPTR;  // Only filter inbound packets
            pla.pa_headname = "inet";
            pla.pa_hook = icmp_pfil_hook;

            err = pfil_link(&pla);
            if (err != 0) {
                printf("Failed to link pfil hook (error: %d)\n", err);
                pfil_remove_hook(icmp_pfil_hook);
                return err;
            }

            printf("ICMP Firewall Module Loaded\n");
            return 0;

        case MOD_UNLOAD:
            if (icmp_pfil_hook) {
                pfil_remove_hook(icmp_pfil_hook);
            }
            printf("ICMP Firewall Module Unloaded. Total ICMP Packets Dropped: %d\n", dropped_icmp_count);
            return 0;

        default:
            return EOPNOTSUPP;
    }
}

static moduledata_t icmp_filter_mod = {
    "icmp_filter",
    load_module,
    NULL
};

DECLARE_MODULE(icmp_filter, icmp_filter_mod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);