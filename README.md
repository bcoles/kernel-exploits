# Kernel Exploits

Various kernel exploits


## CVE-2019-13272

Linux local root exploit.

Updated version of Jann Horn's [exploit](https://bugs.chromium.org/p/project-zero/issues/detail?id=1903) for [CVE-2019-13272](https://nvd.nist.gov/vuln/detail/CVE-2019-13272).

> In the Linux kernel before 5.1.17, ptrace_link in kernel/ptrace.c mishandles the recording of the credentials of a process that wants to create a ptrace relationship, which allows local users to obtain root access by leveraging certain scenarios with a parent-child process relationship, where a parent drops privileges and calls execve (potentially allowing control by an attacker). One contributing factor is an object lifetime issue (which can also cause a panic). Another contributing factor is incorrect marking of a ptrace relationship as privileged, which is exploitable through (for example) Polkit's pkexec helper with PTRACE_TRACEME. NOTE: SELinux deny_ptrace might be a usable workaround in some environments.


## CVE-2018-18955

Linux local root exploit.

Wrapper for Jann Horn's [exploit](https://bugs.chromium.org/p/project-zero/issues/detail?id=1712) for [CVE-2018-18955](https://nvd.nist.gov/vuln/detail/CVE-2018-18955).

> In the Linux kernel 4.15.x through 4.19.x before 4.19.2, map_write() in kernel/user_namespace.c allows privilege escalation because it mishandles nested user namespaces with more than 5 UID or GID ranges. A user who has CAP_SYS_ADMIN in an affected user namespace can bypass access controls on resources outside the namespace, as demonstrated by reading /etc/shadow. This occurs because an ID transformation takes place properly for the namespaced-to-kernel direction but not for the kernel-to-namespaced direction.


## CVE-2018-5333

Linux local root exploit.

Updated version of wbowling's [exploit](https://gist.github.com/wbowling/9d32492bd96d9e7c3bf52e23a0ac30a4) for [CVE-2018-5333](https://nvd.nist.gov/vuln/detail/CVE-2018-5333).

> In the Linux kernel through 4.14.13, the rds_cmsg_atomic function in net/rds/rdma.c mishandles cases where page pinning fails or an invalid address is supplied, leading to an rds_atomic_free_op NULL pointer dereference.


## CVE-2017-1000112

Linux local root exploit.

Updated version of xairy's [exploit](https://github.com/xairy/kernel-exploits/tree/master/CVE-2017-1000112) for [CVE-2017-1000112](https://nvd.nist.gov/vuln/detail/CVE-2017-1000112).

> Linux kernel: Exploitable memory corruption due to UFO to non-UFO path switch. When building a UFO packet with MSG_MORE __ip_append_data() calls ip_ufo_append_data() to append. However in between two send() calls, the append path can be switched from UFO to non-UFO one, which leads to a memory corruption. In case UFO packet lengths exceeds MTU, copy = maxfraglen - skb->len becomes negative on the non-UFO path and the branch to allocate new skb is taken. This triggers fragmentation and computation of fraggap = skb_prev->len - maxfraglen. Fraggap can exceed MTU, causing copy = datalen - transhdrlen - fraggap to become negative. Subsequently skb_copy_and_csum_bits() writes out-of-bounds. A similar issue is present in IPv6 code. The bug was introduced in e89e9cf539a2 ("[IPv4/IPv6]: UFO Scatter-gather approach") on Oct 18 2005.


## CVE-2017-7308

Linux local root exploit.

Updated version of xairy's [exploit](https://github.com/xairy/kernel-exploits/tree/master/CVE-2017-7308) for [CVE-2017-7308](https://nvd.nist.gov/vuln/detail/CVE-2017-7308).

> The packet_set_ring function in net/packet/af_packet.c in the Linux kernel through 4.10.6 does not properly validate certain block-size data, which allows local users to cause a denial of service (integer signedness error and out-of-bounds write), or gain privileges (if the CAP_NET_RAW capability is held), via crafted system calls.


## CVE-2016-8655

Linux local root exploit.

Updated version of rebel's [exploit](https://packetstormsecurity.com/files/140063/Linux-Kernel-4.4.0-AF_PACKET-Race-Condition-Privilege-Escalation.html) for [CVE-2016-8655](https://nvd.nist.gov/vuln/detail/CVE-2016-8655).

> Race condition in net/packet/af_packet.c in the Linux kernel through 4.8.12 allows local users to gain privileges or cause a denial of service (use-after-free) by leveraging the CAP_NET_RAW capability to change a socket version, related to the packet_set_ring and packet_setsockopt functions.
