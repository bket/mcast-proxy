/*	$OpenBSD:$	*/

/*
 * Copyright (c) 2017 Rafael Zalamena <rzalamena@openbsd.org>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <arpa/inet.h>

#include <sys/socket.h>
#include <sys/time.h>
#include <sys/tree.h>

#include <netinet/in.h>

#include <event.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "mcast-proxy.h"

enum mr_state {
	MS_NOTJOINED,
	MS_JOINED,
};

struct multicast_route {
	RB_ENTRY(multicast_route)	 mr_entry;

	enum mr_state			 mr_state;
	enum mr_version			 mr_version;
	int				 mr_af;
	union uaddr			 mr_group;
	struct event			 mr_timer;
	/* Version timer. */
	struct event			 mr_vtimer;
	/* Lowest version recorded during the version timer. */
	enum mr_version			 mr_lowestversion;
	struct intf_data		*mr_upstream;

	/* Origin tree. */
	struct motree			 mr_motree;
};
RB_HEAD(mrtree, multicast_route) mrtree = RB_INITIALIZER(&mrtree);

void mrt_addorigin(struct multicast_route *, struct intf_data *, union uaddr *);
void _mrt_delorigin(struct multicast_route *, struct multicast_origin *);
void mrt_delorigin(struct multicast_route *, union uaddr *);

void mrt_timeradd(struct event *);
void mrt_timer(int, short, void *);
void mrt_vtimeradd(struct multicast_route *);
void mrt_vtimer(int, short, void *);
struct multicast_route *mrt_new(void);
void mrt_free(struct multicast_route *);
struct multicast_route *mrt_find4(struct in_addr *);
struct multicast_route *mrt_find6(struct in6_addr *);
int mrcmp(struct multicast_route *, struct multicast_route *);
RB_PROTOTYPE(mrtree, multicast_route, mr_entry, mrcmp);
void mrt_nextstate(struct multicast_route *);

void
mrt_addorigin(struct multicast_route *mr, struct intf_data *id,
    union uaddr *addr)
{
	struct multicast_origin	*mo, *mon;

	mo = calloc(1, sizeof(*mo));
	if (mo == NULL) {
		log_warn("%s: calloc", __func__);
		return;
	}

	mo->mo_alive = 1;
	mo->mo_id = id;
	mo->mo_af = mr->mr_af;
	mo->mo_addr = *addr;

	mon = RB_INSERT(motree, &mr->mr_motree, mo);
	if (mon != NULL) {
		free(mo);
		mo = mon;

		/* Update the kernel routes in case they have expired. */
		if (mr->mr_upstream != NULL) {
			if (mo->mo_af == AF_INET)
				mcast_addroute(mr->mr_upstream->id_vindex,
				    addr, &mr->mr_group, &mr->mr_motree);
			else
				mcast_addroute6(mr->mr_upstream->id_vindex6,
				    addr, &mr->mr_group, &mr->mr_motree);
		}
		mo->mo_alive = 1;
		return;
	}

	if (id == upstreamif || mr->mr_upstream) {
		if (mr->mr_upstream == NULL)
			mr->mr_upstream = upstreamif;

		if (mo->mo_af == AF_INET)
			mcast_addroute(mr->mr_upstream->id_vindex, addr,
			    &mr->mr_group, &mr->mr_motree);
		else
			mcast_addroute6(mr->mr_upstream->id_vindex6, addr,
			    &mr->mr_group, &mr->mr_motree);
	}

	/* Do not keep upstream as node in the origin tree. */
	if (id == upstreamif) {
		RB_REMOVE(motree, &mr->mr_motree, mo);
		free(mo);
	}
}

void
_mrt_delorigin(struct multicast_route *mr, struct multicast_origin *mo)
{
	RB_REMOVE(motree, &mr->mr_motree, mo);

	if (mr->mr_upstream != NULL) {
		/*
		 * If this was the last node in the origin tree we can
		 * uninstall the whole group, otherwise update the
		 * installed routes with the current origins.
		 */
		if (RB_EMPTY(&mr->mr_motree)) {
			if (mo->mo_af == AF_INET)
				mcast_delroute(mr->mr_upstream->id_vindex,
				    &mo->mo_addr, &mr->mr_group);
			else
				mcast_delroute6(mr->mr_upstream->id_vindex6,
				    &mo->mo_addr, &mr->mr_group);
		} else {
			if (mo->mo_af == AF_INET)
				mcast_addroute(mr->mr_upstream->id_vindex,
				    &mo->mo_addr, &mr->mr_group,
				    &mr->mr_motree);
			else
				mcast_addroute6(mr->mr_upstream->id_vindex6,
				    &mo->mo_addr, &mr->mr_group,
				    &mr->mr_motree);
		}
	}

	free(mo);
}

void
mrt_delorigin(struct multicast_route *mr, union uaddr *addr)
{
	struct multicast_origin	*mo;
	struct multicast_origin	 key;

	memset(&key, 0, sizeof(key));
	key.mo_af = mr->mr_af;
	key.mo_addr = *addr;
	mo = RB_FIND(motree, &mr->mr_motree, &key);

	if (mo == NULL)
		return;

	_mrt_delorigin(mr, mo);
}

void
mrt_timeradd(struct event *ev)
{
	struct timeval	 tv = { IGMP_GROUP_MEMBERSHIP_INTERVAL, 0 };

	if (evtimer_pending(ev, &tv))
		evtimer_del(ev);

	evtimer_add(ev, &tv);
}

void
mrt_querytimeradd(void)
{
	struct multicast_route	*mr;

	/* Activate all group expire timers. */
	RB_FOREACH(mr, mrtree, &mrtree)
		mrt_timeradd(&mr->mr_timer);
}

void
mrt_vtimeradd(struct multicast_route *mr)
{
	mrt_timeradd(&mr->mr_vtimer);
}

void
mrt_timer(__unused int sd, __unused short ev, void *arg)
{
	struct multicast_route	*mr = arg;
	struct multicast_origin	*mo, *mon;

	if (mr->mr_af == AF_INET)
		log_debug("%s: group %s timer expired",
		    __func__, addr4tostr(&mr->mr_group.v4));
	else
		log_debug("%s: group %s timer expired",
		    __func__, addr6tostr(&mr->mr_group.v6));

	/* Remove origins that did not respond. */
	RB_FOREACH_SAFE(mo, motree, &mr->mr_motree, mon) {
		if (mo->mo_alive) {
			/* Mark as dead until next update. */
			mo->mo_alive = 0;
			continue;
		}

		_mrt_delorigin(mr, mo);
	}

	mrt_nextstate(mr);

	/* Remove the group if there is no more origins. */
	if (RB_EMPTY(&mr->mr_motree))
		mrt_free(mr);
}

void
mrt_vtimer(__unused int sd, __unused short ev, void *arg)
{
	struct multicast_route	*mr = arg;

	if (mr->mr_af == AF_INET)
		log_debug("%s: group %s version timer expired",
		    __func__, addr4tostr(&mr->mr_group.v4));
	else
		log_debug("%s: group %s version timer expired",
		    __func__, addr6tostr(&mr->mr_group.v6));

	mrt_vtimeradd(mr);

	/*
	 * Apply the RFC 2236 section 5 and RFC 4541 section 2.1.1 sub
	 * item 1: the IGMPv2 is the most compatible version of the
	 * protocol.
	 *
	 * This is the default fallback version.
	 */
	if (mr->mr_version == MV_IGMPV2)
		return;

	/*
	 * If we are on a 'special' version, reset the lowest value and
	 * expect another report with a version different than v2. If no
	 * new reports with different version comes in, assume that
	 * there are no more to enter a compatibility mode.
	 */
	mr->mr_version = mr->mr_lowestversion;
	mr->mr_lowestversion = MV_IGMPV2;
}

struct multicast_route *
mrt_new(void)
{
	struct multicast_route	*mr;

	mr = calloc(1, sizeof(*mr));
	if (mr == NULL) {
		log_warn("%s: calloc", __func__);
		return NULL;
	}

	mr->mr_state = MS_NOTJOINED;
	mr->mr_version = MV_IGMPV3;
	mr->mr_lowestversion = MV_IGMPV3;
	RB_INIT(&mr->mr_motree);

	evtimer_set(&mr->mr_timer, mrt_timer, mr);
	evtimer_set(&mr->mr_vtimer, mrt_vtimer, mr);
	mrt_timeradd(&mr->mr_timer);
	mrt_timeradd(&mr->mr_vtimer);

	return mr;
}

void
mrt_free(struct multicast_route *mr)
{
	struct multicast_origin	*mo, *mon;
	struct timeval		 tv;
	struct sockaddr_storage	 ss;

	if (evtimer_pending(&mr->mr_timer, &tv))
		evtimer_del(&mr->mr_timer);

	if (evtimer_pending(&mr->mr_vtimer, &tv))
		evtimer_del(&mr->mr_vtimer);

	RB_FOREACH_SAFE(mo, motree, &mr->mr_motree, mon)
		_mrt_delorigin(mr, mo);

	ss.ss_family = mr->mr_af;
	if (ss.ss_family == AF_INET)
		sstosin(&ss)->sin_addr = mr->mr_group.v4;
	else
		sstosin6(&ss)->sin6_addr = mr->mr_group.v6;

	log_debug("%s: remove group %s", __func__, addrtostr(&ss));

	RB_REMOVE(mrtree, &mrtree, mr);

	free(mr);
}

void
mrt_cleanup(void)
{
	struct multicast_route	*mr, *mrn;

	RB_FOREACH_SAFE(mr, mrtree, &mrtree, mrn)
		mrt_free(mr);
}

struct multicast_route *
mrt_find4(struct in_addr *in)
{
	struct multicast_route	 key;

	memset(&key, 0, sizeof(key));
	key.mr_af = AF_INET;
	key.mr_group.v4 = *in;
	return RB_FIND(mrtree, &mrtree, &key);
}

struct multicast_route *
mrt_insert4(enum mr_version mv, struct intf_data *id,
    struct in_addr *origin, struct in_addr *group)
{
	struct multicast_route	*mr, *mrn;
	union uaddr		 uorigin;

	/* Sanity check: only use multicast groups. */
	if (!IN_MULTICAST(ntohl(group->s_addr))) {
		log_debug("%s(%s, %s): not multicast group",
		    __func__, id->id_name, addr4tostr(group));
		return NULL;
	}

	/* Try to find it, if it exists just add the new origin. */
	mr = mrt_find4(group);
	if (mr != NULL)
		goto add_origin;

	/* Otherwise create one and insert. */
	mr = mrt_new();
	if (mr == NULL)
		return NULL;

	mr->mr_af = AF_INET;
	mr->mr_group.v4 = *group;
	mrn = RB_INSERT(mrtree, &mrtree, mr);
	if (mrn != NULL) {
		mrt_free(mr);
		mr = mrn;
	}

 add_origin:
	/*
	 * Always use the lowest version immediately, otherwise wait the
	 * query timeout before switching. See mrt_vtimer() for more
	 * details.
	 */
	if (mr->mr_version > mv)
		mr->mr_version = mv;
	if (mr->mr_lowestversion > mv)
		mr->mr_lowestversion = mv;

	uorigin.v4 = *origin;
	mrt_addorigin(mr, id, &uorigin);

	mrt_nextstate(mr);

	return mr;
}

void
mrt_remove4(struct in_addr *origin, struct in_addr *group)
{
	struct multicast_route	*mr;
	union uaddr		 uorigin;

	mr = mrt_find4(group);
	if (mr == NULL)
		return;

	/* IGMPv1 compatibility mode does not accept fast-leave. */
	if (mr->mr_version == MV_IGMPV1)
		return;

	uorigin.v4 = *origin;
	mrt_delorigin(mr, &uorigin);
	mrt_nextstate(mr);
	if (RB_EMPTY(&mr->mr_motree))
		mrt_free(mr);
}

struct multicast_route *
mrt_find6(struct in6_addr *in6)
{
	struct multicast_route	 key;

	memset(&key, 0, sizeof(key));
	key.mr_af = AF_INET6;
	key.mr_group.v6 = *in6;
	return RB_FIND(mrtree, &mrtree, &key);
}

struct multicast_route *
mrt_insert6(enum mr_version mv, struct intf_data *id,
    struct in6_addr *origin, struct in6_addr *group)
{
	struct multicast_route	*mr, *mrn;
	union uaddr		 uorigin;

	/* Sanity check: only use multicast groups. */
	if (!IN6_IS_ADDR_MULTICAST(group)) {
		log_debug("%s(%s, %s): not multicast group",
		    __func__, id->id_name, addr6tostr(group));
		return NULL;
	}

	/* Try to find it, if it exists just add the new origin. */
	mr = mrt_find6(group);
	if (mr != NULL)
		goto add_origin;

	/* Otherwise create one and insert. */
	mr = mrt_new();
	if (mr == NULL)
		return NULL;

	mr->mr_af = AF_INET6;
	mr->mr_group.v6 = *group;
	mrn = RB_INSERT(mrtree, &mrtree, mr);
	if (mrn != NULL) {
		mrt_free(mr);
		mr = mrn;
	}

 add_origin:
	/*
	 * Always use the lowest version immediately, otherwise wait the
	 * query timeout before switching. See mrt_vtimer() for more
	 * details.
	 */
	if (mr->mr_version > mv)
		mr->mr_version = mv;
	if (mr->mr_lowestversion > mv)
		mr->mr_lowestversion = mv;

	uorigin.v6 = *origin;
	mrt_addorigin(mr, id, &uorigin);

	mrt_nextstate(mr);

	return mr;
}

void
mrt_remove6(struct in6_addr *origin, struct in6_addr *group)
{
	struct multicast_route	*mr;
	union uaddr		 uorigin;

	mr = mrt_find6(group);
	if (mr == NULL)
		return;

	uorigin.v6 = *origin;
	mrt_delorigin(mr, &uorigin);
	mrt_nextstate(mr);
	if (RB_EMPTY(&mr->mr_motree))
		mrt_free(mr);
}

void
mrt_nextstate(struct multicast_route *mr)
{
	struct sockaddr_storage		ss;

	if (upstreamif == NULL) {
		log_debug("%s: no upstream interface", __func__);
		return;
	}

	ss.ss_family = mr->mr_af;
	switch (ss.ss_family) {
	case AF_INET:
		sstosin(&ss)->sin_addr = mr->mr_group.v4;
		break;
	case AF_INET6:
		sstosin6(&ss)->sin6_addr = mr->mr_group.v6;
		break;
	default:
		fatalx("%s: unknown family %d",
		    __func__, ss.ss_family);
	}

	switch (mr->mr_state) {
	case MS_NOTJOINED:
		/* Don't join if there is no interest. */
		if (RB_EMPTY(&mr->mr_motree))
			return;

		mcast_join(upstreamif, &ss);
		mr->mr_state = MS_JOINED;
		break;

	case MS_JOINED:
		/* Don't leave if there is still peers. */
		if (!RB_EMPTY(&mr->mr_motree))
			return;

		mcast_leave(upstreamif, &ss);
		mr->mr_state = MS_NOTJOINED;
		break;

	default:
		log_debug("%s: invalid state %d",
		    __func__, mr->mr_state);
		break;
	}
}

RB_GENERATE(mrtree, multicast_route, mr_entry, mrcmp);

int
mrcmp(struct multicast_route *mr1, struct multicast_route *mr2)
{
	size_t			 addrsize;

	if (mr1->mr_af > mr2->mr_af)
		return 1;
	else if (mr1->mr_af < mr2->mr_af)
		return -1;

	addrsize = (mr1->mr_af == AF_INET) ?
	    sizeof(mr1->mr_group.v4) : sizeof(mr1->mr_group.v6);

	return memcmp(&mr1->mr_group, &mr2->mr_group, addrsize);
}

RB_GENERATE(motree, multicast_origin, mo_entry, mocmp);

int
mocmp(struct multicast_origin *mo1, struct multicast_origin *mo2)
{
	size_t			 addrsize;

	if (mo1->mo_af > mo2->mo_af)
		return 1;
	else if (mo1->mo_af < mo2->mo_af)
		return -1;

	addrsize = (mo1->mo_af == AF_INET) ?
	    sizeof(mo1->mo_addr.v4) : sizeof(mo1->mo_addr.v6);

	return memcmp(&mo1->mo_addr, &mo2->mo_addr, addrsize);
}
