/*
 *  linux/arch/arm/kernel/signal.c
 *
 *  Copyright (C) 1995-2009 Russell King
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/gfp.h>
#include <linux/mm.h>

#include <asm/elf.h>
#include <asm/unistd.h>

#include <asm/domain.h>
#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm/bug.h>

static struct pt_regs init_regs;
asmlinkage unsigned long sys_jump_in(unsigned long addr, struct pt_regs *regs)
{
    printk("[jump] addr=0x%08lx, pc=0x%08x\n", addr, ((unsigned int*)regs)[15]);
    memcpy(&init_regs, regs, sizeof(struct pt_regs));
    // ((unsigned long*)regs)[0] = 1107;
    ((unsigned long*)regs)[15] = addr;
    return 1107;
}

asmlinkage void sys_jump_out(struct pt_regs *regs)
{
    printk("[jump out] pc=0x%08x\n", ((unsigned int*)regs)[15]);
    memcpy(regs, &init_regs, sizeof(struct pt_regs));
    printk("[jump out] pc=0x%08x\n", ((unsigned int*)regs)[15]);
}

#define DOM_MAX 16
#define ENTRY_EXIT_GAP 20

struct domain_info {
    pid_t tid;
    unsigned long addr;
    struct pt_regs regs;
};

static struct domain_info di[DOM_MAX] = {{0}};

static void set_domain_client(unsigned int domain, unsigned int type)
{
    do {
        struct thread_info *thread = current_thread_info();
        unsigned int dom_ = thread->cpu_domain;
        dom_ &= ~domain_val(domain, DOMAIN_MANAGER);
        thread->cpu_domain = dom_ | domain_val(domain, type);
        do {
            __asm__ __volatile__(
                    "mcr	p15, 0, %0, c3, c0	@ set domain"
                    : : "r" (thread->cpu_domain));
            isb();
        } while (0);
    } while (0);
}

asmlinkage unsigned long sys_enter_sandbox(unsigned long addr, struct pt_regs *regs)
{
    unsigned long dacr = 0;
    pgd_t *pgd;
    pud_t *pud;
    pmd_t *pmd;
    unsigned int sandbox_domain = 3;

    for (sandbox_domain = 3; sandbox_domain < DOM_MAX; ++sandbox_domain) {
        if (!di[sandbox_domain].tid)
            break;
    }
    di[sandbox_domain].tid = task_pid_vnr(current);
    di[sandbox_domain].addr = addr;

    /* backup register and set jump_to_jni as callee */
    memcpy(&di[sandbox_domain].regs, regs, sizeof(struct pt_regs));
    ((unsigned long*)regs)[15] = addr + 15*(1<<12) + (1<<11) + 1;

    printk("pid = %d, tid = %d\n", task_tgid_vnr(current), task_pid_vnr(current));

	pgd = pgd_offset(current->mm, addr-SECTION_SIZE);
	pud = pud_offset(pgd, addr-SECTION_SIZE);
	pmd = pmd_offset(pud, addr-SECTION_SIZE);
	if ((addr-SECTION_SIZE) & SECTION_SIZE)
        pmd++;
	printk("[0x%lx] *pgd=%08llx\n", addr-SECTION_SIZE, (long long)pmd_val(*pmd));

	pgd = pgd_offset(current->mm, addr);
	pud = pud_offset(pgd, addr);
	pmd = pmd_offset(pud, addr);
	if (addr & SECTION_SIZE)
        pmd++;
	printk("[0x%lx] *pgd=%08llx\n", addr, (long long)pmd_val(*pmd));

    /* Update domain */
    *pmd = (*pmd & 0xffffff1f) | (sandbox_domain << 5);
	printk("[0x%lx] *pgd=%08llx\n", addr, (long long)pmd_val(*pmd));

    /* Read from DACR */
    __asm__ __volatile__(
            "mrc p15, 0, %[result], c3, c0, 0\n"
            : [result] "=r" (dacr) : );
	printk("[0x%lx] dacr=0x%lx\n", addr, dacr);

    // dacr = 3 << (2*sandbox_domain);
    /* Write to DACR */
    // modify_domain(sandbox_domain, DOMAIN_MANAGER);
    set_domain_client(sandbox_domain, DOMAIN_CLIENT);
    set_domain_client(DOMAIN_USER, DOMAIN_NOACCESS);
    return addr;
}

asmlinkage void sys_exit_sandbox(struct pt_regs *regs)
{
    unsigned long dacr = 0;
    pgd_t *pgd;
    pud_t *pud;
    pmd_t *pmd;
    unsigned long addr;
    unsigned int sandbox_domain = 3;

    printk("pid = %d, tid = %d\n", task_tgid_vnr(current), task_pid_vnr(current));
    for (sandbox_domain = 3; sandbox_domain < DOM_MAX; ++sandbox_domain) {
        if (di[sandbox_domain].tid == task_pid_vnr(current))
            break;
    }
    memcpy(regs, &di[sandbox_domain].regs, sizeof(struct pt_regs));
    di[sandbox_domain].tid = 0;
    addr = di[sandbox_domain].addr;

	pgd = pgd_offset(current->mm, addr-SECTION_SIZE);
	pud = pud_offset(pgd, addr-SECTION_SIZE);
	pmd = pmd_offset(pud, addr-SECTION_SIZE);
	if ((addr-SECTION_SIZE) & SECTION_SIZE)
        pmd++;
	printk("[0x%lx] *pgd=%08llx\n", addr-SECTION_SIZE, (long long)pmd_val(*pmd));

	pgd = pgd_offset(current->mm, addr);
	pud = pud_offset(pgd, addr);
	pmd = pmd_offset(pud, addr);
	if (addr & SECTION_SIZE)
        pmd++;
	printk("[0x%lx] *pgd=%08llx\n", addr, (long long)pmd_val(*pmd));

    /* Restore domain */
    *pmd = (*pmd & 0xffffff1f) | (1 << 5);
	printk("[0x%lx] *pgd=%08llx\n", addr, (long long)pmd_val(*pmd));

    /* Read from DACR */
    __asm__ __volatile__(
            "mrc p15, 0, %[result], c3, c0, 0\n"
            : [result] "=r" (dacr) : );
	printk("[0x%lx] dacr=0x%lx\n", addr, dacr);

    /* Write to DACR */
    set_domain_client(DOMAIN_USER, DOMAIN_CLIENT);
    set_domain_client(sandbox_domain, DOMAIN_NOACCESS);
}
