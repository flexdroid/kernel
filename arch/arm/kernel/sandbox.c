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

asmlinkage void sys_set_sandbox(unsigned long addr)
{
    unsigned long pfn;
    // pte_t *pte;
    pgd_t *pgd;
    pud_t *pud;
    pmd_t *pmd;

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

    if (addr % SECTION_SIZE) {
        printk("[sys_set_sandbox] fail. addr(0x%lx) is not SECTION_SIZE aligned\n", addr);
        return;
    }

	pgd = pgd_offset(current->mm, addr);
	pud = pud_offset(pgd, addr);
    pmd = pmd_offset(pud, addr);
	if (addr & SECTION_SIZE)
        pmd++;

    pfn = page_to_pfn(alloc_pages(GFP_USER, 8));
    printk("[sys_set_sandbox] 0x%lx\n", pfn);
    // pte = pte_alloc_map(current->mm, NULL, pmd, addr);
    // pte = (pte_t*)alloc_pages_exact(SZ_1K, GFP_USER);
    // printk("[sys_set_sandbox] %p\n", pte);

    // section offset | user r/w permission | domain number | section c & b
    *pmd = (pfn << 12) | (12 << 8) | (1 << 5) | (14);
    // *pmd = ((pmd_t)pte & 0xfffffc00) | (1 << 5) | 1;
	printk("[0x%lx] *pgd=%08llx", addr, (long long)pmd_val(*pmd));

    /*
    pfn = page_to_pfn(alloc_pages(GFP_USER, 0));
    *pte = (pfn << 12) | 0xffe;
    printk(", *pte=%08llx", (long long)pte_val(*pte));
    */
	printk("\n");
}

asmlinkage void sys_show_pmd(unsigned long addr)
{
    pgd_t *pgd;
    pud_t *pud;
    pmd_t *pmd;

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
}

#define DOM_MAX 16
#define ENTRY_EXIT_GAP 20

static unsigned int domain_entry_pc[DOM_MAX] = {0};

static void set_domain_client(unsigned int domain, unsigned int type)
{
    do {
        struct thread_info *thread = current_thread_info();
        unsigned int dom_ = thread->cpu_domain;
        dom_ &= ~domain_val(domain, DOMAIN_MANAGER);
        printk("[sandbox] dom_=0x%x\n", dom_);
        thread->cpu_domain = dom_ | domain_val(domain, type);
        do {
            __asm__ __volatile__(
                    "mcr	p15, 0, %0, c3, c0	@ set domain"
                    : : "r" (thread->cpu_domain));
            isb();
        } while (0);
    } while (0);
}

asmlinkage unsigned int sys_enter_sandbox(unsigned long addr)
{
    unsigned long dacr = 0;
    unsigned int pc = (unsigned int)((int*)&dacr)[28];
    pgd_t *pgd;
    pud_t *pud;
    pmd_t *pmd;
    unsigned int sandbox_domain = 3;

    for (sandbox_domain = 3; sandbox_domain < DOM_MAX; ++sandbox_domain) {
        if (!domain_entry_pc[sandbox_domain])
            break;
    }
    domain_entry_pc[sandbox_domain] = pc;

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
#ifdef CONFIG_CPU_USE_DOMAINS
    printk("[sandbox] CONFIG_CPU_USE_DOMAINS is turned on\n");
#else
    printk("[sandbox] CONFIG_CPU_USE_DOMAINS is turned off\n");
#endif
    /*
    __asm__ __volatile__(
            "mcr p15, 0, %[input], c3, c0, 0\n"
            : : [input] "r" (dacr) );
            */

    /* Read from DACR */
    __asm__ __volatile__(
            "mrc p15, 0, %[result], c3, c0, 0\n"
            : [result] "=r" (dacr) : );
	printk("[0x%lx] dacr=0x%lx\n", addr, dacr);

    return sandbox_domain;
}

asmlinkage void sys_exit_sandbox(unsigned long addr, unsigned int domain)
{
    unsigned long dacr = 0;
    unsigned int pc = (unsigned int)((int*)&dacr)[28];
    pgd_t *pgd;
    pud_t *pud;
    pmd_t *pmd;

    printk("pid = %d, tid = %d\n", task_tgid_vnr(current), task_pid_vnr(current));
    printk("gap = %u (0x%x - 0x%x)\n", pc - domain_entry_pc[domain], pc, domain_entry_pc[domain]);
    domain_entry_pc[domain] = 0;

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
    set_domain_client(domain, DOMAIN_NOACCESS);
#ifdef CONFIG_CPU_USE_DOMAINS
    printk("[sandbox] CONFIG_CPU_USE_DOMAINS is turned on\n");
#else
    printk("[sandbox] CONFIG_CPU_USE_DOMAINS is turned off\n");
#endif
    /*
    __asm__ __volatile__(
            "mcr p15, 0, %[input], c3, c0, 0\n"
            : : [input] "r" (dacr) );
            */

    /* Read from DACR */
    __asm__ __volatile__(
            "mrc p15, 0, %[result], c3, c0, 0\n"
            : [result] "=r" (dacr) : );
	printk("[0x%lx] dacr=0x%lx\n", addr, dacr);
}
