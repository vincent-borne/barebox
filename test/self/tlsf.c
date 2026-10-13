// SPDX-License-Identifier: GPL-2.0-only

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <common.h>
#include <bselftest.h>
#include <malloc.h>
#include <tlsf.h>
#include <linux/log2.h>
#include <linux/sizes.h>

BSELFTEST_GLOBALS();

static struct {
	void *pool;
	unsigned int requests;
	bool added;
} store;

static void request_store(tlsf_t tlsf, size_t bytes)
{
	size_t pool_size = roundup_pow_of_two(bytes);

	store.requests++;
	if (store.pool)
		return;

	store.pool = malloc(pool_size);
	if (!store.pool)
		return;

	store.added = tlsf_add_pool(tlsf, store.pool, pool_size) != NULL;
}

static void test_growth_case(size_t size, size_t alignment)
{
	void *control, *initial_pool, *ptr;
	tlsf_t tlsf;

	memset(&store, 0, sizeof(store));
	control = malloc(tlsf_size());
	initial_pool = malloc(SZ_4K);
	if (!assert_cond(control && initial_pool))
		goto out;

	tlsf = tlsf_create(control);
	if (!assert_cond(tlsf != NULL))
		goto out;
	if (!assert_cond(tlsf_add_pool(tlsf, initial_pool, SZ_4K) != NULL))
		goto out;

	tlsf_register_store(tlsf, request_store);
	if (alignment)
	{
		ptr = tlsf_memalign(tlsf, alignment, size);
	}
	else
	{
		ptr = tlsf_malloc(tlsf, size);
	}

	assert_inteq(store.requests, 1);
	assert_cond(store.added);
	if (!assert_cond(ptr != NULL))
	{
		pr_err("allocation of %zu bytes with alignment %zu failed after growth\n",
		       size, alignment);
	}
	else 
	{
		if (alignment)
			assert_inteq((uintptr_t)ptr % alignment, 0);
		memset(ptr, 0xa5, size);
		tlsf_free(tlsf, ptr);
	}
	assert_inteq(tlsf_check(tlsf), 0);

out:
	free(store.pool);
	free(initial_pool);
	free(control);
}

static void test_tlsf_growth(void)
{
	/* A request exactly on a size-class boundary already succeeds. */
	test_growth_case(SZ_64K - SZ_1K, 0);

	/*
	 * These requests fit in a 64 KiB pool after overhead, but their
	 * lookup starts at the 64 KiB class. The growth request must account
	 * for that rounding or the newly added pool will be skipped.
	 */
	test_growth_case(SZ_64K - SZ_512, 0);
	test_growth_case(SZ_64K - SZ_512, 64);

	/* Pool overhead pushes an exact power-of-two request into 128 KiB. */
	test_growth_case(SZ_64K, 0);
}
bselftest(core, test_tlsf_growth);
