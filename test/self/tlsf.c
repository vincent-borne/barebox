// SPDX-License-Identifier: GPL-2.0-only

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <common.h>
#include <bselftest.h>
#include <malloc.h>
#include <tlsf.h>
#include <linux/kasan.h>
#include <linux/log2.h>
#include <linux/sizes.h>

BSELFTEST_GLOBALS();

enum store_mode {
	STORE_EXACT,
	STORE_POWER_OF_TWO,
	STORE_FAIL,
	STORE_NONE,
};

static struct {
	void *pool;
	size_t pool_size;
	unsigned int requests;
	bool added;
	enum store_mode mode;
} store;

static void request_store(tlsf_t tlsf, size_t bytes)
{
	store.requests++;
	if (store.pool || store.mode == STORE_FAIL)
		return;

	store.pool_size = store.mode == STORE_POWER_OF_TWO ?
		roundup_pow_of_two(bytes) : bytes;
	store.pool = malloc(store.pool_size);
	if (!store.pool)
		return;

	store.added = tlsf_add_pool(tlsf, store.pool, store.pool_size) != NULL;
}

static void test_growth_case(size_t size, size_t alignment, enum store_mode mode,
			     bool expect_success, unsigned int expected_requests)
{
	void *control, *initial_pool, *ptr;
	tlsf_t tlsf;

	memset(&store, 0, sizeof(store));
	store.mode = mode;
	control = malloc(tlsf_size());
	initial_pool = malloc(SZ_4K);
	if (!assert_cond((control && initial_pool)))
		goto out;

	tlsf = tlsf_create(control);
	if (!assert_cond(tlsf != NULL))
		goto out;
	if (!assert_cond(tlsf_add_pool(tlsf, initial_pool, SZ_4K) != NULL))
		goto out;

	if (mode != STORE_NONE)
		tlsf_register_store(tlsf, request_store);
	if (alignment)
		ptr = tlsf_memalign(tlsf, alignment, size);
	else
		ptr = tlsf_malloc(tlsf, size);

	assert_inteq(store.requests, expected_requests);
	assert_inteq(store.added, (expected_requests && mode != STORE_FAIL));
	if (!assert_cond((ptr != NULL) == expect_success)) {
		pr_err("unexpected result for size %zu, alignment %zu, store mode %u\n",
		       size, alignment, mode);
	}
	if (ptr) {
		if (alignment)
			assert_inteq((uintptr_t)ptr % alignment, 0);
		memset(ptr, 0xa5, size);
		tlsf_free(tlsf, ptr);
	}
	assert_inteq(tlsf_check(tlsf), 0);
	assert_inteq(tlsf_check_pool(initial_pool), 0);
	if (store.added) {
		assert_inteq(tlsf_check_pool(store.pool), 0);
		tlsf_remove_pool(tlsf, store.pool);
	}
	tlsf_remove_pool(tlsf, initial_pool);

out:
	/* The nested allocator poisons these buffers, including its metadata. */
	if (store.pool)
		kasan_unpoison_shadow(store.pool, store.pool_size);
	if (initial_pool)
		kasan_unpoison_shadow(initial_pool, SZ_4K);
	free(store.pool);
	free(initial_pool);
	free(control);
}

static void test_tlsf_growth(void)
{
	enum store_mode mode;

	for (mode = STORE_EXACT; mode <= STORE_POWER_OF_TWO; mode++) {
		/* The initial pool suffices; no growth should be requested. */
		test_growth_case(SZ_128, 0, mode, true, 0);

		/* Exercise an intermediate class, not just powers of two. */
		test_growth_case(SZ_4K + SZ_8, 0, mode, true, 1);

		/* A request exactly on a size-class boundary already succeeds. */
		test_growth_case(SZ_64K - SZ_1K, 0, mode, true, 1);

		/*
		 * These requests fit in a 64 KiB pool after overhead, but their
		 * lookup starts at the 64 KiB class. The growth request must account
		 * for that rounding or the newly added pool will be skipped.
		 */
		test_growth_case(SZ_64K - SZ_512, 0, mode, true, 1);
		test_growth_case(SZ_64K - SZ_512, 64, mode, true, 1);

		/* Pool overhead pushes a power-of-two request into a larger pool. */
		test_growth_case(SZ_64K, 0, mode, true, 1);
	}

	/* An unsuccessful callback must not be retried indefinitely. */
	test_growth_case(SZ_64K - SZ_512, 0, STORE_FAIL, false, 1);
	test_growth_case(SZ_64K - SZ_512, 0, STORE_NONE, false, 0);

	/* Rounding beyond the last searchable class must not request a pool. */
	test_growth_case(tlsf_block_size_max() - tlsf_align_size(), 0,
			 STORE_FAIL, false, 0);
}
bselftest(core, test_tlsf_growth);
