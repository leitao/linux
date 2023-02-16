#ifndef IOU_ALLOC_CACHE_H
#define IOU_ALLOC_CACHE_H

/*
 * Don't allow the cache to grow beyond this size.
 */
#define IO_ALLOC_CACHE_MAX	512

struct io_cache_entry {
	struct io_wq_work_node node;
};

static inline bool io_alloc_cache_put(struct io_alloc_cache *cache,
				      struct io_cache_entry *entry)
{
	if (cache->nr_cached < IO_ALLOC_CACHE_MAX) {
		cache->nr_cached++;
		wq_stack_add_head(&entry->node, &cache->list);
		return true;
	}
	return false;
}

static inline struct io_cache_entry *io_alloc_cache_get(struct io_alloc_cache *cache)
{
	struct io_wq_work_node *node;

	if (cache->list.next) {
		node = cache->list.next;
		cache->list.next = node->next;

		return container_of(node, struct io_cache_entry, node);
	}

	return NULL;
}

static inline void io_alloc_cache_init(struct io_alloc_cache *cache)
{
	cache->list.next = NULL;
	cache->nr_cached = 0;
}

static inline void io_alloc_cache_free(struct io_alloc_cache *cache,
					void (*free)(struct io_cache_entry *))
{
	struct io_wq_work_node *node;

	while (cache->list.next) {
		node = cache->list.next;

		cache->list.next = node->next;
		free(container_of(node, struct io_cache_entry, node));
	}

	cache->nr_cached = 0;
}
#endif
