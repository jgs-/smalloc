#include <sys/param.h>
#include <sys/systm.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/resourcevar.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/proc.h>
#include <sys/malloc.h>
#include <sys/vnode.h>
#include <sys/conf.h>
#include <sys/stat.h>
#include <sys/queue.h>
#include <sys/pool.h>
#include <sys/smalloc.h>
#include <machine/exec.h>
#include <sys/syscallargs.h>
#include <uvm/uvm.h>
#include <uvm/uvm_device.h>
#include <uvm/uvm_vnode.h>

#define MALLOC_MAXSHIFT 4096 
#define MALLOC_MINSIZE	16
#define MALLOC_PAGEMASK (4096 - 1)
#define MALLOC_MINSIZE_S 64

#define CHUNK_MASK 0xfffffffffffff000;

#define PAGEROUND(x)  		(((x) + (MALLOC_PAGEMASK)) & ~MALLOC_PAGEMASK)
#define CHUNK_POS(c, p, s) 	(((c) - (p)) / (sz))

RB_GENERATE_STATIC(regions, region_info, entry, region_cmp);
RB_GENERATE_STATIC(freebies, region_info, frees, region_cmp);

int info_pool_init = 0;
struct pool info_pool;
struct pool page_pool;

void set_region(void **, size_t, void *);
struct region_info *get_region(struct proc *, size_t);
int size_cmp(void *, void *);

int
size_cmp(void *arg_a, void *arg_b)
{
	struct region_info *a = arg_a;
	struct region_info *b = arg_b;

	if (a->size < b->size)
		return (-1);
	else if (a->size == b->size)
		return 0;
	else
		return 1;
}

int
region_cmp(void *arg_a, void *arg_b)
{
	struct region_info *a = arg_a;
	struct region_info *b = arg_b;

	if (a->base < b->base)
		return (-1);
	else if (b->base <= a->base && a->base < (b->base + b->length))
		return 0;
	else
		return 1;
}

void *
smalloc_mmap(struct proc *p, size_t sz)
{
	int i, r;
	void *pre;
	vaddr_t hint = (vaddr_t)NULL;
	off_t pos = 0;

	if (sz <= PAGE_SIZE) {
		if (p->p_p->dp->cache == 0)
			smalloc_pages(p, SMALLOC_MAX_CACHE);

		for (i = 0; p->p_p->dp->cache && (i < SMALLOC_MAX_CACHE); i++) {
			if (p->p_p->dp->freepages[i] != NULL) {
				pre = p->p_p->dp->freepages[i];
				p->p_p->dp->freepages[i] = NULL;
				p->p_p->dp->cache--;
				return pre;
			}
		}
	}

	// hint = uvm_map_hint(p->p_vmspace, PROT_READ | PROT_WRITE);
	r = uvm_mmap(&p->p_vmspace->vm_map,
		     &hint,
		     sz,
		     PROT_READ | PROT_WRITE,
		     VM_PROT_ALL,
		     MAP_ANON | MAP_PRIVATE,
		     NULL,
		     pos,
		     p->p_rlimit[RLIMIT_MEMLOCK].rlim_cur,
		     p);
	if (r)
		return NULL;
	return (void *)hint;
}

size_t
round_sz(size_t x)
{
	x--;
	x |= x >> 1;
	x |= x >> 2;
	x |= x >> 4;
	x |= x >> 8;
	x |= x >> 16;
	x++;

	return x;
}

int
smalloc_init(struct proc *p)
{
	struct dir_info *d;

	d = malloc(sizeof(struct dir_info), M_SUBPROC, M_WAITOK);
	if (d == NULL)
		printf("sys_malloc: smalloc_init not enough memory\n");

	if (!info_pool_init) {
		pool_init(&info_pool, 
			  sizeof(struct region_info), 
			  0, 
		 	  0, 
		  	  PR_NOWAIT, 
		  	  NULL, 
		  	  NULL);
		pool_init(&page_pool, 
			  sizeof(struct page_info), 
			  0, 
		 	  0, 
		  	  PR_NOWAIT, 
		  	  NULL, 
		  	  NULL);
			  
		pool_prime(&info_pool, 1024);
		pool_prime(&page_pool, 1024);

		info_pool_init = 1;
	}

	RB_INIT(&d->region_head);
	RB_INIT(&d->free_head);
	d->cache = 0;
	p->p_p->dp = d;

	return 0;
}

void
smalloc_remap(struct proc *old, struct proc *new)
{
        struct region_info *rp, *np;

        RB_FOREACH(rp, freebies, &old->p_p->dp->free_head) {
                np = pool_get(&info_pool, PR_NOWAIT);
                np->base = rp->base;
                np->size = rp->size;
                np->length = rp->length;
                np->total = rp->total;
                np->free = rp->free;

                RB_INSERT(freebies, &new->p_p->dp->free_head, np);
        }

        RB_FOREACH(rp, regions, &old->p_p->dp->region_head) {
                np = pool_get(&info_pool, PR_NOWAIT);
                np->base = rp->base;
                np->size = rp->size;
                np->length = rp->length;
                np->total = rp->total;
                np->free = rp->free;

                RB_INSERT(regions, &new->p_p->dp->region_head, np);
        }
}

void
smalloc_destroy(struct proc *p)
{
	/*
	struct region_info *r;

	RB_FOREACH(r, regions, &p->p_p->dp->region_head) {
                RB_REMOVE(regions, &p->p_p->dp->region_head, r); 
                pool_put(&info_pool, r); 
	}
	*/
}

void
smalloc_pages(struct proc *p, size_t n)
{
	int i;
	void *pages, *t;

	t = pages = smalloc_mmap(p, n * PAGE_SIZE);
	for (i = 0; i < n; i++, t += PAGE_SIZE) {
		p->p_p->dp->freepages[i] = t;
		p->p_p->dp->cache++;
	}
}

void *
smalloc_chunk(struct proc *p, size_t sz)
{
	int i;
	void *ret;
	struct region_info f, *r = NULL, *rp;

	if (sz == 0)
		return NULL;

	if (sz < PAGE_SIZE) {
		f.size = sz;

		RB_FOREACH(rp, freebies, &p->p_p->dp->free_head) {
			if (rp->size == sz) {
				r = rp;
				break;
			}
		}
	}

	if (!r) {
		r = pool_get(&info_pool, PR_NOWAIT);
		if (!(r->base = smalloc_mmap(p, PAGEROUND(sz))))
			return NULL;

		if (sz >= PAGE_SIZE) {
			r->size = sz;
			r->length = sz;
			r->free = 0;
			RB_INSERT(regions, &p->p_p->dp->region_head, r);
		} else {
			r->size = sz;
			r->length = PAGE_SIZE;
			r->total = r->free = (PAGE_SIZE / sz);
			memset(r->chunks, 0, r->total);
			RB_INSERT(freebies, &p->p_p->dp->free_head, r);
		}
	}

	if (sz < PAGE_SIZE) {
		for (i = 0; r->chunks[i] != 0; i++);

		r->free--;
		r->chunks[i] = 1;

		if (r->free == 0) {
			RB_REMOVE(freebies, &p->p_p->dp->free_head, r);
			RB_INSERT(regions, &p->p_p->dp->region_head, r);
		}

		ret = r->base + (sz * i);
		return ret;
	} else {
		return r->base;
	}
}

void
smalloc_unmap(struct proc *p, vaddr_t page, size_t sz)
{
	struct uvm_map_deadq dead_entries;

	if (vm_map_lock_try(&p->p_vmspace->vm_map)) {
		TAILQ_INIT(&dead_entries);
		uvm_unmap_remove(&p->p_vmspace->vm_map, page, page + sz, &dead_entries, 0, 1);
	}

	vm_map_unlock(&p->p_vmspace->vm_map);
	uvm_unmap_detach(&dead_entries, 0);
}

void
smalloc_free(struct proc *p, unsigned long addr)
{
	unsigned int i, l;
	struct region_info f, *r = NULL;
	char flag = 0;

	if (&p->p_p->dp->region_head == NULL) {
		printf("smalloc_free: something has gone horrible wrong maybe\n");
		return;
	}

	if ((void *)addr == NULL) {
		printf("null\n");
		return;
	}

	f.base = (void *)addr;

	if (!RB_EMPTY(&p->p_p->dp->free_head)) {
		flag = 0;
		r = RB_FIND(freebies, &p->p_p->dp->free_head, &f);
	}

	if (!r && !RB_EMPTY(&p->p_p->dp->region_head)) {
		flag = 1;
		r = RB_FIND(regions, &p->p_p->dp->region_head, &f);
	}

	if (!r) {
		printf("WTF %p\n", addr);
		return;
	}

	if (r->size >= PAGE_SIZE) {
		smalloc_unmap(p, (vaddr_t)r->base, r->length);
		RB_REMOVE(regions, &p->p_p->dp->region_head, r);
		pool_put(&info_pool, r);
	} else {
		l = (addr - (unsigned long)(r->base)) / (PAGE_SIZE / (PAGE_SIZE / r->size));
		if (r->chunks[l]) {
			r->chunks[l] = 0;
			r->free++;

			if (r->free == r->total) {
				if (flag == 1)
					RB_REMOVE(regions, &p->p_p->dp->region_head, r);
				else
					RB_REMOVE(freebies, &p->p_p->dp->free_head, r);
				
				if (p->p_p->dp->cache < SMALLOC_MAX_CACHE) {
					for (i = 0; i < SMALLOC_MAX_CACHE; i++) {
						if (p->p_p->dp->freepages[i] == NULL) {
							p->p_p->dp->freepages[i] = r->base;
							p->p_p->dp->cache++;
							break;
						}
					}
				} else 
					smalloc_unmap(p, (vaddr_t)r->base, r->length);
				pool_put(&info_pool, r);
			} else if (r->free == 1) {
				RB_INSERT(freebies, &p->p_p->dp->free_head, r);
				RB_REMOVE(regions, &p->p_p->dp->region_head, r);
			}
		}
	}

	return;
}

int
sys_realloc(struct proc *p, void *v, register_t *retval)
{
	char flag;
	size_t s;
	void *tmp;
	long *addr;
	struct region_info f, *r;

	struct sys_realloc_args *uap = v;

	if (p->p_p->dp == NULL && smalloc_init(p)) {
		*retval = (register_t)(NULL);
		return 1;
	}

	addr = SCARG(uap, p);
	s = round_sz(SCARG(uap, s));

	if (s < MALLOC_MINSIZE_S)
		s = MALLOC_MINSIZE_S;

	if (!addr) {
		*retval = (register_t)smalloc_chunk(p, s);
		return 0;
	} else {
		f.base = (void *)addr;
		r = NULL;

		if (!RB_EMPTY(&p->p_p->dp->free_head)) {
			flag = 0;
			r = RB_FIND(freebies, &p->p_p->dp->free_head, &f);
		}

		if (!r && !RB_EMPTY(&p->p_p->dp->region_head)) {
			flag = 1;
			r = RB_FIND(regions, &p->p_p->dp->region_head, &f);
		}

		if (!r) {
			printf("sys_realloc: fucked, f.base=%p\n", f.base);
			*retval = (register_t)NULL;
			return 1;
		}

		if (r->size >= s)
			s = r->size;

		if (!(*retval = (register_t)smalloc_chunk(p, s))) {
			return 1;
		}

		tmp = malloc(r->size, M_SUBPROC, M_WAITOK);
		copyin(f.base, tmp, r->size);
		copyout(tmp, (void *)*retval, r->size);
		free(tmp, M_SUBPROC);

		return 0;
	}
}

int
sys_free(struct proc *p, void *v, register_t *retval)
{
	smalloc_free(p, *(unsigned long *)v);
	return 0;
}
