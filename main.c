#include <stdio.h>
#include "ncx_slab.h"

int main(int argc, char **argv)
{
	char *p = NULL;
	size_t 	pool_size = 4096000;  //4M 
	ncx_slab_stat_t stat;
	u_char 	*space;
	space = (u_char *)malloc(pool_size);
	ncx_slab_pool_t *sp;
	sp = (ncx_slab_pool_t*) space;
	sp->addr = space;
	sp->min_shift = 3;
	sp->end = space + pool_size;
	ncx_slab_init(sp);

	ncx_prarm_init();
    ncx_mem_step();
    ncx_access();
    ncx_diff();
    ncx_point();
    ncx_get_type();
    ncx_proc_write();
    ncx_lag_check();

	int i;
	for (i = 0; i < 1000000; i++) 
	{   
		p = ncx_slab_alloc(sp, 128 + i); 
		if (p == NULL) 
		{   
			printf("%d\n", i); 
			return -1; 
		}   
		ncx_slab_free(sp, p); 
	}   
	ncx_slab_stat(sp, &stat);

	for (i = 0; i < 2500; i++) 
	{   
		p = ncx_slab_alloc(sp, 30 + i); 
		if (p == NULL) 
		{   
			printf("%d\n", i); 
			return -1; 
		}   
		
		if (i % 3 == 0) 
		{
			ncx_slab_free(sp, p);
		}
	}   
	ncx_slab_stat(sp, &stat);
	free(space);
	return 0;
}