#include "self_define.h"

#ifdef __KERNEL__
#include <linux/slab.h>
#else
#include <stdlib.h>
#include <string.h>
#endif

void *my_malloc(unsigned int size)
{
    void *result;

#ifdef __KERNEL__
    result = kmalloc(GFP_KERNEL, size); // GFP_KERNEL, GFP_ATOMIC
#else                                   /* user space */
    result = malloc(size);
#endif

    return result;
}

void my_free(void *ptr)
{
#ifdef __KERNEL__
    kfree(ptr);
#else /* user space */
    free(ptr);
#endif
}

struct hmap *map_init(unsigned int size)
{
    // [struct ft_kv *, ..., ...]
    struct hmap *map = malloc(sizeof(struct hmap));
    map->size = size;
    map->map = malloc(sizeof(struct kv *) * size);
    memset(map->map, 0, sizeof(struct kv *) * size);
    return map;
}

/*
set a key:val in the hmap
*/
int set_map(struct hmap *map, char *key, struct flow_data *val)
{
    int exist = 0;
    int key_l = strlen(key);
    struct kv *flow_key = map->map[key_l % MAP_SIZE];
    struct kv *head = flow_key;

    // if the bucket doesn't have any flow
    if (flow_key == NULL)
    {
        struct kv *new_flow = malloc(sizeof(struct kv));
        strncpy(new_flow->key, key, 15);
        new_flow->key[15] = '\0';
        new_flow->val = val;
        new_flow->next = NULL;
        map->map[key_l % MAP_SIZE] = new_flow;
        return 0;
    }
    // check whether the key has already exised or not
    while (flow_key)
    {
        if (strcmp(flow_key->key, key) == 0)
        {
            exist = 1;
            break;
        }
        flow_key = flow_key->next;
    }
    // if so, update it's value
    if (exist)
    {
        flow_key->val = val;
    }
    // else set a new kv and update the bucket head
    else
    {
        struct kv *new_flow = malloc(sizeof(struct kv));
        strncpy(new_flow->key, key, 15);
        new_flow->key[15] = '\0';
        new_flow->val = val;
        new_flow->next = head;
        map->map[key_l % MAP_SIZE] = new_flow;
    }
    return 0;
}

/*
Get a value of the specific key
*/
struct flow_data *get_map(struct hmap *map, char *key)
{
    int key_l = strlen(key);
    struct kv *flow_key = map->map[key_l % MAP_SIZE];
    struct flow_data *val = NULL;

    // if the bucket doesn't have any flow
    while (flow_key)
    {
        if (strcmp(flow_key->key, key) == 0)
        {
            val = flow_key->val;
            break;
        }
        flow_key = flow_key->next;
    }

    return val;
}

void del_map(struct hmap *map, char *key)
{
    int key_l = strlen(key);
    struct kv **indirect = &map->map[key_l % MAP_SIZE];
    struct kv *node;
    while (*indirect)
    {
        if (strcmp((*indirect)->key, key) == 0)
        {
            node = *indirect;
            *indirect = node->next;
            free(node);
            break;
        }
        indirect = &(*indirect)->next;
    }
    return;
}

void clean_up(struct hmap *map)
{
    free(map->map);
    free(map);
    return;
}

int main(void)
{
    printf("=== Start map testing ===");
    struct hmap *map = map_init(MAP_SIZE);
    clean_up(map);
    printf("=== End map testing ===");
    return 0;
}
