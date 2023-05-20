#include "self_define.h"

#ifdef __KERNEL__
#include <linux/slab.h>
#include <linux/string.h>
#else
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#endif

void *my_malloc(size_t size)
{
    void *result;

#ifdef __KERNEL__
    result = kmalloc(size, GFP_KERNEL); // GFP_KERNEL, GFP_ATOMIC
#else /* user space */
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

/*
Initialize the hmap
*/
struct hmap *map_init(unsigned int size){
    // [struct ft_kv *, ..., ...]
    struct hmap *map = my_malloc(sizeof(struct hmap));
    map->size = size;
    map->map = my_malloc(sizeof(struct kv *) * size);
    memset(map->map, 0, sizeof(struct kv *) * size);
    return map;
}

/*
set a key:val in the hmap
*/
int set_map(struct hmap *map, char *key, struct packet_data val){
    int exist = 0;
    int key_l = strlen(key);
    struct kv *flow_key = map->map[key_l%MAP_SIZE];
    struct kv *head = flow_key;
    
    // if the bucket doesn't have any flow
    if(flow_key == NULL){
        struct kv *new_flow = my_malloc(sizeof(struct kv));
        strncpy(new_flow->key, key, 15);
        new_flow->key[15] = '\0';
        new_flow->val = val;
        new_flow->next = NULL;
        map->map[key_l%MAP_SIZE] = new_flow;
        return 0;
    }
    // check whether the key has already exised or not
    while(flow_key){
        if(strcmp(flow_key->key, key) == 0){
            exist = 1;
            break;
        }
        flow_key = flow_key->next;
    }
    // if so, update it's value
    if(exist){
        flow_key->val = val;
    }
    // else set a new kv and update the bucket head
    else{
        struct kv *new_flow = my_malloc(sizeof(struct kv));
        strncpy(new_flow->key, key, 15);
        new_flow->key[15] = '\0';
        new_flow->val = val;
        new_flow->next = head;
        map->map[key_l%MAP_SIZE] = new_flow;
    }
    return 0;
}

/*
Get a value of the specific key
*/
struct packet_data get_map(struct hmap *map, char *key){
    int key_l = strlen(key);
    struct kv *flow_key = map->map[key_l%MAP_SIZE];
    struct packet_data val = {};

    // if the bucket doesn't have any flow
    while(flow_key){
        if(strcmp(flow_key->key, key) == 0){
            val = flow_key->val;
            break;
        }
        flow_key = flow_key->next;
    }

    return val;
}

/*
Delete a key from hmap
*/
void del_map(struct hmap *map, char *key){
    int key_l = strlen(key);
    struct kv **indirect = &map->map[key_l%MAP_SIZE];
	struct kv *node;
	while (*indirect){
		if (strcmp((*indirect)->key, key) == 0){
            printf("del %s val: %s\n", (*indirect)->key, (*indirect)->val.payload);
			node = *indirect;
			*indirect = node->next;
			my_free(node);
			break;
		}
		indirect = &(*indirect)->next;
	}    
    return;
}

/*
Clean up the hmap
*/
void clean_up(struct hmap *map){
    struct kv **indirect;
    struct kv *node;
    
    for(int i=0;i<MAP_SIZE;i++){
        indirect = &map->map[i];
        while (*indirect){
            printf("clean up %s val: %s\n", (*indirect)->key, (*indirect)->val.payload);
            node = *indirect; 
            *indirect = node->next;
            free(node);
        }    
    }
    free(map->map);
    free(map);
    return;
}

int main(void){
    printf("=== Start map testing ===\n");
    struct hmap *map = map_init(MAP_SIZE);
    char *key1 = "gary";
    char *key2 = "steve";
    char *key3 = "leon";
    char *key4 = "robin";
    struct packet_data data1 = {{'h', 'e', 'l', 'l','o', '\0'}};
    struct packet_data data2 = {{'w', 'o', 'r', 'l','d', '\0'}};
    struct packet_data data3 = {{'a', 'b', 'c', 'd','e', '\0'}};
    struct packet_data data4 = {{'1', '2', '3', '4', 0x97, '\0'}};
    set_map(map, key1, data1);
    set_map(map, key2, data2);
    set_map(map, key3, data3);
    set_map(map, key4, data4);
    printf("Get %s val : %s\n", key3, get_map(map, key3).payload);
    del_map(map, key4);
    clean_up(map);
    printf("=== End map testing ===\n");
    return 0;
}
