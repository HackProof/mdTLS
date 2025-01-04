
#ifndef __TABLE_H__
#define __TABLE_H__

#define MAX_ENTRIES 1000
#define MAX_NAME_LENGTH 256

#ifndef OPENSSL_NO_MDTLS

#ifdef REF
struct forward_table
{
  int num_of_entries;
  unsigned char *forward_names[MAX_ENTRIES];
  int name_lengths[MAX_ENTRIES];
  unsigned char *forward_ips[MAX_ENTRIES];
  int ip_lengths[MAX_ENTRIES];
  int forward_ports[MAX_ENTRIES];
} *table;
#else
#ifdef REF_TABLE
extern struct forward_table
{
  int num_of_entries;
  unsigned char *forward_names[MAX_ENTRIES];
  int name_lengths[MAX_ENTRIES];
  unsigned char *forward_ips[MAX_ENTRIES];
  int ip_lengths[MAX_ENTRIES];
  int forward_ports[MAX_ENTRIES];
} *table;
#else
extern struct forward_table
{
  int num_of_entries;
  unsigned char *forward_names[MAX_ENTRIES];
  int name_lengths[MAX_ENTRIES];
  unsigned char *forward_ips[MAX_ENTRIES];
  int ip_lengths[MAX_ENTRIES];
  int forward_ports[MAX_ENTRIES];
} *table;
#endif //REF_TABLE
#endif //REF



#endif //OPENSSL_NO_MDTLS

int init_forward_table(unsigned char *filename);
void free_forward_table(void);

int insert_entry(unsigned char *name, int nlen, unsigned char *ip, int ilen, int port);
int find_by_name(unsigned char *buf, int len);
unsigned char *get_name_by_index(int index);
int get_name_length(int index);
unsigned char *get_ip_by_index(int index);
int get_port_by_index(int index);

#endif  /* __TABLE_H__ */
