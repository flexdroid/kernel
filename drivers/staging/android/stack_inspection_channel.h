#ifndef _LINUX_STACK_INSPECTION_CHANNEL_H
#define _LINUX_STACK_INSPECTION_CHANNEL_H

#define PRINT_TIME 1

int request_inspect_gids(int);
#if PRINT_TIME
void print_time(int);
#endif

#endif /* _LINUX_STACK_INSPECTION_CHANNEL_H */
