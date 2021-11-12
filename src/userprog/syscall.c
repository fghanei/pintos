#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "pagedir.h"
#include "../threads/vaddr.h"
#include "string.h"

static void syscall_handler (struct intr_frame *);
void exit(int);
int write(int fd, const void* buffer, unsigned size);
void validate_address(void *);
void validate_address(void *ptr){
	//0xC0000000
       if(  !is_user_vaddr(ptr) || ptr == NULL || (unsigned int) ptr >= (unsigned int)(PHYS_BASE) || pagedir_get_page(thread_current()->pagedir,ptr) == NULL) 
		exit(-1);

}

void exit(int status ) {
	char *save_ptr;
	char *name = strtok_r(thread_current()->name, " ", &save_ptr);
        printf("%s: exit(%d)\n", name, status);
        thread_exit();

}
int write(int fd, const void* buffer, unsigned size){

	putbuf((char *)buffer, size);
	return (int) size;

}
void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED)
{

        validate_address((void *)f->esp);
		
        int call = *(int *)f->esp;
        if(call == SYS_EXIT){
		
                validate_address(f->esp + 4);
   //             unsigned int arg1 = ((unsigned int)(f->));
                exit(*(int *)(f->esp + 4));
        } else if( call == SYS_WRITE){ 
		 validate_address(f->esp + 4);
 		validate_address(f->esp + 8);
 		validate_address(f->esp + 12);
		int fd = *(int *)(f->esp + 4);
		char *buf = *(char **) (f->esp + 8);
		unsigned size = *(unsigned *)(f->esp + 12);
		printf("%p\n", f->esp + 4);
		printf("%p\n", f->esp + 8); printf("%p\n", f->esp + 12);
		hex_dump(buf, buf ,128, true);
		//printf
		printf("%p\n", buf); printf("%p\n", buf + size);
		validate_address(buf);
		validate_address(buf + size);


		f->eax = write(fd, (const void *)buf, size);		
	}

//printf("syscall\n");


}
