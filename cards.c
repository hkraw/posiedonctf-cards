#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<unistd.h>
#include"SECCOMP.h"

#define TRUE 1
#define FALSE 0
#define SAD 9999

struct sock_filter seccompfilter[]={
  BPF_STMT(BPF_LD | BPF_W | BPF_ABS, ArchField),
  BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
  BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),
  BPF_STMT(BPF_LD | BPF_W | BPF_ABS, SyscallNum),
  Allow(read),
  Allow(write),
  Allow(open),
  Allow(mprotect),
  Allow(rt_sigreturn),
  Allow(brk),
  Allow(exit),
  Allow(exit_group),
  BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),
};

struct sock_fprog filterprog={
  .len=sizeof(seccompfilter)/sizeof(struct sock_filter),
  .filter=seccompfilter
};

typedef struct cardinfo{
	long int size_name_card;
	long int ncards;
	char *name_of_card;
}CARD_INFO;

typedef struct card{
	long int cardnumber;
	char color[0x8];
	CARD_INFO *card;
	long int iscard;
}CARD;

int total_cards = 0;
CARD *mycard[0x10];
unsigned int sizes[0x10];
int checks[0x10];

void apply_seccomp(){
  if(prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)){
    perror("Seccomp Error");
    exit(1);
  }
  if(prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&filterprog)==-1){
    perror("Seccomp Error");
    exit(1);
  }
  return;
}

void exit_error(char *error)
{
	printf("%s.\n",error);
	exit(SAD);
}

int return_number()
{
	char buff[0x10];
	int i;
	read(0,buff,0x3);	
	i = atoi(buff);
	return i;
}

void delete()
{
	unsigned int idx;
	printf("Enter index of the card: ");
	idx = return_number();
	if(idx>total_cards||checks[idx]){
		puts("No");
		return;
	}
	free(mycard[idx]);
	free(mycard[idx]->card);
	free(mycard[idx]->card->name_of_card);
	checks[idx]=1;
	printf("Done.\n");
}

void edit_name()
{
	unsigned int idx;
	printf("Enter the index of the card: ");
	idx = return_number();
	if(idx>total_cards||!mycard[idx]->iscard) {
		puts("Nope");
		return;
	}
	printf("Enter new name: ");
	read(0,mycard[idx]->card->name_of_card,sizes[idx]);
	puts("Edited");	
}

void view()
{
	unsigned int idx;
	printf("Enter the index of the card: ");
	idx = return_number();
	if(idx>total_cards||checks[idx]) {
		puts("Nope");
		return;
	}
	printf("===============================\n");
	printf("Card No: %ld.\n",mycard[idx]->cardnumber);
	printf("Card Size: %ld.\n",mycard[idx]->card->size_name_card);
	printf("Card name: %s.\n",mycard[idx]->card->name_of_card);
}

void add()
{
	unsigned int size;
	if(total_cards>0x8) {
		exit_error("No");
	}
	mycard[total_cards] = (CARD*)malloc(0x28);
	mycard[total_cards]->cardnumber=total_cards;
	printf("Enter size of the name of the card: ");
	size=return_number();
	if(size>0x100){
		exit_error("I'm not sure but you are not allowed to do that");
	}
	mycard[total_cards]->card = (CARD_INFO *)malloc(0x28);
	mycard[total_cards]->card->size_name_card = size;
	mycard[total_cards]->iscard = TRUE;
	mycard[total_cards]->card->name_of_card = malloc(size);
	mycard[total_cards]->card->ncards = total_cards;
	printf("Enter card color: ");
	read(0,mycard[total_cards]->color,0x7);	
	printf("Enter name: ");
	read(0,mycard[total_cards]->card->name_of_card,size);
	printf("Done.\n");
	sizes[total_cards]=size;
	total_cards++;
}

void menu()
{
	printf("=========================\n");
	printf("|1.|Add card.          ||\n");
	printf("|2.|Remove card.       ||\n");
	printf("|3.|Edit name.         ||\n");
	printf("|4.|View card.         ||\n");
	printf("|5.|Exit.              ||\n");
	printf("=========================\n");
	printf("Choice: ");
}

void initialize()
{
	setvbuf(stdin,NULL,_IONBF,0);
	setvbuf(stdout,NULL,_IONBF,0);
	alarm(60);
	apply_seccomp();
	return;
}
int main()
{
	int choice;
	char name[0x40];
	initialize();
	while(TRUE) {
		menu();
		choice = return_number();
		switch(choice) {
			case 1:
				add();
				break;
			case 2:
				delete();
				break;
			case 3:
				edit_name();
				break;
			case 4:
				view();
				break;
			case 5:
				printf("Bye.\n");
				exit(TRUE);
			case 6:
				printf("Enter your secret name: ");
				read(0,name,0x40);
				break;
			default:
				printf("Sad.\n");
				break;
		}
	}
	return 0;
}
