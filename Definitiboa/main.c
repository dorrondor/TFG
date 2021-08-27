#include <zmq.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <netinet/in.h>

#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>

#include <libmnl/libmnl.h>
#include <libnftnl/chain.h>

#include "add-chain.h"
#include "rem-chain.h"
#include "add-rule.h"
#include "rem-rule.h"
#include "add-table.h"
#include "rem-table.h"

#define Tam_max 80

int main(int argc, char *argv[]){

    void *context = zmq_ctx_new ();
    void *responder = zmq_socket (context, ZMQ_REP);
    int i=0, r;
    char *dei[9];
    int rc = zmq_bind (responder, "tcp://*:5555");
	assert (rc == 0);
    char buffer [Tam_max];

    while (1) {
        zmq_recv (responder, buffer, Tam_max, 0);
        
        char *token = strtok (buffer, " ");
        while( token != NULL ) {
            dei[i]=token;
            i++;
            token = strtok(NULL, " ");            
        }
        //i++;
        if(strcmp(dei[0], "addTab") == 0){
            printf("addTab\n");
            r=addTab(i,dei);
            
        }
        if(strcmp(dei[0], "remTab") == 0){
            printf("remTab\n");
            r=remTab(i,dei);
            
        }
        if(strcmp(dei[0], "addCha") == 0){
            printf("addCha\n");
            r=addCha(i,dei);
            
        }
        if(strcmp(dei[0], "remCha") == 0){
            printf("RemCha\n");
            r=remCha(i,dei);            
        }
        if(strcmp(dei[0], "addRul") == 0){
            printf("addRul\n");
            r=addRul(i,dei);
            
        }
        if(strcmp(dei[0], "remRul") == 0){
            printf("remRul\n");
            r=remRul(i,dei);
            
        }
        i=0;
        if(r!=0){
            zmq_send (responder, "ERR", 3, 0);
        }else{
            zmq_send (responder, "ACK", 3, 0);
        }
    }
    return 0;
    
}
