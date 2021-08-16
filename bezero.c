#include <zmq.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

#define ERR -1
#define MAX 80

int main (void)
{
    printf ("Connecting to hello world server...\n");
    void *context = zmq_ctx_new ();
    void *requester = zmq_socket (context, ZMQ_REQ);
    zmq_connect (requester, "tcp://localhost:5555");

    char send_buffer [MAX], recv_buffer [3];
    printf("Sartu komandoa!\n");
    scanf("%[^\n]", &send_buffer);
    printf("%s", send_buffer);
    
    int request_nbr;
    for (request_nbr = 0; request_nbr != MAX; request_nbr++) {
        zmq_send (requester, send_buffer, MAX, 0);
        zmq_recv (requester, recv_buffer, 3, 0);
    }
    
    zmq_close (requester);
    zmq_ctx_destroy (context);
    
    if(strcmp(recv_buffer,"ACK")==0){
        return 0;        
    }else{
        return ERR;
    }
} 
