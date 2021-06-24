#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
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
#include "upd-table.h"

#define Tam_max 80

int main(int argc, char *argv[]){

    int era1, era2, era3, era4, r;
    char fam[Tam_max], tab[Tam_max], kat[Tam_max], ize[Tam_max], sta[Tam_max], hok[Tam_max], pri[Tam_max], pol[Tam_max];
    char *dei1[3];
    char *dei2[4];
    char *dei3[7];
    
    while(true){
    //Menu nagusia
    printf("\033c");
    printf("Taula batekin interaktuatzeko sakatu:   1\n");
    printf("Kate batekin interaktuatzeko sakatu:    2\n");    
    printf("Arau batekin interaktuatzeko sakatu:    3\n");
    printf("Programa ixteko sakatu:                 4\n");
    scanf("%d", &era1);
    
    
    //Taula/Kate/Arau menua
    switch (era1){
        case 1:
            era3=-1;
            era4=-1;
            printf("\033c");
            printf("Taula berri bat sortzeko sakatu:    1\n");
            printf("Taula bat ezabatzeko sakatu:        2\n");    
            printf("Taula bat eguneratzeko sakatu:      3\n");    
            printf("Atzera joateko sakatu:              0\n");            
            scanf("%d", &era2);
            break;
        case 2:
            era2=-1;
            era4=-1;
            printf("\033c");
            printf("Kate sinple bat sortzeko sakatu:    1\n");
            printf("Kate konplexu bat sortzeko sakatu:  2\n");
            printf("Kate bat ezabatzeko sakatu:         3\n");    
            printf("Atzera joateko sakatu:              0\n");
            scanf("%d", &era3);
            break;
        case 3:
            era2=-1;
            era3=-1;
            printf("\033c");
            printf("Arau berri bat sortzeko sakatu:         1\n");
            printf("Arau bat ezabatzeko sakatu:             2\n");    
            printf("Atzera joateko sakatu:                  0\n");
            scanf("%d", &era4);
            break;
        case 4:
            printf("\033c");
            exit(0);
    }
    
    //Taulen menua
    switch (era2){
        //add
        case 1:
            printf("\033c");
            printf("SEMANTIKA: Familia Izena\n");
            scanf("%s %s", &fam, &ize);
            dei1[1]=fam;
            dei1[2]=ize;
            r=addTab(3,dei1);
            break;
        //rem
        case 2:
            printf("\033c");
            printf("SEMANTIKA: Familia Izena\n");
            scanf("%s %s", &fam, &ize);
            dei1[1]=fam;
            dei1[2]=ize;
            r=remTab(3,dei1);
            break;
        //upd
        case 3:
            printf("\033c");
            printf("SEMANTIKA: Familia Izena State\n");
            scanf("%s %s %s", &fam, &ize, &sta);
            dei2[1]=fam;
            dei2[2]=ize;
            dei2[3]=sta;
            r=updTab(4,dei2);
            break;            
    }
    
    //Kateen menua
    switch (era3){
        //add
        case 1:
            printf("\033c");
            printf("SEMANTIKA: Familia Taula Katea\n");
            scanf("%s %s %s", &fam, &tab, &kat);
            dei2[1]=fam;
            dei2[2]=tab;
            dei2[3]=kat;
            r=addCha(4,dei2);
            break;
        case 2:
            printf("\033c");
            printf("SEMANTIKA: Familia Taula Katea [<hooknum> <prio> <policy>]\n");
            scanf("%s %s %s %s %s %s", &fam, &tab, &kat, &hok, &pri, &pol);
            dei3[1]=fam;
            dei3[2]=tab;
            dei3[3]=kat;
            dei3[4]=hok;
            dei3[5]=pri;
            dei3[6]=pol;
            r=addCha(7,dei3);
            break;
        //rem
        case 3:
            printf("\033c");
            printf("SEMANTIKA: Familia Taula Katea\n");
            scanf("%s %s %s", &fam, &tab, &kat);
            dei2[1]=fam;
            dei2[2]=tab;
            dei2[3]=kat;
            r=remCha(4,dei2);
            break;
    }
    
    //Arauen menua
    switch (era4){
        //add
        case 1:
            printf("\033c");
            printf("SEMANTIKA: Familia Taula Katea\n");
            scanf("%s %s %s", &fam, &tab, &kat);
            dei2[1]=fam;
            dei2[2]=tab;
            dei2[3]=kat;
            r=addRul(4,dei2);
            break;
        //rem
        case 2:
            printf("\033c");
            printf("SEMANTIKA: Familia Taula Katea\n");
            scanf("%s %s %s", &fam, &tab, &kat);
            dei2[1]=fam;
            dei2[2]=tab;
            dei2[3]=kat;
            r=remRul(4,dei2);
            break;
    }
    }
    
}
