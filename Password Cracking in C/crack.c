//Password Cracking Function
//takes in list of 100 usernames and password hashes and attempts to crack them
//mangled list takes around 10-12 minutes to complete 
//run basic list with "./crack -i shadow -o shadow_cracked -l password.lst"
//run mangled list with "./crack -i shadowMangled -o shadowMangled_cracked -l password.lst -m"
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <crypt.h>
#include <ctype.h>
#include <stdlib.h>
#include <stddef.h>


int main(int argc, char* argv[]) {
    
    int mFlag = 0;
    char inFileName[20];
    char outFileName[20];
    char pasList[20];
    int a;
    int cycle = 1;

    opterr = 0;
    while((a = getopt (argc, argv, "mi:o:l:")) != -1){
        printf("Switch Cycle #: %d\n",cycle);
        cycle++;
        switch (a){
            case 'i':
                strcpy(inFileName, optarg);
                break;
            case 'o':
                strcpy(outFileName, optarg);
                break;
            case 'l':
                strcpy(pasList, optarg);
                break;
            case 'm':
                mFlag = 1;
                break;
            case '?':
                if (optopt == 'i' || optopt == 'o' || optopt == 'l')
                    fprintf (stderr, "Option -%c requires an argument.\n", optopt);
                else if (isprint (optopt))
                    fprintf (stderr, "Unknown option `-%c'.\n", optopt);
                else
                    fprintf (stderr, "Unknown option character `\\x%x'.\n", optopt);
                return 1;
            default:
                abort ();
        }
    } 
    
    FILE* in = fopen(inFileName, "r");
    FILE* out = fopen(outFileName, "w");
    FILE* plist = fopen(pasList, "r");
    

    char word[64];
    char username[16];
    
    while (fgets(word, sizeof(word), in)) {
        printf("Current Line: %s",word);
        char delimiters[2] = ":";
        char *token, *cp;
        
        cp = strdupa (word);                
        token = strtok (cp, delimiters);     
        int count = 1;
        
        while(token != NULL){
            if(count==1){                     //token should be username
                memset(username,0,16);
                strcpy(username, token); 
            }
            if(count==2){                     //token is now hashvalue from shadow
                char key[64];
                while (fgets(key, sizeof(key), plist)) {
                    key[strlen(key)-1] = '\0';
                    char *salt = "$1$";
                    char *hashValue;
                    hashValue = strdup(crypt(key, salt));
                    if(strcmp(token, hashValue)==0){ //token matches hash made from password list
                        fprintf(out,"Username: %s, Password: %s\n", username, key);
                        break;
                    }
                    if(mFlag==1){
                        int i;
                        char *newKey;
                        for(i=0;i<10;i++){
                            char num[10];
                            sprintf(num, "%d",i);
                            newKey = strcat(key, num);
                            hashValue = strdup(crypt(newKey, salt));
                            if(strcmp(token, hashValue)==0){ //token matches hash made from password
                                fprintf(out,"Username: %s, Password: %s\n", username, newKey);
                                break;
                            }
                            newKey[strlen(newKey)-1]='\0';
                        }
                    }
                }
                fseek(plist, 0, SEEK_SET);
            }
            token = strtok (NULL, delimiters);
            count++;
        }
    }
    fclose(in);
    fclose(out);
    fclose(plist);
    return 0;
}