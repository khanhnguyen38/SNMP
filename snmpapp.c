/**
*
* SNMP Project
* authors: Tung Dang - Khanh Nguyen
*/
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <arpa/inet.h>
#include <string.h>
#include <math.h>

/**
* SNMP GET function
*/
int snmp_get(struct snmp_session *sess_handle, oid *theoid, size_t theoid_len){
            struct snmp_pdu *pdu;
            struct snmp_pdu *response;
            struct variable_list *vars;
            
            FILE *f = fopen("file.txt", "w");
            
            u_char *buf;
            int j;
            int status;

            pdu = snmp_pdu_create(SNMP_MSG_GET);

            snmp_add_null_var(pdu, theoid, theoid_len);
            
            status = snmp_synch_response(sess_handle, pdu, &response);
            netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_QUICK_PRINT, 1);
            if (status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR) {
            for(vars = response->variables; vars; vars = vars->next_variable) {
                   fprint_value(f, vars->name, vars->name_length, vars);               
             }
            if (response) {
                snmp_free_pdu(response);
            }
            }
            fclose(f);
            return status;
}


/**
* SNMP GETNEXT function
*/
int snmp_getnext(struct snmp_session *sess_handle, oid *theoid, size_t theoid_len){
            struct snmp_pdu *pdu;
            struct snmp_pdu *response;
            struct variable_list *vars;
            
            FILE *f = fopen("file.txt", "w");
            
            u_char *buf;
            int j;
            int status;

            pdu = snmp_pdu_create(SNMP_MSG_GETNEXT);

            snmp_add_null_var(pdu, theoid, theoid_len);
            
            status = snmp_synch_response(sess_handle, pdu, &response);
            netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_QUICK_PRINT, 1);
            if (status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR) {
            for(vars = response->variables; vars; vars = vars->next_variable) {
                   fprint_value(f, vars->name, vars->name_length, vars);               
             }
            if (response) {
                snmp_free_pdu(response);
                
            }
            }
            fclose(f);
            return status;
}

/**
* SNMP WALK function
* Reference from 
* http://www.opensource.apple.com/source/net_snmp/net_snmp-10/net-snmp/apps/snmpwalk.c
*/
int snmp_walk(struct snmp_session *ss, oid *root, size_t rootlen){
        netsnmp_session session;
        struct snmp_pdu *pdu;
        struct snmp_pdu *response;
        struct variable_list *vars;
        int j;
        int check;
        int count;
        int status;
        int running = 1;
        int numprinted = 0;           
        int exitval = 0;
        FILE *f = fopen("temp.txt", "a");
        oid name[MAX_OID_LEN];
        size_t name_length;
        
        memmove(name, root, rootlen * sizeof(oid));
        name_length = rootlen;
        
        while (running) {

            pdu = snmp_pdu_create(SNMP_MSG_GETNEXT);
            snmp_add_null_var(pdu, name, name_length);

            status = snmp_synch_response(ss, pdu, &response);
            netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_QUICK_PRINT, 1);
            if (status == STAT_SUCCESS) {
                if (response->errstat == SNMP_ERR_NOERROR) {
                     //check resulting variables 
                    for (vars = response->variables; vars;
                         vars = vars->next_variable) {
                        if ((vars->name_length < rootlen)
                            || (memcmp(root, vars->name, rootlen * sizeof(oid))
                                != 0)) 
                        {
                             //not part of this subtree 
                            running = 0;
                            continue;
                        }
                        numprinted++;
                        //write value to temp file
                        fprint_value(f,vars->name, vars->name_length, vars);
                        //print_objid(vars->name, vars->name_length);
                        if ((vars->type != SNMP_ENDOFMIBVIEW) &&
                            (vars->type != SNMP_NOSUCHOBJECT) &&
                            (vars->type != SNMP_NOSUCHINSTANCE)) {
                            /*
                             * not an exception value 
                             */
                            if (check && snmp_oid_compare(name, name_length,
                                        vars->name, vars->name_length) >= 0) 
                            {
                                fprintf(stderr, "Error: OID not increasing: ");
                                fprint_objid(stderr, name, name_length);
                                fprintf(stderr, " >= ");
                                fprint_objid(stderr, vars->name,vars->name_length);
                                fprintf(stderr, "\n");
                                running = 0;
                                exitval = 1;
                            }
                            memmove((char *) name, (char *) vars->name, 
                                    vars->name_length * sizeof(oid));
                            name_length = vars->name_length;
                        } else
                             //stop 
                            running = 0;
                    }
                    } else {
                    /*
                     * error in response, print it 
                     */
                    running = 0;
                    if (response->errstat == SNMP_ERR_NOSUCHNAME) {
                        printf("End of MIB\n");
                    } else {
                        fprintf(stderr, "Error in packet.\nReason: %s\n",
                                snmp_errstring(response->errstat));
                        if (response->errindex != 0) {
                            fprintf(stderr, "Failed object: ");
                            for (count = 1, vars = response->variables;
                                 vars && count != response->errindex;
                                 vars = vars->next_variable, count++)
                                /*EMPTY*/;
                            if (vars)
                                fprint_objid(stderr, vars->name,
                                             vars->name_length);
                            fprintf(stderr, "\n");
                        }
                        exitval = 2;
                    }
                }
            } else if (status == STAT_TIMEOUT) {
                fprintf(stderr, "Timeout: No Response from %s\n",
                        session.peername);
                running = 0;
                exitval = 1;
            } else {                /* status == STAT_ERROR */
                snmp_sess_perror("snmpwalk", ss);
                running = 0;
                exitval = 1;
            }
            if (response)
                snmp_free_pdu(response);
            }
        if (numprinted == 0 && status == STAT_SUCCESS) {
        /*
         * no printed successful results, which may mean we were
         * pointed at an only existing instance.  Attempt a GET, just
         * for get measure. 
         */
        snmp_getnext(ss, root, rootlen);
        }
        fclose(f);
        return exitval;
}

/*
* delay x seconds
*/
void delay(int seconds)
{
    long pause;
    clock_t now, then;
    
    pause =seconds*(CLOCKS_PER_SEC);
    now = then = clock();
    while ((now-then) < pause)
        now = clock();
}
/*
* Get inOctet of an interface
*/
long snmp_getInOct(struct snmp_session *sess_handle, char ifnum[5]){
            struct snmp_pdu *pdu;
            struct snmp_pdu *response;
            struct variable_list *vars;

            u_char *buf;
            int j;
            int status;
            oid inOct [MAX_OID_LEN];
            size_t inOct_len = MAX_OID_LEN;
            int *sp;
            char theoid[30] ="1.3.6.1.2.1.2.2.1.10.";
            strcat(theoid, ifnum);
            read_objid(theoid, inOct, &inOct_len);
            long result = 0;
            
            
            pdu = snmp_pdu_create(SNMP_MSG_GET);

            snmp_add_null_var(pdu, inOct, inOct_len);
            
            status = snmp_synch_response(sess_handle, pdu, &response);
            netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_QUICK_PRINT, 1);
            if (status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR) {
            for(vars = response->variables; vars; vars = vars->next_variable) {         
                sp = malloc(1 + vars->val_len);
                memcpy(sp, vars->val.integer, vars->val_len);
                result = *sp;
                free(sp);  
            }
            if (response) {
                snmp_free_pdu(response);
            }
            }

    return result;
}

/**
* get OutOctet of an interface
*/
long snmp_getOutOct(struct snmp_session *sess_handle, char ifnum[5]){
            struct snmp_pdu *pdu;
            struct snmp_pdu *response;
            struct variable_list *vars;

            u_char *buf;
            int j;
            int status;
            oid outOct [MAX_OID_LEN];
            size_t outOct_len = MAX_OID_LEN;
            int *sp;
            char theoid[30] ="1.3.6.1.2.1.2.2.1.16.";
            strcat(theoid, ifnum);
            //printf("%s\n", theoid);
            read_objid(theoid, outOct, &outOct_len);
            long result = 0;
            
            
            pdu = snmp_pdu_create(SNMP_MSG_GET);

            snmp_add_null_var(pdu, outOct, outOct_len);
            
            status = snmp_synch_response(sess_handle, pdu, &response);
            netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_QUICK_PRINT, 1);
            if (status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR) {
            for(vars = response->variables; vars; vars = vars->next_variable) {
            //print_variable(vars->name, vars->name_length, vars);
            
            sp = malloc(1 + vars->val_len);
            memcpy(sp, vars->val.integer, vars->val_len);
            result = *sp;
            free(sp);  
      }
            if (response) {
                snmp_free_pdu(response);
            }
            }

    return result;
}

/*
* Estabish a SNMP session
*/
struct snmp_session *setup_snmp_session(int version, char* community, char* hostname){
    struct snmp_session session;
    struct snmp_session *sess_handle;
    init_snmp("snmpapp");
    snmp_sess_init( &session );
    session.version = version;
    session.community = community;
    session.community_len = strlen(session.community);
    session.peername = hostname;
    sess_handle = snmp_open(&session);
    return sess_handle;

}

/*
* main function
*/
int main(int argc, char * argv[]) {
    if(argc <4) {
        printf("Please supply a hostname interval_time number_of_sample\n");
        exit(1);
    }
    
    char *t;
    int interval = strtol(argv[2], &t, 10); 
    int num = strtol(argv[3], &t, 10);
    int r;

    oid ifip [MAX_OID_LEN];
    oid if_oid[MAX_OID_LEN];
    size_t ifip_len = MAX_OID_LEN;
    size_t if_len = MAX_OID_LEN;
    
    //Establish session        
    struct snmp_session *sess_handle=setup_snmp_session(SNMP_VERSION_2c,"public",argv[1]);
    
    /*
    * Find interfaces and IP addresses
    */
    //Read oid ipAdEntAddr and ipAdEntIfIndex
    read_objid("1.3.6.1.2.1.4.20.1.1", ifip, &ifip_len);
    read_objid("1.3.6.1.2.1.4.20.1.2", if_oid, &if_len);

    snmp_walk(sess_handle, if_oid, if_len);
    snmp_walk(sess_handle, ifip, ifip_len);
    
    
    FILE *fin;
    //unable to open temp file
    if( ( fin = fopen( "temp.txt", "r" ) ) == NULL ) {
      fprintf( stderr, "Error opening file.\n" );
      exit( 1 );
    }
    char line[30];
    char value[30];
    char result1[10][15];   
    int index = 0;
    int j;
    while (fgets(line, 30, fin) != NULL) {
        sscanf(line,"%s", value);
        strcpy(result1[index], value);
        index++;
    }
    char ifnum[index/2][5];
    printf("INTERFACES:\n");
    printf("______________________________\n");
    printf("| Interface |        IP       |\n");
    printf("______________________________\n");
    for (j=0; j< index/2; j += 1) {
        printf("| %9s | %15s |\n", result1[j], result1[(index+1)/2+j]);
        strcpy(ifnum[j], result1[j]);
    }
    printf("______________________________\n");
    fclose(fin);
    remove("temp.txt");


    /* 
    * Find neighbor IP addresses and display
    */
    FILE *fin2;
    printf("\nNEIGHBORS:\n");

    oid neigip [MAX_OID_LEN];
    size_t neigip_len = MAX_OID_LEN;
    
    //read ipNetToMediaTable
    read_objid("1.3.6.1.2.1.4.22", neigip, &neigip_len);
        
    snmp_walk(sess_handle, neigip, neigip_len);
    //unable to open temp file
    if( ( fin2 = fopen( "temp.txt", "r" ) ) == NULL ) {
        fprintf( stderr, "Error opening file.\n" );
        exit( 1 );
    }
    char line2[30];
    char value2[30];
    char neighbor[10][15];
    int index2 = 0;
    int k;
    while (fgets(line2, 30, fin2) != NULL) {
        sscanf(line2,"%s", value2);
        strcpy(neighbor[index2], value2);
        index2++;
    }
    printf("______________________________\n");
    printf("| Interface |    Neighbor     |\n");
    printf("______________________________\n");
    int l = index2/2;
    for(k=0; k < index2/4; k +=1) {
        printf("| %9s | %15s |\n", neighbor[k], neighbor[k+l]);
        
    }
    printf("______________________________\n");
    fclose(fin2);
    remove("temp.txt");
    
    /*
    * Calculate traffic and display
    */
    printf("\nTRAFFIC:\n");
    long intraffic[num];
    long outtraffic[num];
    int i, m;
    for (m=0; m<index/2; m++) 
    {
        printf("Interface: %s\n", ifnum[m]);
        printf("____________\n");
        //In traffic
        printf("IN TRAFFIC\n");
	    printf("|Second | Traffic (Kb/s) \n");
        for (i=0; i<num; i++)
        { 
        	
			long inoct1 = snmp_getInOct(sess_handle, ifnum[m]);      
			delay(interval);
			long inoct2 = snmp_getInOct(sess_handle, ifnum[m]);
			
			/*
			* calculate in traffic
			*/
			if (inoct2 > inoct1) {
				intraffic[i] = ((inoct2-inoct1) * 8 /1024) / interval;
			}
			//wrap around
			else {
				intraffic[i] = (((inoct2-inoct1) * 8 * pow(2,32) /1024))/ interval;
			}
			//print time interval
			printf("|%6d | ", i*interval);
			int n =0;
			while (n<intraffic[i])
			{ 
				printf("*");
				n+=2;
			} 
			printf("(%ld)\n", intraffic[i]);
		}
		printf("____________\n");

		// Out traffic
		printf("OUT TRAFFIC\n");
		printf("|Second | Traffic (Kb/s) \n");
		for (i=0; i<num; i++)
		{
			long outoct1 = snmp_getOutOct(sess_handle, ifnum[m]);
			delay(interval);
			long outoct2 = snmp_getOutOct(sess_handle, ifnum[m]);
	
			//calculate out traffic
			if (outoct2 > outoct1) {
				outtraffic[i] = ((outoct2-outoct1) * 8 /1024) / interval;
			}
			//wrap around
			else {
				outtraffic[i] = (((outoct2-outoct1) * 8 * pow(2,32) /1024))/ interval;
			}
			printf("|%6d | ", i*interval);
			int n =0;
			while (n<outtraffic[i]) 
			{ 
				printf("*");
				n+=2;
			} 
			printf("(%ld)\n", outtraffic[i]);
			}
        printf("____________\n");      
    }
    
    //clean up
    snmp_close(sess_handle);
    SOCK_CLEANUP;
    
    return (0);
}