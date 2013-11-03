#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <arpa/inet.h>
#include <string.h>

void delay(int seconds);

void print_ip(int ip)
{
    unsigned char bytes[4];
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;	
    printf("%d.%d.%d.%d\n", bytes[3], bytes[2], bytes[1], bytes[0]);        
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
* Get inOct
*/
int snmp_getInOct(struct snmp_session *sess_handle){
			struct snmp_pdu *pdu;
            struct snmp_pdu *response;
            struct variable_list *vars;

         	u_char *buf;
         	int j;
            int status;
			oid inOct [MAX_OID_LEN];
    		size_t inOct_len = MAX_OID_LEN;
    		int *sp;
			read_objid("1.3.6.1.2.1.2.2.1.10", inOct, &inOct_len);
			int result = 0;
			
			
            pdu = snmp_pdu_create(SNMP_MSG_GETNEXT);

			snmp_add_null_var(pdu, inOct, inOct_len);
			
            status = snmp_synch_response(sess_handle, pdu, &response);
			netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_QUICK_PRINT, 1);
			if (status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR) {
            //for(vars = response->variables; vars; vars = vars->next_variable) {
            //        print_variable(vars->name, vars->name_length, vars);   	
            //} 
                  /* manipuate the information ourselves */
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
* getOutOct
*/
int snmp_getOutOct(struct snmp_session *sess_handle){
			struct snmp_pdu *pdu;
            struct snmp_pdu *response;
            struct variable_list *vars;

         	u_char *buf;
         	int j;
            int status;
			oid outOct [MAX_OID_LEN];
    		size_t outOct_len = MAX_OID_LEN;
    		int *sp;
			read_objid("1.3.6.1.2.1.2.2.1.16", outOct, &outOct_len);
			int result = 0;
			
			
            pdu = snmp_pdu_create(SNMP_MSG_GETNEXT);

			snmp_add_null_var(pdu, outOct, outOct_len);
			
            status = snmp_synch_response(sess_handle, pdu, &response);
			netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_QUICK_PRINT, 1);
			if (status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR) {
            //for(vars = response->variables; vars; vars = vars->next_variable) {
            //        print_variable(vars->name, vars->name_length, vars);   	
            //} 
                  /* manipuate the information ourselves */
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
* SNMP GETNEXT
*/
int snmp_get(struct snmp_session *sess_handle, oid *theoid, size_t theoid_len){
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
                    //size_t buf_len=256, out_len=256;
                    //int i =sprint_realloc_by_type(&buf, &buf_len, &out_len, 1, vars, NULL, NULL, NULL);
                    //int i=sprint_realloc_variable(&buf, &buf_len, &out_len, 1, theoid, theoid_len, vars); 
            			//printf("%d\n", i);
            			//printf("%s\n", buf);
            			
                    //buf = malloc(1+buf_len);
                    
                    //printf("value is: %s\n",buf);
                    //int j =sprint_realloc_value (&buf, &buf_len, &out_len, 1, vars->name, vars->name_length, vars);
                    
                    
                    //printf("value is: %lu\n", (*buf+out_len));
                    
                  /*  
                    char *sp;
      				sp = malloc(1 + vars->val_len);
		       	  	memcpy(sp, vars->val.string, vars->val_len);
		       	  	struct in_addr ip_addr;
    				ip_addr.s_addr = sp;
    				
    				printf("The IP address is %s\n", inet_ntoa(ip_addr));
         			//sp[vars->val_len] = '\0';
         			//printf("value is: %d\n", sp);
         			//print_ip(sp);
         			//free(sp);*/

          }
          
      

			if (response) {
            	snmp_free_pdu(response);
			}
			}
            return status;
}

/**
* SNMP WALK
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
    	FILE *f = fopen("file.txt", "a");
    	oid name[MAX_OID_LEN];
    	size_t name_length;
    	
        memmove(name, root, rootlen * sizeof(oid));
   	 	name_length = rootlen;
        
		while (running) {
        /*
         * create PDU for GETNEXT request and add object name to request 
         */
        pdu = snmp_pdu_create(SNMP_MSG_GETNEXT);
        snmp_add_null_var(pdu, name, name_length);

        /*
         * do the request 
         */
        status = snmp_synch_response(ss, pdu, &response);
        netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_QUICK_PRINT, 1);
        if (status == STAT_SUCCESS) {
            if (response->errstat == SNMP_ERR_NOERROR) {
                /*
                 * check resulting variables 
                 */
                for (vars = response->variables; vars;
                     vars = vars->next_variable) {
                    if ((vars->name_length < rootlen)
                        || (memcmp(root, vars->name, rootlen * sizeof(oid))
                            != 0)) {
                        /*
                         * not part of this subtree 
                         */
                        running = 0;
                        continue;
                    }
                    numprinted++;
                   
                    fprint_value(f,vars->name, vars->name_length, vars);
                    //print_objid(vars->name, vars->name_length);
                    if ((vars->type != SNMP_ENDOFMIBVIEW) &&
                        (vars->type != SNMP_NOSUCHOBJECT) &&
                        (vars->type != SNMP_NOSUCHINSTANCE)) {
                        /*
                         * not an exception value 
                         */
                        if (check
                            && snmp_oid_compare(name, name_length,
                                                vars->name,
                                                vars->name_length) >= 0) {
                            fprintf(stderr, "Error: OID not increasing: ");
                            fprint_objid(stderr, name, name_length);
                            fprintf(stderr, " >= ");
                            fprint_objid(stderr, vars->name,
                                         vars->name_length);
                            fprintf(stderr, "\n");
                            running = 0;
                            exitval = 1;
                        }
                        memmove((char *) name, (char *) vars->name,
                                vars->name_length * sizeof(oid));
                        name_length = vars->name_length;
                    } else
                        /*
                         * an exception value, so stop 
                         */
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
        snmp_get(ss, root, rootlen);
    }
    fclose(f);
    return exitval;
}

/*
* Estabish session
*/
struct snmp_session *setup_snmp_session(int version, char* community, char* host){

                    struct snmp_session session;
                    struct snmp_session *sess_handle;

                    init_snmp("snmpapp");
                    snmp_sess_init( &session );
                    session.version = version;
                    session.community = community;
                    session.community_len = strlen(session.community);
                    session.peername = host;
                    sess_handle = snmp_open(&session);
                    return sess_handle;

}

/*
* main
*/
int main(int argc, char * argv[]) {
    if(argc <4) {
        printf("Please supply a hostname interval_time number_of_sample\n");
        exit(1);
    }
    
    
	char *t;
	long conv = strtol(argv[2], &t, 10);	
	long num = strtol(argv[3], &t, 10);
	int r;

	oid ifip [MAX_OID_LEN];
    oid if_oid[MAX_OID_LEN];
    size_t ifip_len = MAX_OID_LEN;
    size_t if_len = MAX_OID_LEN;
    
            
	struct snmp_session   *sess_handle=setup_snmp_session(SNMP_VERSION_2c,"public",argv[1]);
	read_objid("1.3.6.1.2.1.4.20.1.1", ifip, &ifip_len);
	read_objid("1.3.6.1.2.1.4.20.1.2", if_oid, &if_len);

	//snmp_get(sess_handle, ifip, ifip_len);	
	//snmp_get(sess_handle, serial_oid, serial_len);
	printf("Interfaces and IP address\n");
	snmp_walk(sess_handle, ifip, ifip_len);
	snmp_walk(sess_handle, if_oid, if_len);
	
	
	FILE *fin;
	if( ( fin = fopen( "file.txt", "r" ) ) == NULL ) {
      fprintf( stderr, "Error opening file.\n" );
      exit( 1 );
   }
	char line[80];
	char value[80];
	char result[10][15];
	int index = 0;
	while (fgets(line, 80, fin) != NULL) {
    	sscanf(line,"%s", value);
    	//result[index] = value;
    	strcpy(result[index], value);
    	index++;
    	//printf("%s\n", value);
	}
	printf("_____________________\n");
	for (int j=0; j< index/2; j += 1) {
		printf("| %s | %s |\n", result[j], result[(index+1)/2+j]);
	}
	printf("_____________________\n");
	fclose(fin);
	oid neigip [MAX_OID_LEN];
    //oid neig_oid[MAX_OID_LEN];
    size_t neigip_len = MAX_OID_LEN;
    //size_t neig_len = MAX_OID_LEN;
	read_objid("1.3.6.1.2.1.4.22", neigip, &neigip_len);


	printf("\nNeighbour:\n");
	//snmp_walk(sess_handle, neigip, neigip_len);
	

	printf("\nTraffic:\n");
	int delta[num];
	for (int i=0; i<num; i++)
	{
	int oct1 = snmp_getInOct(sess_handle);
	int oct3 = snmp_getOutOct(sess_handle);
	delay(conv);
	int oct2 = snmp_getInOct(sess_handle);
	int oct4 = snmp_getOutOct(sess_handle);
	
	//calculate bandwidth utilization
	delta[i] = ((oct2-oct1) + (oct4-oct3) * 8 *100) / (conv*300);
	printf("--------\n");
	printf("|%d | %d|\n", i*(int)conv, delta[i]);
	}
	//snmp_get(sess_handle, inOct, inOct_len);
	snmp_close(sess_handle);
	SOCK_CLEANUP;
	return (0);
}