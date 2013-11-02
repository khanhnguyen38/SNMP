#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <arpa/inet.h>
#include <string.h>


void print_ip(int ip)
{
    unsigned char bytes[4];
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;	
    printf("%d.%d.%d.%d\n", bytes[3], bytes[2], bytes[1], bytes[0]);        
}

/**
* SNMP GETNEXT
*/
int snmp_get(struct snmp_session *sess_handle, oid *theoid, size_t theoid_len){
            struct snmp_pdu *pdu;
            struct snmp_pdu *response;
            struct variable_list *vars;

         
         int j;
            int status;

            pdu = snmp_pdu_create(SNMP_MSG_GETNEXT);

			snmp_add_null_var(pdu, theoid, theoid_len);
			
            status = snmp_synch_response(sess_handle, pdu, &response);
			netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_QUICK_PRINT, 1);
			if (status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR) {
            for(vars = response->variables; vars; vars = vars->next_variable) {
                    //print_value(vars->name, vars->name_length, vars);
                    u_char *buf;
                    size_t buf_len=256, out_len=256;
                    int i =sprint_realloc_ipaddress(&buf, &buf_len, &out_len, 1, vars, NULL, NULL, NULL);
                    
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
                   
                    print_variable(vars->name, vars->name_length, vars);
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
int main(int argc, char ** argv) {
    if(argv[1] == NULL){
        printf("Please supply a hostname\n");
        exit(1);
    }

	oid ifip [MAX_OID_LEN];
    oid if_oid[MAX_OID_LEN];
    size_t ifip_len = MAX_OID_LEN;
    size_t if_len = MAX_OID_LEN;
            
	struct snmp_session   *sess_handle=setup_snmp_session(SNMP_VERSION_2c,"public",argv[1]);
	read_objid("1.3.6.1.2.1.4.20.1.1", ifip, &ifip_len);
	read_objid("1.3.6.1.2.1.4.20.1.2", if_oid, &if_len);

	snmp_get(sess_handle, ifip, ifip_len);	
	//snmp_get(sess_handle, serial_oid, serial_len);
	printf("Interfaces and IP address\n");
	//snmp_walk(sess_handle, ifip, ifip_len);
	//snmp_walk(sess_handle, if_oid, if_len);
	
	
	oid neigip [MAX_OID_LEN];
    //oid neig_oid[MAX_OID_LEN];
    size_t neigip_len = MAX_OID_LEN;
    //size_t neig_len = MAX_OID_LEN;
	read_objid("1.3.6.1.2.1.4.22", neigip, &neigip_len);
	//read_objid("1.3.6.1.2.1.4.20.1.2", neig_oid, &neig_len);


	printf("\nNeighbour:\n");
	//snmp_walk(sess_handle, neigip, neigip_len);
//	snmp_walk(sess_handle, neig_oid, neig_len);
	
	snmp_close(sess_handle);
	SOCK_CLEANUP;
	return (0);
}