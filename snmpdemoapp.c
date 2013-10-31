 #include <net-snmp/net-snmp-config.h>
    #include <net-snmp/net-snmp-includes.h>
    #include <string.h>

    int snmp_get(struct snmp_session *sess_handle, oid *theoid, size_t theoid_len){
            struct snmp_pdu *pdu;
            struct snmp_pdu *response;
            struct variable_list *vars;

         
            int status;

            pdu = snmp_pdu_create(SNMP_MSG_GETNEXT);

			snmp_add_null_var(pdu, theoid, theoid_len);
			
            status = snmp_synch_response(sess_handle, pdu, &response);
			netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_QUICK_PRINT, 1);
			if (status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR) {
            for(vars = response->variables; vars; vars = vars->next_variable)
                    print_value(vars->name, vars->name_length, vars);
			if (response) {
            	snmp_free_pdu(response);
			}
			}
            return status;


    }

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

    int main(int argc, char ** argv)
    {
            if(argv[1] == NULL){
            printf("Please supply a hostname\n");
            exit(1);
    }
       oid id_oid[MAX_OID_LEN];
            oid serial_oid[MAX_OID_LEN];
            size_t id_len = MAX_OID_LEN;
            size_t serial_len = MAX_OID_LEN;
            
struct snmp_session   *sess_handle=setup_snmp_session(SNMP_VERSION_2c,"public",argv[1]);
read_objid("1.3.6.1.2.1.4.20.1.1", id_oid, &id_len);
read_objid("1.3.6.1.2.1.4.20.1.2", serial_oid, &serial_len);
snmp_get(sess_handle, id_oid, id_len);
snmp_get(sess_handle, serial_oid, serial_len);
snmp_close(sess_handle);

        return (0);
}