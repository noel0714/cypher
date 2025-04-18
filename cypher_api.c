#include <cypher_api.h>

/* ---------------------------------- constant, macro definitions ------------------------------- */
/* ------------------------------------ structure definitions ------------------------------------*/
/* -------------------------------------- global variables -------------------------------------- */
/* ------------------------------------ function prototypes ------------------------------------- */


/* --------------------------------------- function body ---------------------------------------- */

int secu_IttEncrypt(char *ps_itt_cd, char *ps_in_plain, char *ps_out_encdata)
{
    int rc = -1;
    int i_out_len = -1;

	char *ps_in_buf = NULL;
	
	int  i_in_len = strlen(ps_in_plain);
	int	 i_buf_size = (i_in_len + 16 - (i_in_len % 16)) * 2 + 1;
	
	ps_in_buf = malloc(i_buf_size);
    if(ps_in_buf == NULL) {
        *ps_out_encdata = 0x00;
        return -1;
    }
	memset(ps_in_buf, 0x00, i_buf_size);
	memcpy(ps_in_buf, ps_in_plain, strlen(ps_in_plain));
 
    rc = Ext_Chiper_Encrypt(ps_itt_cd, ps_in_buf, strlen(ps_in_buf), ps_out_encdata, &i_out_len, 0x00);
    
	if(ps_in_buf != NULL)
		free(ps_in_buf);

	return 0;
}

int secu_IttDecrypt(char *ps_itt_cd, char *ps_in_cyper, char *ps_out_decdata)
{
    int rc = -1;
    int i_out_len = -1;
    

	Ext_Chiper_Decrypt(ps_itt_cd, ps_in_cyper, strlen(ps_in_cyper), ps_out_decdata, &i_out_len, 0x00);
	
    return 0;
}

