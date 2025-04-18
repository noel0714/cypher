#ifndef __CYPHER_API_H_INCLUDED__
#define __CYPHER_API_H_INCLUDED__

/* --------------------------------------- include files ---------------------------------------- */
/* ---------------------------------- constant, macro definitions ------------------------------- */

/* ------------------------------------ structure definitions ------------------------------------*/
/* -------------------------------------- global variables -------------------------------------- */
/* ------------------------------------ function prototypes ------------------------------------- */

int secu_IttEncrypt    (char *ps_itt_cd, char *ps_in_cypher, char *ps_out_decdata);
int secu_IttDecrypt    (char *ps_itt_cd, char *ps_in_cypher, char *ps_out_decdata);


/* --------------------------------------- function body ---------------------------------------- */

#endif  /* #ifndef __CYPHER_API_H_INCLUDED__ */

