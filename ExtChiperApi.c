#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <memory.h>

#include <inc/Base64.h>
#include <inc/KeyFile.h>
#include <inc/SEED_KISA.h>

int	Ext_Chiper_Encrypt(char *comCode, char *inbuf, int insize, char *outbuf, int *outsize, char *addition)
{
	int		rc, i;
	KEY_BUFF	keyBuf;

	rc = GetCompanyKey(comCode, &keyBuf);
	if ( rc != RC_NRM)
		return rc;

	return __ext_chiper_encrypt(comCode, &keyBuf, inbuf, insize, outbuf, outsize, addition);
}

int	__ext_chiper_encrypt(char *comCode, KEY_BUFF *pKeyBuf, char *inbuf, int insize, char *outbuf, int *outsize, char *addition)
{
	int		rc, i;
	int		plen = 0;	/* 패딩길이    */
	BYTE	pc;			/* 패딩바이트  */
	
	int		tsize;
	char	*tbuf;
	
	switch(pKeyBuf->Method1) {
		case SEEDCBC :
			Mapis_SEED_CBC_Encrypt(pKeyBuf->Key, pKeyBuf->IV, inbuf, outbuf);
			*outsize = strlen(outbuf);

			break;

		case SEEDECB :
			Mapis_SEED_ECB_Encrypt(pKeyBuf->Key, pKeyBuf->Padval, inbuf, outbuf);
			*outsize = strlen(outbuf);

			break;

		case AESECB		:
		case AESECB_B64	:
            MM_AES_ECB_Encrypt(pKeyBuf->Method1, pKeyBuf->Key, pKeyBuf->Padval, inbuf, outbuf);
            *outsize = strlen(outbuf);

            break;

		case AESCBC     :
        case AESCBC_B64 :
            MM_AES_CBC_Encrypt(pKeyBuf->Method1, pKeyBuf->Key, pKeyBuf->IV, pKeyBuf->Padval, inbuf, outbuf);
            *outsize = strlen(outbuf);

            break;

		case BASE64 :
			tsize = Base64encode_len(insize);
			if(tsize <= 0)
				return RC_ERR;

			tbuf = (char*)malloc(tsize + 1);
			if(tbuf == 0x00)
				return RC_MEMFAIL;

			rc = Base64encode(tbuf, inbuf, insize);
			*(tbuf+rc) = 0x00;
			memcpy(outbuf,	tbuf,	rc);
			*outsize = rc;

			break;

		case PKCS5 :
			plen = SeedBlockSize - insize % SeedBlockSize;

			pc = (BYTE) plen;
			for( i = 0 ; i < plen; i++ ) {
				inbuf[insize+i] = pc;
			}
			*(inbuf+insize+plen) = 0x00;
				
			break;	

		default :
			rc = RC_ERR;
			goto FAIL;
	}

	switch(pKeyBuf->Method2) {

		case SEEDCBC :
			if(pKeyBuf->Method1 == BASE64) {
				Mapis_SEED_CBC_Encrypt(pKeyBuf->Key, pKeyBuf->IV, inbuf, outbuf);
				*outsize = strlen(outbuf);
			} else if(pKeyBuf->Method1 == PKCS5) {
				Mapis_SEED_CBC_Encrypt(pKeyBuf->Key, pKeyBuf->IV, inbuf, outbuf);
                *outsize = strlen(outbuf)-SeedBlockSize*2;

				memset(outbuf+*outsize, 0x00, SeedBlockSize*2);
			}

			break;
		
		case SEEDCBC_B64 :
            if(pKeyBuf->Method1 == BASE64 || pKeyBuf->Method1 == PKCS5) {
                Mapis_SEED_CBC_Encrypt_B64(pKeyBuf->Key, pKeyBuf->IV, inbuf, outbuf);
                *outsize = strlen(outbuf);
            }

            break;

		case SEEDECB :
			if(pKeyBuf->Method1 == BASE64) {
				Mapis_SEED_ECB_Encrypt(pKeyBuf->Key, pKeyBuf->Padval, tbuf, outbuf);
				*outsize = strlen(outbuf);
			}

			break;

		case AESECB     :
        case AESECB_B64 :
            MM_AES_ECB_Encrypt(pKeyBuf->Method2, pKeyBuf->Key, pKeyBuf->Padval, inbuf, outbuf);
            *outsize = strlen(outbuf);

            break;

		case AESCBC     :
        case AESCBC_B64 :
            MM_AES_CBC_Encrypt(pKeyBuf->Method2, pKeyBuf->Key, pKeyBuf->IV, pKeyBuf->Padval, inbuf, outbuf);
            *outsize = strlen(outbuf);

            break;

		case BASE64 :
			if(pKeyBuf->Method1 == SEEDECB || pKeyBuf->Method1 == SEEDCBC || pKeyBuf->Method1 == AESCBC) {
				tsize = Base64encode_len(*outsize);
				if(tsize <= 0)
					return RC_ERR;

				tbuf = (char*)malloc(tsize + 1);
				if(tbuf == 0x00)
					return RC_MEMFAIL;

				rc = Base64encode(tbuf, outbuf, *outsize);
				*(tbuf+rc) = 0x00;
				memcpy(outbuf,	tbuf,	rc);
				*outsize = rc;
			}

			break;

		default :
			break;
	}

	if(tbuf != 0x00)
		free(tbuf);

FAIL:
	return rc;
}

int	Ext_Chiper_Decrypt(char *comCode, char *inbuf, int insize, char *outbuf, int *outsize, char *addition)
{
	int	rc = RC_NRM, i;
	KEY_BUFF	keyBuf;

	rc = GetCompanyKey(comCode, &keyBuf);
	if( rc != RC_NRM)
		return rc;
	
	return __ext_chiper_decrypt(comCode, &keyBuf, inbuf, insize, outbuf, outsize, addition);
}

int	__ext_chiper_decrypt(char *comCode, KEY_BUFF *pKeyBuf, char *inbuf, int insize, char *outbuf, int *outsize, char *addition)
{
	int	rc = RC_NRM, i;
	int padValue = 0;

	int		tsize = 0;
	char	*tbuf = 0x00;
	
	switch(pKeyBuf->Method2) {

		case SEEDCBC :
			Mapis_SEED_CBC_Decrypt(pKeyBuf->Key, pKeyBuf->IV, inbuf, outbuf);
			*outsize = strlen(outbuf);

			break;

		case SEEDECB :
			Mapis_SEED_ECB_Decrypt(pKeyBuf->Key, pKeyBuf->Padval, inbuf, outbuf);
			*outsize = strlen(outbuf);
			break;

		case AESECB :
		case AESECB_B64 :
            MM_AES_ECB_Decrypt(pKeyBuf->Method2, pKeyBuf->Key, pKeyBuf->Padval, inbuf, outbuf);
            *outsize = strlen(outbuf);

            break;

		case AESCBC :
        case AESCBC_B64 :
            MM_AES_CBC_Decrypt(pKeyBuf->Method2, pKeyBuf->Key, pKeyBuf->IV, pKeyBuf->Padval, inbuf, outbuf);
            *outsize = strlen(outbuf);
            break;

		case BASE64 :
			tsize = Base64decode_len(inbuf);
			if(tsize <= 0)
				return RC_ERR;

			tbuf = (char*)malloc(tsize + 1);
			if(tbuf == 0x00)
				return RC_MEMFAIL;

			rc = Base64decode(tbuf, inbuf);
			*(tbuf+rc) = 0x00;

			break;

		case NONE :
			break;

		default :
			rc = RC_ERR;
			goto FAIL;
	}

	switch(pKeyBuf->Method1) {

		case SEEDCBC :

			rc = RC_NRM;

			if(pKeyBuf->Method2 == NONE) {
				Mapis_SEED_CBC_Decrypt(pKeyBuf->Key, pKeyBuf->IV, inbuf, outbuf);
				*outsize = strlen(outbuf);
			}
			else if(pKeyBuf->Method2 == BASE64) {
				Mapis_SEED_CBC_Decrypt(pKeyBuf->Key, pKeyBuf->IV, tbuf, outbuf);
				*outsize = strlen(outbuf);
			}

			break;

		case SEEDECB :

			rc = RC_NRM;

			if(pKeyBuf->Method2 == NONE) {
				Mapis_SEED_ECB_Decrypt(pKeyBuf->Key, pKeyBuf->Padval, inbuf, outbuf);
				*outsize = strlen(outbuf);
			}
			else if(pKeyBuf->Method2 == BASE64) {
				Mapis_SEED_ECB_Decrypt(pKeyBuf->Key, pKeyBuf->Padval, tbuf, outbuf);
				*outsize = strlen(outbuf);
			}

			break;

		case AESECB :
        case AESECB_B64 :
            MM_AES_ECB_Decrypt(pKeyBuf->Method1, pKeyBuf->Key, pKeyBuf->Padval, inbuf, outbuf);
            *outsize = strlen(outbuf);
            break;

		case AESCBC :
        case AESCBC_B64 :
            MM_AES_CBC_Decrypt(pKeyBuf->Method1, pKeyBuf->Key, pKeyBuf->IV, pKeyBuf->Padval, inbuf, outbuf);
            *outsize = strlen(outbuf);
            break;

		case BASE64 :
			rc = Base64decode(outbuf, inbuf);
			*(outbuf+rc) = 0x00;
			*outsize = rc;

			rc = RC_NRM;

			break;

		case PKCS5 :
			if(strcmp(comCode, "KBANK") != 0 && pKeyBuf->Method2 != AESECB_B64) {
				padValue = (int) outbuf[*outsize-1];
				for(i = *outsize-1; i >= *outsize-padValue; i--)
					*(outbuf+i) = 0x00;
				
				*outsize = strlen(outbuf);
			}

			break;
		default :
			rc = RC_ERR;
			break;
	}

	if(tbuf != 0x00)
		free(tbuf);

FAIL:
	return rc;
}

/*---------------------------------------------------------------------------*/
/* End of ExtChaiperApi.c                                                    */
/*---------------------------------------------------------------------------*/
