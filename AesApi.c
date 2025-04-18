/*---------------------------------------------------------------------------*/
/* AES API                                                          */
/*                                                                           */
/*---------------------------------------------------------------------------*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <memory.h>

#include <inc/aes.h>

#include <inc/KeyFile.h>
#include <inc/SEED_KISA.h>
#include <inc/aes.h>

/*---------------------------------------------------------------------------*/
void MM_AES_ECB_Encrypt(int method, unsigned char *grpKey, char padval, char *org, char *out)
{
	struct	AES_ctx ctx;

	BYTE	*pdwOutBuff;
	BYTE	tmpBlock[AES_BLOCKLEN+1];
	int 	pdwOutSize, pdwOutCnt;

	char	*encodedText;
	int		i, rc;

	int		orgsize = strlen(org);

	/*-----------------------------------------------------------------------*/
	/* Block Size 계산                                                       */
	/*-----------------------------------------------------------------------*/
	if(orgsize % AES_BLOCKLEN)
		pdwOutCnt = (orgsize / AES_BLOCKLEN) + 1;
	else
		pdwOutCnt = orgsize / AES_BLOCKLEN;

	pdwOutSize = AES_BLOCKLEN * pdwOutCnt;
	pdwOutBuff = malloc(pdwOutSize + 1);
	if(pdwOutBuff == 0x00) {
		*out = 0x00;
		return;
	}

	/*-----------------------------------------------------------------------*/
    /* AES128 Encrypt                                                        */
	/*-----------------------------------------------------------------------*/
	AES_init_ctx(&ctx, grpKey);

	memset(pdwOutBuff, padval, pdwOutSize);
	memcpy(pdwOutBuff, org , orgsize); 
	// 블럭단위 암호화
	for(i = 0; i < pdwOutSize; i+=AES_BLOCKLEN) {
		AES_ECB_encrypt(&ctx, pdwOutBuff+i);
	}

	/*-----------------------------------------------------------------------*/
    /* 출력결과 인코딩 처리                                                  */
	/*-----------------------------------------------------------------------*/
	if(method >= 30) {
		/* Base64 인코딩 */
		encodedText = malloc(pdwOutSize * 2);
		if(encodedText == 0x00) {
			*out = 0x00;
			return;
		}

		rc = Base64encode(encodedText, pdwOutBuff, pdwOutSize);
		*(encodedText+rc) = 0x00;
		memcpy(out, encodedText, rc);

		free(encodedText);
	} else{
		/* HEX 인코딩 */
		for( i = 0 ; i < pdwOutSize ; i++ ) {
			out[i*2  ] = (pdwOutBuff[i] >> 4)   + 0x30;
			out[i*2+1] = (pdwOutBuff[i] & 0x0f) + 0x30;
			if (out[i*2  ] > 0x39 ) out[i*2  ] += 7;
			if (out[i*2+1] > 0x39 ) out[i*2+1] += 7;
		}

		*(out+(pdwOutSize*2)) = 0x00;
	}

	free(pdwOutBuff);

	return;
}

/*---------------------------------------------------------------------------*/
void MM_AES_ECB_Decrypt(int method, unsigned char *grpKey, char padval, char *encorg, char *norout)
{
	struct AES_ctx ctx;

	BYTE    *pdwOutBuff;
    BYTE    tmpBlock[AES_BLOCKLEN+1];

	char	temp[4], temp2[8];
    int 	i, pos, value;

	int outBuffLen = strlen(encorg) + 1;
	pdwOutBuff = malloc(outBuffLen);
	if(pdwOutBuff == 0x00) {
		*norout = 0x00;
		return;
	}

	/*-----------------------------------------------------------------------*/
    /* 입력값 디코딩 처리                                                    */
    /*-----------------------------------------------------------------------*/
    memset(pdwOutBuff, 0x00, outBuffLen);
	if(method >= 30) {
		pos = Base64decode(pdwOutBuff, encorg);
	} else {
		for( i = 0, pos = 0 ; i < strlen(encorg) ; i += 2 ) {
			memcpy(temp, encorg+i, 2);
			temp[0] = tolower(temp[0]);
			temp[1] = tolower(temp[1]);
			sprintf(temp2, "0x%.2s", temp);
			value = strtol(temp2, 0x00, 16);
#if defined (BIG_ENDIAN)
			value = value << 24;
#endif
			memcpy(&pdwOutBuff[pos], (char*)&value,	sizeof(char));
			pos++;
		}
	}

	/*-----------------------------------------------------------------------*/
	/* AES Block 단위로 Decrypt                                             */
	/*-----------------------------------------------------------------------*/
	AES_init_ctx(&ctx, grpKey);

	for(i = 0; i < pos; i+=AES_BLOCKLEN) {
		AES_ECB_decrypt(&ctx, pdwOutBuff+i);
	}

	int		padVal = pdwOutBuff[pos-1];
	char	padMem[16+1];

	/*-----------------------------------------------------------------------*/
	/* PKCS5 패팅 초기화                                                     */
	/*-----------------------------------------------------------------------*/
	if(padVal != 0) {
		memset(padMem, padVal, padVal);
		if(memcmp(pdwOutBuff+strlen(pdwOutBuff)-padVal, padMem, padVal) == 0) {
			//printf(">>> 패딩값 초기화...[%02x]\n", padVal);
			*(pdwOutBuff+strlen(pdwOutBuff)-padVal) = 0x00;
		}

	}

	memcpy(norout,  pdwOutBuff, strlen(pdwOutBuff));
	*(norout+strlen(pdwOutBuff)) = 0x00;

	free(pdwOutBuff);

    return;
}

void MM_AES_CBC_Encrypt(int method, unsigned char *grpKey, unsigned char *iv, char padval, char *org, char *out)
{
	struct	AES_ctx ctx;

	BYTE	*pdwOutBuff;
	BYTE	tmpBlock[AES_BLOCKLEN+1];
	int 	pdwOutSize, pdwOutCnt;

	char	*encodedText;
	int		i, rc;

	int		orgsize = strlen(org);

	/*-----------------------------------------------------------------------*/
	/* Block Size 계산                                                       */
	/*-----------------------------------------------------------------------*/
	if(orgsize % AES_BLOCKLEN)
		pdwOutCnt = (orgsize / AES_BLOCKLEN) + 1;
	else
		pdwOutCnt = orgsize / AES_BLOCKLEN;

	pdwOutSize = AES_BLOCKLEN * pdwOutCnt;
	pdwOutBuff = malloc(pdwOutSize + 1);
	if(pdwOutBuff == 0x00) {
		*out = 0x00;
		return;
	}

	/*-----------------------------------------------------------------------*/
    /* AES128 Encrypt                                                        */
	/*-----------------------------------------------------------------------*/
	AES_init_ctx_iv(&ctx, grpKey, iv);
    
	memset(pdwOutBuff, padval, pdwOutSize);
	memcpy(pdwOutBuff, org , orgsize); 
	
	AES_CBC_encrypt_buffer(&ctx, pdwOutBuff, pdwOutSize);

	/*-----------------------------------------------------------------------*/
    /* 출력결과 인코딩 처리                                                  */
	/*-----------------------------------------------------------------------*/
	if(method >= 30) {
		/* Base64 인코딩 */
		encodedText = malloc(pdwOutSize * 2);
		if(encodedText == 0x00) {
			*out = 0x00;
			return;
		}

		rc = Base64encode(encodedText, pdwOutBuff, pdwOutSize);
		*(encodedText+rc) = 0x00;
		memcpy(out, encodedText, rc);

		free(encodedText);
	} else{
		/* HEX 인코딩 */
		for( i = 0 ; i < pdwOutSize ; i++ ) {
			out[i*2  ] = (pdwOutBuff[i] >> 4)   + 0x30;
			out[i*2+1] = (pdwOutBuff[i] & 0x0f) + 0x30;
			if (out[i*2  ] > 0x39 ) out[i*2  ] += 7;
			if (out[i*2+1] > 0x39 ) out[i*2+1] += 7;
		}

		*(out+(pdwOutSize*2)) = 0x00;
	}

	free(pdwOutBuff);

	return;
}

void MM_AES_CBC_Decrypt(int method, unsigned char *grpKey, unsigned char *iv, char padval, char *encorg, char *norout)
{
	struct AES_ctx ctx;

	BYTE    *pdwOutBuff;
    BYTE    tmpBlock[AES_BLOCKLEN+1];

	char	temp[4], temp2[8];
    int 	i, pos, value;

	pdwOutBuff = malloc(strlen(encorg) + 1);
	if(pdwOutBuff == 0x00) {
		*norout = 0x00;
		return;
	}
    memset(pdwOutBuff,  0x00,   strlen(encorg) + 1);

	/*-----------------------------------------------------------------------*/
    /* 입력값 디코딩 처리                                                    */
    /*-----------------------------------------------------------------------*/
	if(method >= 30) {
		pos = Base64decode(pdwOutBuff, encorg);
	} else {
		for( i = 0, pos = 0 ; i < strlen(encorg) ; i += 2 ) {
			memcpy(temp, encorg+i, 2);
			temp[0] = tolower(temp[0]);
			temp[1] = tolower(temp[1]);
			sprintf(temp2, "0x%.2s", temp);
			value = strtol(temp2, 0x00, 16);
#if defined (BIG_ENDIAN)
			value = value << 24;
#endif
			memcpy(&pdwOutBuff[pos], (char*)&value,	sizeof(char));
			pos++;
		}
	}

	/*-----------------------------------------------------------------------*/
	/* AES CBC Decrypt                                             */
	/*-----------------------------------------------------------------------*/
	AES_init_ctx_iv(&ctx, grpKey, iv);
    AES_CBC_decrypt_buffer(&ctx, pdwOutBuff, pos);

	memcpy(norout,	pdwOutBuff,	strlen(pdwOutBuff));
	*(norout+strlen(pdwOutBuff)) = 0x00;

	free(pdwOutBuff);

    return;
}


/*---------------------------------------------------------------------------*/
/* End of AesApi.c                                                          */
/*---------------------------------------------------------------------------*/
