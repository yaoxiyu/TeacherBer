#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "BER/itcast_asn1_der.h"
#include "BER/itcastderlog.h"

typedef struct _Teacher
{
    char name[64];
    int age;
    char *p;
    int pLen;
}Teacher;

void freeTeacher(Teacher **pTeacher){
    if (pTeacher == NULL){
        return;
    }
    if (pTeacher != NULL){
        if ((*pTeacher)->p != NULL){
            free((*pTeacher)->p);
            (*pTeacher)->p = NULL;
        }
        free(*pTeacher);
        *pTeacher = NULL;
    }
}

int TeacherEncode(Teacher *pTeacher, unsigned char **out, int *outLen){
    int             ret = 0;
    ITCAST_ANYBUF   *pTmp = NULL;
    ITCAST_ANYBUF   *pHeadBuf = NULL;
    ITCAST_ANYBUF   *pTmpBuf = NULL;
    ITCAST_ANYBUF   *pOutData = NULL;

    unsigned char   *tmpOut = NULL;
    int             tmpOutLen = 0;

    // 把C语言的buf 转化成 ITCAST_ANYBUF
    ret = DER_ITCAST_String_To_AnyBuf(&pTmpBuf, pTeacher->name, strlen(pTeacher->name));
    if (ret != 0){
        printf("func DER_ITCAST_String_To_AnyBuf() err:%d\n", ret);
        return ret;
    }

    // 编码 name
    ret = DER_ItAsn1_WritePrintableString(pTmpBuf, &pHeadBuf);
    if (ret != 0 ){
        DER_ITCAST_FreeQueue(pTmpBuf);
        printf("func DER_ItAsn1_WritePrintableString() err:%d\n", ret);
        return ret;
    }
    DER_ITCAST_FreeQueue(pTmpBuf);
    // 两个辅助指针变量 指向 同一个节点
    pTmp = pHeadBuf;

    // 编码 age
    ret = DER_ItAsn1_WriteInteger(pTeacher->age, &(pTmp->next));
    if (ret != 0){
        printf("func DER_ItAsn1_WriteInteger() err:%d\n", ret);
        return ret;
    }
    pTmp = pTmp->next;

    // 编码 p
    ret = EncodeChar(pTeacher->p, pTeacher->pLen, &pTmp->next);
    if (ret != 0){
        printf("func EncodeChar() err:%d\n", ret);
        return ret;
    }
    pTmp = pTmp->next;

    // 编码 pLen
    ret = DER_ItAsn1_WriteInteger(pTeacher->pLen, &(pTmp->next));
    if (ret != 0){
        printf("func DER_ItAsn1_WriteInteger() err:%d\n", ret);
        return ret;
    }
    pTmp = pTmp->next;

    ret = DER_ItAsn1_WriteSequence(pHeadBuf, &pOutData);
    if (ret != 0){
        DER_ITCAST_FreeQueue(pHeadBuf);
        printf("func DER_ItAsn1_WriteSequence() err:%d\n", ret);
        return ret;
    }

    DER_ITCAST_FreeQueue(pHeadBuf);

    *out = pOutData->pData;
    *outLen = pOutData->dataLen;

    return 0;
}


int TeacherDecode(unsigned char *inData, int inLen, Teacher **pStruct){

    int             ret = 0;
    ITCAST_ANYBUF   *pTmp = NULL;
    ITCAST_ANYBUF   *pHeadBuf = NULL;
    ITCAST_ANYBUF   *pOutData = NULL;
    ITCAST_ANYBUF   *pTmpAnyBuf = NULL;

    Teacher         *pStructTeacher = NULL;
    // 转码 unsigned char * 为 ITCAST_ANYBUF
    ret = DER_ITCAST_String_To_AnyBuf(&pTmpAnyBuf, inData, inLen);
    if (ret != 0){
        if (pTmpAnyBuf != NULL){
            DER_ITCAST_FreeQueue(pTmpAnyBuf);
        }
        printf("func DER_ITCAST_String_To_AnyBuf() err:%d\n", ret);
        return ret;
    }
    // 解码 Teacher 结构体
    ret = DER_ItAsn1_ReadSequence(pTmpAnyBuf, &pHeadBuf);
    if (ret != 0){
        DER_ITCAST_FreeQueue(pTmpAnyBuf);
        printf("func DER_ItAsn1_ReadSequence() err:%d\n", ret);
        return ret;
    }

    // 给Teacher开辟内存空间
    if (pStructTeacher == NULL){
        pStructTeacher = (Teacher*)malloc(sizeof(Teacher));
        if (pStructTeacher == NULL){
            ret = -1;
            printf("Teacher malloc err:%d\n", ret);
            return ret;
        }
        memset(pStructTeacher, 0, sizeof(Teacher));
    }

    pTmp = pHeadBuf;

    // 解码 name
    ret = DER_ItAsn1_ReadPrintableString(pTmp, &pOutData);
    if (ret != 0){
        freeTeacher(&pStructTeacher);
        DER_ITCAST_FreeQueue(pHeadBuf);
        printf("func DER_ItAsn1_ReadPrintableString() err:%d\n", ret);
        return ret;
    }

    // ppPrintableString->pData  --> name
    memcpy(pStructTeacher->name, pOutData->pData, pOutData->dataLen);

    pTmp = pTmp->next;

    // 解码 age
    ret = DER_ItAsn1_ReadInteger(pTmp, &(pStructTeacher->age));
    if (ret != 0){
        freeTeacher(&pStructTeacher);
        DER_ITCAST_FreeQueue(pHeadBuf);
        printf("func DER_ItAsn1_ReadInteger() err:%d\n", ret);
        return ret;
    }

    pTmp = pTmp->next;

    // 解码 p
    ret = DER_ItAsn1_ReadPrintableString(pTmp, &pOutData);
    if (ret != 0){
        freeTeacher(&pStructTeacher);
        DER_ITCAST_FreeQueue(pHeadBuf);
        printf("func DER_ItAsn1_ReadPrintableString() err:%d\n", ret);
        return ret;
    }

    // ppPrintableString->pData  --> p
    pStructTeacher->p = malloc(pOutData->dataLen + 1);
    if (pStructTeacher->p == NULL){
        freeTeacher(&pStructTeacher);
        DER_ITCAST_FreeQueue(pHeadBuf);
        ret = -1;
        printf("Teacher->p malloc err:%d\n", ret);
        return ret;
    }
    memcpy(pStructTeacher->p, pOutData->pData, pOutData->dataLen);
    pStructTeacher->p[pOutData->dataLen] = '\0';

    pTmp = pTmp->next;

    // 解码 plen
    ret = DER_ItAsn1_ReadInteger(pTmp, &(pStructTeacher->pLen));
    if (ret != 0){
        freeTeacher(&pStructTeacher);
        DER_ITCAST_FreeQueue(pHeadBuf);
        printf("func DER_ItAsn1_ReadInteger() err:%d\n", ret);
        return ret;
    }

    *pStruct = pStructTeacher;



    return 0;
}



int myWriteFile(unsigned char *buf, int len){
    FILE *fp = NULL;
    fp = fopen("D:/teacher.ber", "wb+");
    if (fp == NULL){
        printf("fopen file error!\n");
        return -1;
    }

    fwrite(buf, 1, len, fp);
    fclose(fp);
    return 0;
}

int main(){
    int             ret = 0;
    Teacher         t1;
    Teacher         *pT2 = NULL;
    unsigned char   *myOut = NULL;
    int             myOutLen;

    t1.age = 10;
    strcpy(t1.name, "yxy");
    t1.p = malloc(64);
    strcpy(t1.p, "dsadsadas");
    t1.pLen = strlen(t1.p);

    printf("before -- myOut = %s, myOutLen = %d\n", myOut, myOutLen);

    TeacherEncode(&t1, &myOut, &myOutLen);

    printf("after -- myOut = %s, myOutLen = %d\n", myOut, myOutLen);

    // myWriteFile(myOut, myOutLen);

    TeacherDecode(myOut, myOutLen, &pT2);

    if (strcmp(pT2->name, t1.name) == 0
    && memcmp(pT2->p, t1.p, pT2->pLen) == 0){
        printf("编解码成功\n");
    } else {
        printf("编解码失败\n");
    }

    freeTeacher(&pT2);

    return 0;
    
}

