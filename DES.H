/***************************** des.h *************************************/
/* Header file for Data Encryption Standard Algorithms                   */
/***************************** des.h *************************************/

/* prototypes */

void setparity(char *key);
void initkey(char *key);
void encrypt(char *blk);
void decrypt(char *blk);

/* tables */

extern unsigned char Pmask[];
extern unsigned char IPtbl[];
extern unsigned char Etbl[];
extern unsigned char Ptbl[];
extern unsigned char stbl[8][4][16];
extern unsigned char PC1tbl[];
extern unsigned char PC2tbl[];
extern unsigned char ex6[8][2][4];
