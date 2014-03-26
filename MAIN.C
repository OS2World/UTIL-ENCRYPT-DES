/* data encryption standard front end
/* usage des [-e -d] keyvalue infile outfile
*/
#include <stdio.h>
#include <string.h>
#include "des.h"

void main(int argc, char *argv[])
{
   FILE *fi,*fo;
   char key[9];
   char blk[8];

   if(argc > 4)
   {
      strncpy(key,argv[2],8);
      key[8] = '\0';
      setparity(key);

      initkey(key);
      if((fi = fopen(argv[3],"rb")) != NULL)
      {
         if((fo = fopen(argv[4],"wb")) != NULL)
         {
            while(!feof(fi))
            {
               memset(blk,0,8);
               if(fread(blk,1,8,fi) != 0)
               {
                  if(stricmp(argv[1],"-e")==0)
                     encrypt(blk);
                  else
                     decrypt(blk);
                  fwrite(blk,1,8,fo);
               }
            }
            fclose(fo);
         }
         fclose(fi);
      }
   }
   else
      printf("\n USAGE: des [-e -d] keyvalue infile outfile \n");
}
