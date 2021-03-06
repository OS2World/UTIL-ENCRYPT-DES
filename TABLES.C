/* tables.c */
/* tables for DES algorithm */

/* macros to define a permutation table */
#define ps(n)        ((unsigned char)(0x80 >> (n - 1)))
#define b(n,r)       ((n>r || n < r-7) ? 0 : ps(n-(r-8)))
#define p(n)         b(n,8),b(n,16),b(n,24),b(n,32),b(n,40),\
                     b(n,48),b(n,56),b(n,64)
#define q(n)         p((n) + 4)

/* permutation masks */
unsigned char Pmask[] = {
   p(1),p(2),p(3),p(4),p(5),p(6),p(7),p(8),
   p(9),p(10),p(11),p(12),p(13),p(14),p(15),p(16),
   p(17),p(18),p(19),p(20),p(21),p(22),p(23),p(24),
   p(25),p(26),p(27),p(28),p(29),p(30),p(31),p(32),
   p(33),p(34),p(35),p(36),p(37),p(38),p(39),p(40),
   p(41),p(42),p(43),p(44),p(45),p(46),p(47),p(48),
   p(49),p(50),p(51),p(52),p(53),p(54),p(55),p(56),
   p(57),p(58),p(59),p(60),p(61),p(62),p(63),p(64)
};

/* initial and inverse-initial permutation table */
unsigned char IPtbl[] = {
   p(58),p(50),p(42),p(34),p(26),p(18),p(10),p(2),
   p(60),p(52),p(44),p(36),p(28),p(20),p(12),p(4),
   p(62),p(54),p(46),p(38),p(30),p(22),p(14),p(6),
   p(64),p(56),p(48),p(40),p(32),p(24),p(16),p(8),
   p(57),p(49),p(41),p(33),p(25),p(17),p(9),p(1),
   p(59),p(51),p(43),p(35),p(27),p(19),p(11),p(3),
   p(61),p(53),p(45),p(37),p(29),p(21),p(13),p(5),
   p(63),p(55),p(47),p(39),p(31),p(23),p(15),p(7)
};

/* permutation table E for f functions */
unsigned char Etbl[] = {
   p(32),p(1),p(2),p(3),p(4),p(5),
   p(4),p(5),p(6),p(7),p(8),p(9),
   p(8),p(9),p(10),p(11),p(12),p(13),
   p(12),p(13),p(14),p(15),p(16),p(17),
   p(16),p(17),p(18),p(19),p(20),p(21),
   p(20),p(21),p(22),p(23),p(24),p(25),
   p(24),p(25),p(26),p(27),p(28),p(29),
   p(28),p(29),p(30),p(31),p(32),p(1)
};

/* permutation table P for f function */
unsigned char Ptbl[] = {
   p(16),p(7),p(20),p(21),p(29),p(12),p(28),p(17),
   p(1),p(15),p(23),p(26),p(5),p(8),p(31),p(10),
   p(2),p(8),p(24),p(14),p(32),p(27),p(3),p(9),
   p(19),p(13),p(30),p(6),p(22),p(11),p(4),p(25)
};

/* table for converting six bit to four bit streams */
unsigned char  stbl[8][4][16] = {
/* s1 */
   14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,
   0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,
   4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,
   15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13,
/* s2 */
   15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10,
   3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,
   0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15,
   13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9,
/* s3 */
   10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8,
   13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,
   13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,
   1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12,
/* s4 */
   7,14,13,3,0,6,9,10,1,2,8,5,1,12,4,15,
   13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,
   10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,
   3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14,
/* s5 */
   2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9,
   14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,
   4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14,
   11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3,
/* s6 */
   12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11,
   10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,
   9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,
   4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13,
/* s7 */
   4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,
   13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,
   1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,
   6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12,
/* s8 */
   13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,
   1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,
   7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8,
   2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11
};

/* Permuted choice l for Key Schedule calculation */
unsigned char PC1tbl[] = {
   p(57),p(49),p(41),p(33),p(25),p(17),p(9),
   p(1),p(58),p(50),p(42),p(34),p(26),p(18),
   p(10),p(2),p(59),p(51),p(43),p(35),p(27),
   p(19),p(11),p(3),p(60),p(52),p(44),p(36),
   p(0),p(0),p(0),p(0),

   p(63),p(55),p(47),p(39),p(31),p(23),p(15),
   p(7),p(62),p(54),p(46),p(38),p(30),p(22),
   p(14),p(6),p(61),p(53),p(45),p(37),p(29),
   p(21),p(13),p(5),p(28),p(20),p(12),p(4),
   p(0),p(0),p(0),p(0)
   };
/* Permuted choice l for Key Schedule calculation */
unsigned char PC2tbl[] = {
   p(14),p(17),p(11),p(24),p(1),p(5),p(3),p(28),
   p(15),p(6),p(21),p(10),p(23),p(19),p(12),p(4),
   p(26),p(8),p(16),p(7),p(27),p(20),p(13),p(2),

   p(41),p(52),p(31),p(27),p(1),p(5),p(3),p(28),
   p(15),p(45),p(33),p(48),p(44),p(49),p(39),p(56),
   p(34),p(53),p(46),p(42),p(50),p(36),p(29),p(32)
   };

/* For extracting 6-bit strings from 64 bit string */
unsigned char ex6[8][2][4] = {
   /* byte , >> <<, & */
   /* s=8 */
   0,2,0,0x3f,
   0,2,0,0x3f,
   /* s=7 */
   0,0,4,0x30,
   1,4,0,0x0f,
   /* s=6 */
   1,0,2,0x3c,
   2,6,0,0x03,
   /* s=5 */
   2,0,0,0x3f,
   2,0,0,0x3f,
   /* s=4 */
   3,2,0,0x3f,
   3,2,0,0x3f,
   /* s=3 */
   3,0,4,0x30,
   4,4,0,0x0f,
   /* s=2 */
   4,0,2,0x3c,
   5,6,0,0x03,
   /* s=1 */
   5,0,0,0x3f,
   5,0,0,0x3f,
};

