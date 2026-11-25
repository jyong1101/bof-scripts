CC ?= gcc
SRC = src
W   = -w
B32 = -m32 -fno-stack-protector -z execstack -no-pie -fno-omit-frame-pointer $(W)
F32 = -m32 -fno-stack-protector            -no-pie -fno-omit-frame-pointer $(W)
.PHONY: all clean
B64 = -fno-stack-protector -no-pie -fno-omit-frame-pointer $(W)

all: flags chatty_echo chatty_echo-pad varsrc winarg64 align64 menu32 cyclic32 fmtwrite32 got32 pie32 canary32 blind32 pieblind32 canaryfork32 relro32 combo64 ret2libc32 libc64 scanf32 twoarg64 var64 strarg64 twoarg32 strcpy32 pie64 threearg64 gated32 alarm32 decoywin32 fixedread32 scanfnum32 randbanner32 filtered32 toupper32 login32 cyclic32 fmtwrite32 got32 pie32 canary32 blind32 pieblind32 canaryfork32 relro32 combo64 ret2libc32 libc64 scanf32 twoarg64 var64 strarg64 twoarg32 strcpy32 pie64 threearg64 gated32 alarm32 decoywin32 fixedread32 scanfnum32 randbanner32 filtered32 toupper32 got32 pie32 canary32 blind32 pieblind32 canaryfork32 relro32 combo64 ret2libc32 libc64 scanf32 twoarg64 var64 strarg64 twoarg32 strcpy32 pie64 threearg64 gated32 alarm32 decoywin32 fixedread32 scanfnum32 randbanner32 filtered32 toupper32 canary32 blind32 pieblind32 canaryfork32 relro32 combo64 ret2libc32 libc64 scanf32 twoarg64 var64 strarg64 twoarg32 strcpy32 pie64 threearg64 gated32 alarm32 decoywin32 fixedread32 scanfnum32 randbanner32 filtered32 toupper32 pieblind32 canaryfork32 relro32 combo64 ret2libc32 libc64 scanf32 twoarg64 var64 strarg64 twoarg32 strcpy32 pie64 threearg64 gated32 alarm32 decoywin32 fixedread32 scanfnum32 randbanner32 filtered32 toupper32 relro32 combo64 ret2libc32 libc64 scanf32 twoarg64 var64 strarg64 twoarg32 strcpy32 pie64 threearg64 gated32 alarm32 decoywin32 fixedread32 scanfnum32 randbanner32 filtered32 toupper32 ret2libc32 libc64 scanf32 twoarg64 var64 strarg64 twoarg32 strcpy32 pie64 threearg64 gated32 alarm32 decoywin32 fixedread32 scanfnum32 randbanner32 filtered32 toupper32 scanf32 twoarg64 var64 strarg64 twoarg32 strcpy32 pie64 threearg64 gated32 alarm32 decoywin32 fixedread32 scanfnum32 randbanner32 filtered32 toupper32 var64 strarg64 twoarg32 strcpy32 pie64 threearg64 gated32 alarm32 decoywin32 fixedread32 scanfnum32 randbanner32 filtered32 toupper32 twoarg32 strcpy32 pie64 threearg64 gated32 alarm32 decoywin32 fixedread32 scanfnum32 randbanner32 filtered32 toupper32 gated32 alarm32 decoywin32 fixedread32 scanfnum32 randbanner32 filtered32 toupper32 gated32 alarm32 decoywin32 fixedread32 scanfnum32 randbanner32 filtered32 toupper32 filtered32 toupper32 fmtsecret32 fmtsecret64 fmtglobal64 fmtglobal32 fmtsmall32 fmttarget64 fmtnonzero64 fmtnonzero32 fmtgotwin32 fmtgotwin64 fmtcanary32 fmtcanary64 fmtpie32 fmtpie64 fmtboth64 fmtprefix32 fmtshort32 adjchar32 adjbool32 adjbool64 adjone32 varpair32 adjmem32 adjcmd32 shellwin32 shellwin64 bufleak32 bufleak64 bufsmall32 fmtguess32 fmtguess64 fmtpass32 fmtgotshell32 varscanf32 varstrcpy32 locone64 locstr32 randguard32 randguard64 randarg32 gatedfmt32 hexwin32 revwin32 fmtloop32 tight64 smalldec32 loginfmt32 randarg2_32 randarg64 fmtrandlocal32 echoloop32 decoyfmt32 decoytaunt32 plainshift32 plainshift32-pad gatedecho32 gatedecho32-pad gatedshift32 gatedshift32-pad slowcanary32 gatedshell32 menulibc32 logincanary32 menufmt32 menucanary32 gatedpie32 loginread32 gatedcanary32 scanfshell32 tworead32 fnptr32 strncpy32 papercode32 paperkey32 paperlogin32 paperlab64 labcalc64 twoprompt64 twoquiet64 nameecho32 namelibc32 namebuf32 echoname32 paperquiet64 fmtglobbuf32 floodguard64 fmtpieone64 tokecho32 hintreply32 freeflag32 fmtexample32 fmtsession32 lencheck32 taghex32 canarysay32 canarymute32
chatty_echo:     $(SRC)/chatty_echo.c ; $(CC) $(B32) -I$(SRC) -o $@ $<
chatty_echo-pad: $(SRC)/chatty_echo.c ; $(CC) $(B32) -DPAD -I$(SRC) -o $@ $<
varsrc:          $(SRC)/varsrc.c      ; $(CC) $(F32) -I$(SRC) -o $@ $<
winarg64: $(SRC)/winarg64.c ; $(CC) $(B64) -I$(SRC) -o $@ $<
align64:  $(SRC)/align64.c  ; $(CC) $(B64) -I$(SRC) -o $@ $<

menu32: $(SRC)/menu32.c ; $(CC) $(F32) -I$(SRC) -o $@ $<

cyclic32: $(SRC)/cyclic32.c ; $(CC) $(B32) -I$(SRC) -o $@ $<

fmtwrite32: $(SRC)/fmtwrite32.c ; $(CC) $(F32) -I$(SRC) -o $@ $<

got32: $(SRC)/got32.c ; $(CC) $(F32) -z norelro -I$(SRC) -o $@ $<

P32 = -m32 -fno-stack-protector -pie -fPIE -fno-omit-frame-pointer $(W)
pie32: $(SRC)/pie32.c ; $(CC) $(P32) -I$(SRC) -o $@ $<

C32 = -m32 -fstack-protector-all -no-pie -fno-omit-frame-pointer $(W)
canary32: $(SRC)/canary32.c ; $(CC) $(C32) -I$(SRC) -o $@ $<

blind32: $(SRC)/blind32.c ; $(CC) $(B32) -I$(SRC) -o $@ $<

pieblind32: $(SRC)/pieblind32.c ; $(CC) $(P32) -I$(SRC) -o $@ $<

canaryfork32: $(SRC)/canaryfork32.c ; $(CC) $(C32) -I$(SRC) -o $@ $<

R32 = -m32 -fno-stack-protector -no-pie -fno-omit-frame-pointer -Wl,-z,relro,-z,now $(W)
relro32: $(SRC)/relro32.c ; $(CC) $(R32) -I$(SRC) -o $@ $<

K64 = -fstack-protector-all -no-pie -fno-omit-frame-pointer $(W)
combo64: $(SRC)/combo64.c ; $(CC) $(K64) -I$(SRC) -o $@ $<

ret2libc32: $(SRC)/ret2libc32.c ; $(CC) $(F32) -I$(SRC) -o $@ $<

N64 = -fno-stack-protector -no-pie -fno-omit-frame-pointer $(W)
libc64: $(SRC)/libc64.c ; $(CC) $(N64) -I$(SRC) -o $@ $<

twoarg32: $(SRC)/twoarg32.c ; $(CC) $(B32) -I$(SRC) -o $@ $<
strcpy32: $(SRC)/strcpy32.c ; $(CC) $(B32) -I$(SRC) -o $@ $<
pie64: $(SRC)/pie64.c ; $(CC) -fno-stack-protector -fpie -pie -fno-omit-frame-pointer $(W) -I$(SRC) -o $@ $<
filtered32: $(SRC)/filtered32.c ; $(CC) $(B32) -I$(SRC) -o $@ $<
toupper32: $(SRC)/toupper32.c ; $(CC) $(B32) -I$(SRC) -o $@ $<

alarm32: $(SRC)/alarm32.c ; $(CC) $(B32) -I$(SRC) -o $@ $<
decoywin32: $(SRC)/decoywin32.c ; $(CC) $(B32) -I$(SRC) -o $@ $<
fixedread32: $(SRC)/fixedread32.c ; $(CC) $(B32) -I$(SRC) -o $@ $<
scanfnum32: $(SRC)/scanfnum32.c ; $(CC) $(B32) -I$(SRC) -o $@ $<
randbanner32: $(SRC)/randbanner32.c ; $(CC) $(B32) -I$(SRC) -o $@ $<

plainshift32: $(SRC)/gatedshift32.c ; $(CC) $(B32) -DNOGATE -I$(SRC) -o $@ $<
plainshift32-pad: $(SRC)/gatedshift32.c ; $(CC) $(B32) -DNOGATE -DPAD -I$(SRC) -o $@ $<
gatedecho32: $(SRC)/gatedecho32.c ; $(CC) -m32 -fno-stack-protector -z execstack -no-pie -fno-omit-frame-pointer $(W) -I$(SRC) -o $@ $<
gatedecho32-pad: $(SRC)/gatedecho32.c ; $(CC) -m32 -fno-stack-protector -z execstack -no-pie -fno-omit-frame-pointer -DPAD $(W) -I$(SRC) -o $@ $<
gatedshift32: $(SRC)/gatedshift32.c ; $(CC) $(B32) -I$(SRC) -o $@ $<
gatedshift32-pad: $(SRC)/gatedshift32.c ; $(CC) $(B32) -DPAD -I$(SRC) -o $@ $<
slowcanary32: $(SRC)/slowcanary32.c ; $(CC) $(C32) -I$(SRC) -o $@ $<
gatedshell32: $(SRC)/gatedshell32.c ; $(CC) $(B32) -I$(SRC) -o $@ $<
menulibc32: $(SRC)/menulibc32.c ; $(CC) $(F32) -I$(SRC) -o $@ $<
logincanary32: $(SRC)/logincanary32.c ; $(CC) $(C32) -I$(SRC) -o $@ $<
menufmt32: $(SRC)/menufmt32.c ; $(CC) $(F32) -I$(SRC) -o $@ $<
menucanary32: $(SRC)/menucanary32.c ; $(CC) $(C32) -I$(SRC) -o $@ $<
gatedpie32: $(SRC)/gatedpie32.c ; $(CC) $(P32) -I$(SRC) -o $@ $<
loginread32: $(SRC)/loginread32.c ; $(CC) $(B32) -I$(SRC) -o $@ $<
gatedcanary32: $(SRC)/gatedcanary32.c ; $(CC) $(C32) -I$(SRC) -o $@ $<
scanfshell32: $(SRC)/scanfshell32.c ; $(CC) $(B32) -I$(SRC) -o $@ $<
tworead32: $(SRC)/tworead32.c ; $(CC) $(B32) -I$(SRC) -o $@ $<
fnptr32: $(SRC)/fnptr32.c ; $(CC) $(B32) -I$(SRC) -o $@ $<
strncpy32: $(SRC)/strncpy32.c ; $(CC) $(B32) -I$(SRC) -o $@ $<
login32: $(SRC)/login32.c ; $(CC) $(B32) -I$(SRC) -o $@ $<

gated32: $(SRC)/gated32.c ; $(CC) $(B32) -I$(SRC) -o $@ $<



threearg64: $(SRC)/threearg64.c ; $(CC) $(B64) -I$(SRC) -o $@ $<

strarg64: $(SRC)/strarg64.c ; $(CC) $(B64) -I$(SRC) -o $@ $<

var64: $(SRC)/var64.c ; $(CC) $(B64) -I$(SRC) -o $@ $<

twoarg64: $(SRC)/twoarg64.c ; $(CC) $(B64) -I$(SRC) -o $@ $<

scanf32: $(SRC)/scanf32.c ; $(CC) $(B32) -I$(SRC) -o $@ $<

# --- round 3 (21 Nov): format-string family + frame-read guards. See bof.md "Round 3".
fmtsecret32: $(SRC)/fmtsecret32.c ; $(CC) -m32 -fno-stack-protector -no-pie -fno-omit-frame-pointer $(W) -I$(SRC) -o $@ $<
fmtsecret64: $(SRC)/fmtsecret64.c ; $(CC) -fno-stack-protector -no-pie -fno-omit-frame-pointer $(W) -I$(SRC) -o $@ $<
fmtglobal64: $(SRC)/fmtglobal64.c ; $(CC) -fno-stack-protector -no-pie -fno-omit-frame-pointer $(W) -I$(SRC) -o $@ $<
fmtglobal32: $(SRC)/fmtglobal32.c ; $(CC) -m32 -fno-stack-protector -no-pie -fno-omit-frame-pointer $(W) -I$(SRC) -o $@ $<
fmtsmall32: $(SRC)/fmtsmall32.c ; $(CC) -m32 -fno-stack-protector -no-pie -fno-omit-frame-pointer $(W) -I$(SRC) -o $@ $<
fmttarget64: $(SRC)/fmttarget64.c ; $(CC) -fno-stack-protector -no-pie -fno-omit-frame-pointer $(W) -I$(SRC) -o $@ $<
fmtnonzero64: $(SRC)/fmtnonzero64.c ; $(CC) -fno-stack-protector -no-pie -fno-omit-frame-pointer $(W) -I$(SRC) -o $@ $<
fmtnonzero32: $(SRC)/fmtnonzero32.c ; $(CC) -m32 -fno-stack-protector -no-pie -fno-omit-frame-pointer $(W) -I$(SRC) -o $@ $<
fmtgotwin32: $(SRC)/fmtgotwin32.c ; $(CC) -m32 -fno-stack-protector -no-pie -fno-omit-frame-pointer $(W) -I$(SRC) -o $@ $<
fmtgotwin64: $(SRC)/fmtgotwin64.c ; $(CC) -fno-stack-protector -no-pie -fno-omit-frame-pointer $(W) -I$(SRC) -o $@ $<
fmtcanary32: $(SRC)/fmtcanary32.c ; $(CC) -m32 -fstack-protector-all -no-pie -fno-omit-frame-pointer $(W) -I$(SRC) -o $@ $<
fmtcanary64: $(SRC)/fmtcanary64.c ; $(CC) -fstack-protector-all -no-pie -fno-omit-frame-pointer $(W) -I$(SRC) -o $@ $<
fmtpie32: $(SRC)/fmtpie32.c ; $(CC) -m32 -fno-stack-protector -pie -fPIE -fno-omit-frame-pointer $(W) -I$(SRC) -o $@ $<
fmtpie64: $(SRC)/fmtpie64.c ; $(CC) -fno-stack-protector -pie -fPIE -fno-omit-frame-pointer $(W) -I$(SRC) -o $@ $<
fmtboth64: $(SRC)/fmtboth64.c ; $(CC) -fstack-protector-all -pie -fPIE -fno-omit-frame-pointer $(W) -I$(SRC) -o $@ $<
fmtprefix32: $(SRC)/fmtprefix32.c ; $(CC) -m32 -fno-stack-protector -no-pie -fno-omit-frame-pointer $(W) -I$(SRC) -o $@ $<
fmtshort32: $(SRC)/fmtshort32.c ; $(CC) -m32 -fno-stack-protector -no-pie -fno-omit-frame-pointer $(W) -I$(SRC) -o $@ $<
adjchar32: $(SRC)/adjchar32.c ; $(CC) -m32 -fno-stack-protector -no-pie -fno-omit-frame-pointer $(W) -I$(SRC) -o $@ $<
adjbool32: $(SRC)/adjbool32.c ; $(CC) -m32 -fno-stack-protector -no-pie -fno-omit-frame-pointer $(W) -I$(SRC) -o $@ $<
adjbool64: $(SRC)/adjbool64.c ; $(CC) -fno-stack-protector -no-pie -fno-omit-frame-pointer $(W) -I$(SRC) -o $@ $<
adjone32: $(SRC)/adjone32.c ; $(CC) -m32 -fno-stack-protector -no-pie -fno-omit-frame-pointer $(W) -I$(SRC) -o $@ $<
varpair32: $(SRC)/varpair32.c ; $(CC) -m32 -fno-stack-protector -no-pie -fno-omit-frame-pointer $(W) -I$(SRC) -o $@ $<
adjmem32: $(SRC)/adjmem32.c ; $(CC) -m32 -fno-stack-protector -no-pie -fno-omit-frame-pointer $(W) -I$(SRC) -o $@ $<
adjcmd32: $(SRC)/adjcmd32.c ; $(CC) -m32 -fno-stack-protector -no-pie -fno-omit-frame-pointer $(W) -I$(SRC) -o $@ $<
shellwin32: $(SRC)/shellwin32.c ; $(CC) -m32 -fno-stack-protector -no-pie -fno-omit-frame-pointer $(W) -I$(SRC) -o $@ $<
shellwin64: $(SRC)/shellwin64.c ; $(CC) -fno-stack-protector -no-pie -fno-omit-frame-pointer $(W) -I$(SRC) -o $@ $<
bufleak32: $(SRC)/bufleak32.c ; $(CC) -m32 -fno-stack-protector -no-pie -z execstack -fno-omit-frame-pointer $(W) -I$(SRC) -o $@ $<
bufleak64: $(SRC)/bufleak64.c ; $(CC) -fno-stack-protector -no-pie -z execstack -fno-omit-frame-pointer $(W) -I$(SRC) -o $@ $<
bufsmall32: $(SRC)/bufsmall32.c ; $(CC) -m32 -fno-stack-protector -no-pie -z execstack -fno-omit-frame-pointer $(W) -I$(SRC) -o $@ $<
fmtguess32: $(SRC)/fmtguess32.c ; $(CC) -m32 -fno-stack-protector -no-pie -fno-omit-frame-pointer $(W) -I$(SRC) -o $@ $<
fmtguess64: $(SRC)/fmtguess64.c ; $(CC) -fno-stack-protector -no-pie -fno-omit-frame-pointer $(W) -I$(SRC) -o $@ $<
fmtpass32: $(SRC)/fmtpass32.c ; $(CC) -m32 -fno-stack-protector -no-pie -fno-omit-frame-pointer $(W) -I$(SRC) -o $@ $<
fmtgotshell32: $(SRC)/fmtgotshell32.c ; $(CC) -m32 -fno-stack-protector -no-pie -fno-omit-frame-pointer $(W) -I$(SRC) -o $@ $<
varscanf32: $(SRC)/varscanf32.c ; $(CC) -m32 -fno-stack-protector -no-pie -fno-omit-frame-pointer $(W) -I$(SRC) -o $@ $<
varstrcpy32: $(SRC)/varstrcpy32.c ; $(CC) -m32 -fno-stack-protector -no-pie -fno-omit-frame-pointer $(W) -I$(SRC) -o $@ $<
locone64: $(SRC)/locone64.c ; $(CC) -fno-stack-protector -no-pie -fno-omit-frame-pointer $(W) -I$(SRC) -o $@ $<
locstr32: $(SRC)/locstr32.c ; $(CC) -m32 -fno-stack-protector -no-pie -fno-omit-frame-pointer $(W) -I$(SRC) -o $@ $<
# --- round 5: anti-script (per-connection values, gates, disguised flags) + lab's last exercise
randguard32: $(SRC)/randguard32.c ; $(CC) -m32 -fno-stack-protector -no-pie -fno-omit-frame-pointer $(W) -I$(SRC) -o $@ $<
randguard64: $(SRC)/randguard64.c ; $(CC) -fno-stack-protector -no-pie -fno-omit-frame-pointer $(W) -I$(SRC) -o $@ $<
randarg32: $(SRC)/randarg32.c ; $(CC) -m32 -fno-stack-protector -no-pie -fno-omit-frame-pointer $(W) -I$(SRC) -o $@ $<
gatedfmt32: $(SRC)/gatedfmt32.c ; $(CC) -m32 -fno-stack-protector -no-pie -fno-omit-frame-pointer $(W) -I$(SRC) -o $@ $<
hexwin32: $(SRC)/hexwin32.c ; $(CC) -m32 -fno-stack-protector -no-pie -fno-omit-frame-pointer $(W) -I$(SRC) -o $@ $<
revwin32: $(SRC)/revwin32.c ; $(CC) -m32 -fno-stack-protector -no-pie -fno-omit-frame-pointer $(W) -I$(SRC) -o $@ $<
fmtloop32: $(SRC)/fmtloop32.c ; $(CC) -m32 -fno-stack-protector -no-pie -fno-omit-frame-pointer $(W) -I$(SRC) -o $@ $<
tight64: $(SRC)/tight64.c ; $(CC) -fno-stack-protector -no-pie -fno-omit-frame-pointer $(W) -I$(SRC) -o $@ $<
smalldec32: $(SRC)/smalldec32.c ; $(CC) -m32 -fno-stack-protector -no-pie -fno-omit-frame-pointer $(W) -I$(SRC) -o $@ $<
# --- round 7
loginfmt32: $(SRC)/loginfmt32.c ; $(CC) -m32 -fno-stack-protector -no-pie -fno-omit-frame-pointer $(W) -I$(SRC) -o $@ $<
randarg2_32: $(SRC)/randarg2_32.c ; $(CC) -m32 -fno-stack-protector -no-pie -fno-omit-frame-pointer $(W) -I$(SRC) -o $@ $<
randarg64: $(SRC)/randarg64.c ; $(CC) -fno-stack-protector -no-pie -fno-omit-frame-pointer $(W) -I$(SRC) -o $@ $<
fmtrandlocal32: $(SRC)/fmtrandlocal32.c ; $(CC) -m32 -fno-stack-protector -no-pie -fno-omit-frame-pointer $(W) -I$(SRC) -o $@ $<
echoloop32: $(SRC)/echoloop32.c ; $(CC) -m32 -fno-stack-protector -no-pie -z execstack $(W) -I$(SRC) -o $@ $<
decoyfmt32: $(SRC)/decoyfmt32.c ; $(CC) -m32 -fno-stack-protector -no-pie -fno-omit-frame-pointer $(W) -I$(SRC) -o $@ $<
decoytaunt32: $(SRC)/decoytaunt32.c ; $(CC) -m32 -fno-stack-protector -no-pie -fno-omit-frame-pointer $(W) -I$(SRC) -o $@ $<
# --- round 23: the value is on the PAPER (out of band)
papercode32: $(SRC)/papercode32.c ; $(CC) -m32 -fno-stack-protector -no-pie -fno-omit-frame-pointer $(W) -I$(SRC) -o $@ $<
paperkey32: $(SRC)/paperkey32.c ; $(CC) -m32 -fno-stack-protector -no-pie -fno-omit-frame-pointer $(W) -I$(SRC) -o $@ $<
paperlogin32: $(SRC)/paperlogin32.c ; $(CC) -m32 -fno-stack-protector -no-pie -fno-omit-frame-pointer $(W) -I$(SRC) -o $@ $<
paperlab64: $(SRC)/paperlab64.c ; $(CC) -fno-stack-protector -no-pie -fno-omit-frame-pointer $(W) -I$(SRC) -o $@ $<
labcalc64: $(SRC)/labcalc64.c ; $(CC) -fno-stack-protector -no-pie -fno-omit-frame-pointer $(W) -I$(SRC) -o $@ $<
twoprompt64: $(SRC)/twoprompt64.c ; $(CC) -fno-stack-protector -no-pie -fno-omit-frame-pointer $(W) -I$(SRC) -o $@ $<
twoquiet64: $(SRC)/twoquiet64.c ; $(CC) -fno-stack-protector -no-pie -fno-omit-frame-pointer $(W) -I$(SRC) -o $@ $<
nameecho32: $(SRC)/nameecho32.c ; $(CC) $(B32) -I$(SRC) -o $@ $<
namelibc32: $(SRC)/namelibc32.c ; $(CC) $(F32) -I$(SRC) -o $@ $<
namebuf32: $(SRC)/namebuf32.c ; $(CC) -m32 -fno-stack-protector -no-pie -z execstack -fno-omit-frame-pointer $(W) -I$(SRC) -o $@ $<
echoname32: $(SRC)/echoname32.c ; $(CC) -m32 -fno-stack-protector -no-pie -z execstack -fno-omit-frame-pointer $(W) -I$(SRC) -o $@ $<
paperquiet64: $(SRC)/paperquiet64.c ; $(CC) -fno-stack-protector -no-pie -fno-omit-frame-pointer $(W) -I$(SRC) -o $@ $<
fmtglobbuf32: $(SRC)/fmtglobbuf32.c ; $(CC) -m32 -fno-stack-protector -no-pie $(W) -I$(SRC) -o $@ $<
floodguard64: $(SRC)/floodguard64.c ; $(CC) -fno-stack-protector -no-pie -fno-omit-frame-pointer $(W) -I$(SRC) -o $@ $<
fmtpieone64: $(SRC)/fmtpieone64.c ; $(CC) -fno-stack-protector -pie -fPIE $(W) -I$(SRC) -o $@ $<
tokecho32: $(SRC)/tokecho32.c ; $(CC) -m32 -fno-stack-protector -no-pie -z execstack $(W) -I$(SRC) -o $@ $<
hintreply32: $(SRC)/hintreply32.c ; $(CC) -m32 -fno-stack-protector -no-pie $(W) -I$(SRC) -o $@ $<
freeflag32: $(SRC)/freeflag32.c ; $(CC) -m32 -fno-stack-protector -no-pie $(W) -I$(SRC) -o $@ $<
fmtexample32: $(SRC)/fmtexample32.c ; $(CC) -m32 -fno-stack-protector -no-pie $(W) -I$(SRC) -o $@ $<
fmtsession32: $(SRC)/fmtsession32.c ; $(CC) -m32 -fno-stack-protector -no-pie $(W) -I$(SRC) -o $@ $<
lencheck32: $(SRC)/lencheck32.c ; $(CC) -m32 -fno-stack-protector -no-pie $(W) -I$(SRC) -o $@ $<
taghex32: $(SRC)/taghex32.c ; $(CC) -m32 -fno-stack-protector -no-pie -fno-omit-frame-pointer $(W) -I$(SRC) -o $@ $<
canarysay32: $(SRC)/canarysay32.c ; $(CC) $(C32) -I$(SRC) -o $@ $<
canarymute32: $(SRC)/canarymute32.c ; $(CC) $(C32) -I$(SRC) -o $@ $<

clean: ; rm -f chatty_echo chatty_echo-pad varsrc winarg64 align64 menu32 cyclic32 fmtwrite32 got32 pie32 canary32 blind32 pieblind32 canaryfork32 relro32 combo64 ret2libc32 libc64 scanf32 twoarg64 var64 strarg64 twoarg32 strcpy32 pie64 threearg64 gated32 alarm32 decoywin32 fixedread32 scanfnum32 randbanner32 filtered32 toupper32 fmtsecret32 fmtsecret64 fmtglobal64 fmtglobal32 fmtsmall32 fmttarget64 fmtnonzero64 fmtnonzero32 fmtgotwin32 fmtgotwin64 fmtcanary32 fmtcanary64 fmtpie32 fmtpie64 fmtboth64 fmtprefix32 fmtshort32 adjchar32 adjbool32 adjbool64 adjone32 varpair32 adjmem32 adjcmd32 shellwin32 shellwin64 bufleak32 bufleak64 bufsmall32 fmtguess32 fmtguess64 fmtpass32 fmtgotshell32 varscanf32 varstrcpy32 locone64 locstr32 randguard32 randguard64 randarg32 gatedfmt32 hexwin32 revwin32 fmtloop32 tight64 smalldec32 loginfmt32 randarg2_32 randarg64 fmtrandlocal32 echoloop32 decoyfmt32 decoytaunt32 plainshift32 plainshift32-pad gatedecho32 gatedecho32-pad gatedshift32 gatedshift32-pad slowcanary32 gatedshell32 menulibc32 logincanary32 menufmt32 menucanary32 gatedpie32 loginread32 gatedcanary32 scanfshell32 tworead32 fnptr32 strncpy32 papercode32 paperkey32 paperlogin32 paperlab64 labcalc64 twoprompt64 twoquiet64 nameecho32 namelibc32 namebuf32 echoname32 paperquiet64 fmtglobbuf32 floodguard64 fmtpieone64 tokecho32 hintreply32 freeflag32 fmtexample32 fmtsession32 lencheck32 taghex32 canarysay32 canarymute32

# Dummy flags, regenerated so a fresh checkout/backup is self-sufficient.
# They were previously only on disk, so a restored copy failed every test.
.PHONY: flags
flags:
	@mkdir -p flags
	@printf 'SIT{chatty_echo_shift}\n' > flags/chatty.txt
	@printf 'SIT{var_from_source}\n' > flags/varsrc.txt
	@printf 'SIT{r0p_w1th_arg}\n' > flags/winarg.txt
	@printf 'SIT{st4ck_4l1gned}\n' > flags/align.txt
	@printf 'SIT{m3nu_n4v1g4t3d}\n' > flags/menu.txt
	@printf 'SIT{cycl1c_0ffs3t}\n' > flags/cyclic.txt
	@printf 'SIT{ex4ct_hn_wr1t3}\n' > flags/fmtwrite.txt
	@printf 'SIT{g0t_0v3rwr1t3_sh3ll}\n' > flags/got.txt
	@printf 'SIT{p13_r3b4s3d}\n' > flags/pie.txt
	@printf 'SIT{c4n4ry_pr3s3rv3d}\n' > flags/canary.txt
	@printf 'SIT{bl1nd_cr4sh_0r4cl3}\n' > flags/blind.txt
	@printf 'SIT{p4rt14l_0v3rwr1t3}\n' > flags/pieblind.txt
	@printf 'SIT{c4n4ry_brut3d}\n' > flags/canaryfork.txt
	@printf 'SIT{full_r3lr0_d4t4_ptr}\n' > flags/relro.txt
	@printf 'SIT{c0mp0s3d_unse3n_sh4p3}\n' > flags/combo.txt
	@printf 'SIT{r3t2l1bc_ch41n}\n' > flags/libc.txt
	@printf 'SIT{r3t2l1bc_64b1t}\n' > flags/libc64.txt
	@printf 'SIT{sc4nf_wh1t3sp4c3}\n' > flags/scanf.txt
	@printf 'SIT{tw0_4rg_r0p}\n' > flags/twoarg.txt
	@printf 'SIT{v4r64_m0v_cmp}\n' > flags/var64.txt
	@printf 'SIT{p0int3r_4rg_r0p}\n' > flags/strarg.txt
	@printf 'SIT{cd3cl_tw0_4rgs}\n' > flags/twoarg32.txt
	@printf 'SIT{strcpy_n0_nulls}\n' > flags/strcpy32.txt
	@printf 'SIT{p13_64b1t_r3b4s3}\n' > flags/pie64.txt
	@printf 'SIT{thr33_4rg_rdx}\n' > flags/threearg.txt
	@printf 'SIT{0ff_by_0n3_3bp}\n' > flags/offbyone.txt
	@printf 'SIT{g4t3s_b34t3n_l1v3}\n' > flags/guarded.txt
	@printf 'SIT{l1v3_g4t3s_4nsw3r3d}\n' > flags/gated.txt
	@printf 'SIT{b34t_th3_4l4rm}\n' > flags/alarm.txt
	@printf 'SIT{r34l_w1nn3r_p1ck3d}\n' > flags/decoy.txt
	@printf 'SIT{r4w_r34d_n0_n3wl1n3}\n' > flags/fixedread.txt
	@printf 'SIT{num3r1c_g4t3_p4ss3d}\n' > flags/scanfnum.txt
	@printf 'SIT{b4nn3r_1ndep3nd3nt}\n' > flags/randbanner.txt
	@printf 'SIT{f1lt3r_d0dg3d}\n' > flags/filtered.txt
	@printf 'SIT{t0upp3r_surv1v3d}\n' > flags/toupper.txt
	@printf 'SIT{l0g1n_fr0m_r0d4t4}\n' > flags/login.txt
	@printf 'SIT{s3c0nd_r34d_w1ns}\n' > flags/tworead.txt
	@printf 'SIT{fn_p0int3r_r3d1r3ct}\n' > flags/fnptr.txt
	@printf 'SIT{strncpy_wr0ng_b0und}\n' > flags/strncpy.txt
	@printf 'SIT{sh3llc0d3_n0_wh1t3sp4c3}\n' > flags/scanfshell.txt
	@printf 'SIT{g4t3_pluS_c4n4ry}\n' > flags/gatedcanary.txt
	@printf 'SIT{l0g1n_th3n_s3c0nd_r34d}\n' > flags/loginread.txt
	@printf 'SIT{p13_b3h1nd_4_g4t3}\n' > flags/gatedpie.txt
	@printf 'SIT{m3nu_pluS_c4n4ry}\n' > flags/menucanary.txt
	@printf 'SIT{fmt_b3h1nd_4_m3nu}\n' > flags/menufmt.txt
	@printf 'SIT{l0g1n_pluS_c4n4ry}\n' > flags/logincanary.txt
	@printf 'SIT{r3t2l1bc_b3h1nd_m3nu}\n' > flags/menulibc.txt
	@printf 'SIT{sh3llc0d3_p4st_4_g4t3}\n' > flags/gatedshell.txt
	@printf 'SIT{p4t13nc3_n0t_v14bl3}\n' > flags/slowcanary.txt
	@printf 'SIT{sh1ft_p4st_th3_g4t3}\n' > flags/gatedshift.txt
	@printf 'SIT{sh1ft_m34sur3d_p4st_g4t3}\n' > flags/gatedecho.txt
	@printf 'SIT{l4b_4tt4ck1_p01nt3r_0n_st4ck}\n' > flags/fmtsecret32.txt
	@printf 'SIT{p01nt3r_0n_st4ck_64}\n' > flags/fmtsecret64.txt
	@printf 'SIT{gl0b4l_r34d_4ddr_4t_t41l}\n' > flags/fmtglobal64.txt
	@printf 'SIT{gl0b4l_r34d_32}\n' > flags/fmtglobal32.txt
	@printf 'SIT{sm4ll_v4lu3_n33ds_t41l_4ddr}\n' > flags/fmtsmall32.txt
	@printf 'SIT{hn_wr1t3_64b1t}\n' > flags/fmttarget64.txt
	@printf 'SIT{4ny_n0nz3r0_w1ll_d0}\n' > flags/fmtnonzero64.txt
	@printf 'SIT{n0nz3r0_32_p1c}\n' > flags/fmtnonzero32.txt
	@printf 'SIT{g0t_t0_w1n_n0_l34k}\n' > flags/fmtgotwin32.txt
	@printf 'SIT{g0t_t0_w1n_64}\n' > flags/fmtgotwin64.txt
	@printf 'SIT{fmt_l34ks_c4n4ry_th3n_b0f}\n' > flags/fmtcanary32.txt
	@printf 'SIT{fmt_c4n4ry_64}\n' > flags/fmtcanary64.txt
	@printf 'SIT{fmt_l34ks_p13_b4s3}\n' > flags/fmtpie32.txt
	@printf 'SIT{fmt_p13_64}\n' > flags/fmtpie64.txt
	@printf 'SIT{c4n4ry_4nd_p13_0n3_l34k}\n' > flags/fmtboth64.txt
	@printf 'SIT{pr3f1x_c0unts_t0w4rds_n}\n' > flags/fmtprefix32.txt
	@printf 'SIT{23_byt3s_0n3_hn}\n' > flags/fmtshort32.txt
	@printf 'SIT{l4b_4tt4ck2_ch4r_gu4rd}\n' > flags/adjchar32.txt
	@printf 'SIT{4uth3nt1c4t3d_n0nz3r0}\n' > flags/adjbool32.txt
	@printf 'SIT{4uth3nt1c4t3d_64}\n' > flags/adjbool64.txt
	@printf 'SIT{l3v3l_must_b3_3x4ctly_1}\n' > flags/adjone32.txt
	@printf 'SIT{tw0_f13lds_0n3_p4yl04d}\n' > flags/varpair32.txt
	@printf 'SIT{strncmp_0n_th3_n31ghb0ur}\n' > flags/adjmem32.txt
	@printf 'SIT{0v3rwr1t3_th3_c0mm4nd}\n' > flags/adjcmd32.txt
	@printf 'SIT{w1n_1s_4_sh3ll_typ3_c4t}\n' > flags/shellwin32.txt
	@printf 'SIT{sh3ll_w1n_64_4l1gn3d}\n' > flags/shellwin64.txt
	@printf 'SIT{l4b_n0p_sl3d_buff3r_4ddr}\n' > flags/bufleak32.txt
	@printf 'SIT{buff3r_4ddr_64}\n' > flags/bufleak64.txt
	@printf 'SIT{sh3llc0d3_4ft3r_th3_r3t}\n' > flags/bufsmall32.txt
	@printf 'SIT{l34k_th3_numb3r_s4y_1t_b4ck}\n' > flags/fmtguess32.txt
	@printf 'SIT{h1gh_h4lf_0f_th3_w0rd}\n' > flags/fmtguess64.txt
	@printf 'SIT{p4ssw0rd_r34d_0ff_th3_st4ck}\n' > flags/fmtpass32.txt
	@printf 'SIT{g0t_t0_4_sh3ll_w1n}\n' > flags/fmtgotshell32.txt
	@printf 'SIT{sc4nf_gu4rd_3x4ct_0n3}\n' > flags/varscanf32.txt
	@printf 'SIT{th3_c0py_1s_th3_0v3rfl0w}\n' > flags/varstrcpy32.txt
	@printf 'tr0ub4dor_and_3\n' > flags/fmtpass_pw.txt
	@printf 'SIT{l0c4ls_n0t_4_struct_spr4y}\n' > flags/locone64.txt
	@printf 'SIT{l0c4l_r0l3_b3c0m3s_r00t}\n' > flags/locstr32.txt
	@printf 'SIT{r34d_th3_c0d3_3v3ry_t1m3}\n' > flags/randguard32.txt
	@printf 'SIT{r4nd0m_gu4rd_64}\n' > flags/randguard64.txt
	@printf 'SIT{w1n_k3y_ch4ng3s_d41ly}\n' > flags/randarg32.txt
	@printf 'SIT{g4t3_th3n_f0rm4t_str1ng}\n' > flags/gatedfmt32.txt
	@printf 'SIT{pr1nt3d_4s_h3x_n0t_l0st}\n' > flags/hexwin32.txt
	@printf 'SIT{b4ckw4rds_1s_st1ll_4_fl4g}\n' > flags/revwin32.txt
	@printf 'SIT{l4b_l4st_3x3rc1s3_w1th_4slr}\n' > flags/fmtloop32.txt
	@printf 'SIT{n0_r00m_f0r_th3_r3t_g4dg3t}\n' > flags/tight64.txt
	@printf 'SIT{lucky_numb3r_1s_tw0_d1g1ts}\n' > flags/smalldec32.txt
	@printf 'SIT{l0g1n_th3n_f0rm4t_str1ng}\n' > flags/loginfmt32.txt
	@printf 'SIT{0n3_c0nst4nt_0n3_4nn0unc3d}\n' > flags/randarg2_32.txt
	@printf 'SIT{4nn0unc3d_k3y_p0p_rd1}\n' > flags/randarg64.txt
	@printf 'SIT{wr1t3_wh4t_th3_b4nn3r_s4ys}\n' > flags/fmtrandlocal32.txt
	@printf 'SIT{th3_r34l_0n3_n0t_th3_h1nt}\n' > flags/decoyfmt32.txt
	@printf 'SIT{n0t_l0ck3d_4ny_m0r3}\n' > flags/decoytaunt32.txt
	@printf 'SIT{th3_c0d3_w4s_0n_th3_p4p3r}\n' > flags/papercode32.txt
	@printf '0x5eaf00d5\n' > flags/papercode_secret.txt
	@printf 'SIT{k3y_c0mput3d_fr0m_th3_n0t3s}\n' > flags/paperkey32.txt
	@printf '0x1337\n' > flags/paperkey_secret.txt
	@printf 'SIT{cr3d3nt14ls_fr0m_th3_h4nd0ut}\n' > flags/paperlogin32.txt
	@printf 'examuser:Wint3r-2026\n' > flags/paperlogin_secret.txt
	@printf 'SIT{pr0f3ss0rs_0wn_w0rd1ng_0n_p4p3r}\n' > flags/paperlab64.txt
	@printf 'SIT{c0mput3_th3_d1st4nc3}\n' > flags/labcalc64.txt
	@printf 'SIT{s3c0nd_pr0mpt_1s_th3_bug}\n' > flags/twoprompt64.txt
	@printf 'SIT{n0_0ffs3t_s3c0nd_pr0mpt}\n' > flags/twoquiet64.txt
	@printf 'SIT{sh3llc0d3_4ft3r_th3_n4m3}\n' > flags/nameecho32.txt
	@printf 'SIT{l1bc_4ft3r_th3_n4m3}\n' > flags/namelibc32.txt
	@printf 'SIT{buff3r_4ddr_4ft3r_th3_n4m3}\n' > flags/namebuf32.txt
	@printf 'SIT{p4p3r_w1n_b3h1nd_4_pr0mpt}\n' > flags/paperquiet64.txt
	@printf 'SIT{n0t_0n_th3_st4ck}\n' > flags/fmtglobbuf32.txt
	@printf 'SIT{b0th_s1d3s_0f_th3_c0mp4r3}\n' > flags/floodguard64.txt
	@printf 'SIT{0n3_pr1ntf_n0t_3n0ugh}\n' > flags/fmtpieone64.txt
	@printf 'SIT{just_c0nn3ct_4nd_typ3}\n' > flags/freeflag32.txt
	@printf 'SIT{t4g_1s_n0t_th3_r3turn_4ddr}\n' > flags/taghex32.txt
	@printf 'SIT{c4n4ry_s41d_b3f0r3_ch3ck}\n' > flags/canarysay32.txt
	@printf 'SIT{c4n4ry_s41d_b3f0r3_ch3ck}\n' > flags/canarymute32.txt
	@echo "    dummy flags written"
