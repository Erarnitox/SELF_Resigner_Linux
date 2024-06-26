@shift
@echo off
setlocal enabledelayedexpansion
color 0A
cls
mode con:lines=32

:createFolder
if not exist self (md self)
if not exist raps (md raps)

:init
set selfctrlflags=4000000000000000000000000000000000000000000000000000000000000002
set selfcapflags=00000000000000000000000000000000000000000000003B0000000100040000
set output=4xxstd
set outputmsg=[4.XX STD]
set elfsdk=41
set keyrev=1C
set fwver=0004002000000000
set ctrlflagswitch=FALSE
set capflagswitch=FALSE
set compress=TRUE
set compressmsg=[ON]         

:mainmenu
if exist tool\selfinfo.txt (del tool\selfinfo.txt)
if exist tool\selflist.txt (del tool\selflist.txt)
if exist tool\bruteforce.txt (del tool\bruteforce.txt)
if exist tool\resultlen.txt (del tool\resultlen.txt)
cls
echo ===============================================================================
echo ^|                         TrueAncestor SELF Resigner                          ^|
echo ^|                                  by JjKkYu                                  ^|
echo ^|                                Verision 1.96                                ^|
echo ===============================================================================
echo ^|               CEX CFW                ^|                DEX OFW               ^|
echo ===============================================================================
echo ^| 1. Decrypt EBOOT.BIN Only            ^| 9. Decrypt EBOOT.BIN (FSELF) Only    ^|
echo ^| 2. Resign to NON-DRM EBOOT           ^| 10. Resign to NON-DRM EBOOT          ^|
echo ^| 3. Resign to NPDRM EBOOT             ^| 11. Resign to NPDRM EBOOT            ^|
echo ^| 4. Decrypt SELF/SPRX Only            ^|                                      ^|
echo ^| 5. Fast Resign NON-DRM SELF/SPRX     ^|                                      ^|
echo ^| 6. Fast Resign NPDRM SELF/SPRX       ^|                                      ^|
echo ^| 7. Custom Sign to NON-DRM SELF/SPRX  ^|                                      ^|
echo ^| 8. Custom Sign to NPDRM SELF/SPRX    ^|                                      ^|
echo ===============================================================================
echo ^|           SWITCH (CEX CFW)           ^|              INFORMATION             ^|
echo ===============================================================================
echo ^| O. Output Method: %outputmsg%         ^| C. Credits                           ^|
echo ^| D. Compress Data: %compressmsg%      ^| I. Instructions                      ^|
echo ^|                                      ^| G. Get Series Tools                  ^|
echo ^|                                      ^| T. About TrueAncestor                ^|
echo ===============================================================================
echo ^| Note: Place EBOOT.BIN/ELF into Resigner folder before operation.            ^|
echo ^|       Place SELF/SPRX files into self folder before operation.              ^|
echo ===============================================================================

set choice=NONE
set /p choice=[?] Please enter your choice (1-11/O/D/C/I/G/T):
if %choice%==1 (goto decself)
if %choice%==2 (goto disccex)
if %choice%==3 (goto npdrmcex)
if %choice%==4 (goto decsprx)
if %choice%==5 (goto selfcex)
if %choice%==6 (goto kliccex)
if %choice%==7 (goto custnondrm)
if %choice%==8 (goto custnpdrm)
if %choice%==9 (goto decfself)
if %choice%==10 (goto discdex)
if %choice%==11 (goto npdrmdex)
if %choice%==C (goto credits)
if %choice%==c (goto credits)
if %choice%==I (goto ins)
if %choice%==i (goto ins)
if %choice%==G (goto getTools)
if %choice%==g (goto getTools)
if %choice%==T (goto aboutta)
if %choice%==t (goto aboutta)
if %choice%==X (goto exit)
if %choice%==x (goto exit)
if %choice%==O (goto outputoption)
if %choice%==o (goto outputoption)
if %choice%==D (goto compressoption)
if %choice%==d (goto compressoption)
if %choice%==NONE (goto mainmenu)
echo [^^!] Invalid input, please enter among (1-11/O/D/C/I/G/T).
echo [*] Press any key to continue...
pause>nul
goto mainmenu

:decself
if not exist EBOOT.BIN (
echo [^^!] EBOOT.BIN cannot be found.
echo [^^!] Decrypt aborted.
echo [*] Press any key to continue...
pause>nul
goto mainmenu
)
if exist EBOOT.ELF (del EBOOT.ELF)
echo [*] Decrypting EBOOT.BIN...
tool\scetool.exe --decrypt EBOOT.BIN EBOOT.ELF>nul
if exist EBOOT.ELF (
echo [*] Decrypt finished.
) else (
echo [^^!] Decrypt EBOOT.BIN failed.
)
echo [*] Press any key to continue...
pause>nul
goto mainmenu

:disccex
set autoresign=FALSE
if not exist EBOOT.BIN (
if not exist EBOOT.ELF (
echo [^^!] EBOOT.BIN/ELF cannot be found.
echo [^^!] Resign aborted.
echo [*] Press any key to continue...
pause>nul
goto mainmenu
)
)
if not exist EBOOT.ELF (
echo [*] Decrypting EBOOT.BIN...
tool\scetool.exe --decrypt EBOOT.BIN EBOOT.ELF>nul
set autoresign=TRUE
)
if not exist EBOOT.ELF (
echo [^^!] Decrypt EBOOT.BIN failed.
echo [^^!] Resign aborted.
echo [*] Press any key to continue...
pause>nul
goto mainmenu
)
if exist EBOOT.BIN (
if exist EBOOT.BIN.BAK (del EBOOT.BIN.BAK)
ren EBOOT.BIN EBOOT.BIN.BAK
)
echo [*] Patching EBOOT.ELF...
tool\FixELF EBOOT.ELF %elfsdk%
echo [*] Encrypting EBOOT.ELF...
if %capflagswitch%==TRUE (
tool\scetool.exe -v --sce-type=SELF --compress-data=%compress% --skip-sections=TRUE --key-revision=%keyrev% --self-auth-id=1010000001000003 --self-vendor-id=01000002 --self-type=APP --self-app-version=0001000000000000 --self-fw-version=%fwver% --self-cap-flags=%selfcapflags% --encrypt EBOOT.ELF EBOOT.BIN>nul
)
if %capflagswitch%==FALSE (
if %ctrlflagswitch%==FALSE (
tool\scetool.exe -v --sce-type=SELF --compress-data=%compress% --skip-sections=TRUE --key-revision=%keyrev% --self-auth-id=1010000001000003 --self-vendor-id=01000002 --self-type=APP --self-app-version=0001000000000000 --self-fw-version=%fwver% --encrypt EBOOT.ELF EBOOT.BIN>nul
)
)
if %capflagswitch%==FALSE (
if %ctrlflagswitch%==TRUE (
tool\scetool.exe -v --sce-type=SELF --compress-data=%compress% --skip-sections=TRUE --key-revision=%keyrev% --self-auth-id=1010000001000003 --self-vendor-id=01000002 --self-type=APP --self-app-version=0001000000000000 --self-fw-version=%fwver% --self-ctrl-flags=%selfctrlflags% --encrypt EBOOT.ELF EBOOT.BIN>nul
)
)
if %autoresign%==TRUE (del EBOOT.ELF)
echo [*] Resign finished.
echo [*] Press any key to continue...
pause>nul
goto mainmenu

:npdrmcex
if %output%==4xxode (
echo [^^!] NPDRM Resign is inapplicable for ODE Output.
pause>nul
goto mainmenu
)
set autoresign=FALSE
if not exist EBOOT.BIN (
if not exist EBOOT.ELF (
echo [*] EBOOT.BIN/ELF cannot be found.
echo [*] Press any key to continue...
pause>nul
goto mainmenu
)
)
if not exist EBOOT.ELF (
echo [*] Decrypting EBOOT.BIN...
tool\scetool.exe --decrypt EBOOT.BIN EBOOT.ELF>nul
set autoresign=TRUE
)
if not exist EBOOT.ELF (
echo [^^!] Decrypt EBOOT.BIN failed.
echo [^^!] Resign aborted.
echo [*] Press any key to continue...
pause>nul
goto mainmenu
)
set contentid=NONE
tool\scetool.exe -i EBOOT.BIN>tool\selfinfo.txt
for /f "skip=3 tokens=1,*" %%i in (tool\selfinfo.txt) do if "%%i"=="ContentID" set contentid=%%j
if %contentid%==NONE (goto customcid)
:usecid
set usecid=NONE
echo [*] Found ContentID in EBOOT.BIN: %contentid%
set /p usecid=[?] Return to use this Content-ID / Enter A to enter custom ContentID:
if %usecid%==NONE (goto encrypt)
if %usecid%==A (goto customcid)
if %usecid%==a (goto customcid)
)
:customcid
set customcid=NONE
echo [*] Enter custom ContentID:
echo [*] Please follow this sample ContentID:JP9000-NPJA00001_00-0000000000000000
set /p customcid=[?] Enter custom ContentID / A to Abort:
if %customcid%==NONE (goto customcid)
if %customcid%==A (goto mainmenu)
if %customcid%==a (goto mainmenu)
set cidlength=0
for /l %%a in (0 1 99) do if not "!customcid:~%%a,1!"=="" set /a cidlength=%%a+1
if %cidlength% NEQ 36 (
echo [^^!] Invalid ContentID format, please enter following the sample ContentID.
echo [*] Press any key to continue...
pause>nul
goto customcid
)
if %customcid:~6,1% NEQ - (
echo [^^!] Invalid ContentID format, please enter following the sample ContentID.
echo [*] Press any key to continue...
pause>nul
goto customcid
)
if %customcid:~16,4% NEQ _00- (
echo [^^!] Invalid ContentID format, please enter following the sample ContentID.
echo [*] Press any key to continue...
pause>nul
goto customcid
)
set contentid=%customcid%
:encrypt
if exist EBOOT.BIN (
if exist EBOOT.BIN.BAK (del EBOOT.BIN.BAK)
ren EBOOT.BIN EBOOT.BIN.BAK
)
echo [*] Patching EBOOT.ELF...
tool\FixELF EBOOT.ELF %elfsdk%
echo [*] Encrypting EBOOT.ELF...
set npapptype=EXEC
if %contentid:~7,1%==B (set npapptype=UEXEC)
if %ctrlflagswitch%==FALSE (
tool\scetool.exe -v --sce-type=SELF --compress-data=%compress% --skip-sections=TRUE --key-revision=%keyrev% --self-auth-id=1010000001000003 --self-add-shdrs=TRUE --self-vendor-id=01000002 --self-type=NPDRM --self-app-version=0001000000000000 --self-fw-version=%fwver% --np-license-type=FREE --np-content-id=%contentid% --np-app-type=%npapptype% --np-real-fname=EBOOT.BIN --encrypt EBOOT.ELF EBOOT.BIN>nul
)
if %ctrlflagswitch%==TRUE (
tool\scetool.exe -v --sce-type=SELF --compress-data=%compress% --skip-sections=TRUE --key-revision=%keyrev% --self-auth-id=1010000001000003 --self-add-shdrs=TRUE --self-vendor-id=01000002 --self-type=NPDRM --self-app-version=0001000000000000 --self-fw-version=%fwver% --self-ctrl-flags=%selfctrlflags% --np-license-type=FREE --np-content-id=%contentid% --np-app-type=%npapptype% --np-real-fname=EBOOT.BIN --encrypt EBOOT.ELF EBOOT.BIN>nul
)
if %autoresign%==TRUE (del EBOOT.ELF)
echo [*] Resign finished.
echo [*] Press any key to continue...
pause>nul
goto mainmenu

:decsprx
cd self
if exist ..\tool\selflist.txt (del ..\tool\selflist.txt)
if exist *.self (dir *.self /b >..\tool\selflist.txt)
if exist *.sprx (dir *.sprx /b >>..\tool\selflist.txt)
cd..
set /a count=0
cls
echo ===============================================================================
echo  SELF/SPRX Files List
echo ===============================================================================
if exist tool\selflist.txt (
for /f %%f in (tool\selflist.txt) do (
set /a count+=1
set a!count!=%%f
if count NEQ 0 (echo  !count!. %%f )
)
) else (echo  No SELF/SPRX is Found.)
echo ===============================================================================
if !count!==0 (
pause>nul
goto mainmenu
)
echo  Note: To decrypt NPDRM file, EBOOT.BIN might be needed in Resigner folder.
echo ===============================================================================
:decsel
set selfsel=NONE
set /p selfsel=[?] Enter SELF/SPRX file number to decrypt / B to Back:
if %selfsel%==NONE (goto decsprx)
if %selfsel%==B (goto mainmenu)
if %selfsel%==b (goto mainmenu)
if %selfsel% GTR !count! (
echo [^^!] Invalid input, please enter again.
echo [*] Press any key to continue...
pause>nul
goto decsprx
)
if %selfsel% LSS 1 (
echo [^^!] Invalid input, please enter again.
echo [*] Press any key to continue...
pause>nul
goto decsprx
)
set selfname=!a%selfsel%!
set shortname=%selfname:~0,-5%
set sufname=%selfname:~-4,4%
if %sufname%==self (
set elfsuffix=elf
)
if %sufname%==SELF (
set elfsuffix=ELF
)
if %sufname%==sprx (
set elfsuffix=prx
)
if %sufname%==SPRX (
set elfsuffix=PRX
)
if exist self\%shortname%.%elfsuffix% (del self\%shortname%.%elfsuffix%)
echo [*] Decrypting %selfname%...
tool\scetool.exe --decrypt self\%selfname% self\%shortname%.%elfsuffix%>nul
if not exist self\%shortname%.%elfsuffix% (
goto chkcontentid
)
echo [*] Decrypt file to %shortname%.%elfsuffix% successfully.
echo [*] Press any key to continue...
pause>nul
goto decsprx
:chkcontentid
set contentid=NONE
tool\scetool.exe -i self\%selfname%>tool\selfinfo.txt
for /f "skip=3 tokens=1,*" %%i in (tool\selfinfo.txt) do if "%%i"=="ContentID" set contentid=%%j
if %contentid%==NONE (
echo [^^!] Decrypt %selfname% failed.
echo [*] Press any key to continue...
pause>nul
goto decsprx
)
echo [*] Found ContentID in %sufname% file: %contentid%
:chklist
if not exist tool\kliclist.txt (goto chkpool)
set klicensee=NONE
for /f "tokens=1,*" %%i in (tool\kliclist.txt) do if "%%i"=="%contentid%" set klicensee=%%j
for /l %%a in (0 1 99) do if not "!klicensee:~%%a,1!"=="" set /a kliclen=%%a+1
if %kliclen% NEQ 32 (
goto chkpool
) else (
echo [*] Found Klicensee in Klic List: %klicensee%
goto decklic
)
:chkpool
if not exist tool\klicpool.txt (goto chkeboot)
tool\klicencebruteforce -x self\%selfname% tool\klicpool.txt data\keys>tool\bruteforce.txt
for /f "skip=3 tokens=1,*" %%i in (tool\bruteforce.txt) do if "%%i"=="[*]" set bruteforceresult=%%j
if %bruteforceresult:~4,2%==no (goto chkeboot)
set klicensee=%bruteforceresult:~24,32%
tool\Rtlen %bruteforceresult%>tool\resultlen.txt
set /p resultlen=<tool\resultlen.txt
if %resultlen%==43 set klicensee=%bruteforceresult:~11,32%
echo [*] Found Klicensee in Klic Pool: %klicensee%
echo %contentid% %klicensee%>>tool\kliclist.txt
goto decklic
:chkeboot
if not exist EBOOT.BIN (
echo [*] EBOOT.BIN cannot be found in Resigner folder.
echo [^^!] Decrypt %selfname% failed.
echo [*] Press any key to continue...
pause>nul
goto decsprx
)
if exist EBOOT.ELF (del EBOOT.ELF)
tool\scetool.exe --decrypt EBOOT.BIN EBOOT.ELF>nul
if not exist EBOOT.ELF (
echo [^^!] Decrypt EBOOT.BIN failed.
echo [^^!] Decrypt %selfname% failed.
echo [*] Press any key to continue...
pause>nul
goto decsprx
)
echo [*] Start BruteForce Detecting Klicensee, please wait...
tool\klicencebruteforce -x self\%selfname% EBOOT.ELF data\keys>tool\bruteforce.txt
if exist EBOOT.ELF (del EBOOT.ELF)
for /f "skip=3 tokens=1,*" %%i in (tool\bruteforce.txt) do if "%%i"=="[*]" set bruteforceresult=%%j
if %bruteforceresult:~4,2%==no (
echo [^^!] Cannot find Klicensee, BruteForce Detecting failed.
echo [^^!] Decrypt %selfname% failed.
echo [*] Press any key to continue...
pause>nul
goto decsprx
) else (
goto foundkliceboot
)
:foundkliceboot
set klicensee=%bruteforceresult:~24,32%
tool\Rtlen %bruteforceresult%>tool\resultlen.txt
set /p resultlen=<tool\resultlen.txt
if %resultlen%==43 set klicensee=%bruteforceresult:~11,32%
echo [*] Found Klicensee in EBOOT.BIN: %klicensee%
echo %klicensee%>>tool\klicpool.txt
echo %contentid% %klicensee%>>tool\kliclist.txt
:decklic
tool\scetool.exe --np-klicensee %klicensee% --decrypt self\%selfname% self\%shortname%.%elfsuffix%>nul
if not exist self\%shortname%.%elfsuffix% (
echo [^^!] Decrypt !selfname%count%! failed.
echo [*] Press any key to continue...
pause>nul
)
echo [*] Decrypt file to %shortname%.%elfsuffix% successfully.
echo [*] Press any key to continue...
pause>nul
goto decsprx

:selfcex
cd self
if exist ..\tool\selflist.txt (del ..\tool\selflist.txt)
if exist *.self (dir *.self /b >..\tool\selflist.txt)
if exist *.sprx (dir *.sprx /b >>..\tool\selflist.txt)
cd..
set /a count=0
cls
echo ===============================================================================
echo  SELF/SPRX Files List
echo ===============================================================================
if exist tool\selflist.txt (
for /f %%f in (tool\selflist.txt) do (
set /a count+=1
set a!count!=%%f
if count NEQ 0 (echo  !count!. %%f )
)
) else (echo  No SELF/SPRX is Found.)
echo ===============================================================================
if !count!==0 (
pause>nul
goto mainmenu
)
:selfsel
set selfsel=NONE
set /p selfsel=[?] Enter SELF/SPRX file number to resign / A for All / B to Back:
if %selfsel%==NONE (goto selfcex)
if %selfsel%==A (goto selfall)
if %selfsel%==a (goto selfall)
if %selfsel%==B (goto mainmenu)
if %selfsel%==b (goto mainmenu)
if %selfsel% GTR !count! (
echo [^^!] Invalid input, please enter again.
echo [*] Press any key to continue...
pause>nul
goto selfsel
)
if %selfsel% LSS 1 (
echo [^^!] Invalid input, please enter again.
echo [*] Press any key to continue...
pause>nul
goto selfsel
)
set selfname=!a%selfsel%!
set shortname=%selfname:~0,-5%
set sufname=%selfname:~-4,4%
if %sufname%==self (
set elfsuffix=elf
set baksuffix=bak
)
if %sufname%==SELF (
set elfsuffix=ELF
set baksuffix=BAK
)
if %sufname%==sprx (
set elfsuffix=prx
set baksuffix=bak
)
if %sufname%==SPRX (
set elfsuffix=PRX
set baksuffix=BAK
)
if exist self\%shortname%.%elfsuffix% (del self\%shortname%.%elfsuffix%)
echo [*] Decrypting %selfname%...
tool\scetool.exe --decrypt self\%selfname% self\%shortname%.%elfsuffix%>nul
if not exist self\%shortname%.%elfsuffix% (
echo [^^!] Decrypt %selfname% failed.
echo [^^!] Resign aborted.
echo [*] Press any key to continue...
pause>nul
goto selfcex
)
if exist self\%selfname%.%baksuffix% (del self\%selfname%.%baksuffix%)
copy self\%selfname% self\%selfname%.%baksuffix%>nul
echo [*] Patching %shortname%.%elfsuffix%...
tool\FixELF self\%shortname%.%elfsuffix% %elfsdk%
echo [*] Encrypting %shortname%.%elfsuffix%...
if %capflagswitch%==TRUE (
tool\scetool.exe -v --sce-type=SELF --compress-data=%compress% --skip-sections=TRUE --key-revision=%keyrev% --self-auth-id=1010000001000003 --self-vendor-id=01000002 --self-type=APP --self-app-version=0001000000000000 --self-fw-version=%fwver% --self-cap-flags=%selfcapflags% --encrypt self\%shortname%.%elfsuffix% self\%selfname%>nul
)
if %capflagswitch%==FALSE (
if %ctrlflagswitch%==FALSE (
tool\scetool.exe -v --sce-type=SELF --compress-data=%compress% --skip-sections=TRUE --key-revision=%keyrev% --self-auth-id=1010000001000003 --self-vendor-id=01000002 --self-type=APP --self-app-version=0001000000000000 --self-fw-version=%fwver% --encrypt self\%shortname%.%elfsuffix% self\%selfname%>nul
)
)
if %capflagswitch%==FALSE (
if %ctrlflagswitch%==TRUE (
tool\scetool.exe -v --sce-type=SELF --compress-data=%compress% --skip-sections=TRUE --key-revision=%keyrev% --self-auth-id=1010000001000003 --self-vendor-id=01000002 --self-type=APP --self-app-version=0001000000000000 --self-fw-version=%fwver% --self-ctrl-flags=%selfctrlflags% --encrypt self\%shortname%.%elfsuffix% self\%selfname%>nul
)
)
if exist self\%shortname%.%elfsuffix% (del self\%shortname%.%elfsuffix%)
echo [*] Resign finished.
echo [*] Press any key to continue...
pause>nul
goto selfcex

:selfall
set /a count=0
set /a error=0
for /f %%f in (tool\selflist.txt) do (
set /a count+=1
set selfname%count%=%%f
set shortname%count%=!selfname%count%:~0,-5!
set sufname%count%=!selfname%count%:~-4,4!
if !sufname%count%!==self (
set elfsuffix%count%=elf
set baksuffix%count%=bak
)
if !sufname%count%!==SELF (
set elfsuffix%count%=ELF
set baksuffix%count%=BAK
)
if !sufname%count%!==sprx (
set elfsuffix%count%=prx
set baksuffix%count%=bak
)
if !sufname%count%!==SPRX (
set elfsuffix%count%=PRX
set baksuffix%count%=BAK
)
if exist self\!shortname%count%!.!elfsuffix%count%! (del self\!shortname%count%!.!elfsuffix%count%!)
echo [*] Resigning !selfname%count%!...
tool\scetool.exe --decrypt self\!selfname%count%! self\!shortname%count%!.!elfsuffix%count%!>nul
if not exist self\!shortname%count%!.!elfsuffix%count%! (
echo [^^!] Decrypt !selfname%count%! failed.
echo [^^!] Resign !selfname%count%! aborted.
set /a error+=1
)
if exist self\!shortname%count%!.!elfsuffix%count%! (
if exist self\!selfname%count%!.!baksuffix%count%! (del self\!selfname%count%!.!baksuffix%count%!)
copy self\!selfname%count%! self\!selfname%count%!.!baksuffix%count%!>nul
tool\FixELF self\!shortname%count%!.!elfsuffix%count%! %elfsdk%
if %capflagswitch%==TRUE (
tool\scetool.exe -v --sce-type=SELF --compress-data=%compress% --skip-sections=TRUE --key-revision=%keyrev% --self-auth-id=1010000001000003 --self-vendor-id=01000002 --self-type=APP --self-app-version=0001000000000000 --self-fw-version=%fwver% --self-cap-flags=%selfcapflags% --encrypt self\!shortname%count%!.!elfsuffix%count%! self\!selfname%count%!>nul
)
if %capflagswitch%==FALSE (
if %ctrlflagswitch%==FALSE (
tool\scetool.exe -v --sce-type=SELF --compress-data=%compress% --skip-sections=TRUE --key-revision=%keyrev% --self-auth-id=1010000001000003 --self-vendor-id=01000002 --self-type=APP --self-app-version=0001000000000000 --self-fw-version=%fwver% --encrypt self\!shortname%count%!.!elfsuffix%count%! self\!selfname%count%!>nul
)
)
if %capflagswitch%==FALSE (
if %ctrlflagswitch%==TRUE (
tool\scetool.exe -v --sce-type=SELF --compress-data=%compress% --skip-sections=TRUE --key-revision=%keyrev% --self-auth-id=1010000001000003 --self-vendor-id=01000002 --self-type=APP --self-app-version=0001000000000000 --self-fw-version=%fwver% --self-ctrl-flags=%selfctrlflags% --encrypt self\!shortname%count%!.!elfsuffix%count%! self\!selfname%count%!>nul
)
)
if exist self\!shortname%count%!.!elfsuffix%count%! (del self\!shortname%count%!.!elfsuffix%count%!)
echo [*] Resign !selfname%count%! finished.
)
)
if %error%==0 (
echo [*] Resign all SELF/SPRX files successfully.
) else (
echo [^^!] Resign all SELF/SPRX files finished, %error% file^(s^) failed.
)
echo [*] Press any key to continue...
pause>nul
goto mainmenu

:kliccex
if %output%==4xxode (
echo [^^!] NPDRM Resign is inapplicable for ODE Output.
pause>nul
goto mainmenu
)
cd self
if exist ..\tool\selflist.txt (del ..\tool\selflist.txt)
if exist *.self (dir *.self /b >..\tool\selflist.txt)
if exist *.sprx (dir *.sprx /b >>..\tool\selflist.txt)
cd..
set /a count=0
cls
echo ===============================================================================
echo  SELF/SPRX Files List
echo ===============================================================================
if exist tool\selflist.txt (
for /f %%f in (tool\selflist.txt) do (
set /a count+=1
set a!count!=%%f
if count NEQ 0 (echo  !count!. %%f )
)
) else (echo  No SELF/SPRX is Found.)
echo ===============================================================================
if !count!==0 (
pause>nul
goto mainmenu
)
echo  Note: BruteForce Detecting Klicensee method will be used in this option.
echo        EBOOT.BIN must be placed into Resigner folder for detecting Klicensee.
echo        Make sure that EBOOT.BIN and SELF/SPRX files are from the same game.
echo ===============================================================================
set klicgo=NONE
set /p klicgo=[?] Enter any key to continue / B to Back:
if %klicgo%==NONE (goto checkeboot)
if %klicgo%==B (goto mainmenu)
if %klicgo%==b (goto mainmenu)
)
:checkeboot
if not exist EBOOT.BIN (
echo [^^!] EBOOT.BIN cannot be found in Resigner folder.
echo [^^!] Resign aborted.
echo [*] Press any key to continue...
pause>nul
goto kliccex
)
set contentid=NONE
tool\scetool.exe -i EBOOT.BIN>tool\selfinfo.txt
for /f "skip=3 tokens=1,*" %%i in (tool\selfinfo.txt) do if "%%i"=="ContentID" set contentid=%%j
if %contentid%==NONE (
echo [^^!] EBOOT.BIN should be an NPDRM EBOOT.
echo [^^!] Resign aborted.
echo [*] Press any key to continue...
pause>nul
goto kliccex
)
if exist tool\kliclist.txt (goto kliclist)
goto klicdec
:kliclist
set klicensee=NONE
for /f "tokens=1,*" %%i in (tool\kliclist.txt) do if "%%i"=="%contentid%" set klicensee=%%j
for /l %%a in (0 1 99) do if not "!klicensee:~%%a,1!"=="" set /a kliclen=%%a+1
if %kliclen% NEQ 32 (
goto bruteforcepool
) else (
echo [*] Found ContentID in EBOOT.BIN: %contentid%
echo [*] Found Klicensee in Klic List: %klicensee%
goto klicresign
)
:bruteforcepool
if not exist tool\klicpool.txt (goto klicdec)
set /p usesprx=<tool\selflist.txt
tool\klicencebruteforce -x self\%usesprx% tool\klicpool.txt data\keys>tool\bruteforce.txt
for /f "skip=3 tokens=1,*" %%i in (tool\bruteforce.txt) do if "%%i"=="[*]" set bruteforceresult=%%j
if %bruteforceresult:~4,2%==no (goto klicdec)
set klicensee=%bruteforceresult:~24,32%
tool\Rtlen %bruteforceresult%>tool\resultlen.txt
set /p resultlen=<tool\resultlen.txt
if %resultlen%==43 set klicensee=%bruteforceresult:~11,32%
echo [*] Found ContentID in EBOOT.BIN: %contentid%
echo [*] Found Klicensee in Klic Pool: %klicensee%
echo %contentid% %klicensee%>>tool\kliclist.txt
goto klicresign
:klicdec
if exist EBOOT.ELF (del EBOOT.ELF)
tool\scetool.exe --decrypt EBOOT.BIN EBOOT.ELF>nul
if not exist EBOOT.ELF (
echo [^^!] Decrypt EBOOT.BIN failed.
echo [^^!] Resign aborted.
echo [*] Press any key to continue...
pause>nul
goto kliccex
)
:bruteforceeboot
echo [*] Start BruteForce Detecting Klicensee, please wait...
echo [*] Found ContentID in EBOOT.BIN: %contentid%
set /p usesprx=<tool\selflist.txt
tool\klicencebruteforce -x self\%usesprx% EBOOT.ELF data\keys>tool\bruteforce.txt
if exist EBOOT.ELF (del EBOOT.ELF)
for /f "skip=3 tokens=1,*" %%i in (tool\bruteforce.txt) do if "%%i"=="[*]" set bruteforceresult=%%j
if %bruteforceresult:~4,2%==no (
echo [^^!] Cannot find Klicensee, BruteForce Detecting failed.
echo [^^!] Resign aborted.
echo [*] Press any key to continue...
pause>nul
goto kliccex
) else (
goto klicfoundeboot
)
:klicfoundeboot
set klicensee=%bruteforceresult:~24,32%
tool\Rtlen %bruteforceresult%>tool\resultlen.txt
set /p resultlen=<tool\resultlen.txt
if %resultlen%==43 set klicensee=%bruteforceresult:~11,32%
echo [*] Found Klicensee in EBOOT.BIN: %klicensee%
echo %klicensee%>>tool\klicpool.txt
echo %contentid% %klicensee%>>tool\kliclist.txt
:klicresign
set /a count=0
set /a error=0
for /f %%f in (tool\selflist.txt) do (
set /a count+=1
set selfname%count%=%%f
set shortname%count%=!selfname%count%:~0,-5!
set sufname%count%=!selfname%count%:~-4,4!
if !sufname%count%!==self (
set elfsuffix%count%=elf
set baksuffix%count%=bak
)
if !sufname%count%!==SELF (
set elfsuffix%count%=ELF
set baksuffix%count%=BAK
)
if !sufname%count%!==sprx (
set elfsuffix%count%=prx
set baksuffix%count%=bak
)
if !sufname%count%!==SPRX (
set elfsuffix%count%=PRX
set baksuffix%count%=BAK
)
set npapptype%count%=SPRX
if %contentid:~7,1%==B (set npapptype%count%=USPRX)
if exist self\!shortname%count%!.!elfsuffix%count%! (del self\!shortname%count%!.!elfsuffix%count%!)
echo [*] Resigning !selfname%count%!...
tool\scetool.exe --np-klicensee %klicensee% --decrypt self\!selfname%count%! self\!shortname%count%!.!elfsuffix%count%!>nul
if not exist self\!shortname%count%!.!elfsuffix%count%! (
echo [^^!] Decrypt !selfname%count%! failed.
echo [^^!] Resign !selfname%count%! aborted.
set /a error+=1
)
if exist self\!shortname%count%!.!elfsuffix%count%! (
if exist self\!selfname%count%!.!baksuffix%count%! (del self\!selfname%count%!.!baksuffix%count%!)
copy self\!selfname%count%! self\!selfname%count%!.!baksuffix%count%!>nul
tool\FixELF self\!shortname%count%!.!elfsuffix%count%! %elfsdk%
if %ctrlflagswitch%==FALSE (
tool\scetool.exe -v --sce-type=SELF --compress-data=%compress% --skip-sections=TRUE --key-revision=%keyrev% --self-auth-id=1010000001000003 --self-add-shdrs=TRUE --self-vendor-id=01000002 --self-type=NPDRM --self-app-version=0001000000000000 --self-fw-version=%fwver% --np-license-type=FREE --np-content-id=%contentid% --np-app-type=!npapptype%count%! --np-klicensee=%klicensee% --np-real-fname=!selfname%count%! --encrypt self\!shortname%count%!.!elfsuffix%count%! self\!selfname%count%!>nul
)
if %ctrlflagswitch%==TRUE (
tool\scetool.exe -v --sce-type=SELF --compress-data=%compress% --skip-sections=TRUE --key-revision=%keyrev% --self-auth-id=1010000001000003 --self-add-shdrs=TRUE --self-vendor-id=01000002 --self-type=NPDRM --self-app-version=0001000000000000 --self-fw-version=%fwver% --self-ctrl-flags=%selfctrlflags% --np-license-type=FREE --np-content-id=%contentid% --np-app-type=!npapptype%count%! --np-klicensee=%klicensee% --np-real-fname=!selfname%count%! --encrypt self\!shortname%count%!.!elfsuffix%count%! self\!selfname%count%!>nul
)
if exist self\!shortname%count%!.!elfsuffix%count%! (del self\!shortname%count%!.!elfsuffix%count%!)
echo [*] Resign !selfname%count%! finished.
)
)
if %error%==0 (
echo [*] Resign all SELF/SPRX files successfully.
) else (
echo [^^!] Resign all SELF/SPRX files finished, %error% file^(s^) failed.
)
echo [*] Press any key to continue...
pause>nul
goto mainmenu

:custnondrm
cd self
if exist ..\tool\selflist.txt (del ..\tool\selflist.txt)
if exist *.elf (dir *.elf /b >..\tool\selflist.txt)
if exist *.prx (dir *.prx /b >>..\tool\selflist.txt)
cd..
set /a count=0
cls
echo ===============================================================================
echo  ELF/PRX Files List
echo ===============================================================================
if exist tool\selflist.txt (
for /f %%f in (tool\selflist.txt) do (
set /a count+=1
set a!count!=%%f
if count NEQ 0 (echo  !count!. %%f )
)
) else (echo  No ELF/PRX is Found.)
echo ===============================================================================
if !count!==0 (
pause>nul
goto mainmenu
)
:elfselnondrm
set selfsel=NONE
set /p selfsel=[?] Enter ELF/PRX file number to resign / B to Back:
if %selfsel%==NONE (goto custnondrm)
if %selfsel%==B (goto mainmenu)
if %selfsel%==b (goto mainmenu)
if %selfsel% GTR !count! (
echo [^^!] Invalid input, please enter again.
echo [*] Press any key to continue...
pause>nul
goto elfselnondrm
)
if %selfsel% LSS 1 (
echo [^^!] Invalid input, please enter again.
echo [*] Press any key to continue...
pause>nul
goto elfselnondrm
)
set elfname=!a%selfsel%!
set shortname=%elfname:~0,-4%
set sufname=%elfname:~-3,3%
if %sufname%==elf (
set selfsuffix=self
set baksuffix=bak
)
if %sufname%==ELF (
set selfsuffix=SELF
set baksuffix=BAK
)
if %sufname%==prx (
set selfsuffix=sprx
set baksuffix=bak
)
if %sufname%==PRX (
set selfsuffix=SPRX
set baksuffix=BAK
)
if exist self\%shortname%.%selfsuffix% (del self\%shortname%.%selfsuffix%)
echo [*] Patching %elfname%...
tool\FixELF self\%elfname% %elfsdk%
echo [*] Encrypting %elfname%...
if %capflagswitch%==TRUE (
tool\scetool.exe -v --sce-type=SELF --compress-data=%compress% --skip-sections=TRUE --key-revision=%keyrev% --self-auth-id=1010000001000003 --self-vendor-id=01000002 --self-type=APP --self-app-version=0001000000000000 --self-fw-version=%fwver% --self-cap-flags=%selfcapflags% --encrypt self\%elfname% self\%shortname%.%selfsuffix%>nul
)
if %capflagswitch%==FALSE (
if %ctrlflagswitch%==FALSE (
tool\scetool.exe -v --sce-type=SELF --compress-data=%compress% --skip-sections=TRUE --key-revision=%keyrev% --self-auth-id=1010000001000003 --self-vendor-id=01000002 --self-type=APP --self-app-version=0001000000000000 --self-fw-version=%fwver% --encrypt self\%elfname% self\%shortname%.%selfsuffix%>nul
)
)
if %capflagswitch%==FALSE (
if %ctrlflagswitch%==TRUE (
tool\scetool.exe -v --sce-type=SELF --compress-data=%compress% --skip-sections=TRUE --key-revision=%keyrev% --self-auth-id=1010000001000003 --self-vendor-id=01000002 --self-type=APP --self-app-version=0001000000000000 --self-fw-version=%fwver% --self-ctrl-flags=%selfctrlflags% --encrypt self\%elfname% self\%shortname%.%selfsuffix%>nul
)
)
echo [*] Custom sign finished.
echo [*] Press any key to continue...
pause>nul
goto custnondrm

:custnpdrm
if %output%==4xxode (
echo [^^!] NPDRM Resign is inapplicable for ODE Output.
pause>nul
goto mainmenu
)
cd self
if exist ..\tool\selflist.txt (del ..\tool\selflist.txt)
if exist *.elf (dir *.elf /b >..\tool\selflist.txt)
if exist *.prx (dir *.prx /b >>..\tool\selflist.txt)
cd..
set /a count=0
cls
echo ===============================================================================
echo  ELF/PRX Files List
echo ===============================================================================
if exist tool\selflist.txt (
for /f %%f in (tool\selflist.txt) do (
set /a count+=1
set a!count!=%%f
if count NEQ 0 (echo  !count!. %%f )
)
) else (echo  No ELF/PRX is Found.)
echo ===============================================================================
if !count!==0 (
pause>nul
goto mainmenu
)
:elfselnpdrm
set selfsel=NONE
set /p selfsel=[?] Enter ELF/PRX file number to resign / B to Back:
if %selfsel%==NONE (goto custnpdrm)
if %selfsel%==B (goto mainmenu)
if %selfsel%==b (goto mainmenu)
if %selfsel% GTR !count! (
echo [^^!] Invalid input, please enter again.
echo [*] Press any key to continue...
pause>nul
goto elfselnpdrm
)
if %selfsel% LSS 1 (
echo [^^!] Invalid input, please enter again.
echo [*] Press any key to continue...
pause>nul
goto elfselnpdrm
)
set elfname=!a%selfsel%!
set shortname=%elfname:~0,-4%
set sufname=%elfname:~-3,3%
if %sufname%==elf (
set selfsuffix=self
set baksuffix=bak
)
if %sufname%==ELF (
set selfsuffix=SELF
set baksuffix=BAK
)
if %sufname%==prx (
set selfsuffix=sprx
set baksuffix=bak
)
if %sufname%==PRX (
set selfsuffix=SPRX
set baksuffix=BAK
)
:customcid
set customcid=NONE
echo [*] Please follow this sample ContentID:JP9000-NPJA00001_00-0000000000000000
set /p customcid=[?] Enter custom ContentID / A to Abort:
if %customcid%==NONE (goto customcid)
if %customcid%==A (goto custnpdrm)
if %customcid%==a (goto custnpdrm)
set cidlength=0
for /l %%a in (0 1 99) do if not "!customcid:~%%a,1!"=="" set /a cidlength=%%a+1
if %cidlength% NEQ 36 (
echo [^^!] Invalid ContentID format, please enter following the sample ContentID.
echo [*] Press any key to continue...
pause>nul
goto customcid
)
if %customcid:~6,1% NEQ - (
echo [^^!] Invalid ContentID format, please enter following the sample ContentID.
echo [*] Press any key to continue...
pause>nul
goto customcid
)
if %customcid:~16,4% NEQ _00- (
echo [^^!] Invalid ContentID format, please enter following the sample ContentID.
echo [*] Press any key to continue...
pause>nul
goto customcid
)
set contentid=%customcid%
:customklic
set klicensee=NONE
echo [*] Please follow this KLicensee sample:00000000000000000000000000000000
set /p klicensee=[?] Please enter KLicensee / A to Abort:
if %klicensee%==NONE (goto customklic)
if %klicensee%==A (goto custnpdrm)
if %klicensee%==a (goto custnpdrm)
set kliclen=0
for /l %%a in (0 1 99) do if not "!klicensee:~%%a,1!"=="" set /a kliclen=%%a+1
if %kliclen% NEQ 32 (
echo [*] Invalid Klicensee format, please enter following the KLicensee sample.
echo [*] Press any key to continue...
pause>nul
goto customklic
)
set npapptype=SPRX
if %contentid:~7,1%==B (set npapptype=USPRX)
if exist self\%shortname%.%selfsuffix% (del self\%shortname%.%selfsuffix%)
echo [*] Patching %elfname%...
tool\FixELF self\%elfname% %elfsdk%
echo [*] Encrypting %elfname%...
if %ctrlflagswitch%==FALSE (
tool\scetool.exe -v --sce-type=SELF --compress-data=%compress% --skip-sections=TRUE --key-revision=%keyrev% --self-auth-id=1010000001000003 --self-add-shdrs=TRUE --self-vendor-id=01000002 --self-type=NPDRM --self-app-version=0001000000000000 --self-fw-version=%fwver% --np-license-type=FREE --np-content-id=%contentid% --np-app-type=%npapptype% --np-klicensee=%klicensee% --np-real-fname=%shortname%.%selfsuffix% --encrypt self\%elfname% self\%shortname%.%selfsuffix%>nul
)
if %ctrlflagswitch%==TRUE (
tool\scetool.exe -v --sce-type=SELF --compress-data=%compress% --skip-sections=TRUE --key-revision=%keyrev% --self-auth-id=1010000001000003 --self-add-shdrs=TRUE --self-vendor-id=01000002 --self-type=NPDRM --self-app-version=0001000000000000 --self-fw-version=%fwver% --self-ctrl-flags=%selfctrlflags% --np-license-type=FREE --np-content-id=%contentid% --np-app-type=%npapptype% --np-klicensee=%klicensee% --np-real-fname=%shortname%.%selfsuffix% --encrypt self\%elfname% self\%shortname%.%selfsuffix%>nul
)
echo [*] Custom sign finished.
echo [*] Press any key to continue...
pause>nul
goto mainmenu

:decfself
if not exist EBOOT.BIN (
echo [^^!] EBOOT.BIN cannot be found.
echo [^^!] Decrypt aborted.
echo [*] Press any key to continue...
pause>nul
goto mainmenu
)
if exist EBOOT.ELF (del EBOOT.ELF)
echo [*] Decrypting EBOOT.BIN...
tool\unfself EBOOT.BIN EBOOT.ELF>nul
if exist EBOOT.ELF (
echo [*] Decrypt finished.
) else (
echo [^^!] Decrypt EBOOT.BIN failed.
)
echo [*] Press any key to continue...
pause>nul
goto mainmenu

:discdex
set autoresign=FALSE
if not exist EBOOT.BIN (
if not exist EBOOT.ELF (
echo [^^!] EBOOT.BIN/ELF cannot be found.
echo [^^!] Resign aborted.
echo [*] Press any key to continue...
pause>nul
goto mainmenu
)
)
if not exist EBOOT.ELF (
echo [*] Decrypting EBOOT.BIN...
tool\scetool.exe --decrypt EBOOT.BIN EBOOT.ELF>nul
set autoresign=TRUE
)
if not exist EBOOT.ELF (
echo [^^!] Decrypt EBOOT.BIN failed.
echo [^^!] Resign aborted.
echo [*] Press any key to continue...
pause>nul
goto mainmenu
)
if exist EBOOT.BIN (
if exist EBOOT.BIN.BAK (del EBOOT.BIN.BAK)
ren EBOOT.BIN EBOOT.BIN.BAK
)
echo [*] Patching EBOOT.ELF...
tool\FixELF EBOOT.ELF
echo [*] Encrypting EBOOT.ELF...
tool\make_fself EBOOT.ELF EBOOT.BIN>nul
if %autoresign%==TRUE (del EBOOT.ELF)
echo [*] Resign finished.
echo [*] Press any key to continue...
pause>nul
goto mainmenu

:npdrmdex
set autoresign=FALSE
if not exist EBOOT.BIN (
if not exist EBOOT.ELF (
echo [^^!] EBOOT.BIN/ELF cannot be found.
echo [^^!] Resign aborted.
echo [*] Press any key to continue...
pause>nul
goto mainmenu
)
)
if not exist EBOOT.ELF (
echo [*] Decrypting EBOOT.BIN...
tool\scetool.exe --decrypt EBOOT.BIN EBOOT.ELF>nul
set autoresign=TRUE
)
if not exist EBOOT.ELF (
echo [^^!] Decrypt EBOOT.BIN failed.
echo [^^!] Resign aborted.
echo [*] Press any key to continue...
pause>nul
goto mainmenu
)
if exist EBOOT.BIN (
if exist EBOOT.BIN.BAK (del EBOOT.BIN.BAK)
ren EBOOT.BIN EBOOT.BIN.BAK
)
echo [*] Patching EBOOT.ELF...
tool\FixELF EBOOT.ELF
echo [*] Encrypting EBOOT.ELF...
tool\make_fself_npdrm EBOOT.ELF EBOOT.BIN>nul
if %autoresign%==TRUE (del EBOOT.ELF)
echo [*] Resign finished.
echo [*] Press any key to continue...
pause>nul
goto mainmenu

:outputoption
if %output%==4xxstd (
set output=4xxalt
set outputmsg=[4.XX ALT]
set elfsdk=41
set keyrev=1C
set fwver=0004002000000000
set ctrlflagswitch=TRUE
set capflagswitch=FALSE
echo [*] Output method has been set to 4.XX ALT.
pause>nul
goto mainmenu
)
if %output%==4xxalt (
set output=4xxode
set outputmsg=[4.XX ODE]
set elfsdk=33
set keyrev=0A
set fwver=0003005500000000
set ctrlflagswitch=FALSE
set capflagswitch=TRUE
echo [*] Output method has been set to 4.XX ODE.
pause>nul
goto mainmenu
)
if %output%==4xxode (
set output=3xxstd
set outputmsg=[3.XX STD]
set elfsdk=33
set keyrev=04
set fwver=0003004000000000
set ctrlflagswitch=FALSE
set capflagswitch=FALSE
echo [*] Output method has been set to 3.XX STD.
pause>nul
goto mainmenu
)
if %output%==3xxstd (
set output=3xxalt
set outputmsg=[3.XX ALT]
set elfsdk=33
set keyrev=04
set fwver=0003004000000000
set ctrlflagswitch=TRUE
set capflagswitch=FALSE
echo [*] Output method has been set to 3.XX ALT.
pause>nul
goto mainmenu
)
if %output%==3xxalt (
set output=4xxstd
set outputmsg=[4.XX STD]
set elfsdk=41
set keyrev=1C
set fwver=0004002000000000
set ctrlflagswitch=FALSE
set capflagswitch=FALSE
echo [*] Output method has been set to 4.XX STD.
pause>nul
goto mainmenu
)

:compressoption
set compressdata=NONE
if %compress%==FALSE (goto enablecompressoption)
if %compress%==TRUE (goto disablecompressoption)
:enablecompressoption
set /p compressdata=[?] Enter Y to enable Compress Data / any other key to abort:
if %compressdata%==NONE (goto mainmenu)
if %compressdata%==Y (goto enablecompress)
if %compressdata%==y (goto enablecompress)
goto mainmenu
:enablecompress
set compress=TRUE
set compressmsg=[ON]         
goto mainmenu
:disablecompressoption
set /p compressdata=[?] Enter Y to disable Compress Data / any other key to abort:
if %compressdata%==NONE (goto mainmenu)
if %compressdata%==Y (goto disablecompress)
if %compressdata%==y (goto disablecompress)
goto mainmenu
:disablecompress
set compress=FALSE
set compressmsg=[OFF]        
goto mainmenu

:credits
cls
echo ===============================================================================
echo ^|                         TrueAncestor SELF Resigner                          ^|
echo ^|                                  by JjKkYu                                  ^|
echo ^|                                Verision 1.96                                ^|
echo ===============================================================================
echo ^|                                  Credits                                    ^|
echo ===============================================================================
echo ^| naehrwert for scetool                                                       ^|
echo ^| MAGiC333X for KLicence Brute-force Tool                                     ^|
echo ^| Ftsm for FixELF.exe                                                         ^|
echo ^| $ony for PlayStation3 SDK Tools                                             ^|
echo ===============================================================================
echo ^|                              Special Thanks                                 ^|
echo ===============================================================================
echo ^| badzbb,Dupecheck,lzniori,yyhioriyagami,haz367,elpaso666,liujun0792          ^|
echo ===============================================================================
pause>nul
goto mainmenu

:ins
cls
echo ===============================================================================
echo ^|                         TrueAncestor SELF Resigner                          ^|
echo ===============================================================================
echo ^|                                Instructions                                 ^|
echo ===============================================================================
echo ^| 1. What does this tool do?                                                  ^|
echo ^| This tool resigns SELF files to work for all CEX CFW/DEX OFW usage.         ^|
echo ^| Be sure to resign all the EBOOT.BIN, SELF/SPRX files in the game.           ^|
echo ^| If the game gives black screen or freeze, SELF files may need special fix.  ^|
echo ===============================================================================
echo ^| 2. Resign priority                                                          ^|
echo ^| If EBOOT.ELF exists, it will be resigned in priority and remained.          ^|
echo ^| If EBOOT.ELF doesn't exist, EBOOT.BIN will be resigned, ends without ELF.   ^|
echo ===============================================================================
echo ^| 3. Output Method Switch                                                     ^|
echo ^| This switch will change the output method along with the circle below.      ^|
echo ^| 4.XX STD - 4.XX ALT - 4.XX ODE - 3.XX STD - 3.XX ALT - 4.XX STD.            ^|
echo ===============================================================================
echo ^| 4. Compress Data Switch                                                     ^|
echo ^| Turn on this switch will allow to generate files in small size.             ^|
echo ===============================================================================
pause>nul
goto mainmenu

:getTools
cls
echo ===============================================================================
echo ^|                         TrueAncestor SELF Resigner                          ^|
echo ^|                                  by JjKkYu                                  ^|
echo ^|                                Verision 1.96                                ^|
echo ===============================================================================
echo ^|                              Get Series Tools                               ^|
echo ===============================================================================
echo ^| 1. TrueAncestor SELF Resigner                                               ^|
echo ^| This tool is used to resign self files.                                     ^|
echo ^| 2. TrueAncestor PKG Creator                                                 ^|
echo ^| This tool is used to create pkg files.                                      ^|
echo ^| 3. TrueAncestor EDAT Rebuilder                                              ^|
echo ^| This tool is used to rebuild edat ^& sdat files.                             ^|
echo ^| 4. TrueAncestor BACKUP Injector                                             ^|
echo ^| This tool is used to injector files into backup.                            ^|
echo ===============================================================================
echo ^| You can get all the series tools at:                                        ^|
echo ^| http://www.mediafire.com/?jn0fq4ebjd2m                                      ^|
echo ===============================================================================
pause>nul
goto mainMenu

:aboutta
cls
echo ===============================================================================
echo ^|                         TrueAncestor SELF Resigner                          ^|
echo ^|                                  by JjKkYu                                  ^|
echo ^|                                Verision 1.96                                ^|
echo ===============================================================================
echo ^|                             About TrueAncestor                              ^|
echo ===============================================================================
echo ^| True Ancestor is one kind of vampire which is born as a vampire.            ^|
echo ^| This means True Ancestor have pure vampire blood.                           ^|
echo ^| True Ancestor don't need consuming blood to survive nor being nocturnal.    ^|
echo ^| This word is from Tsukihime, a Japanese dojin visual novel by Type-Moon.    ^|
echo ^| Arcueid Brunestud, the main heroine, is the princess of True Ancestor.      ^|
echo ^| If you want to learn more about True Ancestor or Tsukihime, please see:     ^|
echo ^| http://en.wikipedia.org/wiki/Tsukihime                                      ^|
echo ===============================================================================
pause>nul
goto mainmenu

:exit
exit
