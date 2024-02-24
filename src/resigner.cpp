#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <string>
#include <format>
#include <array>

#include "tool/FixELF.hpp"

namespace fs = std::filesystem;

static std::basic_string<char> selfctrlflags{ "4000000000000000000000000000000000000000000000000000000000000002" };
static std::basic_string<char> selfcapflags{ "00000000000000000000000000000000000000000000003B0000000100040000" };
static std::basic_string<char> output{ "4xxstd" };
static std::basic_string<char> outputmsg{ "[4.XX STD]" };
static std::basic_string<char> elfsdk{ "41" };
static std::basic_string<char> keyrev{ "1C" };
static std::basic_string<char> fwver{ "0004002000000000" };
static std::basic_string<char> ctrlflagswitch{ "FALSE" };
static std::basic_string<char> capflagswitch{ "FALSE" };
static std::basic_string<char> compress{ "TRUE" };
static std::basic_string<char> compressmsg{ "[ON]" };
static std::basic_string<char> contentid{ "NONE" };
static std::basic_string<char> autoresign{ "TRUE" };
static std::basic_string<char> selfname;
static std::basic_string<char> sufname;
static std::basic_string<char> shortname;

static int count{ 0 };

// Prototypes
void mainmenu();
void disablecompress();
void disablecompressoption();
void enablecompress();
void enablecompressoption();
void compressoption();
void outputoption();
void npdrmdex();
void discdex();
void decfself();
void customcid();
void elfselnpdrm();
void custnpdrm();
void elfselnondrm();
void custnondrm();
void klicresign();
void klicfoundeboot();
void bruteforceeboot();
void klicdec();
void bruteforcepool();
void checkeboot();
void kliccex();
void selfall();
void selfsel();
void selfcex();
void decklic();
void foundkliceboot();
void chkeboot();
void chkpool();
void chklist();
void chkcontentid();
void decsel();
void decsprx();
void encrypt();
void customcid();
void usecid();
void npdrmcex();
void customklic();
void kliclist();


static inline void cls(){
    std::printf("\033[2J\033[1;1H"); // clear screen
    std::printf("\033[1;32m"); // make the output green
}

auto main() -> int {
    for(;;){
        mainmenu();
    }
}

static inline void wait_input(){
    while ((getchar()) != '\n'); // clear cin buffer
    std::cin.get();
}

void createFolder() {
    if(!fs::exists("self")) fs::create_directory("self");
    if(!fs::exists("raps")) fs::create_directory("raps");
}

void decself() {
    if(!fs::exists("EBOOT.BIN")) {
        std::printf("[^^!] EBOOT.BIN cannot be found.\n"
                           "[^^!] Decrypt aborted.\n"
                           "[*] Press [ENTER] to continue...\n");
                  wait_input();
                  return;
    }

    if(fs::exists("EBOOT.ELF")) fs::remove("EBOOT.ELF");
    std::printf("[*] Decrypting EBOOT.BIN...\n");
    system("./tool/scetool --decrypt EBOOT.BIN EBOOT.ELF");

    if(fs::exists("EBOOT.ELF")) {
        std::printf("[*] Decrypt finished.\n");
    } else {
        std::printf("[^^!] Decrypt EBOOT.BIN failed.\n");
    }
    std::cout << "[*] Press [ENTER] to continue...\n";
    wait_input();
    return;
}

void disccex() {
    bool autoresign{ false };
    if(!fs::exists("EBOOT.BIN")) {
        if(!fs::exists("EBOOT.ELF")) {
            std::printf("[^^!] EBOOT.BIN/ELF cannot be found.\n"
                        "[^^!] Resign aborted.\n"
                        "[*] Press [ENTER] to continue...\n");
            wait_input();
            return;
        }
    }

    if(fs::exists("EBOOT.ELF")) {
        std::printf("[*] Decrypting EBOOT.BIN...\n");
        system("./tool/scetool --decrypt EBOOT.BIN EBOOT.ELF");
        autoresign=true;
    }

    if(!fs::exists("EBOOT.ELF")) {
        std::printf("[^^!] Decrypt EBOOT.BIN failed.\n"
                    "[^^!] Resign aborted.\n"
                    "[*] Press [ENTER] to continue...\n");
        wait_input();
        return;
    }

    if(fs::exists("EBOOT.BIN")) {
        if(fs::exists("EBOOT.BIN.BAK")) fs::remove("EBOOT.BIN.BAK");
        fs::rename("EBOOT.BIN", "EBOOT.BIN.BAK");
    }

    std::printf("[*] Patching EBOOT.ELF...\n");
    fix_elf("EBOOT.ELF", elfsdk);
   
    std::printf("[*] Encrypting EBOOT.ELF...\n");
    if(capflagswitch == "TRUE") {
        system("./tool/scetool -v --sce-type=SELF --compress-data=TRUE --skip-sections=TRUE --key-revision=1C --self-auth-id=1010000001000003 --self-vendor-id=01000002 --self-type=APP --self-app-version=0001000000000000 --self-fw-version=0004002000000000 --self-cap-flags=00000000000000000000000000000000000000000000003B0000000100040000 --encrypt EBOOT.ELF EBOOT.BIN");
    }

    if(capflagswitch == "FALSE") {
        if(ctrlflagswitch == "FALSE") {
            system("./tool/scetool -v --sce-type=SELF --compress-data=TRUE --skip-sections=TRUE --key-revision=1C --self-auth-id=1010000001000003 --self-vendor-id=01000002 --self-type=APP --self-app-version=0001000000000000 --self-fw-version=0004002000000000 --encrypt EBOOT.ELF EBOOT.BIN");
        }
    }

    if (capflagswitch == "FALSE") {
        if (ctrlflagswitch == "TRUE") {
            system("./tool/scetool -v --sce-type=SELF --compress-data=TRUE --skip-sections=TRUE --key-revision=1C --self-auth-id=1010000001000003 --self-vendor-id=01000002 --self-type=APP --self-app-version=0001000000000000 --self-fw-version=0004002000000000 --self-ctrl-flags=4000000000000000000000000000000000000000000000000000000000000002 --encrypt EBOOT.ELF EBOOT.BIN");
        }
    }

    if (autoresign) fs::remove("EBOOT.ELF");
    std::printf("[*] Resign finished.\n"
                "[*] Press [ENTER] to continue...\n");
    wait_input();
    return;
}

void mainmenu() {
    cls();
    createFolder();
    
    if(fs::exists("tool/selfinfo.txt"))     fs::remove("tool/selfinfo.txt"  );
    if(fs::exists("tool/selflist.txt"))     fs::remove("tool/selflist.txt"  );
    if(fs::exists("tool/bruteforce.txt"))   fs::remove("tool/bruteforce.txt");
    if(fs::exists("tool/resultlen.txt"))    fs::remove("tool/resultlen.txt" );
    
    std::printf(" =============================================================================== \n"
                "^|                       TrueAncestor SELF Resigner (Linux)                    ^|\n"
                "^|                           by JjKkYu and Erarnitox                           ^|\n"
                "^|                                Verision 2.00                                ^|\n"
                " =============================================================================== \n"
                "^|               CEX CFW                ^|                DEX OFW              ^|\n"
                " =============================================================================== \n"
                "^| 1. Decrypt EBOOT.BIN Only            ^| 9. Decrypt EBOOT.BIN (FSELF) Only   ^|\n"
                "^| 2. Resign to NON-DRM EBOOT           ^| 10. Resign to NON-DRM EBOOT         ^|\n"
                "^| 3. Resign to NPDRM EBOOT             ^| 11. Resign to NPDRM EBOOT           ^|\n"
                "^| 4. Decrypt SELF/SPRX Only            ^|                                     ^|\n"
                "^| 5. Fast Resign NON-DRM SELF/SPRX     ^|                                     ^|\n"
                "^| 6. Fast Resign NPDRM SELF/SPRX       ^|                                     ^|\n"
                "^| 7. Custom Sign to NON-DRM SELF/SPRX  ^|                                     ^|\n"
                "^| 8. Custom Sign to NPDRM SELF/SPRX    ^|                                     ^|\n"
                " =============================================================================== \n"
                "^|                               SWITCH (CEX CFW)                              ^|\n"
                " =============================================================================== \n"
                "^| 12. Output Method: %s                                               ^|\n"
                "^| 13. Compress Data: %s                                                     ^|\n"
                "^|                                                                             ^|\n"
                "^|                                                                             ^|\n"
                " =============================================================================== \n"
                "^| Note: Place EBOOT.BIN/ELF into Resigner folder before operation.            ^|\n"
                "^|       Place SELF/SPRX files into self folder before operation.              ^|\n"
                " =============================================================================== \n",
                outputmsg.c_str(), compressmsg.c_str());

    int choice{ '0' };
    std::printf("Please enter your choice (1-13):");
    std::cin >> choice;

    switch(choice){
        case 1:  decself(); break;
        case 2:  disccex(); break;
        case 3:  npdrmcex(); break;
        case 4:  decsprx(); break;
        case 5:  selfcex(); break;
        //case 6:  kliccex(); break;
        //case 7:  custnondrm(); break;
        //case 8:  custnpdrm(); break;
        //case 9:  decfself(); break;
        //case 10: discdex(); break;
        //case 11: npdrmdex(); break;
        case 12 : outputoption(); break;
        case 13 : compressoption(); break;
    }

    std::cout << "Invalid input, please enter among (1-11/O/D/C/I/G/T)." << std::endl;
    std::cout << "[*] Press [ENTER] to continue..." << std::endl;
    
    return;
}


void npdrmcex() {
    if (output == "4xxode") {
        std::printf("[^^!] NPDRM Resign is inapplicable for ODE Output.");
        wait_input();
        return;
    }

    std::string autoresign="FALSE";
    if(!fs::exists("EBOOT.BIN")) {
        if (!fs::exists("EBOOT.ELF")) {
            std::puts("[*] EBOOT.BIN/ELF cannot be found.");
            std::puts("[*] Press any key to continue...");
            wait_input();
            return;
        }
    }

    if (!fs::exists("EBOOT.ELF")) {
        std::puts("[*] Decrypting EBOOT.BIN...");
        system("./tool/scetool --decrypt EBOOT.BIN EBOOT.ELF");
        autoresign="TRUE";
    }

    if (!fs::exists("EBOOT.ELF")) {
        std::puts("[^^!] Decrypt EBOOT.BIN failed.");
        std::puts("[^^!] Resign aborted.)");
        std::puts("[*] Press any key to continue...");
        wait_input();
        return;
    }

    contentid="NONE";
    system("./tool/scetool -i EBOOT.BIN>./tool/selfinfo.txt");
    
    std::ifstream file("./tool/selfinfo.txt");
    std::string line;

    // Skip the first 3 lines
    for (int i = 0; i < 3; ++i) {
        std::getline(file, line);
    }

    while (std::getline(file, line)) {
        std::istringstream iss(line);
        std::string token;

        iss >> token;
        if (token == "ContentID") {
            iss >> contentid;
            break;
        }
    }

    if (contentid == "NONE") {
        customcid();
    }
}

void usecid() {
    int usecid{ 0 };
    std::printf("[*] Found ContentID in EBOOT.BIN: %s\n", contentid.c_str());
    std::printf("usecid=[%s]\1: Return to use this Content-ID Enter\n2: Enter custom ContentID:", contentid.c_str());
    std::cin >> usecid;
    
    if (!usecid || usecid == 1) encrypt();
    else customcid();
}


void customcid() {
    std::basic_string<char> s_customcid{ "NONE" };
    std::puts("[*] Enter custom ContentID:");
    std::puts("[*] Please follow this sample ContentID:JP9000-NPJA00001_00-0000000000000000");
    std::printf("Enter custom ContentID: (Enter A to Abort)");
    std::cin >> s_customcid;

    if (s_customcid=="NONE") {
        customcid();
    } else if (s_customcid=="A") {
        return;
    } else if (s_customcid=="a") {
        return;
    }
    const int cidlength{ static_cast<int>(s_customcid.length()) };

    if(cidlength != 36) {
        std::puts("[^^!] Invalid ContentID format, please enter following the sample ContentID.");
        std::puts("[*] Press any key to continue...");
        wait_input();
        customcid();
    }
    if(s_customcid.at(6) != '-') {
        std::puts("[^^!] Invalid ContentID format, please enter following the sample ContentID.");
        std::puts("[*] Press any key to continue...");
        wait_input();
        customcid();
    }
    if(s_customcid.substr(16,4) != "_00-") {
        std::puts("[^^!] Invalid ContentID format, please enter following the sample ContentID.");
        std::puts("[*] Press any key to continue...");
        wait_input();
        customcid();
    }
    contentid=s_customcid;
}

void encrypt() {
    if(fs::exists("EBOOT.BIN")) {
        if(fs::exists("EBOOT.BIN.BAK")) {
            fs::remove("EBOOT.BIN.BAK");
        }
        fs::rename("EBOOT.BIN", "EBOOT.BIN.BAK");
    }
    std::puts("[*] Patching EBOOT.ELF...");
    fix_elf("EBOOT.ELF", elfsdk);
    std::puts("[*] Encrypting EBOOT.ELF...");
    std::basic_string<char> npapptype{ "EXEC" };
    if(contentid.substr(7,1) == "B") {
        npapptype="UEXEC";
    }
    if(ctrlflagswitch=="FALSE") {
        auto command{ std::format(
            "./tool/scetool -v --sce-type=SELF --compress-data={} --skip-sections=TRUE "
            "--key-revision={} --self-auth-id=1010000001000003 --self-add-shdrs=TRUE "
            "--self-vendor-id=01000002 --self-type=NPDRM --self-app-version=0001000000000000 "
            "--self-fw-version={} --np-license-type=FREE --np-content-id={} --np-app-type={} "
            "--np-real-fname=EBOOT.BIN --encrypt EBOOT.ELF EBOOT.BIN",
            compress, keyrev, fwver, contentid, npapptype
        )};
        system(command.c_str());
    }
    if(ctrlflagswitch=="TRUE") {
        auto command{ std::format(
            "./tool/scetool -v --sce-type=SELF --compress-data={} "
            "--skip-sections=TRUE --key-revision={} --self-auth-id=1010000001000003 "
            "--self-add-shdrs=TRUE --self-vendor-id=01000002 --self-type=NPDRM --self-app-version=0001000000000000 "
            "--self-fw-version={} --self-ctrl-flags={} --np-license-type=FREE "
            "--np-content-id={} --np-app-type={} --np-real-fname=EBOOT.BIN "
            "--encrypt EBOOT.ELF EBOOT.BIN",
            compress, keyrev, fwver, selfctrlflags, contentid, npapptype
        )};
        system(command.c_str());
    }
    if(autoresign=="TRUE") {
        fs::remove("EBOOT.ELF");
    }
    std::puts("[*] Resign finished.");
    std::puts("[*] Press any key to continue...");
    wait_input();
}

auto selectSelf(int n) -> std::string {
    if(fs::exists("./tool/selflist.txt")) {
        std::ifstream selflist("thefile.txt");
        std::string file;
        while (std::getline(selflist, file)) {
            ++count;
            if(count == n) {
                return file;
            }
        }
    }
    return "";
}

void decsprx() {
    // in the self directory
    if(fs::exists("./tool/selflist.txt")) {
        fs::remove("./tool/selflist.txt");
    }
    system("ls self | grep .self > ./tool/selflist.txt");
    system("ls self | grep .sprx > ./tool/selflist.txt");
    
    count = 0;
    cls();

    std::puts("===============================================================================");
    std::puts("SELF/SPRX Files List");
    std::puts("===============================================================================");
    if(fs::exists("./tool/selflist.txt")) {
        std::ifstream selflist("thefile.txt");
        std::string file;
        while (std::getline(selflist, file)) {
            ++count;
            if(count != 0) {
                std::printf(" %d. %s ", count, file.c_str());
            }
        }
     } else {
        std::puts("No SELF/SPRX is Found.");
     }
    std::puts("===============================================================================");
    if(count==0) {
        wait_input();
        return;
    }
    std::puts("Note: To decrypt NPDRM file, EBOOT.BIN might be needed in Resigner folder.");
    std::puts("===============================================================================");
}

void decsel() {
    int selfsel{ 0 };
    std::puts("Enter SELF/SPRX file number to decrypt / 99 to Back:");
    std::cin >> selfsel;
    if(selfsel==0) {
        decsprx();
    }
    if(selfsel==99) {
        return;
    }
    if(selfsel > count) {
        std::puts("[^^!] Invalid input, please enter again.");
        std::puts("[*] Press any key to continue...");
        wait_input();
        decsprx();
    }
    if(selfsel < 1) {
        std::puts("[^^!] Invalid input, please enter again.");
        std::puts("[*] Press any key to continue...");
        wait_input();
        decsprx();
    }
    
    selfname = selectSelf(selfsel);
    shortname = selfname.substr(0,selfname.length()-5);
    sufname = selfname.substr(selfname.length()-4,4);

    std::string elfsuffix;

    if(sufname=="self") {
        elfsuffix="elf";
    }
    if(sufname=="SELF") {
        elfsuffix="ELF";
    }
    if(sufname=="sprx") {
        elfsuffix="prx";
    }
    if(sufname=="SPRX") {
        elfsuffix="PRX";
    }
    if(fs::exists(std::format("./self/{}.{}", shortname, elfsuffix))) { 
        fs::remove(std::format("./self/{}.{}", shortname, elfsuffix));
    }
    std::puts("[*] Decrypting %selfname%...");
    auto command { std::format(
        "./tool/scetool --decrypt ./self/{} ./self/{}.{}",
        selfname, shortname, elfsuffix
    )};
    system(command.c_str());

    if(!fs::exists(std::format("./self/{}.{}", shortname, elfsuffix))) {
        chkcontentid();
    }
    std::puts("[*] Decrypt file to %shortname%.%elfsuffix% successfully.");
    std::puts("[*] Press any key to continue...");
    wait_input();
    decsprx();
}

void chkcontentid() {
    contentid="NONE";
    system( std::format("./tool/scetool -i ./self/{}>./tool/selfinfo.txt", selfname).c_str());
    
    std::ifstream infile("./tool/selfinfo.txt");
    std::string line;
    std::string contentid;

    // Skip first 3 lines
    for (int i{ 0 }; i < 3; ++i) {
        std::getline(infile, line);
    }

    while (std::getline(infile, line)) {
        size_t pos{ line.find_first_of(" \t") };
        if (pos != std::string::npos) {
            std::string token = line.substr(0, pos);

            if (token == "ContentID") {
                contentid = line.substr(pos + 1);
                break;
            }
        }
    }

    if(contentid=="NONE") {
        std::puts("[^^!] Decrypt %selfname% failed.");
        std::puts("[*] Press any key to continue...");
        wait_input();
        decsprx();
    }
    std::printf("[*] Found ContentID in %s file: %s\n", sufname, contentid);
}

void selfcex() {
    if(fs::exists("./tool/selflist.txt ")) {
        fs::remove("./tool/selflist.txt");
    }
    if(fs::exists("*.self ")) {
        system("ls | grep .self >./tool/selflist.txt");
    }
    if(fs::exists("*.sprx ")) {
        system("ls | .sprx >>./tool/selflist.txt");
    }
    int count{ 0 };
    cls();
    std::puts("===============================================================================");
    std::puts(" SELF/SPRX Files List");
    std::puts("===============================================================================");
    if(fs::exists("./tool/selflist.txt ")) {
        std::ifstream infile("./tool/selflist.txt");
        std::string filename;

        const int MAX_COUNT{ 100 };
        std::array<std::string, MAX_COUNT> filenames;
        while (std::getline(infile, filename) && count < MAX_COUNT) {
            filenames[count] = filename;
            ++count;
        }
    } else {
        std::puts(" No SELF/SPRX is Found.");
    }
    std::puts("===============================================================================");
    if(count==0) {
        wait_input();
        return;
    }
}

/*
void chklist() {
    if(!fs::exists("./tool/kliclist.txt")) {
        chkpool();
    }
    klicensee="NONE";
    for /f "tokens=1,*" %%i in (tool\kliclist.txt) do if "%%i"=="%contentid%" set klicensee=%%j
    for /l %%a in (0 1 99) do if not "!klicensee:~%%a,1!"=="" set /a kliclen=%%a+1
    if %kliclen% NEQ 32 (
        chkpool();
    ) else (
        std::puts("[*] Found Klicensee in Klic List: %klicensee%");
        decklic();
    )
}


void chkpool() {
    if(!fs::exists("./tool/klicpool.txt")) {
        chkeboot();
    }
    tool\klicencebruteforce -x self\%selfname% tool\klicpool.txt data\keys>tool\bruteforce.txt
    for /f "skip=3 tokens=1,*" %%i in (tool\bruteforce.txt) do if "%%i"=="[*]" set bruteforceresult=%%j
    if %bruteforceresult:~4,2%==no (
        chkeboot();
    )
    set klicensee=%bruteforceresult:~24,32%
    tool\Rtlen %bruteforceresult%>tool\resultlen.txt
    set /p resultlen=<tool\resultlen.txt
    if %resultlen%==43 set klicensee=%bruteforceresult:~11,32%
    std::puts("[*] Found Klicensee in Klic Pool: %klicensee%");
    std::puts("%contentid% %klicensee%>>tool\kliclist.txt");
    decklic();
}


void chkeboot() {
    if(!fs::exists("EBOOT.BIN ")) {
        std::puts("[*] EBOOT.BIN cannot be found in Resigner folder.");
        std::puts("[^^!] Decrypt %selfname% failed.");
        std::puts("[*] Press any key to continue...");
        wait_input();
        decsprx();
    }
    if(fs::exists("EBOOT.ELF ")) {
        fs::remove("EBOOT.ELF");
    }
    system("./tool/scetool --decrypt EBOOT.BIN EBOOT.ELF");
    if(!fs::exists("EBOOT.ELF ")) {
        std::puts("[^^!] Decrypt EBOOT.BIN failed.");
        std::puts("[^^!] Decrypt %selfname% failed.");
        std::puts("[*] Press any key to continue...");
        wait_input();
        decsprx();
    }
    std::puts("[*] Start BruteForce Detecting Klicensee, please wait...");
    system("./tool/klicencebruteforce -x self\%selfname% EBOOT.ELF data\keys>tool\bruteforce.txt");
    if(fs::exists("EBOOT.ELF ")) {
        fs::remove("EBOOT.ELF");
    }
    for /f "skip=3 tokens=1,*" %%i in (tool\bruteforce.txt) do if "%%i"=="[*]" set bruteforceresult=%%j
    if %bruteforceresult:~4,2%==no (
        std::puts("[^^!] Cannot find Klicensee, BruteForce Detecting failed.");
        std::puts("[^^!] Decrypt %selfname% failed.");
        std::puts("[*] Press any key to continue...");
        wait_input();
        decsprx();
    ) else (
        foundkliceboot();
    )
}


void foundkliceboot() {
    set klicensee=%bruteforceresult:~24,32%
    ./tool/Rtlen %bruteforceresult%>./tool/resultlen.txt
    set /p resultlen=<./tool/resultlen.txt
    if %resultlen%==43 set klicensee=%bruteforceresult:~11,32%
    std::puts("[*] Found Klicensee in EBOOT.BIN: %klicensee%");
    std::puts("%klicensee%>>./tool/klicpool.txt");
    std::puts("%contentid% %klicensee%>>./tool/kliclist.txt");
}


void decklic() {
    ./tool/scetool.exe --np-klicensee %klicensee% --decrypt self\%selfname% self\%shortname%.%elfsuffix%>nul
    if(!fs::exists("self\%shortname%.%elfsuffix% ")) {
        std::puts("[^^!] Decrypt !selfname%count%! failed.");
        std::puts("[*] Press any key to continue...");
        wait_input();
    }
    std::puts("[*] Decrypt file to %shortname%.%elfsuffix% successfully.");
    std::puts("[*] Press any key to continue...");
    wait_input();
    decsprx();
}

void selfsel() {
    selfsel="NONE";
    set /p selfsel=[?] Enter SELF/SPRX file number to resign / A for All / B to Back:

    if(selfsel=="NONE") {
        selfcex();
    }
    if(selfsel=="A") {
        selfall();
    }
    if(selfsel=="a") {
        selfall();
    }
    if(selfsel=="B") {
        mainmenu();
    }
    if(selfsel=="b") {
        mainmenu();
    }
    if(selfsel > count) {
        std::puts("[^^!] Invalid input, please enter again.");
        std::puts("[*] Press any key to continue...");
        wait_input();
        selfsel();
    }
    if(selfsel < 1) {
        std::puts("[^^!] Invalid input, please enter again.");
        std::puts("[*] Press any key to continue...");
        wait_input();
        selfsel();
    }

    set selfname=!a%selfsel%!
    set shortname=%selfname:~0,-5%
    set sufname=%selfname:~-4,4%
    if %sufname%==self (
        elfsuffix="elf";
        baksuffix="bak";
    )
    if %sufname%==SELF (
        elfsuffix="ELF";
        baksuffix="BAK";
    )
    if %sufname%==sprx (
        elfsuffix="prx";
        baksuffix="bak";
    )
    if %sufname%==SPRX (
        elfsuffix="PRX";
        baksuffix="BAK";
    )
    if(fs::exists("self\%shortname%.%elfsuffix% ")) {
        fs::remove("self\%shortname%.%elfsuffix%");
    }
    std::puts("[*] Decrypting %selfname%...");
    ./tool/scetool --decrypt self\%selfname% self\%shortname%.%elfsuffix%>nul
    if(!fs::exists("self\%shortname%.%elfsuffix% ")) {
        std::puts("[^^!] Decrypt %selfname% failed.");
        std::puts("[^^!] Resign aborted.");
        std::puts("[*] Press any key to continue...");
        wait_input();
        selfcex();
    }
    if(fs::exists("self\%selfname%.%baksuffix% ")) {
        fs::remove("self\%selfname%.%baksuffix%");
    }
    copy self\%selfname% self\%selfname%.%baksuffix%>nul
    std::puts("[*] Patching %shortname%.%elfsuffix%...");
    fix_elf(self\%shortname%.%elfsuffix%, %elfsdk%);
    std::puts("[*] Encrypting %shortname%.%elfsuffix%...");
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
    if(fs::exists("self\%shortname%.%elfsuffix% ")) {
        fs::remove("self\%shortname%.%elfsuffix%");
    }
    std::puts("[*] Resign finished.");
    std::puts("[*] Press any key to continue...");
    wait_input();
    selfcex();
}


void selfall() {
    int count="0";
    int error="0";
    for /f %%f in (tool\selflist.txt) do (
        count+=1;
        set selfname%count%=%%f
        set shortname%count%=!selfname%count%:~0,-5!
        set sufname%count%=!selfname%count%:~-4,4!
        if !sufname%count%!==self (
            elfsuffix[count]="elf";
            baksuffix[count]="bak";
        )
        if !sufname%count%!==SELF (
            elfsuffix[count]="ELF";
            baksuffix[count]="BAK";
        )
        if !sufname%count%!==sprx (
            elfsuffix[count]="prx";
            baksuffix[count]="bak";
        )
        if !sufname%count%!==SPRX (
            elfsuffix[count]="PRX";
            baksuffix[count]="BAK";
        )
        if(fs::exists("self\!shortname%count%!.!elfsuffix%count%! ")) {
            fs::remove("self\!shortname%count%!.!elfsuffix%count%!");
        )
        std::puts("[*] Resigning !selfname%count%!...");
        ./tool/scetool --decrypt self\!selfname%count%! self\!shortname%count%!.!elfsuffix%count%!>nul
        if(!fs::exists("self\!shortname%count%!.!elfsuffix%count%! ")) {
            std::puts("[^^!] Decrypt !selfname%count%! failed.");
            std::puts("[^^!] Resign !selfname%count%! aborted.");
            error+=1;
        }
        if(fs::exists("self\!shortname%count%!.!elfsuffix%count%! ")) {
            if(fs::exists("self\!selfname%count%!.!baksuffix%count%! ")) {
                fs::remove("self\!selfname%count%!.!baksuffix%count%!");
            }
            copy self\!selfname%count%! self\!selfname%count%!.!baksuffix%count%!>nul
            fix_elf("self\!shortname%count%!.!elfsuffix%count%!", elfsdk);
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
            if(fs::exists("self\!shortname%count%!.!elfsuffix%count%! ")) {
                fs::remove("self\!shortname%count%!.!elfsuffix%count%!");
            }
            std::puts("[*] Resign !selfname%count%! finished.");
        }
    }
    if %error%==0 (
        std::puts("[*] Resign all SELF/SPRX files successfully.");
    ) else (
        std::puts("[^^!] Resign all SELF/SPRX files finished, %error% file^(s^) failed.");
    )
    std::puts("[*] Press any key to continue...");
    wait_input();
}


void kliccex() {
    if %output%==4xxode (
        std::puts("[^^!] NPDRM Resign is inapplicable for ODE Output.");
        wait_input();
        return;
    )
    cd self
    if(fs::exists("..\tool\selflist.txt ")) {
        fs::remove("..\tool\selflist.txt");
    }
    if(fs::exists("*.self ")) {
        dir *.self /b >..\tool\selflist.txt
    }
    if(fs::exists("*.sprx ")) {
        dir *.sprx /b >>..\tool\selflist.txt
    }
    cd..
    set /a count=0
    cls
    std::puts("===============================================================================");
    std::puts(" SELF/SPRX Files List");
    std::puts("===============================================================================");
    if(fs::exists("tool\selflist.txt ")) {
        for /f %%f in (tool\selflist.txt) do (
            set /a count+=1
            set a!count!=%%f
            if count NEQ 0 (
                std::puts(" !count!. %%f ");
            )
        )
    } else {
        std::puts(" No SELF/SPRX is Found.");
    };
    std::puts("===============================================================================");
    if !count!==0 (
        wait_input();
        return;
    )
    std::puts(" Note: BruteForce Detecting Klicensee method will be used in this option.");
    std::puts("       EBOOT.BIN must be placed into Resigner folder for detecting Klicensee.");
    std::puts("       Make sure that EBOOT.BIN and SELF/SPRX files are from the same game.");
    std::puts("===============================================================================");
    set klicgo=NONE
    set /p klicgo=[?] Enter any key to continue / B to Back:
    if %klicgo%==NONE (
        checkeboot();
    )
    if %klicgo%==B (
        return;
    )
    if %klicgo%==b (
        return;
    )
}


void checkeboot() {
    if(!fs::exists("EBOOT.BIN ")) {
        std::puts("[^^!] EBOOT.BIN cannot be found in Resigner folder.");
        std::puts("[^^!] Resign aborted.");
        std::puts("[*] Press any key to continue...");
        wait_input();
        kliccex();
    }
    set contentid=NONE
    tool\scetool.exe -i EBOOT.BIN>tool\selfinfo.txt
    for /f "skip=3 tokens=1,*" %%i in (tool\selfinfo.txt) do if "%%i"=="ContentID" set contentid=%%j
    if %contentid%==NONE (
        std::puts("[^^!] EBOOT.BIN should be an NPDRM EBOOT.");
        std::puts("[^^!] Resign aborted.");
        std::puts("[*] Press any key to continue...");
        wait_input();
        kliccex();
    )
    if(fs::exists("tool\kliclist.txt ")) {
        kliclist();
    }
    klicdec();
}


void kliclist() {
    set klicensee=NONE
    for /f "tokens=1,*" %%i in (tool\kliclist.txt) do if "%%i"=="%contentid%" set klicensee=%%j
    for /l %%a in (0 1 99) do if not "!klicensee:~%%a,1!"=="" set /a kliclen=%%a+1
    if %kliclen% NEQ 32 (
        bruteforcepool();
    ) else (
        std::puts("[*] Found ContentID in EBOOT.BIN: %contentid%");
        std::puts("[*] Found Klicensee in Klic List: %klicensee%");
        klicresign();
    )
}


void bruteforcepool() {
    if(!fs::exists("tool\klicpool.txt (goto klicdec")) {
    set /p usesprx=<tool\selflist.txt
    tool\klicencebruteforce -x self\%usesprx% tool\klicpool.txt data\keys>tool\bruteforce.txt
    for /f "skip=3 tokens=1,*" %%i in (tool\bruteforce.txt) do if "%%i"=="[*]" set bruteforceresult=%%j
    if %bruteforceresult:~4,2%==no (goto klicdec)
    set klicensee=%bruteforceresult:~24,32%
    tool\Rtlen %bruteforceresult%>tool\resultlen.txt
    set /p resultlen=<tool\resultlen.txt
    if %resultlen%==43 set klicensee=%bruteforceresult:~11,32%
    std::puts("[*] Found ContentID in EBOOT.BIN: %contentid%");
    std::puts("[*] Found Klicensee in Klic Pool: %klicensee%");
    std::puts("%contentid% %klicensee%>>tool\kliclist.txt");
    klicresign();
}


void klicdec() {
    if(fs::exists("EBOOT.ELF")) {
        fs::remove("EBOOT.ELF");
    }
    system("./tool/scetool.exe --decrypt EBOOT.BIN EBOOT.ELF");
    if(!fs::exists("EBOOT.ELF ")) {
        std::puts("[^^!] Decrypt EBOOT.BIN failed.");
        std::puts("[^^!] Resign aborted.");
        std::puts("[*] Press any key to continue...");
        wait_input();
        kliccex();
    }
}


void bruteforceeboot() {
    std::puts("[*] Start BruteForce Detecting Klicensee, please wait...");
    std::puts("[*] Found ContentID in EBOOT.BIN: %contentid%");
    set /p usesprx=<tool\selflist.txt
    tool\klicencebruteforce -x self\%usesprx% EBOOT.ELF data\keys>tool\bruteforce.txt
    if(fs::exists("EBOOT.ELF ")) {
        fs::remove("EBOOT.ELF");
    }
    for /f "skip=3 tokens=1,*" %%i in (tool\bruteforce.txt) do if "%%i"=="[*]" set bruteforceresult=%%j
    if %bruteforceresult:~4,2%==no (
        std::puts("[^^!] Cannot find Klicensee, BruteForce Detecting failed.");
        std::puts("[^^!] Resign aborted.");
        std::puts("[*] Press any key to continue...");
        wait_input();
        kliccex();
    ) else (
        klicfoundeboot();
    )
}


void klicfoundeboot() {
    set klicensee=%bruteforceresult:~24,32%
    tool\Rtlen %bruteforceresult%>tool\resultlen.txt
    set /p resultlen=<tool\resultlen.txt
    if %resultlen%==43 set klicensee=%bruteforceresult:~11,32%
    std::puts("[*] Found Klicensee in EBOOT.BIN: %klicensee%");
    std::puts("%klicensee%>>tool\klicpool.txt");
    std::puts("%contentid% %klicensee%>>tool\kliclist.txt");
}

void klicresign() {
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
    if(fs::exists("self\!shortname%count%!.!elfsuffix%count%!") { 
        fs::remove("self\!shortname%count%!.!elfsuffix%count%!");
    }
    std::puts("[*] Resigning !selfname%count%!...");
    tool\scetool.exe --np-klicensee %klicensee% --decrypt self\!selfname%count%! self\!shortname%count%!.!elfsuffix%count%!>nul
    if(!fs::exists("self\!shortname%count%!.!elfsuffix%count%! ")) {
    std::puts("[^^!] Decrypt !selfname%count%! failed.");
    std::puts("[^^!] Resign !selfname%count%! aborted.");
    set /a error+=1
    )
    if(fs::exists("self\!shortname%count%!.!elfsuffix%count%! ")) {
    if(fs::exists("self\!selfname%count%!.!baksuffix%count%!")) {
        fs::remove("self\!selfname%count%!.!baksuffix%count%!");
    }
    copy self\!selfname%count%! self\!selfname%count%!.!baksuffix%count%!>nul
    fix_elf("self\!shortname%count%!.!elfsuffix%count%!", elfsdk);
    if %ctrlflagswitch%==FALSE (
    tool\scetool.exe -v --sce-type=SELF --compress-data=%compress% --skip-sections=TRUE --key-revision=%keyrev% --self-auth-id=1010000001000003 --self-add-shdrs=TRUE --self-vendor-id=01000002 --self-type=NPDRM --self-app-version=0001000000000000 --self-fw-version=%fwver% --np-license-type=FREE --np-content-id=%contentid% --np-app-type=!npapptype%count%! --np-klicensee=%klicensee% --np-real-fname=!selfname%count%! --encrypt self\!shortname%count%!.!elfsuffix%count%! self\!selfname%count%!>nul
    )
    if %ctrlflagswitch%==TRUE (
    tool\scetool.exe -v --sce-type=SELF --compress-data=%compress% --skip-sections=TRUE --key-revision=%keyrev% --self-auth-id=1010000001000003 --self-add-shdrs=TRUE --self-vendor-id=01000002 --self-type=NPDRM --self-app-version=0001000000000000 --self-fw-version=%fwver% --self-ctrl-flags=%selfctrlflags% --np-license-type=FREE --np-content-id=%contentid% --np-app-type=!npapptype%count%! --np-klicensee=%klicensee% --np-real-fname=!selfname%count%! --encrypt self\!shortname%count%!.!elfsuffix%count%! self\!selfname%count%!>nul
    )
    if(fs::exists("self\!shortname%count%!.!elfsuffix%count%!")){
        fs::remove("self\!shortname%count%!.!elfsuffix%count%!");
    }
    std::puts("[*] Resign !selfname%count%! finished.");
    )
    )
    if %error%==0 (
    std::puts("[*] Resign all SELF/SPRX files successfully.");
    ) else (
    std::puts("[^^!] Resign all SELF/SPRX files finished, %error% file^(s^) failed.");
    )
    std::puts("[*] Press any key to continue...");
    wait_input();
}

void custnondrm() {
    cd self
    if(fs::exists("..\tool\selflist.txt")){
        fs::remove("..\tool\selflist.txt");
    }
    if(fs::exists("*.elf")){
        dir *.elf /b >..\tool\selflist.txt
    }
    if(fs::exists("*.prx")){
        dir *.prx /b >>..\tool\selflist.txt
    }
    cd..
    set /a count=0
    cls
    std::puts("===============================================================================");
    std::puts(" ELF/PRX Files List");
    std::puts("===============================================================================");
    if(fs::exists("tool\selflist.txt ")) {
    for /f %%f in (tool\selflist.txt) do (
    set /a count+=1
    set a!count!=%%f
    if count NEQ 0 (std::puts(" !count!. %%f )");
    )
    ) else (std::puts(" No ELF/PRX is Found.)");
    std::puts("===============================================================================");
    if !count!==0 (
        wait_input();
    )
}


void elfselnondrm() {
    set selfsel=NONE
    set /p selfsel=[?] Enter ELF/PRX file number to resign / B to Back:
    if %selfsel%==NONE (goto custnondrm)
    if %selfsel%==B (goto mainmenu)
    if %selfsel%==b (goto mainmenu)
    if %selfsel% GTR !count! (
    std::puts("[^^!] Invalid input, please enter again.");
    std::puts("[*] Press any key to continue...");
    wait_input();
    elfselnondrm();
    )
    if %selfsel% LSS 1 (
    std::puts("[^^!] Invalid input, please enter again.");
    std::puts("[*] Press any key to continue...");
    wait_input();
    elfselnondrm();
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
    if(fs::exists("self\%shortname%.%selfsuffix%")) {
        fs::remove("self\%shortname%.%selfsuffix%");
    }
    std::puts("[*] Patching %elfname%...");
    fix_elf("self\%elfname%", elfsdk);
    std::puts("[*] Encrypting %elfname%...");
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
    std::puts("[*] Custom sign finished.");
    std::puts("[*] Press any key to continue...");
    wait_input();
    custnondrm();
}


void custnpdrm() {
    if %output%==4xxode (
    std::puts("[^^!] NPDRM Resign is inapplicable for ODE Output.");
    wait_input();
    return;
    )
    cd self
    if(fs::exists("./tool/selflist.txt")) {
        fs::remove("..\tool\selflist.txt");
    }
    if(fs::exists("*.elf"){
        dir *.elf /b >..\tool\selflist.txt
    }
    if(fs::exists("*.prx")){
        dir *.prx /b >>..\tool\selflist.txt
    }
    cd..
    set /a count=0
    cls
    std::puts("===============================================================================");
    std::puts(" ELF/PRX Files List");
    std::puts("===============================================================================");
    if(fs::exists("tool/selflist.txt ")) {
    for /f %%f in (tool\selflist.txt) do (
    set /a count+=1
    set a!count!=%%f
    if count NEQ 0 (std::puts(" !count!. %%f )");
    )
    ) else (std::puts(" No ELF/PRX is Found.)");
    std::puts("===============================================================================");
    if !count!==0 (
    wait_input();
    )
}


void elfselnpdrm() {
    set selfsel=NONE
    set /p selfsel=[?] Enter ELF/PRX file number to resign / B to Back:
    if %selfsel%==NONE (
        custnpdrm();
    )
    if %selfsel%==B (
        return;
    )
    if %selfsel%==b (
        return;
    )
    if %selfsel% GTR !count! (
    std::puts("[^^!] Invalid input, please enter again.");
    std::puts("[*] Press any key to continue...");
    wait_input();
    elfselnpdrm();
    )
    if %selfsel% LSS 1 (
    std::puts("[^^!] Invalid input, please enter again.");
    std::puts("[*] Press any key to continue...");
    wait_input();
    elfselnpdrm();
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
}


void customcid() {
    set customcid=NONE
    std::puts("[*] Please follow this sample ContentID:JP9000-NPJA00001_00-0000000000000000");
    set /p customcid=[?] Enter custom ContentID / A to Abort:
    if %customcid%==NONE (
        customcid();
    )
    if %customcid%==A (
        custnpdrm();
    )
    if %customcid%==a (
        custnpdrm();
    )
    set cidlength=0
    for /l %%a in (0 1 99) do if not "!customcid:~%%a,1!"=="" set /a cidlength=%%a+1
    if %cidlength% NEQ 36 (
    std::puts("[^^!] Invalid ContentID format, please enter following the sample ContentID.");
    std::puts("[*] Press any key to continue...");
    wait_input();
    customcid();
    )
    if %customcid:~6,1% NEQ - (
    std::puts("[^^!] Invalid ContentID format, please enter following the sample ContentID.");
    std::puts("[*] Press any key to continue...");
    wait_input();
    customcid();
    )
    if %customcid:~16,4% NEQ _00- (
    std::puts("[^^!] Invalid ContentID format, please enter following the sample ContentID.");
    std::puts("[*] Press any key to continue...");
    wait_input();
    customcid();
    )
    set contentid=%customcid%
}


void customklic() {
    set klicensee=NONE
    std::puts("[*] Please follow this KLicensee sample:00000000000000000000000000000000");
    set /p klicensee=[?] Please enter KLicensee / A to Abort:
    if %klicensee%==NONE (
        customklic();
    )
    if %klicensee%==A (
        custnpdrm();
    )
    if %klicensee%==a (
        custnpdrm();
    )
    set kliclen=0
    for /l %%a in (0 1 99) do if not "!klicensee:~%%a,1!"=="" set /a kliclen=%%a+1
    if %kliclen% NEQ 32 (
        std::puts("[*] Invalid Klicensee format, please enter following the KLicensee sample.");
        std::puts("[*] Press any key to continue...");
        wait_input();
        customklic();
    )
    set npapptype=SPRX
    if %contentid:~7,1%==B (
        set npapptype=USPRX
    )
    if(fs::exists("self\%shortname%.%selfsuffix% ")) {
        fs::remove("self\%shortname%.%selfsuffix%");
    )
    std::puts("[*] Patching %elfname%...");
    fix_elf("self\%elfname%", elfsdk);
    std::puts("[*] Encrypting %elfname%...");
    if %ctrlflagswitch%==FALSE (
        tool\scetool.exe -v --sce-type=SELF --compress-data=%compress% --skip-sections=TRUE --key-revision=%keyrev% --self-auth-id=1010000001000003 --self-add-shdrs=TRUE --self-vendor-id=01000002 --self-type=NPDRM --self-app-version=0001000000000000 --self-fw-version=%fwver% --np-license-type=FREE --np-content-id=%contentid% --np-app-type=%npapptype% --np-klicensee=%klicensee% --np-real-fname=%shortname%.%selfsuffix% --encrypt self\%elfname% self\%shortname%.%selfsuffix%>nul
    )
    if %ctrlflagswitch%==TRUE (
        tool\scetool.exe -v --sce-type=SELF --compress-data=%compress% --skip-sections=TRUE --key-revision=%keyrev% --self-auth-id=1010000001000003 --self-add-shdrs=TRUE --self-vendor-id=01000002 --self-type=NPDRM --self-app-version=0001000000000000 --self-fw-version=%fwver% --self-ctrl-flags=%selfctrlflags% --np-license-type=FREE --np-content-id=%contentid% --np-app-type=%npapptype% --np-klicensee=%klicensee% --np-real-fname=%shortname%.%selfsuffix% --encrypt self\%elfname% self\%shortname%.%selfsuffix%>nul
    )
    std::puts("[*] Custom sign finished.");
    std::puts("[*] Press any key to continue...");
    wait_input();
}


void decfself() {
    if(!fs::exists("EBOOT.BIN ")) {
        std::puts("[^^!] EBOOT.BIN cannot be found.");
        std::puts("[^^!] Decrypt aborted.");
        std::puts("[*] Press any key to continue...");
        wait_input();
        return;
    }
    if(fs::exists("EBOOT.ELF ")) {
        fs::remove("EBOOT.ELF");
    }
    std::puts("[*] Decrypting EBOOT.BIN...");
    system("./tool/unfself EBOOT.BIN EBOOT.ELF");
    if(fs::exists("EBOOT.ELF ")) {
        std::puts("[*] Decrypt finished.");
    } else {
        std::puts("[^^!] Decrypt EBOOT.BIN failed.");
    }
    std::puts("[*] Press any key to continue...");
    wait_input();
}


void discdex() {
    autoresign="FALSE";
    if(!fs::exists("EBOOT.BIN ")) {
        if(!fs::exists("EBOOT.ELF ")) {
            std::puts("[^^!] EBOOT.BIN/ELF cannot be found.");
            std::puts("[^^!] Resign aborted.");
            std::puts("[*] Press any key to continue...");
            wait_input();
            return;
        }
    }
    if(!fs::exists("EBOOT.ELF ")) {
        std::puts("[*] Decrypting EBOOT.BIN...");
        tool\scetool.exe --decrypt EBOOT.BIN EBOOT.ELF>nul
        autoresign="TRUE";
    }
    if(!fs::exists("EBOOT.ELF ")) {
        std::puts("[^^!] Decrypt EBOOT.BIN failed.");
        std::puts("[^^!] Resign aborted.");
        std::puts("[*] Press any key to continue...");
        wait_input();
        return;
    }
    if(fs::exists("EBOOT.BIN ")) {
        if(fs::exists("EBOOT.BIN.BAK ")) {
            fs::remove("EBOOT.BIN.BAK");
        }
        fs::rename("EBOOT.BIN", "EBOOT.BIN.BAK");
    }
    std::puts("[*] Patching EBOOT.ELF...");
    fix_elf("EBOOT.ELF");
    std::puts("[*] Encrypting EBOOT.ELF...");
    tool\make_fself EBOOT.ELF EBOOT.BIN>nul
    if %autoresign%==TRUE (
        fs::remove("EBOOT.ELF");
    )
    std::puts("[*] Resign finished.");
    std::puts("[*] Press any key to continue...");
    wait_input();
}

void npdrmdex() {
    autoresign="FALSE";
    if(!fs::exists("EBOOT.BIN ")) {
        if(!fs::exists("EBOOT.ELF ")) {
            std::puts("[^^!] EBOOT.BIN/ELF cannot be found.");
            std::puts("[^^!] Resign aborted.");
            std::puts("[*] Press any key to continue...");
            wait_input();
            return;
        }
    }
    if(!fs::exists("EBOOT.ELF ")) {
        std::puts("[*] Decrypting EBOOT.BIN...");
        tool\scetool.exe --decrypt EBOOT.BIN EBOOT.ELF>nul
        autoresign="TRUE";
    }
    if(!fs::exists("EBOOT.ELF ")) {
        std::puts("[^^!] Decrypt EBOOT.BIN failed.");
        std::puts("[^^!] Resign aborted.");
        std::puts("[*] Press any key to continue...");
        wait_input();
        return;
    }
    if(fs::exists("EBOOT.BIN ")) {
        if(fs::exists("EBOOT.BIN.BAK ")) {
            fs::remove("EBOOT.BIN.BAK");
        }
        fs::rename("EBOOT.BIN", "EBOOT.BIN.BAK");
    }
    std::puts("[*] Patching EBOOT.ELF...");
    fix_elf("EBOOT.ELF");
    std::puts("[*] Encrypting EBOOT.ELF...");
    tool\make_fself_npdrm EBOOT.ELF EBOOT.BIN>nul
    if(autoresign=="TRUE") {
        fs::remove("EBOOT.ELF");
    }
    std::puts("[*] Resign finished.");
    std::puts("[*] Press any key to continue...");
    wait_input();
}
*/

void outputoption() {
    if(output=="4xxstd") {
        output="4xxalt";
        outputmsg="[4.XX ALT]";
        elfsdk="41";
        keyrev="1C";
        fwver="0004002000000000";
        ctrlflagswitch="TRUE";
        capflagswitch="FALSE";
        std::puts("[*] Output method has been set to 4.XX ALT.");
        wait_input();
        return;
    } else if(output=="4xxalt") {
        output="4xxode";
        outputmsg="[4.XX ODE]";
        elfsdk="33";
        keyrev="0A";
        fwver="0003005500000000";
        ctrlflagswitch="FALSE";
        capflagswitch="TRUE";
        std::puts("[*] Output method has been set to 4.XX ODE.");
        wait_input();
        return;
    } else if(output=="4xxode") {
        output="3xxstd";
        outputmsg="[3.XX STD]";
        elfsdk="33";
        keyrev="04";
        fwver="0003004000000000";
        ctrlflagswitch="FALSE";
        capflagswitch="FALSE";
        std::puts("[*] Output method has been set to 3.XX STD.");
        wait_input();
        return;
    } else if(output=="3xxstd") {
        output="3xxalt";
        outputmsg="[3.XX ALT]";
        elfsdk="33";
        keyrev="04";
        fwver="0003004000000000";
        ctrlflagswitch="TRUE";
        capflagswitch="FALSE";
        std::puts("[*] Output method has been set to 3.XX ALT.");
        wait_input();
        return;
    } else if(output=="3xxalt") {
        output="4xxstd";
        outputmsg="[4.XX STD]";
        elfsdk="41";
        keyrev="1C";
        fwver="0004002000000000";
        ctrlflagswitch="FALSE";
        capflagswitch="FALSE";
        std::puts("[*] Output method has been set to 4.XX STD.");
        wait_input();
        return;
    }
}


void compressoption() {
    if(compress=="FALSE") enablecompressoption();
    if(compress=="TRUE") disablecompressoption();
}


void enablecompressoption() {
    std::string compressdata{ "NONE" };
    std::printf("Enter Y to enable Compress Data / any other key to abort:");
    std::cin >> compressdata;
    if(compressdata=="NONE") return;
    if(compressdata=="Y") enablecompress();
    if(compressdata=="y") enablecompress();
}


void enablecompress() {
    compress="TRUE";
    compressmsg="[ON]";         
}

void disablecompressoption() {
    std::string compressdata{ "NONE" };
    std::printf("Enter Y to disable Compress Data / any other key to abort:");
    std::cin >> compressdata;
    if(compressdata=="NONE") return;
    if(compressdata=="Y") disablecompress();
    if(compressdata=="y") disablecompress();
}


void disablecompress() {
    compress="FALSE";
    compressmsg="[OFF]";        
}