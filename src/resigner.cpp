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
static std::basic_string<char> bruteforceresult;
static std::basic_string<char> klicensee="NONE";
static std::basic_string<char> elfsuffix;

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
        case 6:  kliccex(); break;
        case 7:  custnondrm(); break;
        case 8:  custnpdrm(); break;
        case 9:  decfself(); break;
        case 10: discdex(); break;
        case 11: npdrmdex(); break;
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
        system("ls self | grep .self >./tool/selflist.txt");
    }
    if(fs::exists("*.sprx ")) {
        system("ls self | grep .sprx >>./tool/selflist.txt");
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

void kliccex() {
    if(output=="4xxode") {
        std::puts("[^^!] NPDRM Resign is inapplicable for ODE Output.");
        wait_input();
        return;
    }
    
    if(fs::exists("./tool/selflist.txt ")) {
        fs::remove("./tool/selflist.txt");
    }
    if(fs::exists("self ")) {
        system("ls self | grep .self >./tool/selflist.txt");
    }
    if(fs::exists("self")) {
        system("ls self | grep .sprx >>./tool/selflist.txt");
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
    };
    std::puts("===============================================================================");
    if(count==0) {
        wait_input();
        return;
    }
    std::puts(" Note: BruteForce Detecting Klicensee method will be used in this option.");
    std::puts("       EBOOT.BIN must be placed into Resigner folder for detecting Klicensee.");
    std::puts("       Make sure that EBOOT.BIN and SELF/SPRX files are from the same game.");
    std::puts("===============================================================================");
    
    std::string klicgo{ "NONE" };
    std::printf("Enter Y to continue / N to Abort:");
    if(klicgo=="Y" || klicgo =="y") {
        checkeboot();
    }
}

void checkeboot() {
    if(!fs::exists("EBOOT.BIN ")) {
        std::puts("[^^!] EBOOT.BIN cannot be found in Resigner folder.");
        std::puts("[^^!] Resign aborted.");
        std::puts("[*] Press any key to continue...");
        wait_input();
        kliccex();
    }
    contentid="NONE";
    system("./tool/scetool -i EBOOT.BIN>./tool/selfinfo.txt");
    //for /f "skip=3 tokens=1,*" %%i in (tool\selfinfo.txt) do if "%%i"=="ContentID" set contentid=%%j
    if(contentid=="NONE") {
        std::puts("[^^!] EBOOT.BIN should be an NPDRM EBOOT.");
        std::puts("[^^!] Resign aborted.");
        std::puts("[*] Press any key to continue...");
        wait_input();
        kliccex();
    }
    if(fs::exists("./tool/kliclist.txt")) {
        kliclist();
    }
    klicdec();
}

void chkeboot() {
    if(!fs::exists("EBOOT.BIN ")) {
        std::puts("[*] EBOOT.BIN cannot be found in Resigner folder.");
        std::puts(std::format("[^^!] Decrypt {} failed.", selfname).c_str());
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
        std::puts(std::format("[^^!] Decrypt {} failed.", selfname).c_str());
        std::puts("[*] Press any key to continue...");
        wait_input();
        decsprx();
    }
    std::puts("[*] Start BruteForce Detecting Klicensee, please wait...");
    system(std::format("./tool/klicencebruteforce -x ./self/{} EBOOT.ELF ./data/keys>./tool/bruteforce.txt", selfname).c_str());
    if(fs::exists("EBOOT.ELF ")) {
        fs::remove("EBOOT.ELF");
    }
    //for /f "skip=3 tokens=1,*" %%i in (tool\bruteforce.txt) do if "%%i"=="[*]" set bruteforceresult=%%j
    std::string bruteforceresult;
    if(bruteforceresult.substr(4,2)=="no") {
        std::puts("[^^!] Cannot find Klicensee, BruteForce Detecting failed.");
        std::puts(std::format("[^^!] Decrypt {} failed.", selfname).c_str());
        std::puts("[*] Press any key to continue...");
        wait_input();
        decsprx();
     } else {
        foundkliceboot();
     }
}

void kliclist() {
    klicensee="NONE";
    //for /f "tokens=1,*" %%i in (tool\kliclist.txt) do if "%%i"=="%contentid%" set klicensee=%%j
    //for /l %%a in (0 1 99) do if not "!klicensee:~%%a,1!"=="" set /a kliclen=%%a+1
    size_t kliclen{ 0 };

    if (kliclen != 32) {
        bruteforcepool();
    } else {
        std::puts(std::format("[*] Found ContentID in EBOOT.BIN: {}", contentid).c_str());
        std::puts(std::format("[*] Found Klicensee in Klic List: {}", klicensee).c_str());
        klicresign();
    }
}

void processKlicList(const std::string& contentId, std::string& kLicensee, int& kLicLen) {
    std::ifstream file("./tool/kliclist.txt");
    if (!file.is_open()) {
        // Handle file not found or other error
        return;
    }

    std::string line;
    while (std::getline(file, line)) {
        std::istringstream iss(line);
        std::string token;
        if (std::getline(iss, token, ' ')) {
            std::string klicToken;
            std::getline(iss, klicToken);

            if (token == contentId) {
                kLicensee = klicToken;
            }
        }
    }
    kLicLen = kLicensee.length();
}

void chklist() {
    if(!fs::exists("./tool/kliclist.txt")) {
        chkpool();
    }
    klicensee="NONE";
    int kLicLen;

    processKlicList(contentid, klicensee, kLicLen);

    if (kLicLen != 32) {
        chkpool();
    } else {
        std::cout << "[*] Found Klicensee in Klic List: " << klicensee << std::endl;
        decklic();
    }
}

void chkpool() {
   if (!fs::exists("./tool/klicpool.txt")) {
        chkeboot();
    }

    system(("./tool/klicencebruteforce -x self/" + selfname + " ./tool/klicpool.txt data/keys > tool\\bruteforce.txt").c_str());

    std::ifstream bruteforceFile("./tool/bruteforce.txt");
    if (!bruteforceFile.is_open()) {
        // Handle file not found or other error
        return;
    }

    std::string line;
    while (std::getline(bruteforceFile, line)) {
        if (line.substr(0, 4) == "[*]") {
            bruteforceresult = line.substr(24, 32);

            std::ofstream resultLenFile("./tool/resultlen.txt");
            resultLenFile << bruteforceresult;
            resultLenFile.close();

            std::ifstream resultLenFileRead("./tool/resultlen.txt");
            int resultlen;
            resultLenFileRead >> resultlen;
            resultLenFileRead.close();

            if (resultlen == 43) {
                bruteforceresult = line.substr(11, 32);
            }

            std::cout << "[*] Found Klicensee in Klic Pool: " << bruteforceresult << std::endl;

            // Write contentid and klicensee to kliclist.txt
            std::ofstream klicListFile("./tool/kliclist.txt", std::ios_base::app);
            if (klicListFile.is_open()) {
                klicListFile << contentid << " " << bruteforceresult << std::endl;
                klicListFile.close();
            } else {
                // Handle error opening kliclist.txt
            }

            decklic();
            break; // Exit loop after processing the first [*] line
        }
    }
}

void foundkliceboot() {
    klicensee = bruteforceresult.substr(24, 32);

    // Execute tool/Rtlen with bruteforceResult as argument and store the output in resultlen.txt
    std::system(("./tool/Rtlen " + bruteforceresult + " > ./tool/resultlen.txt").c_str());

    std::ifstream resultLenFile("./tool/resultlen.txt");
    if (resultLenFile.is_open()) {
        int resultLen;
        if (resultLenFile >> resultLen) {
            if (resultLen == 43) {
                klicensee = bruteforceresult.substr(11, 32);
            }
        }
        resultLenFile.close();
    }

    // Output found Klicensee in EBOOT.BIN
    std::cout << "[*] Found Klicensee in EBOOT.BIN: " << klicensee << std::endl;

    // Append Klicensee to klicpool.txt
    std::ofstream klicpoolFile("./tool/klicpool.txt", std::ios::app);
    if (klicpoolFile.is_open()) {
        klicpoolFile << klicensee << std::endl;
        klicpoolFile.close();
    }

    // Append contentId and Klicensee to kliclist.txt
    std::ofstream kliclistFile("./tool/kliclist.txt", std::ios::app);
    if (kliclistFile.is_open()) {
        kliclistFile << contentid << " " << klicensee << std::endl;
        kliclistFile.close();
    }
}

void decklic() {
    std::string command = "./tool/scetool --np-klicensee " + klicensee + " --decrypt self/" + selfname + " self/" + shortname + "." + elfsuffix;
    std::system(command.c_str());

    if (!fs::exists("self/" + shortname + "." + elfsuffix)) {
        std::cout << "[^^!] Decrypt " << selfname << " failed." << std::endl;
        std::cout << "[*] Press any key to continue..." << std::endl;
        wait_input();
    } else {
        std::cout << "[*] Decrypt file to " << shortname << "." << elfsuffix << " successfully." << std::endl;
        std::cout << "[*] Press any key to continue..." << std::endl;
        wait_input();
        decsprx();
    }
}

void bruteforcepool() {
    if (!fs::exists("./tool/klicpool.txt")) {
        klicdec();
        return;
    }

    std::string usesprx;
    std::ifstream selflistFile("./tool/selflist.txt");
    if (selflistFile.is_open()) {
        std::getline(selflistFile, usesprx);
        selflistFile.close();
    } else {
        // Handle error when selflist.txt cannot be opened
        return;
    }

    std::system(("./tool/klicencebruteforce -x self/" + usesprx + " ./tool/klicpool.txt data/keys > tool/bruteforce.txt").c_str());

    std::ifstream bruteforceFile("./tool/bruteforce.txt");
    if (bruteforceFile.is_open()) {
        std::string line;
        while (std::getline(bruteforceFile, line)) {
            if (line.find("[*]") == 0) {
                std::string bruteforceresult = line;
                if (bruteforceresult.substr(4, 2) == "no") {
                    klicdec();
                    return;
                }

                std::string kLicensee = bruteforceresult.substr(24, 32);
                std::system(("./tool/Rtlen " + bruteforceresult + " > ./tool/resultlen.txt").c_str());

                std::ifstream resultLenFile("./tool/resultlen.txt");
                if (resultLenFile.is_open()) {
                    int resultLen;
                    if (resultLenFile >> resultLen) {
                        if (resultLen == 43) {
                            kLicensee = bruteforceresult.substr(11, 32);
                        }
                    }
                    resultLenFile.close();
                }

                std::cout << "[*] Found ContentID in EBOOT.BIN: " << contentid << std::endl;
                std::cout << "[*] Found Klicensee in Klic Pool: " << kLicensee << std::endl;

                std::ofstream kliclistFile("./tool/kliclist.txt", std::ios::app);
                if (kliclistFile.is_open()) {
                    kliclistFile << contentid << " " << kLicensee << std::endl;
                    kliclistFile.close();
                }

                klicresign();
                return;
            }
        }
        bruteforceFile.close();
    }
}

void klicdec() {
    if (fs::exists("EBOOT.ELF")) {
        fs::remove("EBOOT.ELF");
    }

    std::system("./tool/scetool --decrypt EBOOT.BIN EBOOT.ELF");

    if (!fs::exists("EBOOT.ELF")) {
        std::cout << "[^^!] Decrypt EBOOT.BIN failed." << std::endl;
        std::cout << "[^^!] Resign aborted." << std::endl;
        std::cout << "[*] Press any key to continue..." << std::endl;
        wait_input();
        kliccex();
    }
}

void klicresign() {
    int count = 0;
    int error = 0;

    std::ifstream selflistFile("./tool/selflist.txt");
    if (selflistFile.is_open()) {
        std::string selfname, shortname, sufname, elfsuffix, baksuffix, npapptype;

        while (selflistFile >> selfname) {
            count++;

            shortname = selfname.substr(0, selfname.size() - 5);
            sufname = selfname.substr(selfname.size() - 4, 4);

            if (sufname == "self" || sufname == "SELF") {
                elfsuffix = "elf";
                baksuffix = "bak";
            } else if (sufname == "sprx" || sufname == "SPRX") {
                elfsuffix = "prx";
                baksuffix = "bak";
            }

            npapptype = "SPRX";
            if (contentid.substr(7, 1) == "B") {
                npapptype = "USPRX";
            }

            std::string selfPath = "self/" + shortname + "." + elfsuffix;

            if (fs::exists(selfPath)) {
                fs::remove(selfPath.c_str());
            }

            std::cout << "[*] Resigning " << selfname << "..." << std::endl;

            std::string decryptCommand = "./tool/scetool --np-klicensee " + klicensee + " --decrypt self/" + selfname + " self/" + shortname + "." + elfsuffix + " > nul";
            std::system(decryptCommand.c_str());

            if (!fs::exists(selfPath)) {
                std::cout << "[^^!] Decrypt " << selfname << " failed." << std::endl;
                std::cout << "[^^!] Resign " << selfname << " aborted." << std::endl;
                error++;
            } else {
                if (fs::exists("self/" + selfname + "." + baksuffix)) {
                    fs::remove(("self/" + selfname + "." + baksuffix).c_str());
                }

                std::string backupCommand = "copy self/" + selfname + " self/" + selfname + "." + baksuffix + " > nul";
                std::system(backupCommand.c_str());

                fix_elf("self/" + shortname + "." + elfsuffix, elfsdk);

                std::string scetoolCommand;
                if (ctrlflagswitch == "FALSE") {
                    scetoolCommand = "./tool/scetool -v --sce-type=SELF --compress-data=" + compress + " --skip-sections=TRUE --key-revision=" + keyrev + " --self-auth-id=1010000001000003 --self-add-shdrs=TRUE --self-vendor-id=01000002 --self-type=NPDRM --self-app-version=0001000000000000 --self-fw-version=" + fwver + " --np-license-type=FREE --np-content-id=" + contentid + " --np-app-type=" + npapptype + " --np-klicensee=" + klicensee + " --np-real-fname=" + selfname + " --encrypt self/" + shortname + "." + elfsuffix + " self/" + selfname + " > nul";
                } else {
                    scetoolCommand = "./tool/scetool -v --sce-type=SELF --compress-data=" + compress + " --skip-sections=TRUE --key-revision=" + keyrev + " --self-auth-id=1010000001000003 --self-add-shdrs=TRUE --self-vendor-id=01000002 --self-type=NPDRM --self-app-version=0001000000000000 --self-fw-version=" + fwver + " --self-ctrl-flags=" + selfctrlflags + " --np-license-type=FREE --np-content-id=" + contentid + " --np-app-type=" + npapptype + " --np-klicensee=" + klicensee + " --np-real-fname=" + selfname + " --encrypt self/" + shortname + "." + elfsuffix + " self/" + selfname + " > nul";
                }

                std::system(scetoolCommand.c_str());

                if (fs::exists("self/" + shortname + "." + elfsuffix)) {
                    fs::remove(("self/" + shortname + "." + elfsuffix).c_str());
                }

                std::cout << "[*] Resign " << selfname << " finished." << std::endl;
            }
        }

        selflistFile.close();
    }

    if (error == 0) {
        std::cout << "[*] Resign all SELF/SPRX files successfully." << std::endl;
    } else {
        std::cout << "[^^!] Resign all SELF/SPRX files finished, " << error << " file(s) failed." << std::endl;
    }
    std::cout << "[*] Press any key to continue..." << std::endl;
    wait_input();
}

void custnondrm() {
    fs::current_path("self");

    if (fs::exists("../tool/selflist.txt")) {
        fs::remove("../tool/selflist.txt");
    }

    std::system("ls *.elf /b > ./tool/selflist.txt");
    std::system("ls *.prx /b >> ./tool/selflist.txt");

    fs::current_path("..");

    int count = 0;
    std::string fileName;

    std::cout << "===============================================================================" << std::endl;
    std::cout << " ELF/PRX Files List" << std::endl;
    std::cout << "===============================================================================" << std::endl;

    std::ifstream selfListFile("tool/selflist.txt");
    if (selfListFile.is_open()) {
        while (selfListFile >> fileName) {
            count++;
            std::cout << " " << count << ". " << fileName << std::endl;
        }
        selfListFile.close();
    } else {
        std::cout << " No ELF/PRX is Found." << std::endl;
    }

    std::cout << "===============================================================================" << std::endl;

    if (count == 0) {
        wait_input();
    }
}

void custnpdrm() {
    if (output == "4xxode") {
        std::cout << "[^^!] NPDRM Resign is inapplicable for ODE Output." << std::endl;
        wait_input();
        return;
    }

    fs::current_path("self");

    if (fs::exists("../tool/selflist.txt")) {
        fs::remove("../tool/selflist.txt");
    }

    std::system("ls *.elf >../tool/selflist.txt");
    std::system("ls *.prx >>../tool/selflist.txt");

    fs::current_path("..");

    int count = 0;
    std::string fileName;

    std::cout << "===============================================================================" << std::endl;
    std::cout << " ELF/PRX Files List" << std::endl;
    std::cout << "===============================================================================" << std::endl;

    std::ifstream selfListFile("./tool/selflist.txt");
    if (selfListFile.is_open()) {
        while (selfListFile >> fileName) {
            count++;
            std::cout << " " << count << ". " << fileName << std::endl;
        }
        selfListFile.close();
    } else {
        std::cout << " No ELF/PRX is Found." << std::endl;
    }

    std::cout << "===============================================================================" << std::endl;

    if (count == 0) {
        wait_input();
    }
}

void decfself() {
    if (!fs::exists("EBOOT.BIN")) {
        std::cout << "[^^!] EBOOT.BIN cannot be found." << std::endl;
        std::cout << "[^^!] Decrypt aborted." << std::endl;
        std::cout << "[*] Press any key to continue..." << std::endl;
        wait_input();
        return;
    }

    if (fs::exists("EBOOT.ELF")) {
        fs::remove("EBOOT.ELF");
    }

    std::cout << "[*] Decrypting EBOOT.BIN..." << std::endl;
    std::system("./tool/unfself EBOOT.BIN EBOOT.ELF");

    if (fs::exists("EBOOT.ELF")) {
        std::cout << "[*] Decrypt finished." << std::endl;
    } else {
        std::cout << "[^^!] Decrypt EBOOT.BIN failed." << std::endl;
    }

    std::cout << "[*] Press any key to continue..." << std::endl;
    wait_input();
}

void discdex() {
    std::string autoresign = "FALSE";

    if (!fs::exists("EBOOT.BIN") && !fs::exists("EBOOT.ELF")) {
        std::cout << "[^^!] EBOOT.BIN/ELF cannot be found." << std::endl;
        std::cout << "[^^!] Resign aborted." << std::endl;
        std::cout << "[*] Press any key to continue..." << std::endl;
        wait_input();
        return;
    }

    if (!fs::exists("EBOOT.ELF")) {
        std::cout << "[*] Decrypting EBOOT.BIN..." << std::endl;
        std::system("./tool/scetool --decrypt EBOOT.BIN EBOOT.ELF >nul");
        autoresign = "TRUE";
    }

    if (!fs::exists("EBOOT.ELF")) {
        std::cout << "[^^!] Decrypt EBOOT.BIN failed." << std::endl;
        std::cout << "[^^!] Resign aborted." << std::endl;
        std::cout << "[*] Press any key to continue..." << std::endl;
        wait_input();
        return;
    }

    if (fs::exists("EBOOT.BIN")) {
        if (fs::exists("EBOOT.BIN.BAK")) {
            fs::remove("EBOOT.BIN.BAK");
        }
        fs::rename("EBOOT.BIN", "EBOOT.BIN.BAK");
    }

    std::cout << "[*] Patching EBOOT.ELF..." << std::endl;
    fix_elf("EBOOT.ELF", elfsdk);

    std::cout << "[*] Encrypting EBOOT.ELF..." << std::endl;
    std::system("./tool/make_fself EBOOT.ELF EBOOT.BIN");

    if (autoresign == "TRUE") {
        fs::remove("EBOOT.ELF");
    }

    std::cout << "[*] Resign finished." << std::endl;
    std::cout << "[*] Press any key to continue..." << std::endl;
    wait_input();
}

void npdrmdex() {
    std::string autoresign = "FALSE";

    if (!fs::exists("EBOOT.BIN") && !fs::exists("EBOOT.ELF")) {
        std::cout << "[^^!] EBOOT.BIN/ELF cannot be found." << std::endl;
        std::cout << "[^^!] Resign aborted." << std::endl;
        std::cout << "[*] Press any key to continue..." << std::endl;
        wait_input();
        return;
    }

    if (!fs::exists("EBOOT.ELF")) {
        std::cout << "[*] Decrypting EBOOT.BIN..." << std::endl;
        std::system("./tool/scetool --decrypt EBOOT.BIN EBOOT.ELF");
        autoresign = "TRUE";
    }

    if (!fs::exists("EBOOT.ELF")) {
        std::cout << "[^^!] Decrypt EBOOT.BIN failed." << std::endl;
        std::cout << "[^^!] Resign aborted." << std::endl;
        std::cout << "[*] Press any key to continue..." << std::endl;
        wait_input();
        return;
    }

    if (fs::exists("EBOOT.BIN")) {
        if (fs::exists("EBOOT.BIN.BAK")) {
            fs::remove("EBOOT.BIN.BAK");
        }
        fs::rename("EBOOT.BIN", "EBOOT.BIN.BAK");
    }

    std::cout << "[*] Patching EBOOT.ELF..." << std::endl;
    fix_elf("EBOOT.ELF", elfsdk);

    std::cout << "[*] Encrypting EBOOT.ELF..." << std::endl;
    std::system("./tool/make_fself_npdrm EBOOT.ELF EBOOT.BIN");

    if (autoresign == "TRUE") {
        fs::remove("EBOOT.ELF");
    }

    std::cout << "[*] Resign finished." << std::endl;
    std::cout << "[*] Press any key to continue..." << std::endl;
    wait_input();
}

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