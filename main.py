import hashlib,os,chardet,random,threading,colorama,time,readline,re
from itertools import product

# Define hash patterns
HASHES = (
    ("Blowfish(Eggdrop)", "^\+[a-zA-Z0-9\/\.]{12}$"),
    ("Blowfish(OpenBSD)", "^\$2a\$[0-9]{0,2}?\$[a-zA-Z0-9\/\.]{53}$"),
    ("Blowfish crypt", "^\$2[axy]{0,1}\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{1,}$"),
    (("DES(Unix)", "DES crypt", "DES hash(Traditional)"), "^.{0,2}[a-zA-Z0-9\/\.]{11}$"),
    ("MD5(Unix)", "^\$1\$.{0,8}\$[a-zA-Z0-9\/\.]{22}$"),
    (("MD5(APR)", "Apache MD5"), "^\$apr1\$.{0,8}\$[a-zA-Z0-9\/\.]{22}$"),
    ("MD5(MyBB)", "^[a-fA-F0-9]{32}:[a-z0-9]{8}$"),
    ("MD5(ZipMonster)", "^[a-fA-F0-9]{32}$"),
    (("MD5 crypt", "FreeBSD MD5", "Cisco-IOS MD5"), "^\$1\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{1,}$"),
    ("MD5 apache crypt", "^\$apr1\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{1,}$"),
    ("MD5(Joomla)", "^[a-fA-F0-9]{32}:[a-zA-Z0-9]{16,32}$"),
    ("MD5(Wordpress)", "^\$P\$[a-zA-Z0-9\/\.]{31}$"),
    ("MD5(phpBB3)", "^\$H\$[a-zA-Z0-9\/\.]{31}$"),
    ("MD5(Cisco PIX)", "^[a-zA-Z0-9\/\.]{16}$"),
    (("MD5(osCommerce)", "xt:Commerce"), "^[a-fA-F0-9]{32}:[a-zA-Z0-9]{2}$"),
    ("MD5(Palshop)", "^[a-fA-F0-9]{51}$"),
    ("MD5(IP.Board)", "^[a-fA-F0-9]{32}:.{5}$"),
    ("MD5(Chap)", "^[a-fA-F0-9]{32}:[0-9]{32}:[a-fA-F0-9]{2}$"),
    ("Juniper Netscreen/SSG (ScreenOS)", "^[a-zA-Z0-9]{30}:[a-zA-Z0-9]{4,}$"),
    ("Fortigate (FortiOS)", "^[a-fA-F0-9]{47}$"),
    ("Minecraft(Authme)", "^\$sha\$[a-zA-Z0-9]{0,16}\$[a-fA-F0-9]{64}$"),
    ("Lotus Domino", "^\(?[a-zA-Z0-9\+\/]{20}\)?$"),
    ("Lineage II C4", "^0x[a-fA-F0-9]{32}$"),
    ("CRC-96(ZIP)", "^[a-fA-F0-9]{24}$"),
    ("NT crypt", "^\$3\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{1,}$"),
    ("Skein-1024", "^[a-fA-F0-9]{256}$"),
    (("RIPEMD-320", "RIPEMD-320(HMAC)"), "^[A-Fa-f0-9]{80}$"),
    ("EPi hash", "^0x[A-F0-9]{60}$"),
    ("EPiServer 6.x < v4", "^\$episerver\$\*0\*[a-zA-Z0-9]{22}==\*[a-zA-Z0-9\+]{27}$"),
    ("EPiServer 6.x >= v4", "^\$episerver\$\*1\*[a-zA-Z0-9]{22}==\*[a-zA-Z0-9]{43}$"),
    ("Cisco IOS SHA256", "^[a-zA-Z0-9]{43}$"),
    ("SHA-1(Django)", "^sha1\$.{0,32}\$[a-fA-F0-9]{40}$"),
    ("SHA-1 crypt", "^\$4\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{1,}$"),
    ("SHA-1(Hex)", "^[a-fA-F0-9]{40}$"),
    (("SHA-1(LDAP) Base64", "Netscape LDAP SHA", "NSLDAP"), "^\{SHA\}[a-zA-Z0-9+/]{27}=$"),
    ("SHA-1(LDAP) Base64 + salt", "^\{SSHA\}[a-zA-Z0-9+/]{28,}[=]{0,3}$"),
    ("SHA-512(Drupal)", "^\$S\$[a-zA-Z0-9\/\.]{52}$"),
    ("SHA-512 crypt", "^\$6\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{1,}$"),
    ("SHA-256(Django)", "^sha256\$.{0,32}\$[a-fA-F0-9]{64}$"),
    ("SHA-256 crypt", "^\$5\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{1,}$"),
    ("SHA-384(Django)", "^sha384\$.{0,32}\$[a-fA-F0-9]{96}$"),
    ("SHA-256(Unix)", "^\$5\$.{0,22}\$[a-zA-Z0-9\/\.]{43,69}$"),
    ("SHA-512(Unix)", "^\$6\$.{0,22}\$[a-zA-Z0-9\/\.]{86}$"),
    (("SHA-384", "SHA3-384", "Skein-512(384)", "Skein-1024(384)"), "^[a-fA-F0-9]{96}$"),
    (("SHA-512", "SHA-512(HMAC)", "SHA3-512", "Whirlpool", "SALSA-10", "SALSA-20", "Keccak-512", "Skein-512",
      "Skein-1024(512)"), "^[a-fA-F0-9]{128}$"),
    ("SSHA-1", "^({SSHA})?[a-zA-Z0-9\+\/]{32,38}?(==)?$"),
    (("SSHA-1(Base64)", "Netscape LDAP SSHA", "NSLDAPS"), "^\{SSHA\}[a-zA-Z0-9]{32,38}?(==)?$"),
    (("SSHA-512(Base64)", "LDAP {SSHA512}"), "^\{SSHA512\}[a-zA-Z0-9+]{96}$"),
    ("Oracle 11g", "^S:[A-Z0-9]{60}$"),
    ("SMF >= v1.1", "^[a-fA-F0-9]{40}:[0-9]{8}&"),
    ("MySQL 5.x", "^\*[a-f0-9]{40}$"),
    (("MySQL 3.x", "DES(Oracle)", "LM", "VNC", "FNV-164"), "^[a-fA-F0-9]{16}$"),
    ("OSX v10.7", "^[a-fA-F0-9]{136}$"),
    ("OSX v10.8", "^\$ml\$[a-fA-F0-9$]{199}$"),
    ("SAM(LM_Hash:NT_Hash)", "^[a-fA-F0-9]{32}:[a-fA-F0-9]{32}$"),
    ("MSSQL(2000)", "^0x0100[a-f0-9]{0,8}?[a-f0-9]{80}$"),
    (("MSSQL(2005)", "MSSQL(2008)"), "^0x0100[a-f0-9]{0,8}?[a-f0-9]{40}$"),
    ("MSSQL(2012)", "^0x02[a-f0-9]{0,10}?[a-f0-9]{128}$"),
    (("substr(md5($pass),0,16)", "substr(md5($pass),16,16)", "substr(md5($pass),8,16)", "CRC-64"),
     "^[a-fA-F0-9./]{16}$"),
    (("MySQL 4.x", "SHA-1", "HAVAL-160", "SHA-1(MaNGOS)", "SHA-1(MaNGOS2)", "TIGER-160", "RIPEMD-160",
      "RIPEMD-160(HMAC)",
      "TIGER-160(HMAC)", "Skein-256(160)", "Skein-512(160)"), "^[a-f0-9]{40}$"),
    (("SHA-256", "SHA-256(HMAC)", "SHA-3(Keccak)", "GOST R 34.11-94", "RIPEMD-256", "HAVAL-256", "Snefru-256",
      "Snefru-256(HMAC)", "RIPEMD-256(HMAC)", "Keccak-256", "Skein-256", "Skein-512(256)"), "^[a-fA-F0-9]{64}$"),
    (("SHA-1(Oracle)", "HAVAL-192", "OSX v10.4, v10.5, v10.6", "Tiger-192", "TIGER-192(HMAC)"), "^[a-fA-F0-9]{48}$"),
    (("SHA-224", "SHA-224(HMAC)", "HAVAL-224", "Keccak-224", "Skein-256(224)", "Skein-512(224)"), "^[a-fA-F0-9]{56}$"),
    (("Adler32", "FNV-32", "ELF-32", "Joaat", "CRC-32", "CRC-32B", "GHash-32-3", "GHash-32-5", "FCS-32", "Fletcher-32",
      "XOR-32"), "^[a-fA-F0-9]{8}$"),
    (("CRC-16-CCITT", "CRC-16", "FCS-16"), "^[a-fA-F0-9]{4}$"),
    (("MD5(HMAC(Wordpress))", "MD5(HMAC)", "MD5", "RIPEMD-128", "RIPEMD-128(HMAC)", "Tiger-128", "Tiger-128(HMAC)",
      "RAdmin v2.x", "NTLM", "Domain Cached Credentials(DCC)", "Domain Cached Credentials 2(DCC2)", "MD4", "MD2",
      "MD4(HMAC)", "MD2(HMAC)", "Snefru-128", "Snefru-128(HMAC)", "HAVAL-128", "HAVAL-128(HMAC)", "Skein-256(128)",
      "Skein-512(128)", "MSCASH2"), "^[0-9A-Fa-f]{32}$"),
)

class Generator:
    @staticmethod
    def Random(characters, min_length, max_length, limit):
        char = list(set(characters))
        for _ in range(limit):
            word = ''.join(random.choice(char) for _ in range(random.randint(min_length, max_length)))
            yield word

    @staticmethod
    def BrutForce(characters, min_length, max_length):
        for length in range(min_length, max_length + 1):
            for combination in product(characters, repeat=length):
                yield ''.join(combination)

    @staticmethod
    def Dictionary(file_name_or_path):
        def complete(text, state):
            options = [f for f in os.listdir('.') if f.startswith(text)]
            if state < len(options):
                return options[state]
            else:
                return None

        readline.set_completer(complete)
        readline.parse_and_bind('tab: complete')

        try:
            with open(file_name_or_path, 'rb') as f:
                pass_list = f.readlines()
            for i in pass_list:
                try:
                    detection = chardet.detect(i)
                    encoding = detection["encoding"]
                    yield i.decode(encoding).rstrip()
                except Exception as e:
                    pass
        except FileNotFoundError:
            print("File not found. Please provide a correct file path.")
        except Exception as e:
            print(f"Error occurred while reading the file: {e}")

    @staticmethod
    def generate_wordlist_wildcard(words, numbers):
        replacements = {'o': '0', 'a': '@', 's': '$','l': '1', 'e': '3', 'h':'#'}  # Define replacements
        wordlist = set()

        def generate_variations(word):
            variations = [word.lower(), word.upper(), word.capitalize()]
            for letter, replacement in replacements.items():
                variations.extend([v.replace(letter, replacement) for v in variations])
            return variations

        if numbers:  # Check if numbers are provided by the user
            for word in words:
                variations = generate_variations(word)
                for variation in variations:
                    for number in numbers:
                        wordlist.add(variation + number)
        else:  # If no numbers are provided, generate wordlist without appending numbers
            for word in words:
                variations = generate_variations(word)
                wordlist.update(variations)

        return list(wordlist)
        
    @staticmethod
    def Custom_Wordlist(base_word, numbers=None, replace_a=False, replace_e=False, replace_h=False, replace_l=False, replace_o=False, replace_s=False, append_character=None):
        wordlist = []

        # Generate all possible combinations of uppercase and lowercase letters for each character
        for combination in itertools.product(*zip(base_word.lower(), base_word.upper())):
            modified_word = ''.join(combination)

            # Optionally replace 'a' with '@'
            if replace_a:
                modified_word = modified_word.replace('a', '@')

            # Optionally replace 'e' with '3'
            if replace_e:
                modified_word = modified_word.replace('e', '3')

            # Optionally replace 'h' with '#'
            if replace_h:
                modified_word = modified_word.replace('h', '#')

            # Optionally replace 'l' with '1'
            if replace_l:
                modified_word = modified_word.replace('l', '1')

            # Optionally replace 'o' with '0'
            if replace_o:
                modified_word = modified_word.replace('o', '0')

            # Optionally replace 's' with '$'
            if replace_s:
                modified_word = modified_word.replace('s', '$')

            # Append each number if specified
            if numbers:
                for number in numbers:
                    word_with_number = modified_word + str(number)
                    # Append the provided character if specified
                    if append_character:
                        word_with_number += append_character
                    wordlist.append(word_with_number)
            else:
                # Append the provided character if specified
                if append_character:
                    modified_word += append_character
                wordlist.append(modified_word)

        return wordlist
        
    def Custom_Wordlists_Replace(base_words, numbers=None, append_character=None):
        wordlists = []
        for base_word in base_words:
            wordlist_no_replace = Custom_Wordlist(base_word, numbers, False, False, False, False, False, False, append_character)
            wordlist_replace_all = Custom_Wordlist(base_word, numbers, True, True, True, True, True, True, append_character)
            wordlists.append(wordlist_no_replace)
            wordlists.append(wordlist_replace_all)
        return wordlists

    @staticmethod
    def Identify_Hash_Algorithm(input_hash):
        # Iterate over hash patterns
        for algorithm, pattern in HASHES:
            if re.match(pattern, input_hash):
                return algorithm
        return "Unknown"
    
    @staticmethod
    def Calculate_Hash(word, algorithm):
        """Calculate hash of a word."""
        hasher = hashlib.new(algorithm)
        hasher.update(word.encode('utf-8'))
        return hasher.hexdigest()

    @staticmethod
    def Analyze_Hashes(words, algorithms):
        """Analyze hash of multiple words using multiple algorithms."""
        results = {}
        for word in words:
            word_results = {}
            for algo in algorithms:
                hash_value = Calculate_Hash(word, algo)
                word_results[algo.upper()] = hash_value
            results[word] = word_results
        return results
    
    @staticmethod
    def Generate_RainbowTable(wordlist_file, algorithm, output_file):
        """Generate a rainbow table for the specified algorithm using a wordlist file."""
        table = {}
        with open(wordlist_file, 'r') as f:
            words = f.readlines()
            for word in words:
                word = word.strip()
                hasher = hashlib.new(algorithm)
                hasher.update(word.encode())
                hash_value = hasher.hexdigest()
                table[word] = hash_value

        with open(output_file, 'w') as f:
            for word, hash_value in table.items():
                f.write(f"{word}:{hash_value}\n")
    
    @staticmethod           
    def Generate_RainbowTable_Numbers(algorithm, filename, start, end):
        """Generate a simplified rainbow table for the specified algorithm."""
        table = {}
        with open(filename, 'w') as f:
            for i in range(start, end + 1):
                plaintext = str(i)
                hasher = hashlib.new(algorithm)
                hasher.update(plaintext.encode())
                hash_value = hasher.hexdigest()
                table[plaintext] = hash_value
                f.write(f"{plaintext}:{hash_value}\n")  
                
                
class CheckKey:
    @staticmethod
    def hash_key(_hash, key, num):
        h = HashGenerator(key)
        hash_funcs = {
            '1': h.md5,
            '2': h.sha1,
            '3': h.sha224,
            '4': h.sha256,
            '5': h.sha384,
            '6': h.sha512,
            '7': h.blake2b,
            '8': h.blake2s
        }
        return hash_funcs[num]() == _hash

class HashGenerator:
    def __init__(self, str_input):
        self.hash_str = str_input

    def md5(self):
        return hashlib.md5(self.hash_str.encode()).hexdigest()

    def sha1(self):
        return hashlib.sha1(self.hash_str.encode()).hexdigest()

    def sha224(self):
        return hashlib.sha224(self.hash_str.encode()).hexdigest()

    def sha256(self):
        return hashlib.sha256(self.hash_str.encode()).hexdigest()

    def sha384(self):
        return hashlib.sha384(self.hash_str.encode()).hexdigest()

    def sha512(self):
        return hashlib.sha512(self.hash_str.encode()).hexdigest()

    def blake2b(self):
        return hashlib.blake2b(self.hash_str.encode()).hexdigest()

    def blake2s(self):
        return hashlib.blake2s(self.hash_str.encode()).hexdigest()

class KCrack:
    def __init__(self):
        self.gen = Generator()
        self.key = CheckKey()
        self.red = colorama.Fore.RED
        self.yellow = colorama.Fore.YELLOW
        self.blue = colorama.Fore.BLUE
        self.green = colorama.Fore.GREEN
        self.reset = colorama.Fore.RESET
        self.bright = colorama.Style.BRIGHT
        self.dim = colorama.Style.DIM
        self.normal = colorama.Style.NORMAL
        self.reset_all = colorama.Style.RESET_ALL
        self.intro = f"""
        {self.bright}
        {self.bright}
{self.yellow}    __  __                    __     ______                           __          {self.blue}   ______              
{self.yellow}   / / / /  ____ _   _____   / /_   / ____/   _____  ____ _  _____   / /__        {self.blue}  / ____/  ___    ____ 
{self.yellow}  / /_/ /  / __ `/  / ___/  / __ \ / /       / ___/ / __ `/ / ___/  / //_/        {self.blue} / / __   / _ \  / __ \ 
{self.yellow} / __  /  / /_/ /  (__  )  / / / // /___    / /    / /_/ / / /__   / ,<           {self.blue}/ /_/ /  /  __/ / / / /
{self.yellow}/_/ /_/   \__,_/  /____/  /_/ /_/ \____/   /_/     \__,_/  \___/  /_/|_|{self.blue}   ______{self.blue} \____/   \___/ /_/ /_/ 
                                                                          /_____/                       
 
{self.green}Hash-Cracker & WordList-Generator Tool{self.yellow} By @CyberSpire {self.green}
    """

    def pass_found(self, target, key, obj_time_time):
        # Implementation remains unchanged, just a placeholder for your original method
        main.clear()
        print(self.intro)
        style = "-"*len(key)
        style2 = "-"*len(target)
        hours,mins,sec = main.stop_watch(obj_time_time)
        time_len = "-"*len(f"{hours}{mins}{sec}")
        show_key = f"""{self.bright}{self.red}
        ,-----------{time_len}---------------,
        |     {self.green}Time:   {self.red}[{self.green}{hours}{self.red}:{self.green}{mins}{self.red}:{self.green}{sec}{self.red}]         |
        '---------------{time_len}-----------'{self.bright}{self.red}
        ,---------------------------------{style}{style2}----------------,
        |   {self.green}Password Found :  {self.blue}Target : {self.red}[{self.green}{target}{self.red}] {self.blue}Password : {self.red}[{self.green}{key}{self.red}]   |
        '---------------------------------{style}{style2}----------------'
        {self.reset_all}
        """
        print(show_key)

    def dic_generated(self, target, key, obj_time_time):
        # Implementation remains unchanged, just a placeholder for your original method
        main.clear()
        print(self.intro)
        style = "-"*len(key)
        style2 = "-"*len(target)
        hours,mins,sec = main.stop_watch(obj_time_time)
        time_len = "-"*len(f"{hours}{mins}{sec}")
        show_key = f"""{self.bright}{self.red}
        ,-----------{time_len}---------------,
        |     {self.green}Time:   {self.red}[{self.green}{hours}{self.red}:{self.green}{mins}{self.red}:{self.green}{sec}{self.red}]         |
        '---------------{time_len}-----------'{self.bright}{self.red}
        ,--------------------------------------{style}{style2}------------------,
        |   {self.green}Dictionary Generated :  {self.blue}Target : {self.red}[{self.green}{target}{self.red}] {self.blue}File Saved : {self.red}[{self.green}{key}{self.red}]  |
        '--------------------------------------{style}{style2}------------------'
        {self.reset_all}
        """
        print(show_key)


    def clear(self):
        os.system('cls' if os.name == 'nt' else 'clear')

    def stop_watch(self, start_time):
        tt = time.time() - start_time
        mins, sec = divmod(tt, 60)
        hours, mins = divmod(mins, 60)
        return int(hours), int(mins), int(sec)

    def dic_gen_show(self):
        # Implementation remains unchanged, just a placeholder for your original method
        while self.th_stop:
            for i in ["\\", "|", "/", "-"]:
                time.sleep(0.4)
                dot = i * 3
                print()
                print(f"\033[A{self.bright}{self.red}Generating{dot} {self.reset_all}\033[A")        


    def trying(self, key, obj_time_time):
        # Implementation remains unchanged, just a placeholder for your original method
        hours, mins, sec = main.stop_watch(obj_time_time)
        key_len = " " * int(20 - len(key))
        print()
        print(
            f"\033[A{self.bright}{self.red}Trying [{self.green}{key}{self.red}]{key_len}[{self.blue}{hours}:{mins}:{sec}{self.red}] [{self.blue}Ctrl+C for Kill{self.red}]{self.reset_all}\033[A")

#---------------------------------------

    def my_start(self):
        main.clear()
        self._print_intro()
        while True:
            try:
                self._print_menu()
                command = input(f"{self.bright}{self.red}Enter a command: >>{self.reset_all}")
                if command == "1":
                    self._wordlist_submenu()
                elif command == "2":
                    self._hash_analyzer_submenu()
                elif command == "3":
                    self._brute_force_crack()
                elif command == "4":
                    self._dictionary_crack()
                elif command == "5":
                    self._rainbow_submenu()
                elif command == "0":
                    print(f"{self.bright}{self.green}Thank you for using HashCrack_Gen!{self.reset_all}")
                    exit()
                else:
                    print(f"{self.bright}{self.green}Invalid command. Please try again.{self.reset_all}")
            except KeyboardInterrupt:
                print(f"{self.bright}{self.green}\nOperation interrupted. Please try again.{self.reset_all}")
                break

    def _print_intro(self):
        print(self.intro)

    def _print_menu(self):
        print(f"""{self.bright}{self.red}Select an option: 
        {self.green}1. Generate Wordlist
        2. Hash Analyzer/Generator
        3. Brute Force Crack
        4. Dictionary Crack
        5. Rainbow Table
        0. Exit {self.reset_all}""")
        
    def _wordlist_submenu(self):
        while True:
            try:
                print(f"""{self.bright}{self.red}Wordlist Submenu:
        {self.green}1. Generate Random Letters Wordlist
        2. Generate Custom Wordlist
        0. Back to main menu""")
                choice = input(f"{self.bright}{self.red}Enter your choice: {self.reset_all}")
                if choice == "1":
                    self._generate_wordlist()
                elif choice == "2":
                    self._generate_custom_wordlist()
                elif choice == "0":
                    print(f"{self.bright}{self.blue}Returning to main menu...{self.reset_all}")
                    break
                else:
                    print(f"{self.bright}{self.red}Invalid choice. Please try again.{self.reset_all}")
            except KeyboardInterrupt:
                print(f"{self.bright}{self.red}\nOperation interrupted. Returning to main menu...{self.reset_all}")
                break

    def _hash_analyzer_submenu(self):
        while True:
            try:
                print(f"""{self.bright}{self.red}Hash Analyzer Submenu:
        {self.green}1. Analyze Hash
        2. Generate Hash Value
        0. Back to main menu""")
                choice = input(f"{self.bright}{self.red}Enter your choice: {self.reset_all}")
                if choice == "1":
                    self._identify_hash()
                elif choice == "2":
                    self._hash_generator()
                elif choice == "0":
                    print(f"{self.bright}{self.blue}Returning to main menu...{self.reset_all}")
                    break
                else:
                    print(f"{self.bright}{self.red}Invalid choice. Please try again.{self.reset_all}")
            except KeyboardInterrupt:
                print(f"{self.bright}{self.red}\nOperation interrupted. Returning to main menu...{self.reset_all}")
                break
                
    def _rainbow_submenu(self):
        while True:
            try:
                print(f"""{self.bright}{self.red}RainbowTable Submenu:
        {self.green}1. Generate Wordlist Rainbow Table
        2. Generate Number-Range Rainbow Table
        0. Back to main menu""")
                choice = input(f"{self.bright}{self.red}Enter your choice: {self.reset_all}")
                if choice == "1":
                    self._generate_rainbow_table()
                elif choice == "2":
                    self._generate_rainbow_numbers()
                elif choice == "0":
                    print(f"{self.bright}{self.blue}Returning to main menu...{self.reset_all}")
                    break
                else:
                    print(f"{self.bright}{self.red}Invalid choice. Please try again.{self.reset_all}")
            except KeyboardInterrupt:
                print(f"{self.bright}{self.red}\nOperation interrupted. Returning to main menu...{self.reset_all}")
                break

    def _generate_wordlist(self):
        b_str = input(f"{self.bright}{self.red}Input Characters >>{self.reset_all}")
        b_min = int(input(f"{self.bright}{self.red}Input Min Length Password >>{self.reset_all}"))
        b_max = int(input(f"{self.bright}{self.red}Input Max Length Password >>{self.reset_all}"))
        b_limit = int(input(f"{self.bright}{self.red}Input Total Count of Password wordlist >>{self.reset_all}"))
        b_path = input(f"{self.bright}{self.red}Input File name or path >>{self.reset_all}").replace("'", "").replace('"',
                                                                                                                    "").lstrip().rstrip()
        start_time = time.time()
        b_list = open(b_path, "w")
        th = threading.Thread(target=main.dic_gen_show)
        self.th_stop = True
        th.start()
        for i in self.gen.Random(b_str, b_min, b_max, b_limit):
            b_list.write(str(i) + "\n")
        b_list.close()
        self.th_stop = False
        time.sleep(2)
        main.dic_generated(b_str, b_path, start_time)
        input(f"{self.bright}{self.green}Press Enter to main #{self.reset_all}")
        main.my_start()
                
    def _brute_force_crack(self):
        b_hash = input(f"{self.bright}{self.red}Input Encrypted Hash String >>{self.reset_all}").replace("'", "").replace('"',"").lstrip().rstrip()
        hash_type = input(f"{self.bright}{self.red}Select {self.blue}[1]MD5 [2]SHA1 [3]SHA224 [4]SHA256 [5]SHA384 [6]SHA512 [7]BLAKE2B [8]BLAKE2S \n{self.red}Type >>{self.reset_all}")
        b_str = input(f"{self.bright}{self.red}Input Characters to generate word combinations >>{self.reset_all}")
        b_min = int(input(f"{self.bright}{self.red}Input Min Length Password >>{self.reset_all}"))
        b_max = int(input(f"{self.bright}{self.red}Input Max Length Password >>{self.reset_all}"))
        start_time = time.time()
        for i in self.gen.BrutForce(b_str, b_min, b_max):
            main.trying(i, start_time)
            if self.key.hash_key(b_hash, str(i), hash_type):
                main.pass_found(b_hash, i, start_time)
                break
            else:
                pass
        input(f"{self.bright}{self.green}Press Enter to main #{self.reset_all}")
        main.my_start()
        
    def _dictionary_crack(self):
        b_hash = input(f"{self.bright}{self.red}Input Encrypted Hash String >>{self.reset_all}").replace("'", "").replace('"',"").lstrip().rstrip()
        hash_type = input(f"{self.bright}{self.red}Select {self.blue}[1]MD5 [2]SHA1 [3]SHA224 [4]SHA256 [5]SHA384 [6]SHA512 [7]BLAKE2B [8]BLAKE2S \n{self.red}Type >>{self.reset_all}")
        b_dic = input(f"{self.bright}{self.red}Input Dictionary File Path or Name >>{self.reset_all}")
        start_time = time.time()
        for i in self.gen.Dictionary(b_dic):
            main.trying(i, start_time)
            if self.key.hash_key(b_hash, i, hash_type):
                main.pass_found(b_hash, i, start_time)
                break
            else:
                pass
        input(f"{self.bright}{self.green}Press Enter to main #{self.reset_all}")
        main.my_start()

    def _generate_wildcard(self):
        words = input(f"{self.bright}{self.red}Enter words (separated by spaces): >>{self.reset_all}").split()
        numbers = input(f"{self.bright}{self.red}Enter special symbols & numbers together to append at ending word (separated by spaces): >>{self.reset_all}").split()
        def generate_and_print_wordlist():
            wordlist = self.gen.generate_wordlist_wildcard(words, numbers)
            print(f"{self.bright}{self.blue}Generated Wordlist: {self.reset_all}")
            for word in wordlist:
                print(word)    
        thread = threading.Thread(target=generate_and_print_wordlist)
        thread.start()
        thread.join()
        
    def _generate_custom_wordlist(self):
        base_words = input(f"{self.bright}{self.red}Enter multiple base words separated by commas (e.g., hello,world): >>{self.reset_all}").split(",")
        numbers = input(f"{self.bright}{self.red}Enter multiple numbers separated by commas (e.g., 123,456,789): >>{self.reset_all}").split(",")
        numbers = [int(number) for number in numbers] if numbers else None
        wordlists = self.gen.Custom_Wordlists_Replace(base_words, numbers)
        with open("wordlist.txt", "w") as file:
            for wordlist in wordlists:
                for word in wordlist:
                    file.write(word + "\n")
                file.write("\n")  # Add a blank line between wordlists
        print(f"{self.bright}{self.red}Wordlists generated successfully in file -> wordlist.txt{self.reset_all}")   
        
    
    def _identify_hash(self):
        # Take user input
        input_hash = input(f"{self.bright}{self.red}Enter the hash value: >>{self.reset_all}")
        algorithm = self.gen.Identify_Hash_Algorithm(input_hash)
        print(f"{self.bright}{self.green}The hash is likely generated using {self.red}[{algorithm}]{self.green} algorithm.{self.reset_all}")
        
    def _hash_generator(self):
        words = input(f"{self.bright}{self.red}Enter the words (separated by commas): >>{self.reset_all}").split(',')
        algorithms = input(f"{self.bright}{self.red}Enter the hash algorithms (separated by commas): >>{self.reset_all}").split(',')
        algorithms = [algo.strip().lower() for algo in algorithms]  # Ensure lowercase
        print(f"{self.bright}{self.green}Analyzing hashes...{self.reset_all}")
        hash_results = self.gen.Analyze_Hashes([word.strip() for word in words], algorithms)
        if hash_results:
            print(f"{self.bright}{self.green}Hash analysis complete:{self.reset_all}")
            for word, word_results in hash_results.items():
                print(f"{self.bright}{self.green}Word: {self.yellow}{word}")
                for algo, value in word_results.items():
                    print(f"{self.bright}{self.red}{algo}: {self.yellow}{value}")
                print()

    
    def _generate_rainbow_table(self):
        wordlist_file = input(f"{self.bright}{self.red}Enter the path of the wordlist file: >>{self.reset_all}").strip()
        algorithm = input(f"{self.bright}{self.red}Enter the hash algorithm (md5, sha1, sha256, etc.): >>{self.reset_all}").strip().lower()
        output_file = input(f"{self.bright}{self.red}Enter the output file name: >>{self.reset_all}").strip()
        self.gen.Generate_RainbowTable(wordlist_file, algorithm, output_file)
        print(f"{self.bright}{self.green}Rainbow table generated successfully!{self.reset_all}")

    
    def _generate_rainbow_numbers(self):
        algorithm = input(f"{self.bright}{self.red}Enter the hash algorithm (md5, sha1, sha256): >>{self.reset_all}").lower()
        start = int(input(f"{self.bright}{self.red}Enter the starting number of the range: >>{self.reset_all}"))
        end = int(input(f"{self.bright}{self.red}Enter the ending number of the range: >>{self.reset_all}"))
        filename = input(f"{self.bright}{self.red}Enter the file name to save the rainbow table: >>{self.reset_all}")       
        self.gen.Generate_RainbowTable_Numbers(algorithm, filename, start, end)
        print(f"{self.bright}{self.green}Rainbow table generated successfully!{self.reset_all}")
        
if __name__ == "__main__":
    while True:
        try:
            main = KCrack()
            main.my_start()
        except KeyboardInterrupt:
            pass
