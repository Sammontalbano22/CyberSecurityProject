import string

"""
Author: Sam Montalbano
Date: 4/17/25
Mathematical Cryptography
Project 1

This project is designed to analyze and break Vigenère cipher texts using the 
Index of Coincidence and frequency analysis methods.
"""

# Function: estimate_key_length
# Strategy:Uses strategy 3 from the slides. It measures the number of character coincidences between the ciphertext
# and its shifted versions. The shift that gives the most matches is likely a multiple
# of the key length.
def estimate_key_length(ciphertext: str, max_shift: int = 20) -> int:
    ciphertext = ''.join(filter(str.isalpha, ciphertext.upper()))  #ensures I have only letters.
    coincidences = []
    for shift in range(1, max_shift + 1):
        count = sum(
            1 for i in range(len(ciphertext) - shift)
            if ciphertext[i] == ciphertext[i + shift]
        )
        coincidences.append(count)
    
    # Print coincidence count per shift
    print("\nIndex of Coincidence for each shift:")
    for i, coincidence in enumerate(coincidences, 1):
        print(f"  Shift {i}: {coincidence}")
    
    # Return the shift (likely key length) with the highest coincidences
    return coincidences.index(max(coincidences)) + 1


# Function: split_subtexts
# Splits ciphertext into multiple groups based on the key length
# Each group corresponds to letters encrypted with the same Caesar cipher shift.

def split_subtexts(ciphertext: str, key_length: int) -> list:
    ciphertext = ''.join(filter(str.isalpha, ciphertext.upper()))  # Clean input
    return [''.join(ciphertext[i::key_length]) for i in range(key_length)]


# Function: calculate_frequencies
# Counts the frequency of each letter in a subtext.

def calculate_frequencies(subtext: str) -> dict:
    frequencies = {letter: 0 for letter in string.ascii_uppercase}
    for char in subtext.upper():
        if char in frequencies:
            frequencies[char] += 1
    return frequencies


# Function: frequency_analysis
# Compares the frequency of letters in a subtext to expected English letter frequencies.
# Returns the most likely Caesar shift for that subtext.

def frequency_analysis(subtext: str) -> int:
    english_frequencies = {
        'A': 0.082, 'B': 0.015, 'C': 0.028, 'D': 0.043, 'E': 0.13, 'F': 0.022,
        'G': 0.02, 'H': 0.061, 'I': 0.07, 'J': 0.0015, 'K': 0.0077, 'L': 0.04,
        'M': 0.024, 'N': 0.067, 'O': 0.075, 'P': 0.019, 'Q': 0.00095, 'R': 0.06,
        'S': 0.063, 'T': 0.091, 'U': 0.028, 'V': 0.0098, 'W': 0.024, 'X': 0.0015,
        'Y': 0.02, 'Z': 0.00074
    }
    subtext_frequencies = calculate_frequencies(subtext)
    max_ic = -1  # Max index of coincidence
    best_shift = 0

    # Try all possible shifts to find the best match with English frequencies
    for shift in range(26):
        ic = 0
        for letter in string.ascii_uppercase:
            shifted_letter = chr(((ord(letter) - ord('A') + shift) % 26) + ord('A'))
            ic += subtext_frequencies.get(shifted_letter, 0) * english_frequencies[letter]
        if ic > max_ic:
            max_ic = ic
            best_shift = shift
    return best_shift


# Function: find_vigenere_key
# Uses frequency analysis to deduce each character of the Vigenère key.

def find_vigenere_key(ciphertext: str, key_length: int) -> str:
    subtexts = split_subtexts(ciphertext, key_length)
    key = ''
    for subtext in subtexts:
        shift = frequency_analysis(subtext)
        key += chr(shift + ord('A'))
    return key


# Function: vigenere_decrypt
# Decrypts the ciphertext using the recovered Vigenère key.

def vigenere_decrypt(ciphertext: str, key: str) -> str:
    decrypted_text = ''
    key_length = len(key)
    for i, char in enumerate(ciphertext):
        if char.isalpha():
            shift = ord(key[i % key_length].lower()) - ord('a')
            decrypted_letter = chr(((ord(char.lower()) - ord('a') - shift) % 26) + ord('a'))
            decrypted_text += decrypted_letter
        else:
            decrypted_text += char
    return decrypted_text



ciphertexts = [

    'TQUFEROGQIAEQIAETWTUPQIAOOIYWIRSPERVDXHRWMTGWIDRLXHGSETOCMNTDXOGLPOOWMTRCETVZRIJTPLSLGEZJJENCMWVWPPRCQIGTXTBAESFZZEEXIAAOXHEZYGUXIAAOAHRYMTULWGBYIPNDXIJTPLGFVNGSIIAYIRRJITBDIEVEWPNELWUPVEGSIFRLVHNDKOAPXHRCIWVWPBRYSTUTRGBYPYVHMLYCIMNTR',
    'PYSUHTSHLNGTGWQFOTXRIMZJDGTGWAMLQZEJDVQKVPTXRIZZSEJDVCDXQWHGUSWHNOPVPRBWWISMPQPQUSWHNOPVPRBWWISMPGIZSDONVILHPKPECUEJDVIGFCSPQFJSHRPXSPQFCSSZOOGDLFLFTAMFSHNNPOGDPWRPMEDCBDBCSDCXDCBDBCSHZELBSRPXSPQFRZPCBYRHNNPOGDWPFNUFCMQZEHVNZSPHWDZDOSZOOUAZELBSABOWDCPYCIJOZKVNBDYNNVCRPC',
    'RQZPUIJWYCBMCMHJWYCXSZZCZCVSCHOTIOUEDAIDGILZRTVKEWFCMEEPIQZIPBLPEVPBGSMHCMJFAIZNCZCVEMIXQRRALZZIDMROBLPAIEPISWQPTIDAXPUTPAXEWWEBSXMMWQJEUCWIQAJIDQHPBLPOSWLIYLSZ',
    'AVNAEPAUWWDBCAWGTOTHBSBFYENLGFUHIFYZGPGAZIBCWIELKKZCBYJVRVOWZMCHYENLGFFVSLFZKUIDMMWAFVYHRFICARYHTAAWKBKVWTTJHEQBOAOVZOXQZKWYWVMVGOTSBAEPKUKSUBBJLANLLFKCIANTKHGRZMCHFTRUDFAKBLZCASEFWBCJYVUDGZQFSATVMVGSSOWAYQTZXWZHVRYKXFLLMZBITAOVGKZWBXPMVUFQZJWFTWTZGLABALDMRMGAFIGAZVRFGEQBKUZVCHGLEBHBYEXHIFMFCHYLTFHMDBREPISZGSZRBULDKURGGBOAJVJYXSYGBLZCAKGDUYSAEWTZXDXGBQCMGTLFATBYZVKSBFQGGAWQQLGSZVSNCBHLTLZRFVGMYURGGBANOVOUGLTSBFEQRSGWEGBBQVXLFWYPSETVMUPZMHBLZCTOTVZOBQYENHMFKCIAWWYA',
    'MLNTJKVPIWCJQYPPPOCYSIDOPTJQYEELOTLUQYEVMALHKVONQYENDDMOYPLJOPZIEWTWENSAZSWQCSIDOBTHTCALSAZQKTVOBSAGDWQOKCCHQGAAEKOPPPPNAFNMHWARKVYWJPNWFCPEDMJJMGAZOELWESPIIXWASKUPIIOALCAADLIAWAMWVVXWZGELOVEXQRAVZQOSWVOEELOAEWVOEVZJBSAATZMZBBSAZZWLCWQYBIWHQYKVXUASKMDDMLZQYCWFPNZNBSAMLOBNKIDPTZNLVJWHOQGAXLELDKUPZCPOOPPBTJBSNWFCPEWVRHMOQXTJJWQMDDMHWAXWZCEMOSPPJEPBQCOBXABDKWYPWMALTRWCYMOEPPHXPZPPNWFPWQWRLIQRQMDOJFPQFOMOWTTPBWABZKUFYPQKZNAEPZZZRMEDIEYICWAQWZLOEPYWFHLLXIYZWYALTPWFPEPOBDLTTPCAKVLZICGALZVTCPEXWEDIRNMPEVREBHWAMAAEOPPPCCJMOWZZQVOPWWKWVWBXAIDEELOELHSTJIHWGTDMLNLSAZDWGZRMCIGDDWFHLPNEPHTXAMEWOLEVDKUPZIJKVEDMLRMYQMEWVRHMOQXTJJWQMTDIOWRZXQYPPPCZPWBYKZEDEZKLDSWCGQYCIDWKZKSQKZLOXPHTMQBTJMGAZOELWESPEBLHTEDIEICNDIYZWYALLUBSAIIFCDPNPHTDKQONQQPMOZWHJBZJMHKZWAIYOESAZPEPLLXPJMOPWMAMXLTZUMOSWCGQYBWCWESETPKVLBQDDQYXWLPZTCPEKCEOQOAWQZMWWKCKQIXCEWTWPPPSPTHMTSIDWTZJMEDMAWAESIDYTZOMMAPTJLTOMPJIWKBZBEZIMYXCEOPPJMGAZPOKLLMOIGXEVOWVOERFOBRNMHPIYCTPZCAEVMHCPETTRMOSQEDBSAUZJUZJBLCCPOBCAMEEVLXIDAUPJBOKEYPPPOBLEZDPPPNMHWAXQATYQYPPPYIQQCDWBYEOSPIYZZPRWWQBTKVTJBSAITNBSAVSAAEWZEALTJBZZMLHQYCETPPDHIGAALJLDKUPPPTJOTJATZMZBPTILTALDDMSWLEKAPHTPRMCUBSEVROPPKEYALLJLQNWKACAEVDELPWVOSPPJNTJIWHGEDMMKBEKUQATWKCEEJPYIXAETPPONIHJBSAWYHGEDQYCQVJMHDWHPWOKELOBZGMPLWYGMPLQYKVWESPWJTNLEDIEBTPSBLJOWALFLQYXTFAAZJWHEURKQYXINGIRWQYEOZPBZCMEPWSAZDKUPDWHWTWPPPLMZLTPSMFOMOPWVJWHPPPUZPWVTHTFOQZJBZIMYKEDKUPWZPIIEDMXWBTYQLJADKUPWZPYICLMYPMCOETRMDZWYPSYKESKETPIWHOZPAEWZEALTZWYPSYKEHDIEPPPUZPZWTJETPPEDMTNTTRMDXCEIMTIAEETWKVEDMCKIODMLZQYBWCWVZPPPNRZEVESMLHELUAOELQAMWPPPOIXAEPFCDPALSQEBZZIIOENQAZPJBAKQYPWQRQPSBLJOWALFLQYXTFA',
    'UMMDBZMIVVWBRVPMBVIXCRGENRLMLRAOOEIFOFVIOKPWKVXUTXQZLFZYGKQATREMEWZASFBTKIAMYTPURUZQTDIZEFNGYYIPSROUIUMOUUMDXZVSYWWDKOKTGEOUTXKAJVLYKJAMMVAIOKPAAINDOVVPYRVPVFAEOSTKQVMBOEOEKTZQZJNDUDXMXVVFYJQNRZVSYFZFKRKTKIA'
]
2
for i, ciphertext in enumerate(ciphertexts, start=1):
    print(f"\nCiphertext {i}:")
    key_length = estimate_key_length(ciphertext)
    recovered_key = find_vigenere_key(ciphertext, key_length)
    decrypted_text = vigenere_decrypt(ciphertext, recovered_key)

    print(f"\n  Estimated Key Length: {key_length}")
    print(f"  Recovered Key: {recovered_key}")
    print(f"  Decrypted Text: {decrypted_text}\n")
