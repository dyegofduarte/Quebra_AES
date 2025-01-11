import itertools
from Crypto.Cipher import AES
import sys

def pad_key(key: str, key_size: int = 16) -> bytes:
    """Garante que a chave tenha exatamente o tamanho necessário."""
    return key.encode('utf-8')[:key_size].ljust(key_size, b'\x00')

def remove_pkcs7_padding(plaintext: bytes) -> bytes:
    """Remove padding PKCS#7 do texto descriptografado."""
    padding_len = plaintext[-1]
    if all(p == padding_len for p in plaintext[-padding_len:]):
        return plaintext[:-padding_len]
    return plaintext

def decrypt_aes_ecb(ciphertext: bytes, key: bytes) -> bytes:
    """Descriptografa o texto criptografado usando AES-ECB com PKCS#7 padding."""
    cipher = AES.new(key, AES.MODE_ECB)
    try:
        plaintext = cipher.decrypt(ciphertext)
        # Remove padding PKCS#7
        return remove_pkcs7_padding(plaintext)
    except (ValueError, KeyError):
        return None

def is_plaintext_valid(plaintext: bytes) -> bool:
    """Verifica se o texto descriptografado é legível (UTF-8 válido)."""
    try:
        text = plaintext.decode('utf-8')
        return all(32 <= ord(c) <= 126 or c.isprintable() for c in text)  # Apenas caracteres legíveis
    except UnicodeDecodeError:
        return False

def read_hex_file(file_path: str) -> bytes:
    """Lê um arquivo .hex e retorna o conteúdo como bytes."""
    with open(file_path, 'r') as file:
        hex_data = file.read().strip()  # Lê o conteúdo do arquivo e remove espaços extras
        return bytes.fromhex(hex_data)  # Converte o texto hexadecimal em bytes

def generate_utf8_charset() -> str:
    """Gera um charset contendo caracteres UTF-8 práticos."""
    # Inclui caracteres básicos (ASCII), acentuados e símbolos úteis
    basic_ascii = ''.join(chr(i) for i in range(32, 127))  # ASCII imprimível
    latin1 = ''.join(chr(i) for i in range(160, 256))  # Latin-1 Supplement
    emojis = '😀😁😂🤣😃😄😅😆😉😊😋😎😍😘🥰😇🙃🤔🤩🤗🥳'  # Alguns emojis básicos
    return basic_ascii + latin1 + emojis

def brute_force_aes_ecb(ciphertext: bytes, known_key: str, charset: str):
    """Realiza a busca exaustiva para descobrir o restante da chave."""
    unknown_length = 16 - len(known_key)
    if unknown_length <= 0:
        raise ValueError("A chave conhecida já possui o tamanho máximo de 16 bytes.")
    if len(known_key) > 16:
        raise ValueError("A chave conhecida é maior que 16 bytes.")

    total_combinations = len(charset) ** unknown_length
    print(f"Parte conhecida da chave: '{known_key}'")
    print(f"Tentando {total_combinations} combinações possíveis...\n")

    # Itera sobre todas as combinações possíveis para os caracteres restantes
    for index, combo in enumerate(itertools.product(charset, repeat=unknown_length), start=1):
        # Gera a chave completa com a parte conhecida
        full_key = known_key + ''.join(combo)
        padded_key = pad_key(full_key)

        # Mostra progresso atual, se desabilitar o progresso roda mais rápido 
        #sys.stdout.write(f"\rTentando combinação {index} de {total_combinations}...")  
        #sys.stdout.flush()

        # Descriptografa o texto
        plaintext = decrypt_aes_ecb(ciphertext, padded_key)

        # Verifica se o texto descriptografado é válido
        if plaintext and is_plaintext_valid(plaintext):
            print(f"\nChave encontrada: '{full_key}'")
            print(f"Texto descriptografado: {plaintext.decode('utf-8')}")
            return full_key

    print("\nNenhuma chave válida encontrada.")
    return None


if __name__ == "__main__":
    # Caminho para o arquivo .hex contendo o texto criptografado
    arquivo_hex = "exemplo-1.hex"  # Substitua pelo caminho do seu arquivo .hex

    # Parte conhecida da chave quanto mais caracteres conhecidos, mais rápido para encontrar a chave
    parte_chave_conhecida = "SecurityAESab"  # Parte conhecida da chave (substitua pelo que você sabe)

    ### Quanto mais caracteres tiver o charset, mais demorado o script fica, pois tem mais caracteres/combinações para testar
    #charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"   # Caracteres do ASCII
    #charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()"   # Alguns Caracteres do UTF8, pode-se adicionar mais caracteres para comparação
    charset = generate_utf8_charset()  # Charset UTF-8 gerado

    # Lê o conteúdo criptografado do arquivo .hex
    texto_cifrado = read_hex_file(arquivo_hex)

    # Inicia o processo de brute-force para descobrir a chave
    brute_force_aes_ecb(texto_cifrado, parte_chave_conhecida, charset)