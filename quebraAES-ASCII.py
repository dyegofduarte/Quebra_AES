import itertools
from Crypto.Cipher import AES
import sys

def pad_key(key: str, key_size: int = 16) -> bytes:
    """Ajusta a chave para exatamente 16 bytes (completando ou truncando)."""
    if len(key) > key_size:
        return key[:key_size].encode('utf-8')  # Trunca se for maior que 16 bytes
    return key.encode('utf-8').ljust(key_size, b'\x00')  # Preenche com bytes nulos

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
    """Verifica se o texto descriptografado é legível (caracteres ASCII)."""
    try:
        text = plaintext.decode('utf-8')
        return all(32 <= ord(c) <= 126 or c in ('\n', '\r') for c in text)  # Apenas caracteres legíveis
    except UnicodeDecodeError:
        return False

def read_hex_file(file_path: str) -> bytes:
    """Lê um arquivo .hex e retorna o conteúdo como bytes."""
    with open(file_path, 'r') as file:
        hex_data = file.read().strip()  # Lê o conteúdo do arquivo e remove espaços extras
        return bytes.fromhex(hex_data)  # Converte o texto hexadecimal em bytes

def brute_force_aes_ecb(ciphertext: bytes, known_key: str, charset: str):
    """Realiza a busca exaustiva para descobrir o restante da chave."""
    unknown_length = 16 - len(known_key)
    if unknown_length <= 0:
        raise ValueError("A chave conhecida já possui o tamanho máximo de 16 bytes.")

    total_combinations = len(charset) ** unknown_length
    print(f"Parte conhecida da chave: '{known_key}'")
    print(f"Tentando {total_combinations} combinações possíveis...\n")

    # Itera sobre todas as combinações possíveis para os caracteres restantes
    for index, combo in enumerate(itertools.product(charset, repeat=unknown_length), start=1):
        # Gera a chave completa com a parte conhecida
        full_key = known_key + ''.join(combo)
        padded_key = pad_key(full_key)

        # Mostra progresso atual, editar as 2 alinhas abaixo para ver se vai mais rapido
        sys.stdout.write(f"\rTentando combinação {index} de {total_combinations}...")  
        sys.stdout.flush()

        # Descriptografa o texto
        plaintext = decrypt_aes_ecb(ciphertext, padded_key)

        # Verifica se o texto descriptografado é válido
        if plaintext and is_plaintext_valid(plaintext):
            print(f"\nChave encontrada: '{full_key}'")
            print(f"Texto descriptografado: {plaintext.decode('utf-8')}")
            return full_key

    print("\nNenhuma chave válida encontrada.")
    return None


#############################################
### FUNÇÃO PARA MOSTRAR MANUAL
def manual():
    print("Formas de uso: python quebraAES-ASCII.py <Chave_Conhecida> <Arquivo com texto a Decifrar>")
    print("OBS 1 - A chave deve ter até 16 caracteres")
    print("OBS 2 - Quanto mais caracteres se souber da chave mais ráido o script roda para descobrir a chave")
    sys.exit(1)

#############################################
### FUNÇÃO MAIN
if __name__ == "__main__":
    if len(sys.argv) < 3:
        manual()
    
    # Parte conhecida da chave quanto mais caracteres conhecidos, mais rápido para encontrar a chave
    parte_chave_conhecida = sys.argv[1]
    
    # Arquivo .hex contendo o texto criptografado
    arquivo_hex = sys.argv[2]

    
    ### Quanto mais caracteres tiver o charset, mais demorado o script fica, pois tem mais caracteres/combinações para testar
    charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"   # Caracteres do ASCII
    #charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()"   # Alguns Caracteres do UTF8, pode-se adicionar mais caracteres para comparação
    
    # Lê o conteúdo criptografado do arquivo .hex
    texto_cifrado = read_hex_file(arquivo_hex)

    # Inicia o processo de brute-force para descobrir a chave
    brute_force_aes_ecb(texto_cifrado, parte_chave_conhecida, charset)

