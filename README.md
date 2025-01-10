# Quebra_AES
UFRGS | Computer Systems Security | Criptografia de Chave Pública


# Ferramentas usadas para validação e desenvolvimento do script
https://tophix.com/pt/development-tools/encrypt-text

https://www.devglan.com/online-tools/aes-encryption-decryption


# Enunciado seguido 

1. Considere que você recebeu um texto cifrado usando AES. Sabe-se que o texto cifrado era uma mensagem de texto em ASCII legível, mas se desconhece maiores detalhes (qual idioma, conteúdo, etc.). Considerando a tentativa de força bruta para quebrar a chave usada na cifragem, como você poderia automatizar os testes e saber quando um texto decifrado coerente foi encontrado?

   
2. O objetivo do trabalho é realizar a criptoanálise por força bruta do AES em modo ECB. Cada estudante vai receber dois textos cifrados, codificados em hexadecimal. Sabe-se que foram usadas chaves distintas para as duas cifragens, e que os arquivos que foram cifrados eram mensagens de texto em ASCII legível, mas se desconhece maiores detalhes (qual língua, conteúdo, etc), conforme discutido na questão anterior. Os arquivos com os textos cifrados estão no Moodle, um por estudante do curso.
O primeiro texto está cifrado com uma chave "fraca" (arquivo terminado por "-weak.txt"), da qual os 11 primeiros caracteres são conhecidos e os últimos 5 são somente letras [a-z][A-Z] ou dígitos [0-9]. A chave fraca está na forma
SecurityAESXXXXX


O segundo texto está cifrado com uma chave "forte" (arquivo terminado por "-strong.txt"), da qual 10 caracteres são conhecidos e os últimos 6 são somente letras [a-z][A-Z] ou dígitos [0-9]. A chave forte está na forma
Security00XXXXXX


Em ambos os casos, XXXXX são os caracteres a serem descobertos.
Para o trabalho ser considerado realizado, basta fornecer o identificador contido em cada texto decifrado e a respectiva chave. Você deve incluir também a implementação utilizada e uma breve descrição (10 a 20 linhas) da estratégia usada para resolver o problema. Quantas chaves por segundo você conseguiu testar em cada caso?
