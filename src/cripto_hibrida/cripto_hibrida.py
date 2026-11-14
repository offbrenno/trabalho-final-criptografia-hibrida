"""AES-256-CBC/PBKDF2 e RSA-OAEP. Compatível com os pacotes v1 já gerados."""
import base64
import json
import os
from pathlib import Path
import tempfile
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from .arquivos import ErroCriptografia, copiar_novo
from .chaves import carregar_publica, carregar_privada

PARAMETROS = {'versao': 1, 'cifra': 'aes-256-cbc', 'kdf': 'pbkdf2-sha256',
              'iteracoes': 100000, 'segredo': 'base64-32-bytes',
              'rsa': 'oaep-sha256-mgf1-sha256'}
CABECALHO = b'Salted__'
TAMANHO_SALT = 8  # Formato usado pelo openssl enc 3.2.1 na Parte 2 e pelo pacote v1.
BLOCO_LEITURA = 1024 * 1024


def _oaep():
    return rsa_padding.OAEP(mgf=rsa_padding.MGF1(hashes.SHA256()),
                            algorithm=hashes.SHA256(), label=None)


def _derivar(segredo: bytes, salt: bytes):
    material = PBKDF2HMAC(algorithm=hashes.SHA256(), length=48, salt=salt,
                          iterations=100000).derive(base64.b64encode(segredo))
    return material[:32], material[32:]


def cifrar(entrada: Path, publica: Path, pacote: Path) -> Path:
    entrada, publica, pacote = map(lambda p: Path(p).resolve(), (entrada, publica, pacote))
    if not entrada.is_file():
        raise ErroCriptografia('Arquivo de entrada não encontrado.')
    if pacote.exists():
        raise ErroCriptografia('A pasta do pacote já existe; nenhum arquivo foi sobrescrito.')
    destinatario = carregar_publica(publica)
    segredo, salt = os.urandom(32), os.urandom(TAMANHO_SALT)
    chave, iv = _derivar(segredo, salt)
    pacote.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.hibrida-', dir=pacote.parent) as temp:
        stage = Path(temp)
        cifrador = Cipher(algorithms.AES(chave), modes.CBC(iv)).encryptor()
        padder = padding.PKCS7(128).padder()
        with entrada.open('rb') as origem, (stage/'mensagem.enc').open('wb') as saida:
            saida.write(CABECALHO + salt)
            for bloco in iter(lambda: origem.read(BLOCO_LEITURA), b''):
                saida.write(cifrador.update(padder.update(bloco)))
            saida.write(cifrador.update(padder.finalize()) + cifrador.finalize())
        (stage/'chave_aes.enc').write_bytes(destinatario.encrypt(segredo, _oaep()))
        (stage/'parametros.json').write_text(json.dumps(PARAMETROS, indent=2)+'\n', encoding='utf-8')
        os.rename(stage, pacote)
    return pacote


def decifrar(pacote: Path, privada: Path, saida: Path) -> Path:
    pacote, privada, saida = map(lambda p: Path(p).resolve(), (pacote, privada, saida))
    if saida.exists():
        raise ErroCriptografia('O arquivo de saída já existe; nenhum arquivo foi sobrescrito.')
    try:
        parametros = json.loads((pacote/'parametros.json').read_text(encoding='utf-8'))
    except (OSError, ValueError) as erro:
        raise ErroCriptografia('Pacote ausente ou parâmetros inválidos.') from erro
    if parametros != PARAMETROS:
        raise ErroCriptografia('Formato ou parâmetros do pacote não suportados.')
    destinatario = carregar_privada(privada)
    try:
        segredo = destinatario.decrypt((pacote/'chave_aes.enc').read_bytes(), _oaep())
    except ValueError as erro:
        raise ErroCriptografia('Não foi possível recuperar o segredo: chave ou pacote incompatível.') from erro
    if len(segredo) != 32:
        raise ErroCriptografia('O segredo recuperado deve ter 32 bytes.')
    saida.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.hibrida-', dir=saida.parent) as temp:
        restaurado = Path(temp)/'restaurado'
        try:
            with (pacote/'mensagem.enc').open('rb') as origem, restaurado.open('wb') as destino:
                if origem.read(8) != CABECALHO:
                    raise ErroCriptografia('Cabeçalho do arquivo cifrado inválido.')
                salt = origem.read(TAMANHO_SALT)
                if len(salt) != TAMANHO_SALT:
                    raise ErroCriptografia('Salt incompleto.')
                chave, iv = _derivar(segredo, salt)
                decifrador = Cipher(algorithms.AES(chave), modes.CBC(iv)).decryptor()
                unpadder = padding.PKCS7(128).unpadder()
                for bloco in iter(lambda: origem.read(BLOCO_LEITURA), b''):
                    destino.write(unpadder.update(decifrador.update(bloco)))
                destino.write(unpadder.update(decifrador.finalize()) + unpadder.finalize())
        except ValueError as erro:
            raise ErroCriptografia('Arquivo cifrado truncado, padding inválido ou segredo incorreto.') from erro
        copiar_novo(restaurado, saida)
    return saida
