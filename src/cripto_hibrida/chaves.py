"""Geração e leitura de chaves RSA PEM por biblioteca, sem binário externo."""
from pathlib import Path
import re
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from .arquivos import ErroCriptografia, escrever_novo


def carregar_publica(arquivo: Path) -> rsa.RSAPublicKey:
    try:
        chave = serialization.load_pem_public_key(Path(arquivo).read_bytes())
    except (ValueError, TypeError) as erro:
        raise ErroCriptografia('Chave pública PEM inválida.') from erro
    if not isinstance(chave, rsa.RSAPublicKey) or chave.key_size < 2048:
        raise ErroCriptografia('A chave pública deve ser RSA com pelo menos 2048 bits.')
    return chave


def carregar_privada(arquivo: Path) -> rsa.RSAPrivateKey:
    try:
        chave = serialization.load_pem_private_key(Path(arquivo).read_bytes(), password=None)
    except (ValueError, TypeError) as erro:
        raise ErroCriptografia('Chave privada PEM inválida ou protegida por senha não suportada nesta CLI.') from erro
    if not isinstance(chave, rsa.RSAPrivateKey) or chave.key_size < 2048:
        raise ErroCriptografia('A chave privada deve ser RSA com pelo menos 2048 bits.')
    return chave


def gerar_chaves(pasta: Path, prefixo: str = 'grupo') -> tuple[Path, Path]:
    if not re.fullmatch(r'[A-Za-z0-9_-]+', prefixo):
        raise ErroCriptografia('Prefixo deve conter apenas letras, números, _ ou -.')
    pasta = Path(pasta).resolve()
    privada, publica = pasta / f'{prefixo}_privada.pem', pasta / f'{prefixo}_publica.pem'
    if privada.exists() or publica.exists():
        raise ErroCriptografia('As chaves já existem; escolha outro prefixo ou pasta.')
    chave = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    privada_pem = chave.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption())
    publica_pem = chave.public_key().public_bytes(serialization.Encoding.PEM,
                                                 serialization.PublicFormat.SubjectPublicKeyInfo)
    escrever_novo(privada, privada_pem, privado=True)
    escrever_novo(publica, publica_pem)
    return privada, publica
