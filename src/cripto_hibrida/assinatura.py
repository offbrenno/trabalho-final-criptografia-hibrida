"""Assinatura destacada RSA/SHA-256 de arquivo genérico. Não é assinatura PDF."""
from pathlib import Path
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, utils
from .arquivos import ErroCriptografia, escrever_novo, sha256
from .chaves import carregar_privada, carregar_publica


def assinar(entrada: Path, privada: Path, assinatura: Path) -> Path:
    entrada, privada, assinatura = map(lambda p: Path(p).resolve(), (entrada, privada, assinatura))
    if assinatura.exists():
        raise ErroCriptografia('A assinatura de saída já existe.')
    chave = carregar_privada(privada)
    digest = bytes.fromhex(sha256(entrada))
    dados = chave.sign(digest, padding.PKCS1v15(), utils.Prehashed(hashes.SHA256()))
    escrever_novo(assinatura, dados)
    return assinatura


def verificar(entrada: Path, publica: Path, assinatura: Path) -> bool:
    entrada, publica, assinatura = map(lambda p: Path(p).resolve(), (entrada, publica, assinatura))
    chave = carregar_publica(publica)
    digest = bytes.fromhex(sha256(entrada))
    try:
        chave.verify(assinatura.read_bytes(), digest, padding.PKCS1v15(), utils.Prehashed(hashes.SHA256()))
    except InvalidSignature:
        return False
    return True
