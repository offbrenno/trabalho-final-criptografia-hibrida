"""Hash de arquivos e escrita sem sobrescrever arquivos existentes."""
import hashlib
from pathlib import Path
import shutil


class ErroCriptografia(RuntimeError):
    """Erro de entrada, formato ou operação criptográfica."""


def sha256(arquivo: Path) -> str:
    h = hashlib.sha256()
    with Path(arquivo).open('rb') as entrada:
        for bloco in iter(lambda: entrada.read(1024 * 1024), b''):
            h.update(bloco)
    return h.hexdigest()


def copiar_novo(origem: Path, destino: Path):
    destino.parent.mkdir(parents=True, exist_ok=True)
    # O modo exclusivo impede sobrescrita mesmo em caso de corrida.
    with destino.open('xb') as saida, origem.open('rb') as entrada:
        shutil.copyfileobj(entrada, saida)


def escrever_novo(destino: Path, dados: bytes, privado=False):
    destino.parent.mkdir(parents=True, exist_ok=True)
    with destino.open('xb') as saida:
        if privado:
            destino.chmod(0o600)
        saida.write(dados)
